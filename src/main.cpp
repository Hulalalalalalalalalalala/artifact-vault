#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

namespace {

constexpr const char* kVersion = "0.1.0";
constexpr std::size_t kMaxFileSize = 1u << 22;  // 4 MiB, ample for one certificate

constexpr std::string_view kPemBeginPrefix = "-----BEGIN ";
constexpr std::string_view kPemCertificateBegin = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kPemCertificateEnd = "-----END CERTIFICATE-----";

enum class Encoding { PEM, DER };

struct InspectError {
    std::string message;
};

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

bool isWhitespace(unsigned char ch) {
    return std::isspace(ch) != 0;
}

// RFC 2253 style keeps every attribute value (not only CN). Drop ESC_MSB so
// that converted UTF-8 content (e.g. Chinese names) is printed verbatim
// instead of being escaped as \XX byte sequences.
unsigned long distinguishedNameFlags() {
    return XN_FLAG_RFC2253 & ~static_cast<unsigned long>(ASN1_STRFLGS_ESC_MSB);
}

std::string formatDistinguishedName(X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        throw InspectError{"internal error: cannot allocate BIO"};
    }
    if (X509_NAME_print_ex(bio, name, 0, distinguishedNameFlags()) < 0) {
        BIO_free_all(bio);
        throw InspectError{"internal error: cannot render distinguished name"};
    }
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free_all(bio);
    return result;
}

// Renders an ASN.1 time as UTC with a trailing Z. ASN1_TIME_to_tm yields a
// broken-down UTC time; formatting it directly avoids any local time zone
// conversion, so the result is identical in every TZ setting.
std::string formatUtcZ(const ASN1_TIME* time) {
    struct tm parsed {};
    if (ASN1_TIME_to_tm(time, &parsed) != 1) {
        throw InspectError{"internal error: cannot parse certificate validity date"};
    }
    std::array<char, 32> buffer{};
    if (strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &parsed) == 0) {
        throw InspectError{"internal error: cannot format certificate validity date"};
    }
    return std::string(buffer.data());
}

std::string formatColonHex(const unsigned char* data, std::size_t length) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(length == 0 ? 0 : length * 3 - 1);
    for (std::size_t i = 0; i < length; ++i) {
        if (i != 0) {
            out.push_back(':');
        }
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

std::string readFile(const std::string& path) {
    const std::filesystem::path fsPath(path);
    std::error_code ec;
    if (std::filesystem::exists(fsPath, ec) &&
        !std::filesystem::is_regular_file(fsPath, ec) && !ec) {
        throw InspectError{"failed to read file '" + path +
                           "': path is not a regular file"};
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw InspectError{"failed to read file '" + path +
                           "': cannot open file (does it exist?)"};
    }
    file.seekg(0, std::ios::end);
    const std::streamoff end = file.tellg();
    if (!file || end < 0) {
        throw InspectError{"failed to read file '" + path + "': cannot determine file size"};
    }
    if (static_cast<std::size_t>(end) > kMaxFileSize) {
        throw InspectError{"invalid certificate in '" + path +
                           "': file is too large for a single certificate"};
    }
    std::string contents(static_cast<std::size_t>(end), '\0');
    file.seekg(0, std::ios::beg);
    if (end > 0 && !file.read(contents.data(), end)) {
        throw InspectError{"failed to read file '" + path + "': read error"};
    }
    return contents;
}

// Strict PEM shape check: whitespace may surround the blocks, but there must
// be exactly one CERTIFICATE block. A second certificate, a private key or
// any other PEM object / stray bytes are rejected instead of being skipped.
void validateSinglePemBlock(const std::string& path, const std::string& data) {
    std::size_t pos = 0;
    int certificateBlocks = 0;

    while (true) {
        while (pos < data.size() && isWhitespace(static_cast<unsigned char>(data[pos]))) {
            ++pos;
        }
        if (pos >= data.size()) {
            break;
        }

        if (data.compare(pos, kPemBeginPrefix.size(), kPemBeginPrefix) != 0) {
            throw InspectError{
                "invalid certificate in '" + path +
                "': PEM content must consist of a single CERTIFICATE block surrounded "
                "only by whitespace"};
        }

        const std::size_t newline = data.find('\n', pos);
        const std::size_t lineEnd =
            newline == std::string::npos ? data.size() : newline;
        std::size_t headerEnd = lineEnd;
        if (headerEnd > pos && data[headerEnd - 1] == '\r') {
            --headerEnd;
        }
        const std::string header = data.substr(pos, headerEnd - pos);

        if (header == kPemCertificateBegin) {
            ++certificateBlocks;
            if (certificateBlocks > 1) {
                throw InspectError{
                    "invalid certificate in '" + path +
                    "': more than one CERTIFICATE block found (expected exactly one)"};
            }
            const std::size_t endPos = data.find(kPemCertificateEnd, pos);
            if (endPos == std::string::npos) {
                throw InspectError{
                    "invalid certificate in '" + path +
                    "': CERTIFICATE block is missing its END marker (truncated?)"};
            }
            pos = endPos + kPemCertificateEnd.size();
        } else if (header.size() > kPemBeginPrefix.size() + 5 &&
                   header.compare(header.size() - 5, 5, "-----") == 0) {
            const std::string label =
                header.substr(kPemBeginPrefix.size(),
                              header.size() - kPemBeginPrefix.size() - 5);
            throw InspectError{
                "invalid certificate in '" + path + "': found a '" + label +
                "' PEM block, but only one CERTIFICATE block is accepted"};
        } else {
            throw InspectError{
                "invalid certificate in '" + path +
                "': malformed PEM block header (expected '-----BEGIN CERTIFICATE-----')"};
        }
    }

    if (certificateBlocks == 0) {
        throw InspectError{
            "invalid certificate in '" + path +
            "': no PEM CERTIFICATE block found"};
    }
}

// Decides the encoding purely from content: PEM is textual and begins (after
// optional whitespace) with a dash. A well-formed DER certificate always
// starts with the ASN.1 SEQUENCE tag (0x30), so there is no real ambiguity.
// Returns the fully parsed certificate and the detected encoding.
X509Ptr parseOneCertificate(const std::string& path, const std::string& data,
                            Encoding& encoding) {
    std::size_t first = 0;
    while (first < data.size() && isWhitespace(static_cast<unsigned char>(data[first]))) {
        ++first;
    }
    if (first >= data.size()) {
        throw InspectError{
            "invalid certificate in '" + path +
            "': file is empty or contains only whitespace"};
    }

    if (data[first] == '-') {
        encoding = Encoding::PEM;
        validateSinglePemBlock(path, data);

        BIO* bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
        if (bio == nullptr) {
            throw InspectError{"internal error: cannot allocate BIO"};
        }
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free_all(bio);
        if (cert == nullptr) {
            ERR_clear_error();
            throw InspectError{
                "invalid certificate in '" + path +
                "': PEM CERTIFICATE block could not be decoded (corrupt or truncated?)"};
        }
        return X509Ptr{cert, &X509_free};
    }

    encoding = Encoding::DER;
    const auto* begin = reinterpret_cast<const unsigned char*>(data.data());
    const unsigned char* cursor = begin;
    X509* cert = d2i_X509(nullptr, &cursor, static_cast<long>(data.size()));
    if (cert == nullptr) {
        ERR_clear_error();
        throw InspectError{
            "invalid certificate in '" + path +
            "': not a valid DER X.509 certificate (corrupt or truncated?)"};
    }
    const std::size_t consumed = static_cast<std::size_t>(cursor - begin);
    if (consumed != data.size()) {
        X509_free(cert);
        throw InspectError{
            "invalid certificate in '" + path +
            "': DER certificate is followed by " +
            std::to_string(data.size() - consumed) +
            " extra byte(s); expected exactly one certificate"};
    }
    return X509Ptr{cert, &X509_free};
}

int runInspect(const std::string& path) {
    std::string data;
    try {
        data = readFile(path);
    } catch (const InspectError& e) {
        std::cerr << "trustpeek: " << e.message << '\n';
        return 1;
    }

    Encoding encoding{};
    X509Ptr cert{nullptr, &X509_free};
    try {
        cert = parseOneCertificate(path, data, encoding);
    } catch (const InspectError& e) {
        std::cerr << "trustpeek: " << e.message << '\n';
        return 1;
    }

    // Compose every field before touching stdout, so a failure cannot leave
    // a partial certificate record on standard output.
    std::string subject;
    std::string issuer;
    std::string notBefore;
    std::string notAfter;
    std::string fingerprint;
    try {
        subject = formatDistinguishedName(X509_get_subject_name(cert.get()));
        issuer = formatDistinguishedName(X509_get_issuer_name(cert.get()));
        notBefore = formatUtcZ(X509_get0_notBefore(cert.get()));
        notAfter = formatUtcZ(X509_get0_notAfter(cert.get()));

        unsigned int digestLength = 0;
        unsigned char digest[EVP_MAX_MD_SIZE]{};
        if (X509_digest(cert.get(), EVP_sha256(), digest, &digestLength) != 1) {
            throw InspectError{"internal error: cannot compute SHA-256 fingerprint"};
        }
        fingerprint = formatColonHex(digest, digestLength);
    } catch (const InspectError& e) {
        std::cerr << "trustpeek: " << e.message << '\n';
        return 1;
    }

    std::cout << "Encoding: " << (encoding == Encoding::PEM ? "PEM" : "DER") << '\n';
    std::cout << "Subject: " << subject << '\n';
    std::cout << "Issuer: " << issuer << '\n';
    std::cout << "Not Before: " << notBefore << '\n';
    std::cout << "Not After: " << notAfter << '\n';
    std::cout << "SHA-256 Fingerprint: " << fingerprint << '\n';
    std::cout << "Note: this output only describes the contents of the certificate. "
                 "Reading it successfully does not mean its signature is valid or "
                 "that the certificate is trusted.\n";
    return 0;
}

void printUsage(std::ostream& out) {
    out <<
        "Usage: trustpeek --version\n"
        "       trustpeek inspect <file>\n"
        "\n"
        "Show information about a local X.509 certificate.\n"
        "\n"
        "Commands:\n"
        "  inspect <file>   Display encoding, subject, issuer, validity period\n"
        "                   and SHA-256 fingerprint of one certificate (PEM or DER,\n"
        "                   detected from the file contents).\n"
        "\n"
        "Options:\n"
        "  --version        Show program version.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(std::cerr);
        return 2;
    }

    const std::string_view command(argv[1]);

    if (command == "--version") {
        if (argc != 2) {
            printUsage(std::cerr);
            return 2;
        }
        std::cout << "trustpeek " << kVersion << '\n';
        return 0;
    }

    if (command == "inspect") {
        if (argc != 3) {
            printUsage(std::cerr);
            return 2;
        }
        return runInspect(argv[2]);
    }

    printUsage(std::cerr);
    return 2;
}
