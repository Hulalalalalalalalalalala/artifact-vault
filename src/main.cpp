#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free_all)>;

struct OpenSSLFree {
    void operator()(unsigned char* pointer) const { OPENSSL_free(pointer); }
};

constexpr std::string_view kPemBegin = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kPemEnd = "-----END CERTIFICATE-----";

void print_usage() {
    std::cerr << "Usage:\n"
              << "  trustpeek --version\n"
              << "  trustpeek inspect <file>\n";
}

int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool is_base64_token(char c) {
    return base64_value(c) >= 0 || c == '=';
}

// Strict base64 decoder: length must be a multiple of four and padding may
// only appear at the very end.
bool base64_decode(const std::string& input,
                   std::vector<unsigned char>& output) {
    if (input.size() % 4 != 0) return false;
    output.clear();
    output.reserve(input.size() / 4 * 3);
    for (size_t i = 0; i < input.size(); i += 4) {
        bool last_group = (i + 4 == input.size());
        int values[4] = {};
        int padding = 0;
        for (int j = 0; j < 4; ++j) {
            char c = input[i + j];
            if (c == '=') {
                ++padding;
            } else {
                if (padding > 0) return false;  // data after padding
                values[j] = base64_value(c);
                if (values[j] < 0) return false;
            }
        }
        if (!last_group && padding > 0) return false;
        if (padding > 2) return false;
        output.push_back(static_cast<unsigned char>((values[0] << 2) |
                                                    (values[1] >> 4)));
        if (padding < 2) {
            output.push_back(static_cast<unsigned char>(((values[1] & 0x0f) << 4) |
                                                        (values[2] >> 2)));
        }
        if (padding == 0) {
            output.push_back(static_cast<unsigned char>(((values[2] & 0x03) << 6) |
                                                        values[3]));
        }
    }
    return true;
}

// Verifies that the content is exactly one PEM certificate block surrounded
// by nothing but whitespace, and that the base64 payload is the given DER.
bool validate_single_pem(std::string_view content,
                         const std::vector<unsigned char>& der) {
    enum class State { BeforeMarker, InBody, AfterMarker };
    State state = State::BeforeMarker;
    std::string base64;
    size_t start = 0;
    while (true) {
        size_t newline = content.find('\n', start);
        std::string_view line = content.substr(
            start, newline == std::string_view::npos ? std::string_view::npos
                                                     : newline - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        size_t begin = 0;
        size_t end = line.size();
        while (begin < end &&
               std::isspace(static_cast<unsigned char>(line[begin]))) {
            ++begin;
        }
        while (end > begin &&
               std::isspace(static_cast<unsigned char>(line[end - 1]))) {
            --end;
        }
        std::string_view trimmed = line.substr(begin, end - begin);

        switch (state) {
            case State::BeforeMarker:
                if (!trimmed.empty()) {
                    if (trimmed != kPemBegin) return false;
                    state = State::InBody;
                }
                break;
            case State::InBody:
                if (trimmed == kPemEnd) {
                    state = State::AfterMarker;
                } else if (!trimmed.empty()) {
                    for (char c : trimmed) {
                        if (!is_base64_token(c)) return false;
                    }
                    base64.append(trimmed);
                }
                break;
            case State::AfterMarker:
                if (!trimmed.empty()) return false;
                break;
        }

        if (newline == std::string_view::npos) break;
        start = newline + 1;
    }
    if (state != State::AfterMarker) return false;

    std::vector<unsigned char> decoded;
    return base64_decode(base64, decoded) && decoded == der;
}

bool is_valid_utf8(const std::string& s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    size_t i = 0;
    while (i < s.size()) {
        unsigned c = p[i];
        size_t extra = 0;
        unsigned codepoint = 0;
        if (c < 0x80) {
            ++i;
            continue;
        }
        if ((c & 0xe0) == 0xc0) {
            extra = 1;
            codepoint = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {
            extra = 2;
            codepoint = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            extra = 3;
            codepoint = c & 0x07;
        } else {
            return false;
        }
        if (i + extra >= s.size()) return false;
        for (size_t j = 1; j <= extra; ++j) {
            if ((p[i + j] & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (p[i + j] & 0x3f);
        }
        if (codepoint < (extra == 1 ? 0x80u : extra == 2 ? 0x800u : 0x10000u)) {
            return false;  // overlong encoding
        }
        if (codepoint >= 0xd800 && codepoint <= 0xdfff) return false;  // surrogate
        if (codepoint > 0x10ffff) return false;
        i += extra + 1;
    }
    return true;
}

// Fallback for legacy string types (e.g. T61/IA5 with Latin-1 bytes) that
// OpenSSL cannot turn into proper UTF-8 directly.
std::string latin1_to_utf8(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back(static_cast<char>(0xc0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3f)));
        }
    }
    return out;
}

std::string escape_dn_value(const std::string& value) {
    std::string out;
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        if (c == ',' || c == '+' || c == '=' || c == '"' || c == '\\' ||
            c == '<' || c == '>' || c == '#' || c == ';') {
            out.push_back('\\');
            out.push_back(static_cast<char>(c));
        } else if (c == ' ' && (i == 0 || i + 1 == value.size())) {
            out.append("\\ ");
        } else if (c < 0x20) {
            char buf[5];
            std::snprintf(buf, sizeof(buf), "\\%02X", c);
            out.append(buf);
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

bool format_name(X509_NAME* name, std::string& out) {
    int count = X509_NAME_entry_count(name);
    int previous_set = -1;
    for (int i = 0; i < count; ++i) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        if (entry == nullptr) return false;
        ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING* asn1_value = X509_NAME_ENTRY_get_data(entry);
        if (object == nullptr || asn1_value == nullptr) return false;

        const char* short_name = nullptr;
        std::string dotted_oid;
        int nid = OBJ_obj2nid(object);
        if (nid != NID_undef) short_name = OBJ_nid2sn(nid);
        if (short_name == nullptr) {
            // Size the buffer from the dotted form itself: an unknown OID's
            // decimal text can be arbitrarily long, so a fixed buffer would
            // silently clip its tail and make distinct OIDs look identical.
            int oid_length = OBJ_obj2txt(nullptr, 0, object, 1);
            if (oid_length <= 0) return false;
            dotted_oid.resize(static_cast<size_t>(oid_length));
            int written = OBJ_obj2txt(dotted_oid.data(),
                                      static_cast<int>(dotted_oid.size()) + 1,
                                      object, 1);
            if (written != oid_length) return false;
            short_name = dotted_oid.c_str();
        }

        unsigned char* utf8_raw = nullptr;
        int utf8_length = ASN1_STRING_to_UTF8(&utf8_raw, asn1_value);
        if (utf8_length < 0) return false;
        std::unique_ptr<unsigned char, OpenSSLFree> utf8_guard(
            utf8_raw, OpenSSLFree{});
        std::string value(reinterpret_cast<char*>(utf8_raw),
                          static_cast<size_t>(utf8_length));
        if (!is_valid_utf8(value)) value = latin1_to_utf8(value);

        int current_set = X509_NAME_ENTRY_set(entry);
        if (i > 0) {
            out.append(current_set == previous_set ? "+" : ", ");
        }
        out.append(short_name);
        out.push_back('=');
        out.append(escape_dn_value(value));
        previous_set = current_set;
    }
    return true;
}

bool encode_to_der(X509* cert, std::vector<unsigned char>& der) {
    int length = i2d_X509(cert, nullptr);
    if (length <= 0) return false;
    der.resize(static_cast<size_t>(length));
    unsigned char* pointer = der.data();
    int encoded = i2d_X509(cert, &pointer);
    return encoded == length &&
           pointer == der.data() + der.size();
}

bool format_time(const ASN1_TIME* time, std::string& out) {
    struct tm tm_value {};
    if (ASN1_TIME_to_tm(time, &tm_value) != 1) return false;
    char buffer[32];
    int written = std::snprintf(
        buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm_value.tm_year + 1900, tm_value.tm_mon + 1, tm_value.tm_mday,
        tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec);
    if (written <= 0 || static_cast<size_t>(written) >= sizeof(buffer)) {
        return false;
    }
    out.assign(buffer);
    return true;
}

std::string format_fingerprint(const unsigned char* digest, size_t length) {
    std::string out;
    out.reserve(length * 3);
    for (size_t i = 0; i < length; ++i) {
        char byte_buffer[4];
        std::snprintf(byte_buffer, sizeof(byte_buffer), "%02X", digest[i]);
        if (i != 0) out.push_back(':');
        out.append(byte_buffer);
    }
    return out;
}

// Explains why a non-regular path cannot be read as a certificate. Every
// wording names the actual file type and states that a regular file is
// required.
const char* non_regular_file_reason(mode_t mode) {
    if (S_ISDIR(mode)) return "is a directory, not a regular file";
    if (S_ISFIFO(mode))
        return "is a named pipe (FIFO), not a regular file";
    if (S_ISCHR(mode))
        return "is a character device, not a regular file";
    if (S_ISBLK(mode))
        return "is a block device, not a regular file";
    if (S_ISSOCK(mode))
        return "is a local socket, not a regular file";
    return "is not a regular file";
}

// Reads the whole regular file into contents. Only a complete read that
// reaches end of file is a success: a directory, a named pipe, a device, a
// socket, a partial read followed by an error, or any open/stat failure all
// return a read error message. errno is captured immediately after the
// failing call so the reason always belongs to this operation (never a stale
// "Success").
//
// The type is checked with stat() BEFORE open(): a plain open(O_RDONLY) of a
// FIFO blocks until another process opens it for writing, so a pipe must be
// rejected by its type alone, regardless of writers or the data they could
// send. stat() follows symbolic links, hence a link is accepted or rejected
// according to its final target (a dangling link fails with the stat errno),
// while the diagnostic later reports the path exactly as the user passed it.
bool read_file_contents(const std::string& path, std::string& contents,
                        std::string& error) {
    struct stat status {};
    if (stat(path.c_str(), &status) != 0) {
        int saved_errno = errno;
        error = std::strerror(saved_errno);
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = non_regular_file_reason(status.st_mode);
        return false;
    }

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        int saved_errno = errno;
        error = std::strerror(saved_errno);
        return false;
    }

    // Re-check the type on the opened descriptor: the path could have been
    // replaced between stat() and open(). Reject before reading so a device
    // that yields EOF immediately is still a read failure, never an empty
    // certificate.
    struct stat opened_status {};
    if (fstat(fd, &opened_status) != 0) {
        int saved_errno = errno;
        close(fd);
        error = std::strerror(saved_errno);
        return false;
    }
    if (!S_ISREG(opened_status.st_mode)) {
        close(fd);
        error = non_regular_file_reason(opened_status.st_mode);
        return false;
    }

    contents.clear();
    if (status.st_size > 0) {
        contents.reserve(static_cast<size_t>(status.st_size));
    }
    char buffer[65536];
    while (true) {
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            contents.append(buffer, static_cast<size_t>(bytes_read));
        } else if (bytes_read == 0) {
            break;  // end of file reached after a complete read
        } else if (errno != EINTR) {
            int saved_errno = errno;
            close(fd);
            contents.clear();
            error = std::strerror(saved_errno);
            return false;
        }
    }

    if (close(fd) != 0) {
        int saved_errno = errno;
        contents.clear();
        error = std::strerror(saved_errno);
        return false;
    }
    return true;
}

int inspect_file(const std::string& path) {
    std::string content;
    std::string read_error;
    if (!read_file_contents(path, content, read_error)) {
        std::cerr << "trustpeek: failed to read file '" << path
                  << "': " << read_error << '\n';
        return 1;
    }

    if (content.empty()) {
        std::cerr << "trustpeek: invalid certificate in '" << path
                  << "': empty file\n";
        return 1;
    }

    // The encoding is decided by what actually parses, never by the file
    // extension and never by marker-like text inside the certificate itself
    // (a subject name may legitimately contain "-----BEGIN CERTIFICATE-----").
    //
    // A DER certificate starts with a SEQUENCE tag (0x30), which no PEM file
    // can start with, so the two formats cannot be confused: try DER first
    // and require the certificate to occupy the entire file.
    const auto* const der_begin =
        reinterpret_cast<const unsigned char*>(content.data());
    const auto* const der_end = der_begin + content.size();
    const unsigned char* pointer = der_begin;

    X509Ptr cert(d2i_X509(nullptr, &pointer,
                          static_cast<long>(content.size())),
                 X509_free);
    bool is_pem = false;

    if (cert) {
        if (pointer != der_end) {
            std::cerr << "trustpeek: invalid certificate in '" << path
                      << "': trailing bytes after DER certificate\n";
            return 1;
        }
    } else {
        BioPtr bio(BIO_new_mem_buf(content.data(),
                                  static_cast<int>(content.size())),
                   BIO_free_all);
        if (!bio) {
            std::cerr << "trustpeek: internal error while reading '" << path
                      << "'\n";
            return 1;
        }
        cert.reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!cert) {
            // The marker search below only picks the diagnostic wording;
            // acceptance is always decided by the parse results above.
            if (content.find(kPemBegin) != std::string::npos) {
                std::cerr << "trustpeek: invalid certificate in '" << path
                          << "': PEM certificate block is malformed or "
                             "truncated\n";
            } else {
                std::cerr << "trustpeek: invalid certificate in '" << path
                          << "': DER certificate is malformed or truncated\n";
            }
            return 1;
        }
        is_pem = true;
    }

    std::vector<unsigned char> der;
    if (!encode_to_der(cert.get(), der)) {
        std::cerr << "trustpeek: invalid certificate in '" << path
                  << "': failed to re-encode certificate\n";
        return 1;
    }

    if (is_pem && !validate_single_pem(content, der)) {
        std::cerr << "trustpeek: invalid certificate in '" << path
                  << "': expected exactly one PEM certificate block with no "
                     "other non-whitespace content\n";
        return 1;
    }

    const char* encoding_name = is_pem ? "PEM" : "DER";

    std::string subject;
    std::string issuer;
    std::string not_before;
    std::string not_after;
    if (!format_name(X509_get_subject_name(cert.get()), subject) ||
        !format_name(X509_get_issuer_name(cert.get()), issuer) ||
        !format_time(X509_get0_notBefore(cert.get()), not_before) ||
        !format_time(X509_get0_notAfter(cert.get()), not_after)) {
        std::cerr << "trustpeek: invalid certificate in '" << path
                  << "': failed to parse certificate fields\n";
        return 1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digest_length = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, der.data(), der.size(), digest,
                     &digest_length) != 1) {
        std::cerr << "trustpeek: internal error while hashing '" << path
                  << "'\n";
        return 1;
    }

    std::ostringstream output;
    output << "Encoding: " << encoding_name << '\n'
           << "Subject: " << subject << '\n'
           << "Issuer: " << issuer << '\n'
           << "Not Before: " << not_before << '\n'
           << "Not After: " << not_after << '\n'
           << "SHA-256 Fingerprint: "
           << format_fingerprint(digest, digest_length) << '\n'
           << "Note: this output displays certificate information only; "
              "reading the file successfully does not verify the signature "
              "or establish trust.\n";
    std::cout << output.str();
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "trustpeek 0.1.0\n";
        return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "inspect") {
        return inspect_file(argv[2]);
    }
    print_usage();
    return 2;
}
