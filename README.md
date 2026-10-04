# trustpeek

在离线环境中快速查看本地 X.509 证书的基本信息。标准证书格式由
OpenSSL（libcrypto）解析，处理逻辑使用 C++20 编写。

## 构建与运行

需要 C++20 编译器、CMake 3.20+ 以及 OpenSSL 3.0（libcrypto）。

```sh
cmake -S . -B build
cmake --build build
```

查看版本：

```sh
./build/trustpeek --version
```

输出：

```text
trustpeek 0.1.0
```

## 查看证书：`inspect`

```sh
./build/trustpeek inspect <文件路径>
```

路径中包含空格时正常加引号即可：

```sh
./build/trustpeek inspect "my certs/example.pem"
```

实际示例（PEM 文件）：

```sh
$ ./build/trustpeek inspect example.pem
Encoding: PEM
Subject: CN=example.com,OU=Engineering,O=Acme Corp,C=US
Issuer: CN=Example Root CA,O=Example CA
Not Before: 2026-01-01T00:00:00Z
Not After: 2030-01-01T00:00:00Z
SHA-256 Fingerprint: 59:AE:B7:AA:3A:FA:F5:13:0B:C2:4E:68:CF:90:6A:65:40:BF:62:48:33:4F:42:A9:A8:65:7A:DC:1C:75:7F:06
Note: this output only describes the contents of the certificate. Reading it successfully does not mean its signature is valid or that the certificate is trusted.
```

输出字段说明：

- **Encoding**：文件的实际编码（`PEM` 或 `DER`）。
- **Subject / Issuer**：主体与颁发者的完整可辨别名称（RFC 2253 形式，
  保留证书中的全部属性值，不仅显示通用名 CN；中文等非 ASCII 内容按
  UTF-8 原样显示）。
- **Not Before / Not After**：有效期起止，统一使用带 `Z` 的 UTC 时间，
  与运行机器的本地时区无关。
- **SHA-256 Fingerprint**：对证书本身的 DER 编码计算 SHA-256，以大写
  十六进制、冒号分隔字节显示。同一证书无论以 PEM 还是 DER 保存，指纹
  和其余信息都一致，只有 Encoding 不同。

### 支持的输入范围

- 接受 **PEM**（`-----BEGIN CERTIFICATE-----`）或 **DER** 编码。
- 实际编码由**文件内容**决定，与文件扩展名无关。例如把 PEM 文件改名
  为 `*.der`，输出仍会报告 `PEM`。
- 一次只检查**一个完整证书**：
  - PEM 块前后允许空白；
  - 第二个证书、私钥或其他 PEM 对象、块外任何非空白内容都会被拒绝；
  - DER 证书之后存在多余字节会被拒绝。
- 空文件、只含空白的文件、损坏或截断的数据、只包含公钥的文件，都按
  证书格式错误处理。
- 证书已过期、尚未生效或为自签名，只要内容能完整读取，仍会正常显示
  信息并返回 0。

### “能看到信息”不等于“可以信任”

`inspect` 只解析并展示证书自身携带的字段，**不会**验证签名、校验证书链
或核对吊销状态。读取成功不代表证书签名有效，也不代表该证书可信。是否
可信需要结合颁发者、信任锚与有效期等另行判断。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功读取并展示证书（包括已过期或尚未生效的证书），或 `--version` 成功 |
| `1` | 文件不存在、无法读取，或内容不是一个完整的单一证书；诊断信息写入标准错误并包含文件路径 |
| `2` | 用法错误：缺少检查路径、参数过多或命令未知；同时打印包含 `inspect` 的用法说明 |

发生错误时标准错误给出诊断，标准输出不会留下不完整的证书信息。
