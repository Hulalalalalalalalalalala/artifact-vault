# trustpeek

离线环境下快速查看本地 X.509 证书信息的小工具。不联网、不做信任验证，只读取并展示证书本身携带的内容。

## 构建与运行

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

## 检查证书

```sh
./build/trustpeek inspect <文件路径>
```

示例：

```sh
./build/trustpeek inspect ./cert.pem
```

```text
Encoding: PEM
Subject: C=CN, O=示例科技有限公司, OU=研发部, CN=中文示例证书
Issuer: C=CN, O=示例科技有限公司, OU=研发部, CN=中文示例证书
Not Before: 2026-10-04T16:40:27Z
Not After: 2036-10-01T16:40:27Z
SHA-256 Fingerprint: 9D:B7:65:F9:94:07:DB:F9:93:4E:29:FB:AA:FD:A1:F8:EE:54:9A:EF:4E:E2:80:C6:47:55:B5:58:00:F5:74:23
Note: this output displays certificate information only; reading the file successfully does not verify the signature or establish trust.
```

路径包含空格时加引号即可：

```sh
./build/trustpeek inspect "dir with space/my cert.pem"
```

### 输出字段

| 字段 | 含义 |
| --- | --- |
| `Encoding` | 文件的**实际**编码，`PEM` 或 `DER`，由文件内容决定 |
| `Subject` | 证书主体名称，保留名称中的全部属性（不只显示通用名 CN） |
| `Issuer` | 颁发者名称，同样保留全部属性 |
| `Not Before` | 有效期开始时间，UTC 表示并以 `Z` 结尾 |
| `Not After` | 有效期结束时间，UTC 表示并以 `Z` 结尾 |
| `SHA-256 Fingerprint` | 证书 DER 编码的 SHA-256 指纹，大写十六进制、冒号分隔字节 |

- 名称中的中文等非 ASCII 内容以 UTF-8 输出；未知属性 OID 以点分形式（如 `2.5.4.5=...`）显示。
- 时间一律使用带 `Z` 的 UTC 时间，因此同一证书在任何本地时区下输出都相同。
- 指纹针对证书的 DER 编码计算。同一证书分别保存为 PEM 和 DER 时，除 `Encoding` 外的所有字段完全一致。

## 支持的输入范围

- 一次只检查**一个完整的 X.509 证书**，接受 PEM 或 DER 编码。
- 实际格式根据**文件内容**判断，与扩展名无关。例如把 PEM 文件改名为 `cert.der`，仍会报告 `Encoding: PEM`。
- PEM 证书块前后允许空白（空格、制表符、空行、CRLF）。
- 以下情况一律作为证书格式错误拒绝（退出码 1）：
  - 空文件或仅含空白；
  - 损坏、截断的数据；
  - 只包含公钥、私钥或其他非证书内容；
  - PEM 中出现第二个证书块或其他非空白内容；
  - DER 证书之后存在多余字节。
- 文件不存在、不可读（如权限不足）时报告读取失败。

## 查看信息不等于信任判断

`inspect` 只展示证书“写了什么”，**不判断证书是否可信**。具体来说：

- 不验证证书上的签名，也不验证颁发链；
- 不查询吊销状态（CRL/OCSP），不检查系统信任库；
- 证书已经过期、尚未生效，或者是自签名证书，只要能完整读取就照常显示并返回 0。

因此读取成功只代表文件是一个结构完整的 X.509 证书，不代表其签名有效或应当被信任。输出末尾的 Note 行会持续提醒这一区别。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功输出证书信息（过期、未生效、自签名也返回 0） |
| 1 | 文件无法读取，或内容不是一个完整的单证书（诊断信息写入标准错误，包含出错路径） |
| 2 | 用法错误：缺少检查路径、参数多余、命令未知（同时打印用法说明） |

失败时标准输出不会留下任何半截证书信息。
