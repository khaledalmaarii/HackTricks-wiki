# macOS Gatekeeper

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧**
*
* .

</details>

## Gatekeeper

**Gatekeeper**是为Mac操作系统开发的安全功能，旨在确保用户在其系统上**只运行可信任的软件**。它通过**验证用户从App Store之外的来源下载并尝试打开的软件**（如应用程序、插件或安装程序包）来实现。

Gatekeeper的关键机制在于其**验证**过程。它检查下载的软件是否由**已知开发者签名**，以确保软件的真实性。此外，它还确定软件是否经过了**Apple的公证**，以确认其不包含已知的恶意内容，并且在公证后没有被篡改。

此外，Gatekeeper通过**提示用户批准首次打开**下载的软件来加强用户控制和安全性。这个保护措施有助于防止用户无意中运行可能有害的可执行代码，而他们可能将其误认为是无害的数据文件。

### 应用程序签名

应用程序签名，也称为代码签名，是Apple安全基础设施的关键组成部分。它们用于**验证软件作者的身份**（开发者），并确保代码自上次签名以来没有被篡改。

以下是其工作原理：

1. **签署应用程序：**当开发者准备分发他们的应用程序时，他们使用一个私钥对应用程序进行**签名**。这个私钥与开发者在加入Apple开发者计划时获得的**证书相关联**。签名过程涉及对应用程序的所有部分创建一个加密哈希，并使用开发者的私钥对该哈希进行加密。
2. **分发应用程序：**签名的应用程序随后与开发者的证书一起分发给用户，该证书包含相应的公钥。
3. **验证应用程序：**当用户下载并尝试运行应用程序时，他们的Mac操作系统使用开发者证书中的公钥解密哈希。然后，它根据应用程序的当前状态重新计算哈希，并将其与解密的哈希进行比较。如果它们匹配，这意味着**应用程序自开发者签名以来没有被修改**，系统允许应用程序运行。

应用程序签名是Apple的Gatekeeper技术的重要组成部分。当用户尝试**打开从互联网下载的应用程序**时，Gatekeeper会验证应用程序的签名。如果它使用由Apple颁发给已知开发者的证书进行签名，并且代码没有被篡改，Gatekeeper允许应用程序运行。否则，它会阻止应用程序并向用户发出警报。

从macOS Catalina开始，Gatekeeper还会检查应用程序是否经过了Apple的**公证**，增加了额外的安全层。公证过程会检查应用程序是否存在已知的安全问题和恶意代码，如果这些检查通过，Apple会向应用程序添加一个Gatekeeper可以验证的凭证。

#### 检查签名

在检查一些**恶意软件样本**时，你应该始终**检查二进制文件的签名**，因为签名它的**开发者**可能已经与**恶意软件**有关联。
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

苹果的验签过程是一种额外的保护措施，用于保护用户免受潜在有害软件的侵害。它涉及开发者将他们的应用程序提交给苹果的验签服务进行审查，这与应用审核不应混淆。该服务是一个自动化系统，会对提交的软件进行检查，以查找恶意内容和代码签名可能存在的问题。

如果软件在没有引起任何关注的情况下通过了这个检查，验签服务会生成一个验签票据。然后，开发者需要将这个票据附加到他们的软件上，这个过程被称为“装订”。此外，验签票据也会在网上发布，Gatekeeper（苹果的安全技术）可以访问它。

当用户首次安装或执行软件时，验签票据的存在（无论是附在可执行文件上还是在线找到）会通知Gatekeeper该软件已由苹果进行了验签。因此，Gatekeeper会在初始启动对话框中显示一个描述性消息，指示该软件已经通过苹果的恶意内容检查。这个过程增强了用户对他们在系统上安装或运行的软件的安全性的信心。

### 枚举GateKeeper

GateKeeper是多个安全组件，用于阻止不受信任的应用程序的执行，同时也是其中一个组件。

可以使用以下命令查看GateKeeper的状态：
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
请注意，GateKeeper 签名检查仅针对具有隔离属性的文件进行。
{% endhint %}

GateKeeper 将根据首选项和签名检查来确定是否可以执行二进制文件：

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

保存此配置的数据库位于 **`/var/db/SystemPolicy`**。您可以使用以下命令以 root 身份检查此数据库：
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
请注意，第一条规则以“**App Store**”结尾，第二条规则以“**Developer ID**”结尾，并且在之前的图像中，它被设置为**允许执行来自App Store和已识别开发者的应用程序**。

如果您将该设置修改为App Store，那么“**已经签名的开发者ID**”规则将消失。

还有成千上万个**GKE类型的规则**。
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
这些哈希值来自于 **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`**, **`/var/db/gke.bundle/Contents/Resources/gk.db`** 和 **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**。

**`spctl`** 的选项 **`--master-disable`** 和 **`--global-disable`** 将完全**禁用**这些签名检查：
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

可以使用以下方法**检查应用程序是否被GateKeeper允许**：
```bash
spctl --assess -v /Applications/App.app
```
可以通过GateKeeper添加新规则来允许执行特定应用程序：
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

在下载应用程序或文件时，特定的 macOS 应用程序（如网络浏览器或电子邮件客户端）会为下载的文件附加一个称为“检疫标志”的扩展文件属性。该属性作为一项安全措施，将文件标记为来自不受信任的来源（互联网），并可能携带风险。然而，并非所有应用程序都会附加此属性，例如，常见的 BitTorrent 客户端软件通常会绕过此过程。

当用户尝试执行文件时，**检疫标志的存在会触发 macOS 的 Gatekeeper 安全功能**。

在没有检疫标志的情况下（例如通过某些 BitTorrent 客户端下载的文件），Gatekeeper 的检查可能不会执行。因此，用户在打开从不安全或未知来源下载的文件时应谨慎。

{% hint style="info" %}
**验证**代码签名的有效性是一个**资源密集型**的过程，其中包括生成代码及其所有捆绑资源的加密哈希。此外，检查证书的有效性还涉及在线检查苹果服务器，以查看其是否在签发后被吊销。出于这些原因，每次启动应用程序时运行完整的代码签名和公证检查是**不切实际的**。

因此，这些检查仅在执行带有检疫属性的应用程序时运行。
{% endhint %}

{% hint style="warning" %}
此属性必须由创建/下载文件的应用程序**设置**。

但是，沙盒化的文件将为它们创建的每个文件设置此属性。非沙盒化的应用程序可以自行设置此属性，或者在 **Info.plist** 中指定 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) 键，系统将在创建的文件上设置 `com.apple.quarantine` 扩展属性。
{% endhint %}

可以使用以下命令**检查其状态并启用/禁用**（需要 root 权限）：
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
您还可以使用以下命令**查找文件是否具有扩展属性**：
```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```
检查**扩展属性**的**值**，并找出写入隔离属性的应用程序：
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
# 00c1 -- It has been allowed to eexcute this file
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
然后使用以下命令**删除**该属性：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
使用以下命令查找所有被隔离的文件：

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

隔离信息也存储在由LaunchServices管理的中央数据库中，路径为**`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**。

### XProtect

XProtect是macOS中内置的**反恶意软件**功能。XProtect会在应用程序首次启动或修改时，根据其已知恶意软件和不安全文件类型的数据库对其进行检查。当你通过某些应用程序（如Safari、Mail或Messages）下载文件时，XProtect会自动扫描该文件。如果文件与其数据库中的任何已知恶意软件匹配，XProtect将**阻止文件运行**并向你发出警报。

XProtect数据库由Apple定期更新，包含新的恶意软件定义，并且这些更新会自动下载并安装到你的Mac上。这确保了XProtect始终与最新的已知威胁保持同步。

然而，值得注意的是，**XProtect并不是一个功能完备的防病毒解决方案**。它只检查特定的已知威胁列表，并且不像大多数防病毒软件那样执行实时扫描。

你可以获取有关最新XProtect更新的信息，运行以下命令：

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect位于SIP保护的位置**/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在该bundle中，您可以找到XProtect使用的信息：

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：允许具有这些cdhashes的代码使用旧版授权。
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：禁止通过BundleID和TeamID加载的插件和扩展列表，或指示最低版本。
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**：用于检测恶意软件的Yara规则。
* **`XProtect.bundle/Contents/Resources/gk.db`**：包含被阻止的应用程序和TeamID的哈希的SQLite3数据库。

请注意，还有另一个与XProtect相关的应用程序**`/Library/Apple/System/Library/CoreServices/XProtect.app`**，在运行应用程序时不会涉及它。

## Gatekeeper绕过

任何绕过Gatekeeper的方式（成功让用户下载并在Gatekeeper应该禁止的情况下执行）都被视为macOS中的漏洞。以下是一些过去允许绕过Gatekeeper的技术所分配的CVE：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

当通过**Archive Utility**提取时，**路径超过886个字符**的文件将无法继承com.apple.quarantine扩展属性，从而可以**绕过Gatekeeper对这些文件的限制**。

有关更多信息，请查看[**原始报告**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

当使用**Automator**创建应用程序时，关于其执行所需的信息位于`application.app/Contents/document.wflow`而不是可执行文件中。可执行文件只是一个名为**Automator Application Stub**的通用Automator二进制文件。

因此，您可以使`application.app/Contents/MacOS/Automator\ Application\ Stub` **通过符号链接指向系统中的另一个Automator Application Stub**，它将执行`document.wflow`中的内容（您的脚本），而不会触发Gatekeeper，因为实际的可执行文件没有隔离属性。

示例预期位置：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

有关更多信息，请查看[**原始报告**](https://ronmasas.com/posts/bypass-macos-gatekeeper)。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在此绕过中，创建了一个zip文件，从`application.app/Contents`开始压缩，而不是从`application.app`开始。因此，**隔离属性**被应用于**来自`application.app/Contents`的所有文件**，但未应用于`application.app`，而Gatekeeper正在检查该文件，因此Gatekeeper被绕过，因为当触发`application.app`时，它**没有隔离属性**。
```bash
zip -r test.app/Contents test.zip
```
查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)以获取更多信息。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，利用此漏洞的方式与之前的漏洞非常相似。在这种情况下，我们将从**`application.app/Contents`**生成一个Apple Archive，因此**`application.app`在被**Archive Utility**解压缩时不会获得隔离属性**。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
请查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)以获取更多信息。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于防止任何人在文件中写入属性：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
此外，**AppleDouble**文件格式会复制包含其ACE的文件。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中，可以看到存储在名为**`com.apple.acl.text`**的xattr中的ACL文本表示将被设置为解压后文件的ACL。因此，如果您将应用程序压缩为使用**AppleDouble**文件格式的zip文件，并且该ACL阻止其他xattr写入它...则隔离xattr不会设置到应用程序中：
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file shuold be without a wuarantine xattr
```
查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。

## [2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

发现**Google Chrome由于一些macOS内部问题未设置下载文件的隔离属性**。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
