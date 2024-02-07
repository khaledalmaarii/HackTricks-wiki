# macOS启动/环境约束与信任缓存

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中做广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群组**](https://discord.gg/hRep4RUj7f) 或**电报群组**](https://t.me/peass) 或在**Twitter**上**关注**我**🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧**
*
* .

</details>

## 基本信息

macOS中的启动约束旨在通过**规范化进程的启动方式、启动者和启动位置**来增强安全性。在macOS Ventura中引入，它们提供了一个框架，将**每个系统二进制文件分类为不同的约束类别**，这些类别在**信任缓存**中定义，其中包含系统二进制文件及其相应哈希的列表。这些约束扩展到系统中的每个可执行二进制文件，包括一组**规则**，详细说明了**启动特定二进制文件**的要求。这些规则包括二进制文件必须满足的自身约束、其父进程必须满足的父约束，以及其他相关实体必须遵守的责任约束。

这种机制通过**环境约束**扩展到第三方应用程序，从macOS Sonoma开始，允许开发人员通过指定**一组键和值的环境约束**来保护其应用程序。

您可以在**`launchd`属性列表文件**中保存的约束字典中定义**启动环境和库约束**，或者在**用于代码签名的单独属性列表**文件中定义。

有4种类型的约束：

* **自身约束**：应用于**运行中**的二进制文件。
* **父进程约束**：应用于**进程的父进程**（例如运行XP服务的**`launchd`**）。
* **责任约束**：应用于通过XPC通信调用服务的**进程**。
* **库加载约束**：使用库加载约束有选择地描述可加载的代码。

因此，当一个进程尝试启动另一个进程时 — 通过调用`execve(_:_:_:)`或`posix_spawn(_:_:_:_:_:_:)` — 操作系统会检查**可执行文件**是否满足其**自身约束**。它还会检查**父进程的可执行文件**是否满足可执行文件的**父约束**，以及**负责进程的可执行文件**是否满足可执行文件的**责任进程约束**。如果这些启动约束中有任何一个不满足，操作系统将不运行该程序。

如果在加载库时**库约束的任何部分不成立**，您的进程**不会加载**该库。

## LC类别

LC由**事实**和**逻辑操作**（与、或等）组成，结合事实。

[**LC可以使用的事实已记录**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints)。例如：

* is-init-proc：一个布尔值，指示可执行文件是否必须是操作系统的初始化进程（`launchd`）。
* is-sip-protected：一个布尔值，指示可执行文件是否必须是受系统完整性保护（SIP）保护的文件。
* `on-authorized-authapfs-volume:` 一个布尔值，指示操作系统是否从经授权的、经认证的APFS卷加载了可执行文件。
* `on-authorized-authapfs-volume`：一个布尔值，指示操作系统是否从经授权的、经认证的APFS卷加载了可执行文件。
* Cryptexes卷
* `on-system-volume:` 一个布尔值，指示操作系统是否从当前引导的系统卷加载了可执行文件。
* 在/System...
* ...

当苹果二进制文件签名时，它会将其分配到**信任缓存**中的**LC类别**中。

* **iOS 16个LC类别**已经[**被逆向并记录在这里**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。
* 当前**LC类别（macOS 14** - Somona）已被逆向，并且它们的[**描述可以在这里找到**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。

例如，类别1是：
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: 必须位于系统或Cryptexes卷中。
* `launch-type == 1`: 必须是系统服务（LaunchDaemons中的plist）。
* `validation-category == 1`: 操作系统可执行文件。
* `is-init-proc`: Launchd

### 反向 LC 类别

您可以在[**这里了解更多信息**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints)，但基本上，它们在**AMFI（AppleMobileFileIntegrity）**中定义，因此您需要下载内核开发工具包以获取**KEXT**。以**`kConstraintCategory`**开头的符号是**有趣的**。提取它们，您将获得一个DER（ASN.1）编码流，您需要使用[ASN.1解码器](https://holtstrom.com/michael/tools/asn1decoder.php)或python-asn1库及其`dump.py`脚本进行解码，[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) 这将为您提供更易理解的字符串。

## 环境约束

这些是配置在**第三方应用程序**中的Launch Constraints。开发人员可以选择在其应用程序中使用的**事实**和**逻辑操作数**来限制对其自身的访问。

可以使用以下方法枚举应用程序的环境约束：
```bash
codesign -d -vvvv app.app
```
## 信任缓存

在**macOS**中有几个信任缓存：

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

而在iOS中，看起来是在**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**中。

{% hint style="warning" %}
在运行在苹果硅设备上的macOS中，如果苹果签名的二进制文件不在信任缓存中，AMFI将拒绝加载它。
{% endhint %}

### 枚举信任缓存

之前的信任缓存文件是以**IMG4**和**IM4P**格式，其中IM4P是IMG4格式的有效负载部分。

您可以使用[**pyimg4**](https://github.com/m1stadev/PyIMG4)来提取数据库的有效负载：

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

（另一个选择是使用工具[**img4tool**](https://github.com/tihmstar/img4tool)，即使发布版本较旧且适用于 x86\_64，如果您将其安装在正确的位置，它也可以在 M1 上运行）。

现在，您可以使用工具[**trustcache**](https://github.com/CRKatri/trustcache)以可读格式获取信息：
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
信任缓存遵循以下结构，因此**LC类别是第4列**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
然后，您可以使用[**此脚本**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)来提取数据。

从这些数据中，您可以检查具有**启动约束值为`0`**的应用程序，这些应用程序没有受到约束（[**在此处检查**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)每个值代表什么）。

## 攻击缓解

启动约束将通过**确保进程不会在意外条件下执行**来缓解几种旧攻击：例如来自意外位置的执行或被意外父进程调用（如果只有launchd应该启动它）。

此外，启动约束还**缓解了降级攻击**。

然而，它们**无法缓解常见的XPC**滥用、**Electron**代码注入或没有库验证的**dylib注入**（除非已知可以加载库的团队ID）。

### XPC守护程序保护

在Sonoma版本中，一个显著的点是守护程序XPC服务的**责任配置**。XPC服务对自身负责，而不是连接的客户端负责。这在反馈报告FB13206884中有记录。这种设置可能看起来有缺陷，因为它允许与XPC服务进行某些交互：

- **启动XPC服务**：如果被认为是一个错误，这种设置不允许通过攻击者代码启动XPC服务。
- **连接到活动服务**：如果XPC服务已经运行（可能由其原始应用程序激活），则连接到它没有障碍。

尽管对XPC服务实施约束可能有益于**缩小潜在攻击的窗口**，但它并未解决主要问题。确保XPC服务的安全基本上需要**有效验证连接的客户端**。这仍然是加固服务安全性的唯一方法。另外值得注意的是，所述的责任配置目前正在运行，这可能与预期的设计不符。

### Electron保护

即使要求应用程序必须由LaunchService**打开（在父级约束中）。这可以通过**`open`**（可以设置环境变量）或使用**Launch Services API**（可以指定环境变量）来实现。

## 参考资料

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群**](https://discord.gg/hRep4RUj7f) 或**电报群**](https://t.me/peass) 或在**Twitter**上**🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧**
*
* .

</details>
