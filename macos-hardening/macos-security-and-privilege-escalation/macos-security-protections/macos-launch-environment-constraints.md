# macOS启动/环境约束

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧**
*
* .

</details>

## 基本信息

macOS中的启动约束旨在通过**规定进程的启动方式、启动者和启动位置**来增强安全性。从macOS Ventura开始引入，它们提供了一个框架，将**每个系统二进制文件**分类为不同的约束类别，并在**信任缓存**中定义这些约束类别，信任缓存是一个包含系统二进制文件及其哈希值的列表。这些约束适用于系统中的每个可执行二进制文件，包括一组规则，用于描述启动特定二进制文件的要求。这些规则包括二进制文件必须满足的自身约束、其父进程必须满足的父级约束，以及其他相关实体必须遵守的责任约束。

该机制通过**环境约束**扩展到第三方应用程序，从macOS Sonoma开始，允许开发人员通过指定一组键和值来保护其应用程序的环境约束。

您可以在**`launchd`属性列表文件**中保存约束字典，也可以在代码签名中使用**单独的属性列表**文件来定义**启动环境和库约束**。

约束分为4种类型：

* **自身约束**：应用于**正在运行的**二进制文件。
* **父进程约束**：应用于**进程的父进程**（例如**`launchd`**运行的XP服务）。
* **责任约束**：应用于通过XPC通信调用服务的**进程**的二进制文件。
* **库加载约束**：使用库加载约束来选择性地描述可以加载的代码。

因此，当一个进程尝试启动另一个进程（通过调用`execve(_:_:_:)`或`posix_spawn(_:_:_:_:_:_:)`），操作系统会检查**可执行文件**是否满足其**自身约束**。它还会检查**父进程的可执行文件**是否满足可执行文件的**父级约束**，以及**责任进程的可执行文件**是否满足可执行文件的**责任进程约束**。如果任何这些启动约束不满足，操作系统将不会运行该程序。

如果在加载库时，库约束的任何部分不为真，则您的进程将**不会加载**该库。

## LC类别

LC由**事实**和**逻辑操作**（与、或等）组成，用于组合事实。

[**LC可以使用的事实已经有文档记录**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints)。例如：

* is-init-proc：一个布尔值，指示可执行文件是否必须是操作系统的初始化进程（`launchd`）。
* is-sip-protected：一个布尔值，指示可执行文件是否必须是由系统完整性保护（SIP）保护的文件。
* `on-authorized-authapfs-volume:` 一个布尔值，指示操作系统是否从经过授权、经过身份验证的APFS卷加载了可执行文件。
* `on-authorized-authapfs-volume`：一个布尔值，指示操作系统是否从经过授权、经过身份验证的APFS卷加载了可执行文件。
* Cryptexes卷
* `on-system-volume:` 一个布尔值，指示操作系统是否从当前引导的系统卷加载了可执行文件。
* 在/System内部...
* ...

当苹果二进制文件被签名时，它会被分配到信任缓存中的一个LC类别中。

* **iOS 16个LC类别**已经[**被逆向并记录在这里**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。
* 当前的**LC类别（macOS 14 - Somona）已经被逆向并记录了它们的描述**，可以在[**这里找到**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。

例如，类别1是：
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: 必须位于系统或Cryptexes卷中。
* `launch-type == 1`: 必须是系统服务（在LaunchDaemons中的plist文件）。
* &#x20; `validation-category == 1`: 操作系统可执行文件。
* `is-init-proc`: Launchd

### 反向解析LC类别

你可以在[**这里**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints)找到更多信息，但基本上，它们是在**AMFI（AppleMobileFileIntegrity）**中定义的，所以你需要下载内核开发工具包来获取**KEXT**。以**`kConstraintCategory`**开头的符号是**有趣的**。提取它们，你将得到一个DER（ASN.1）编码的流，你需要使用[ASN.1解码器](https://holtstrom.com/michael/tools/asn1decoder.php)或python-asn1库及其`dump.py`脚本，[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)，它将给你一个更易理解的字符串。

## 环境约束

这些是在**第三方应用程序**中配置的启动约束。开发者可以选择在应用程序中使用的**事实**和**逻辑操作数**来限制对其自身的访问。

可以使用以下命令枚举应用程序的环境约束：
```bash
codesign -d -vvvv app.app
```
## 信任缓存

在**macOS**中有几个信任缓存：

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

而在iOS中，它似乎位于**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**。

### 枚举信任缓存

之前的信任缓存文件采用**IMG4**和**IM4P**格式，其中IM4P是IMG4格式的有效负载部分。

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

（另一个选择是使用工具[**img4tool**](https://github.com/tihmstar/img4tool)，即使是旧版本也可以在M1上运行，如果您将其安装在正确的位置，也可以在x86\_64上运行）。

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
信任缓存遵循以下结构，因此**LC类别是第4列**。
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
然后，您可以使用[**此脚本**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)之类的脚本来提取数据。

从这些数据中，您可以检查具有**启动约束值为`0`**的应用程序，这些应用程序没有受到约束（[**在此处检查**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)每个值的含义）。

## 攻击缓解

启动约束可以通过**确保进程不会在意外条件下执行**来缓解多个旧攻击：例如，来自意外位置的执行或由意外父进程调用（如果只有launchd应该启动它）。

此外，启动约束还可以**缓解降级攻击**。

然而，它们**无法缓解常见的XPC滥用**、**Electron**代码注入或没有库验证的**dylib注入**（除非已知可以加载库的团队ID）。

### XPC守护进程保护

在撰写本文时（Sonoma版本），守护进程XPC服务的**负责进程是XPC服务本身**，而不是连接的客户端（提交FB：FB13206884）。假设有一秒钟的时间，我们仍然**无法在攻击者代码中启动XPC服务**，但如果它已经**处于活动状态**（可能是因为原始应用程序调用了它），那么没有任何阻止我们**连接到它**的措施。因此，尽管设置约束可能是个好主意，并且会**限制攻击时间范围**，但它并不能解决主要问题，我们的XPC服务仍然应该正确验证连接的客户端。这仍然是保护它的唯一方法。而且正如一开始提到的，现在它甚至不起作用。

### Electron保护

即使要求应用程序必须通过**LaunchService打开**（在父进程的约束中）。这可以通过使用**`open`**（可以设置环境变量）或使用**Launch Services API**（可以指示环境变量）来实现。

## 参考资料

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中**为您的公司做广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧**
*
* .

</details>
