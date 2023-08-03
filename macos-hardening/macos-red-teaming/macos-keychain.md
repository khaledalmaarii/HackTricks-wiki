# macOS 密钥链

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 PDF 格式的 HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 主要密钥链

* **用户密钥链** (`~/Library/Keychains/login.keycahin-db`)，用于存储**特定用户的凭据**，如应用程序密码、互联网密码、用户生成的证书、网络密码和用户生成的公钥/私钥。
* **系统密钥链** (`/Library/Keychains/System.keychain`)，用于存储**系统范围的凭据**，如 WiFi 密码、系统根证书、系统私钥和系统应用程序密码。

### 密码密钥链访问

这些文件虽然没有固有的保护，可以**下载**，但它们是加密的，需要**用户的明文密码进行解密**。可以使用 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 这样的工具进行解密。

## 密钥链条目保护

### ACLs

密钥链中的每个条目都受**访问控制列表 (ACLs)** 的管理，ACLs 规定了谁可以对密钥链条目执行各种操作，包括：

* **ACLAuhtorizationExportClear**：允许持有者获取明文密码。
* **ACLAuhtorizationExportWrapped**：允许持有者获取使用另一个提供的密码加密的明文密码。
* **ACLAuhtorizationAny**：允许持有者执行任何操作。

ACLs 还附带了一个**可信应用程序列表**，这些应用程序可以在不提示的情况下执行这些操作。这可以是：

* **N`il`**（无需授权，**每个人都受信任**）
* 一个**空**列表（**没有人**受信任）
* 特定**应用程序**的**列表**。

此外，条目可能包含键**`ACLAuthorizationPartitionID`**，用于标识**teamid、apple**和**cdhash**。

* 如果指定了**teamid**，则为了在**不提示**的情况下**访问条目**值，使用的应用程序必须具有**相同的 teamid**。
* 如果指定了**apple**，则该应用程序需要由**Apple**签名。
* 如果指定了**cdhash**，则应用程序必须具有特定的**cdhash**。

### 创建密钥链条目

当使用**`Keychain Access.app`**创建一个**新的条目**时，适用以下规则：

* 所有应用程序都可以进行加密。
* **没有应用程序**可以导出/解密（无需提示用户）。
* 所有应用程序都可以查看完整性检查。
* 没有应用程序可以更改 ACLs。
* **partitionID** 设置为**`apple`**。

当应用程序在密钥链中创建条目时，规则略有不同：

* 所有应用程序都可以进行加密。
* 只有**创建条目的应用程序**（或其他明确添加的应用程序）可以导出/解密（无需提示用户）。
* 所有应用程序都可以查看完整性检查。
* 没有应用程序可以更改 ACLs。
* **partitionID** 设置为**`teamid:[teamID here]`**。

## 访问密钥链

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
可以使用工具[**LockSmith**](https://github.com/its-a-feature/LockSmith)来进行**密钥链枚举和转储**，而不会生成提示。
{% endhint %}

列出并获取每个密钥链条目的**信息**：

* API **`SecItemCopyMatching`** 提供有关每个条目的信息，并且在使用时可以设置一些属性：
* **`kSecReturnData`**：如果为true，它将尝试解密数据（设置为false以避免潜在的弹出窗口）
* **`kSecReturnRef`**：还获取密钥链条目的引用（如果稍后发现可以在没有弹出窗口的情况下解密，则设置为true）
* **`kSecReturnAttributes`**：获取条目的元数据
* **`kSecMatchLimit`**：返回的结果数量
* **`kSecClass`**：密钥链条目的类型

获取每个条目的**ACL**：

* 使用API **`SecAccessCopyACLList`** 可以获取密钥链条目的ACL，并返回一个ACL列表（如`ACLAuhtorizationExportClear`和之前提到的其他列表），其中每个列表都有：
* 描述
* **受信任的应用程序列表**。这可以是：
* 一个应用程序：/Applications/Slack.app
* 一个二进制文件：/usr/libexec/airportd
* 一个组：group://AirPort

导出数据：

* API **`SecKeychainItemCopyContent`** 获取明文
* API **`SecItemExport`** 导出密钥和证书，但可能需要设置密码以加密导出的内容

以下是**导出密钥而无需提示**的**要求**：

* 如果列出了**1个或多个受信任的**应用程序：
* 需要适当的**授权**（`Nil`），或者是授权访问秘密信息的应用程序允许列表的一部分
* 需要代码签名与**PartitionID**匹配
* 需要代码签名与一个**受信任的应用程序**匹配（或者是正确的KeychainAccessGroup的成员）
* 如果**所有应用程序都受信任**：
* 需要适当的**授权**
* 需要代码签名与**PartitionID**匹配
* 如果**没有PartitionID**，则不需要此项

{% hint style="danger" %}
因此，如果只有**1个应用程序**列出，您需要**在该应用程序中注入代码**。

如果**partitionID**中指定了**apple**，则可以使用**`osascript`**访问它，因此可以信任所有具有apple的partitionID的应用程序。也可以使用**`Python`**进行此操作。
{% endhint %}

### 两个附加属性

* **Invisible**：这是一个布尔标志，用于从**UI**密钥链应用程序中**隐藏**条目
* **General**：用于存储**元数据**（因此**不加密**）
* Microsoft将所有用于访问敏感端点的刷新令牌明文存储。

## 参考资料

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
