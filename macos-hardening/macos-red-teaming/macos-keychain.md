# macOS 密钥链

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 主要密钥链

* **用户密钥链** (`~/Library/Keychains/login.keycahin-db`)，用于存储**用户特定的凭据**，如应用程序密码、互联网密码、用户生成的证书、网络密码和用户生成的公钥/私钥。
* **系统密钥链** (`/Library/Keychains/System.keychain`)，存储**系统范围的凭据**，如 WiFi 密码、系统根证书、系统私钥和系统应用程序密码。

### 密码密钥链访问

这些文件虽然没有固有的保护，可以被**下载**，但是加密的，需要**用户的明文密码才能解密**。可以使用像 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 这样的工具进行解密。

## 密钥链条目保护

### ACLs

密钥链中的每个条目都由**访问控制列表 (ACLs)** 管理，它规定了谁可以对密钥链条目执行各种操作，包括：

* **ACLAuhtorizationExportClear**：允许持有者获取秘密的明文。
* **ACLAuhtorizationExportWrapped**：允许持有者获取用另一个提供的密码加密的明文。
* **ACLAuhtorizationAny**：允许持有者执行任何操作。

ACLs 还伴随着一个**可信应用程序列表**，这些应用程序可以在不提示的情况下执行这些操作。这可能是：

* &#x20;**N`il`**（无需授权，**所有人都被信任**）
* 一个**空**列表（**没有人**被信任）
* 特定**应用程序**的**列表**。

条目还可能包含关键字 **`ACLAuthorizationPartitionID`,** 用于识别**teamid, apple,** 和 **cdhash.**

* 如果指定了 **teamid**，那么为了**访问条目**值**无需**提示，使用的应用程序必须有**相同的 teamid**。
* 如果指定了 **apple**，那么应用程序需要由**Apple**签名。
* 如果指示了 **cdhash**，那么**应用程序**必须有特定的**cdhash**。

### 创建密钥链条目

使用 **`Keychain Access.app`** 创建**新的** **条目**时，适用以下规则：

* 所有应用程序都可以加密。
* **没有应用程序**可以导出/解密（无需提示用户）。
* 所有应用程序都可以看到完整性检查。
* 没有应用程序可以更改 ACLs。
* **partitionID** 被设置为 **`apple`**。

当**应用程序在密钥链中创建条目**时，规则略有不同：

* 所有应用程序都可以加密。
* 只有**创建应用程序**（或任何其他明确添加的应用程序）可以导出/解密（无需提示用户）。
* 所有应用程序都可以看到完整性检查。
* 没有应用程序可以更改 ACLs。
* **partitionID** 被设置为 **`teamid:[teamID here]`**。

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
**钥匙串枚举和转储**不会生成提示的秘密可以使用工具 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 来完成。
{% endhint %}

列出并获取每个钥匙串条目的**信息**：

* API **`SecItemCopyMatching`** 提供每个条目的信息，使用时可以设置一些属性：
* **`kSecReturnData`**：如果为真，它将尝试解密数据（设置为假以避免可能的弹出窗口）
* **`kSecReturnRef`**：还获取钥匙串项目的引用（如果稍后发现可以在没有弹出窗口的情况下解密，则设置为真）
* **`kSecReturnAttributes`**：获取条目的元数据
* **`kSecMatchLimit`**：返回多少结果
* **`kSecClass`**：钥匙串条目的种类

获取每个条目的**ACLs**：

* 使用 API **`SecAccessCopyACLList`** 可以获取**钥匙串项目的 ACL**，它将返回 ACL 列表（如 `ACLAuhtorizationExportClear` 和之前提到的其他列表），每个列表包含：
* 描述
* **受信任的应用程序列表**。这可能是：
* 应用程序：/Applications/Slack.app
* 二进制文件：/usr/libexec/airportd
* 组：group://AirPort

导出数据：

* API **`SecKeychainItemCopyContent`** 获取明文
* API **`SecItemExport`** 导出密钥和证书，但可能需要设置密码以加密导出内容

以下是**无提示导出秘密**的**要求**：

* 如果列出了**1+ 受信任**的应用程序：
* 需要适当的**授权**（**`Nil`**，或成为授权中允许访问秘密信息的应用程序列表的**一部分**）
* 需要代码签名与**PartitionID**匹配
* 需要代码签名与一个**受信任的应用程序**匹配（或成为正确的 KeychainAccessGroup 的成员）
* 如果**所有应用程序都受信任**：
* 需要适当的**授权**
* 需要代码签名与**PartitionID**匹配
* 如果**没有 PartitionID**，则不需要这个

{% hint style="danger" %}
因此，如果列出了**1个应用程序**，你需要在该应用程序中**注入代码**。

如果在**partitionID**中指明了**apple**，你可以使用 **`osascript`** 访问它，所以任何信任所有带有 apple partitionID 的应用程序。**`Python`** 也可以用于此。
{% endhint %}

### 两个额外的属性

* **Invisible**：它是一个布尔标志，用于从**UI**钥匙串应用程序中**隐藏**条目
* **General**：它用于存储**元数据**（所以它**不是加密的**）
* Microsoft 在明文中存储了所有用于访问敏感端点的刷新令牌。

## 参考资料

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧**。

</details>
