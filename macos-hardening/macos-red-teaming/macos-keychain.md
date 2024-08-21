# macOS Keychain

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由 **暗网** 驱动的搜索引擎，提供 **免费** 功能以检查公司或其客户是否被 **窃取恶意软件** **入侵**。

WhiteIntel 的主要目标是打击由于信息窃取恶意软件导致的账户接管和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

***

## 主要钥匙串

* **用户钥匙串** (`~/Library/Keychains/login.keycahin-db`)，用于存储 **用户特定凭据**，如应用程序密码、互联网密码、用户生成的证书、网络密码和用户生成的公钥/私钥。
* **系统钥匙串** (`/Library/Keychains/System.keychain`)，存储 **系统范围的凭据**，如 WiFi 密码、系统根证书、系统私钥和系统应用程序密码。

### 密码钥匙串访问

这些文件虽然没有固有保护且可以被 **下载**，但它们是加密的，需要 **用户的明文密码进行解密**。可以使用像 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 这样的工具进行解密。

## 钥匙串条目保护

### ACLs

钥匙串中的每个条目都受 **访问控制列表 (ACLs)** 的管理，规定谁可以对钥匙串条目执行各种操作，包括：

* **ACLAuhtorizationExportClear**：允许持有者获取秘密的明文。
* **ACLAuhtorizationExportWrapped**：允许持有者获取用另一个提供的密码加密的明文。
* **ACLAuhtorizationAny**：允许持有者执行任何操作。

ACLs 还附带一个 **受信任应用程序列表**，可以在不提示的情况下执行这些操作。可能是：

* **N`il`**（不需要授权，**所有人都被信任**）
* 一个 **空** 列表（**没有人**被信任）
* **特定应用程序** 的 **列表**。

条目还可能包含键 **`ACLAuthorizationPartitionID`**，用于识别 **teamid、apple** 和 **cdhash**。

* 如果指定了 **teamid**，则为了在 **不提示** 的情况下 **访问条目** 值，使用的应用程序必须具有 **相同的 teamid**。
* 如果指定了 **apple**，则应用程序需要由 **Apple** **签名**。
* 如果指明了 **cdhash**，则 **应用程序** 必须具有特定的 **cdhash**。

### 创建钥匙串条目

当使用 **`Keychain Access.app`** 创建 **新** **条目** 时，适用以下规则：

* 所有应用程序都可以加密。
* **没有应用程序** 可以导出/解密（在不提示用户的情况下）。
* 所有应用程序都可以查看完整性检查。
* 没有应用程序可以更改 ACLs。
* **partitionID** 设置为 **`apple`**。

当 **应用程序在钥匙串中创建条目** 时，规则略有不同：

* 所有应用程序都可以加密。
* 只有 **创建应用程序**（或任何其他明确添加的应用程序）可以导出/解密（在不提示用户的情况下）。
* 所有应用程序都可以查看完整性检查。
* 没有应用程序可以更改 ACLs。
* **partitionID** 设置为 **`teamid:[teamID here]`**。

## 访问钥匙串

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
**密钥链枚举和秘密转储**可以使用工具[**LockSmith**](https://github.com/its-a-feature/LockSmith)进行，这不会生成提示。
{% endhint %}

列出并获取每个密钥链条目的**信息**：

* API **`SecItemCopyMatching`**提供每个条目的信息，并且在使用时可以设置一些属性：
* **`kSecReturnData`**：如果为真，它将尝试解密数据（设置为假以避免潜在的弹出窗口）
* **`kSecReturnRef`**：还获取密钥链项的引用（如果稍后看到可以在没有弹出窗口的情况下解密，则设置为真）
* **`kSecReturnAttributes`**：获取条目的元数据
* **`kSecMatchLimit`**：返回多少结果
* **`kSecClass`**：什么类型的密钥链条目

获取每个条目的**ACL**：

* 使用API **`SecAccessCopyACLList`**可以获取**密钥链项的ACL**，它将返回一个ACL列表（如`ACLAuhtorizationExportClear`和之前提到的其他项），每个列表包含：
* 描述
* **受信任的应用程序列表**。这可以是：
* 一个应用程序：/Applications/Slack.app
* 一个二进制文件：/usr/libexec/airportd
* 一个组：group://AirPort

导出数据：

* API **`SecKeychainItemCopyContent`**获取明文
* API **`SecItemExport`**导出密钥和证书，但可能需要设置密码以加密导出内容

这些是能够**在没有提示的情况下导出秘密**的**要求**：

* 如果列出了**1个或多个受信任**的应用程序：
* 需要适当的**授权**（**`Nil`**，或是**允许**访问秘密信息的应用程序列表的一部分）
* 需要代码签名与**PartitionID**匹配
* 需要代码签名与一个**受信任的应用程序**的匹配（或是正确的KeychainAccessGroup的成员）
* 如果**所有应用程序都受信任**：
* 需要适当的**授权**
* 需要代码签名与**PartitionID**匹配
* 如果**没有PartitionID**，则不需要此项

{% hint style="danger" %}
因此，如果列出了**1个应用程序**，您需要**在该应用程序中注入代码**。

如果**apple**在**partitionID**中被指示，您可以使用**`osascript`**访问它，因此任何信任所有应用程序且在partitionID中包含apple的内容。**`Python`**也可以用于此。
{% endhint %}

### 两个额外属性

* **隐形**：这是一个布尔标志，用于**隐藏**密钥链应用程序中的条目
* **通用**：用于存储**元数据**（因此它不是加密的）
* 微软以明文存储所有访问敏感端点的刷新令牌。

## 参考

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)是一个**暗网**驱动的搜索引擎，提供**免费**功能以检查公司或其客户是否被**窃取恶意软件****入侵**。

WhiteIntel的主要目标是打击由于信息窃取恶意软件导致的账户接管和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我们在**Twitter**上的**🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github库提交PR来分享黑客技巧。

</details>
{% endhint %}
