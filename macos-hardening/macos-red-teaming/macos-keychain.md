# macOS钥匙串

{% hint style="success" %}
学习并练习AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)是一个由**暗网**推动的搜索引擎，提供免费功能，用于检查公司或其客户是否受到**窃取恶意软件**的**侵害**。

WhiteIntel的主要目标是打击由信息窃取恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

***

## 主要钥匙串

* **用户钥匙串**（`~/Library/Keychains/login.keycahin-db`），用于存储诸如应用程序密码、互联网密码、用户生成的证书、网络密码和用户生成的公钥/私钥等**特定于用户**的凭据。
* **系统钥匙串**（`/Library/Keychains/System.keychain`），存储**系统范围**的凭据，如WiFi密码、系统根证书、系统私钥和系统应用程序密码。

### 密码钥匙串访问

这些文件虽然没有固有的保护措施，可以被**下载**，但是它们是加密的，需要**用户的明文密码才能解密**。可以使用类似[**Chainbreaker**](https://github.com/n0fate/chainbreaker)的工具进行解密。

## 钥匙串条目保护

### ACLs

钥匙串中的每个条目都受**访问控制列表（ACLs）**的管辖，ACLs规定了谁可以对钥匙串条目执行各种操作，包括：

* **ACLAuhtorizationExportClear**：允许持有者获取密钥的明文。
* **ACLAuhtorizationExportWrapped**：允许持有者获取使用另一个提供的密码加密的明文。
* **ACLAuhtorizationAny**：允许持有者执行任何操作。

ACLs还伴随着一个**可信应用程序列表**，这些应用程序可以在不提示的情况下执行这些操作。这可能是：

* **N`il`**（无需授权，**每个人都受信任**）
* 一个**空**列表（**没有人**受信任）
* 特定**应用程序**的**列表**。

此外，条目可能包含**`ACLAuthorizationPartitionID`**密钥，用于识别**teamid、apple**和**cdhash**。

* 如果指定了**teamid**，则为了**无需提示地访问条目**值，使用的应用程序必须具有**相同的teamid**。
* 如果指定了**apple**，则应用程序需要由**Apple**签名。
* 如果指定了**cdhash**，则**应用程序**必须具有特定的**cdhash**。

### 创建钥匙串条目

当使用**`Keychain Access.app`**创建**新**的**条目**时，适用以下规则：

* 所有应用程序都可以加密。
* **没有应用程序**可以导出/解密（无需提示用户）。
* 所有应用程序都可以查看完整性检查。
* 没有应用程序可以更改ACLs。
* **partitionID**设置为**`apple`**。

当**应用程序在钥匙串中创建条目**时，规则略有不同：

* 所有应用程序都可以加密。
* 只有**创建应用程序**（或明确添加的任何其他应用程序）可以导出/解密（无需提示用户）。
* 所有应用程序都可以查看完整性检查。
* 没有应用程序可以更改ACLs。
* **partitionID**设置为**`teamid:[teamID here]`**。

## 访问钥匙串

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
**密钥链枚举和转储**不会生成提示的机密可以使用工具[**LockSmith**](https://github.com/its-a-feature/LockSmith)来完成
{% endhint %}

列出并获取每个密钥链条目的**信息**：

* API **`SecItemCopyMatching`** 提供每个条目的信息，使用时可以设置一些属性：
* **`kSecReturnData`**：如果为true，将尝试解密数据（设置为false可避免潜在的弹出窗口）
* **`kSecReturnRef`**：还可以获取密钥链条目的引用（如果后来发现可以无需弹出窗口解密，则设置为true）
* **`kSecReturnAttributes`**：获取条目的元数据
* **`kSecMatchLimit`**：返回多少结果
* **`kSecClass`**：密钥链条目的类型

获取每个条目的**ACL**：

* 使用API **`SecAccessCopyACLList`** 可以获取密钥链条目的**ACL**，它将返回一个ACL列表（如`ACLAuhtorizationExportClear`和之前提到的其他），其中每个列表包括：
* 描述
* **受信任应用程序列表**。这可以是：
* 一个应用程序：/Applications/Slack.app
* 一个二进制文件：/usr/libexec/airportd
* 一个组：group://AirPort

导出数据：

* API **`SecKeychainItemCopyContent`** 获取明文
* API **`SecItemExport`** 导出密钥和证书，但可能需要设置密码以加密导出内容

以下是**无需提示即可导出机密**的**要求**：

* 如果列出了**1个或更多受信任的**应用程序：
* 需要适当的**授权**（**`Nil`**，或者是授权访问机密信息的应用程序允许列表的一部分）
* 需要代码签名匹配**PartitionID**
* 需要代码签名与一个**受信任应用程序**匹配（或者是正确的KeychainAccessGroup的成员）
* 如果**所有应用程序都受信任**：
* 需要适当的**授权**
* 需要代码签名匹配**PartitionID**
* 如果**没有PartitionID**，则不需要这个

{% hint style="danger" %}
因此，如果列出了**1个应用程序**，则需要**在该应用程序中注入代码**。

如果**partitionID**中指定了**apple**，则可以使用**`osascript`**访问它，因此任何信任partitionID中带有apple的所有应用程序的内容。也可以使用**`Python`**实现这一点。
{% endhint %}

### 两个额外属性

* **Invisible**：这是一个布尔标志，用于从**UI**密钥链应用程序中**隐藏**条目
* **General**：用于存储**元数据**（因此**未加密**）
* Microsoft将所有用于访问敏感端点的刷新令牌都以明文形式存储。

## 参考资料

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)是一个由**暗网**推动的搜索引擎，提供免费功能，用于检查公司或其客户是否已受到**窃取恶意软件**的**侵害**。

WhiteIntel的主要目标是打击由窃取信息的恶意软件导致的账户劫持和勒索软件攻击。

您可以在以下网址检查他们的网站并尝试他们的引擎，**免费**使用：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
学习并练习AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}
