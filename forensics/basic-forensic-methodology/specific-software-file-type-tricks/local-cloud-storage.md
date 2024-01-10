# 本地云存储

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

在Windows中，可以在`\Users\<username>\AppData\Local\Microsoft\OneDrive`找到OneDrive文件夹。在`logs\Personal`内部，可以找到名为`SyncDiagnostics.log`的文件，其中包含了关于同步文件的一些有趣数据：

* 字节大小
* 创建日期
* 修改日期
* 云中的文件数量
* 文件夹中的文件数量
* **CID**：OneDrive用户的唯一ID
* 报告生成时间
* 操作系统HD的大小

找到CID后，建议**搜索包含此ID的文件**。您可能能够找到名为_**\<CID>.ini**_ 和 _**\<CID>.dat**_ 的文件，这些文件可能包含像与OneDrive同步的文件名等有趣信息。

## Google Drive

在Windows中，可以在`\Users\<username>\AppData\Local\Google\Drive\user_default`找到主要的Google Drive文件夹\
该文件夹包含一个名为Sync_log.log的文件，其中包含账户的电子邮件地址、文件名、时间戳、文件的MD5哈希等信息。即使是已删除的文件也会在该日志文件中出现，并带有相应的MD5。

文件**`Cloud_graph\Cloud_graph.db`**是一个sqlite数据库，其中包含**`cloud_graph_entry`**表。在这个表中，您可以找到**同步**文件的**名称**、修改时间、大小和文件的MD5校验和。

数据库**`Sync_config.db`**的表数据包含账户的电子邮件地址、共享文件夹的路径和Google Drive版本。

## Dropbox

Dropbox使用**SQLite数据库**来管理文件。在这\
您可以在以下文件夹中找到数据库：

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

主要数据库包括：

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx"扩展名意味着**数据库**是**加密的**。Dropbox使用**DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

要更好地理解Dropbox使用的加密，您可以阅读[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)。

然而，主要信息是：

* **熵**：d114a55212655f74bd772e37e64aee9b
* **盐**：0D638C092E8B82FC452883F95F355B8E
* **算法**：PBKDF2
* **迭代次数**：1066

除了那些信息，要解密数据库您还需要：

* **加密的DPAPI密钥**：您可以在注册表中的`NTUSER.DAT\Software\Dropbox\ks\client`找到它（以二进制形式导出此数据）
* **`SYSTEM`** 和 **`SECURITY`** 蜂巢
* **DPAPI主密钥**：可以在`\Users\<username>\AppData\Roaming\Microsoft\Protect`找到
* Windows用户的**用户名**和**密码**

然后您可以使用工具 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**：**

![](<../../../.gitbook/assets/image (448).png>)

如果一切顺利，该工具将指示您需要**使用的主密钥来恢复原始密钥**。要恢复原始密钥，只需使用这个[cyber_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\))，将主密钥作为“密码短语”放入收据中。

得到的十六进制是用于加密数据库的最终密钥，可以用以下方式解密：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** 数据库包含：

* **Email**：用户的电子邮件
* **usernamedisplayname**：用户的名称
* **dropbox\_path**：Dropbox文件夹所在的路径
* **Host\_id**：用于认证云服务的哈希。这只能从网页上撤销。
* **Root\_ns**：用户标识符

**`filecache.db`** 数据库包含与Dropbox同步的所有文件和文件夹的信息。`File_journal` 表包含更有用的信息：

* **Server\_path**：服务器内文件所在的路径（该路径前面有客户端的`host_id`）。
* **local\_sjid**：文件的版本
* **local\_mtime**：修改日期
* **local\_ctime**：创建日期

这个数据库内的其他表包含更多有趣的信息：

* **block\_cache**：Dropbox的所有文件和文件夹的哈希
* **block\_ref**：将`block_cache`表的哈希ID与`file_journal`表中的文件ID关联
* **mount\_table**：Dropbox的共享文件夹
* **deleted\_fields**：Dropbox已删除的文件
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 来轻松构建和**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
