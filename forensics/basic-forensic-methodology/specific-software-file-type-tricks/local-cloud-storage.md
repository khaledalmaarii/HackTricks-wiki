# 本地云存储

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github仓库提交PR来分享您的黑客技巧**。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

在Windows中，您可以在`\Users\<username>\AppData\Local\Microsoft\OneDrive`找到OneDrive文件夹。在`logs\Personal`文件夹中，可以找到名为`SyncDiagnostics.log`的文件，其中包含有关同步文件的一些有趣数据：

* 字节大小
* 创建日期
* 修改日期
* 云端文件数量
* 文件夹中的文件数量
* **CID**：OneDrive用户的唯一ID
* 报告生成时间
* 操作系统的硬盘大小

一旦找到CID，建议**搜索包含此ID的文件**。您可能会找到文件名为：_**\<CID>.ini**_ 和 _**\<CID>.dat**_，其中可能包含与OneDrive同步的文件的名称等有趣信息。

## Google Drive

在Windows中，您可以在`\Users\<username>\AppData\Local\Google\Drive\user_default`找到主Google Drive文件夹\
此文件夹包含一个名为Sync\_log.log的文件，其中包含帐户的电子邮件地址、文件名、时间戳、文件的MD5哈希等信息。即使已删除的文件也会在该日志文件中显示其相应的MD5。

文件**`Cloud_graph\Cloud_graph.db`**是一个包含表**`cloud_graph_entry`**的sqlite数据库。在这个表中，您可以找到**同步的文件**的**名称**、修改时间、大小和文件的MD5校验和。

数据库**`Sync_config.db`**的表数据包含帐户的电子邮件地址、共享文件夹的路径和Google Drive版本。

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

“.dbx”扩展名表示**数据库是加密的**。Dropbox使用**DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

要更好地理解Dropbox使用的加密，您可以阅读[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)。

然而，主要信息包括：

* **熵**：d114a55212655f74bd772e37e64aee9b
* **盐**：0D638C092E8B82FC452883F95F355B8E
* **算法**：PBKDF2
* **迭代次数**：1066

除了这些信息，要解密数据库，您还需要：

* **加密的DPAPI密钥**：您可以在注册表中找到，位于`NTUSER.DAT\Software\Dropbox\ks\client`内（将此数据导出为二进制）
* **`SYSTEM`**和**`SECURITY`**注册表
* **DPAPI主密钥**：可以在`\Users\<username>\AppData\Roaming\Microsoft\Protect`中找到
* Windows用户的**用户名**和**密码**

然后，您可以使用工具[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**：**

![](<../../../.gitbook/assets/image (448).png>)

如果一切顺利，该工具将指示您需要使用的**主密钥**来**恢复原始密钥**。要恢复原始密钥，只需在此[cyber\_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)中将主密钥作为“密码”放入该收据。

生成的十六进制是用于加密数据库的最终密钥，可以使用以下方式解密：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** 数据库包含：

- **Email**：用户的电子邮件
- **usernamedisplayname**：用户的名称
- **dropbox\_path**：Dropbox文件夹的路径
- **Host\_id**：用于在云端进行身份验证的哈希。只能通过网络撤销此哈希。
- **Root\_ns**：用户标识符

**`filecache.db`** 数据库包含与Dropbox同步的所有文件和文件夹的信息。表`File_journal`是包含最有用信息的表：

- **Server\_path**：文件在服务器内的路径（此路径前面带有客户端的`host_id`）。
- **local\_sjid**：文件的版本
- **local\_mtime**：修改日期
- **local\_ctime**：创建日期

此数据库中的其他表包含更多有趣的信息：

- **block\_cache**：Dropbox所有文件和文件夹的哈希
- **block\_ref**：将表`block_cache`中的哈希ID与表`file_journal`中的文件ID相关联
- **mount\_table**：共享Dropbox文件夹
- **deleted\_fields**：已删除的Dropbox文件
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注**我们。
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
