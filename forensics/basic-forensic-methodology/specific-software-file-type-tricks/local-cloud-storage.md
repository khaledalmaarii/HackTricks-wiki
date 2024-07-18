# 本地云存储

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建和 **自动化工作流**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

在 Windows 中，您可以在 `\Users\<username>\AppData\Local\Microsoft\OneDrive` 找到 OneDrive 文件夹。在 `logs\Personal` 中，可以找到名为 `SyncDiagnostics.log` 的文件，其中包含有关同步文件的一些有趣数据：

* 字节大小
* 创建日期
* 修改日期
* 云中的文件数量
* 文件夹中的文件数量
* **CID**：OneDrive 用户的唯一 ID
* 报告生成时间
* 操作系统的硬盘大小

一旦找到 CID，建议 **搜索包含此 ID 的文件**。您可能会找到名为：_**\<CID>.ini**_ 和 _**\<CID>.dat**_ 的文件，这些文件可能包含与 OneDrive 同步的文件名等有趣信息。

## Google Drive

在 Windows 中，您可以在 `\Users\<username>\AppData\Local\Google\Drive\user_default` 找到主要的 Google Drive 文件夹\
此文件夹包含一个名为 Sync\_log.log 的文件，里面有账户的电子邮件地址、文件名、时间戳、文件的 MD5 哈希等信息。即使是已删除的文件也会出现在该日志文件中，并带有相应的 MD5。

文件 **`Cloud_graph\Cloud_graph.db`** 是一个 sqlite 数据库，包含表 **`cloud_graph_entry`**。在此表中，您可以找到 **同步** **文件** 的 **名称**、修改时间、大小和文件的 MD5 校验和。

数据库 **`Sync_config.db`** 的表数据包含账户的电子邮件地址、共享文件夹的路径和 Google Drive 版本。

## Dropbox

Dropbox 使用 **SQLite 数据库** 来管理文件。在此\
您可以在以下文件夹中找到数据库：

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

主要数据库包括：

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

“.dbx” 扩展名表示 **数据库** 是 **加密的**。Dropbox 使用 **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

要更好地理解 Dropbox 使用的加密，您可以阅读 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)。

然而，主要信息是：

* **熵**：d114a55212655f74bd772e37e64aee9b
* **盐**：0D638C092E8B82FC452883F95F355B8E
* **算法**：PBKDF2
* **迭代次数**：1066

除此之外，要解密数据库，您还需要：

* **加密的 DPAPI 密钥**：您可以在注册表中找到它，路径为 `NTUSER.DAT\Software\Dropbox\ks\client`（将此数据导出为二进制）
* **`SYSTEM`** 和 **`SECURITY`** 注册表项
* **DPAPI 主密钥**：可以在 `\Users\<username>\AppData\Roaming\Microsoft\Protect` 找到
* Windows 用户的 **用户名** 和 **密码**

然后您可以使用工具 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

如果一切顺利，该工具将指示您需要 **使用以恢复原始密钥**。要恢复原始密钥，只需使用此 [cyber\_chef 配方](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\))，将主密钥作为配方中的“密码短语”。

生成的十六进制是用于加密数据库的最终密钥，可以用来解密：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** 数据库包含：

* **Email**: 用户的电子邮件
* **usernamedisplayname**: 用户的名称
* **dropbox\_path**: Dropbox 文件夹所在的路径
* **Host\_id: Hash** 用于认证到云端。此项只能从网页上撤销。
* **Root\_ns**: 用户标识符

The **`filecache.db`** 数据库包含与 Dropbox 同步的所有文件和文件夹的信息。表 `File_journal` 是包含更多有用信息的表：

* **Server\_path**: 文件在服务器内部的路径（此路径前面有客户端的 `host_id`）。
* **local\_sjid**: 文件的版本
* **local\_mtime**: 修改日期
* **local\_ctime**: 创建日期

此数据库中的其他表包含更多有趣的信息：

* **block\_cache**: Dropbox 所有文件和文件夹的哈希
* **block\_ref**: 将表 `block_cache` 的哈希 ID 与表 `file_journal` 中的文件 ID 关联
* **mount\_table**: Dropbox 的共享文件夹
* **deleted\_fields**: Dropbox 删除的文件
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术： <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
