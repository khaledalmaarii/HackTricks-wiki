# Phishing Methodology

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

## Methodology

1. 侦查受害者
1. 选择 **受害者域名**。
2. 执行一些基本的网络枚举 **寻找受害者使用的登录门户** 并 **决定** 你将 **冒充** 哪一个。
3. 使用一些 **OSINT** 来 **查找电子邮件**。
2. 准备环境
1. **购买你将用于钓鱼评估的域名**
2. **配置电子邮件服务** 相关记录 (SPF, DMARC, DKIM, rDNS)
3. 使用 **gophish** 配置 VPS
3. 准备活动
1. 准备 **电子邮件模板**
2. 准备 **网页** 以窃取凭据
4. 启动活动！

## 生成类似域名或购买受信任的域名

### 域名变体技术

* **关键词**：域名 **包含** 原始域名的重要 **关键词** (例如，zelster.com-management.com)。
* **带连字符的子域**：将子域的 **点替换为连字符** (例如，www-zelster.com)。
* **新 TLD**：使用 **新 TLD** 的相同域名 (例如，zelster.org)
* **同形异义字**：用 **看起来相似的字母** 替换域名中的一个字母 (例如，zelfser.com)。
* **置换**：在域名中 **交换两个字母** (例如，zelsetr.com)。
* **单数/复数化**：在域名末尾添加或删除 “s” (例如，zeltsers.com)。
* **省略**：从域名中 **删除一个** 字母 (例如，zelser.com)。
* **重复**：在域名中 **重复一个** 字母 (例如，zeltsser.com)。
* **替换**：类似同形异义字，但不那么隐蔽。它用键盘上与原字母相近的字母替换域名中的一个字母 (例如，zektser.com)。
* **子域化**：在域名中引入一个 **点** (例如，ze.lster.com)。
* **插入**：在域名中 **插入一个字母** (例如，zerltser.com)。
* **缺失点**：将 TLD 附加到域名上 (例如，zelstercom.com)

**自动工具**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### 位翻转

由于太阳耀斑、宇宙射线或硬件错误等各种因素，**存储或通信中的某些位可能会自动翻转**。

当这个概念 **应用于 DNS 请求** 时，**DNS 服务器接收到的域名** 可能与最初请求的域名不同。

例如，域名 "windows.com" 中的单个位修改可以将其更改为 "windnws.com"。

攻击者可能会 **利用这一点注册多个位翻转域名**，这些域名与受害者的域名相似。他们的意图是将合法用户重定向到他们自己的基础设施。

有关更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买受信任的域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索可以使用的过期域名。\
为了确保你要购买的过期域名 **已经有良好的 SEO**，你可以搜索它在以下网站的分类：

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 免费)
* [https://phonebook.cz/](https://phonebook.cz) (100% 免费)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

为了 **发现更多** 有效的电子邮件地址或 **验证你已经发现的地址**，你可以检查是否可以对受害者的 smtp 服务器进行暴力破解。 [在这里学习如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用 **任何网络门户访问他们的邮件**，你可以检查它是否容易受到 **用户名暴力破解**，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### 安装

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载。

下载并解压到 `/opt/gophish` 中，然后执行 `/opt/gophish/gophish`\
你将在输出中获得端口 3333 的管理员用户密码。因此，访问该端口并使用这些凭据更改管理员密码。你可能需要将该端口隧道到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在这一步之前，您应该已经**购买了您将要使用的域名**，并且它必须**指向**您正在配置**gophish**的**VPS 的 IP**。
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**邮件配置**

开始安装: `apt-get install postfix`

然后将域名添加到以下文件中:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**还要更改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为您的域名并 **重启您的 VPS。**

现在，创建一个指向 VPS **ip 地址** 的 **DNS A 记录** `mail.<domain>` 和一个指向 `mail.<domain>` 的 **DNS MX** 记录

现在让我们测试发送电子邮件:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行并进行配置。\
将 `/opt/gophish/config.json` 修改为以下内容（注意使用 https）：
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**配置 gophish 服务**

为了创建 gophish 服务，使其能够自动启动并作为服务进行管理，您可以创建文件 `/etc/init.d/gophish`，并添加以下内容：
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
完成配置服务并检查它的方法：
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## 配置邮件服务器和域名

### 等待并保持合法

域名越老，被识别为垃圾邮件的可能性就越小。因此，在进行钓鱼评估之前，您应该尽可能等待更长的时间（至少1周）。此外，如果您放置一个关于声誉行业的页面，获得的声誉将会更好。

请注意，即使您需要等待一周，您现在也可以完成所有配置。

### 配置反向DNS (rDNS) 记录

设置一个将VPS的IP地址解析到域名的rDNS (PTR) 记录。

### 发件人策略框架 (SPF) 记录

您必须**为新域配置SPF记录**。如果您不知道什么是SPF记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#spf)。

您可以使用[https://www.spfwizard.net/](https://www.spfwizard.net)来生成您的SPF策略（使用VPS机器的IP）。

![](<../../.gitbook/assets/image (1037).png>)

这是必须在域名的TXT记录中设置的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告和一致性 (DMARC) 记录

您必须**为新域配置 DMARC 记录**。如果您不知道什么是 DMARC 记录 [**请阅读此页面**](../../network-services-pentesting/pentesting-smtp/#dmarc)。

您需要创建一个新的 DNS TXT 记录，指向主机名 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

您必须**为新域配置 DKIM**。如果您不知道什么是 DMARC 记录 [**请阅读此页面**](../../network-services-pentesting/pentesting-smtp/#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
您需要连接 DKIM 密钥生成的两个 B64 值：
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### 测试您的电子邮件配置得分

您可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com)\
只需访问该页面并向他们提供的地址发送电子邮件：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
您还可以通过向 `check-auth@verifier.port25.com` 发送电子邮件来**检查您的电子邮件配置**，并**阅读响应**（为此，您需要**打开**端口**25**，并在文件 _/var/mail/root_ 中查看响应，如果您以 root 身份发送电子邮件）。\
检查您是否通过了所有测试：
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
您还可以向**您控制的Gmail发送消息**，并检查您Gmail收件箱中的**电子邮件头**，`dkim=pass`应出现在`Authentication-Results`头字段中。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​从Spamhouse黑名单中移除

页面 [www.mail-tester.com](https://www.mail-tester.com) 可以指示您的域名是否被spamhouse阻止。您可以在以下网址请求移除您的域名/IP: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从Microsoft黑名单中移除

您可以在 [https://sender.office.com/](https://sender.office.com) 请求移除您的域名/IP。

## 创建并启动GoPhish活动

### 发送配置

* 设置一些 **名称以识别** 发送者配置
* 决定您将从哪个账户发送钓鱼邮件。建议：_noreply, support, servicedesk, salesforce..._
* 您可以将用户名和密码留空，但请确保勾选忽略证书错误

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
建议使用“**发送测试邮件**”功能来测试一切是否正常。\
我建议将**测试邮件发送到10分钟邮件地址**以避免在测试中被列入黑名单。
{% endhint %}

### 邮件模板

* 设置一些 **名称以识别** 模板
* 然后写一个 **主题**（没有奇怪的内容，只是您在常规邮件中可能会看到的内容）
* 确保您已勾选“**添加跟踪图像**”
* 编写 **邮件模板**（您可以使用变量，如以下示例所示）：
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
注意，**为了提高电子邮件的可信度**，建议使用客户的电子邮件中的某些签名。建议：

* 向一个**不存在的地址**发送电子邮件，并检查回复是否有任何签名。
* 搜索**公共电子邮件**，如 info@ex.com 或 press@ex.com 或 public@ex.com，并向他们发送电子邮件，等待回复。
* 尝试联系**一些有效的发现**电子邮件，并等待回复。

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
电子邮件模板还允许**附加要发送的文件**。如果您还想使用一些特别制作的文件/文档窃取 NTLM 挑战，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。
{% endhint %}

### 登陆页面

* 写一个**名称**
* **编写网页的 HTML 代码**。请注意，您可以**导入**网页。
* 标记**捕获提交的数据**和**捕获密码**
* 设置**重定向**

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
通常，您需要修改页面的 HTML 代码并在本地进行一些测试（可能使用一些 Apache 服务器）**直到您满意结果。** 然后，将该 HTML 代码写入框中。\
请注意，如果您需要**使用一些静态资源**用于 HTML（可能是一些 CSS 和 JS 页面），您可以将它们保存在 _**/opt/gophish/static/endpoint**_ 中，然后从 _**/static/\<filename>**_ 访问它们。
{% endhint %}

{% hint style="info" %}
对于重定向，您可以**将用户重定向到受害者的合法主网页**，或者例如将他们重定向到 _/static/migration.html_，放置一些**旋转轮**（**[https://loading.io/](https://loading.io)**）5秒钟，然后指示该过程成功。
{% endhint %}

### 用户与组

* 设置一个名称
* **导入数据**（请注意，为了使用示例模板，您需要每个用户的名字、姓氏和电子邮件地址）

![](<../../.gitbook/assets/image (163).png>)

### 活动

最后，创建一个活动，选择一个名称、电子邮件模板、登陆页面、URL、发送配置文件和组。请注意，URL 将是发送给受害者的链接。

注意，**发送配置文件允许发送测试电子邮件以查看最终的钓鱼电子邮件的样子**：

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
我建议**将测试电子邮件发送到 10 分钟邮件地址**以避免在测试中被列入黑名单。
{% endhint %}

一切准备就绪后，只需启动活动！

## 网站克隆

如果出于任何原因您想克隆网站，请查看以下页面：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## 后门文档和文件

在某些钓鱼评估中（主要针对红队），您还希望**发送包含某种后门的文件**（可能是 C2，或者只是触发身份验证的东西）。\
查看以下页面以获取一些示例：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## 钓鱼 MFA

### 通过代理 MitM

之前的攻击非常聪明，因为您伪造了一个真实的网站并收集了用户输入的信息。不幸的是，如果用户没有输入正确的密码，或者您伪造的应用程序配置了 2FA，**这些信息将无法让您冒充被欺骗的用户**。

这就是像 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、** [**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具有用的地方。这个工具将允许您生成类似 MitM 的攻击。基本上，攻击的工作方式如下：

1. 您**冒充真实网页的登录**表单。
2. 用户**发送**他的**凭据**到您的假页面，工具将这些发送到真实网页，**检查凭据是否有效**。
3. 如果账户配置了**2FA**，MitM 页面将要求输入，一旦**用户输入**，工具将其发送到真实网页。
4. 一旦用户通过身份验证，您（作为攻击者）将**捕获凭据、2FA、cookie 和任何信息**，在工具执行 MitM 时的每次交互。

### 通过 VNC

如果您不是**将受害者发送到一个与原始页面外观相同的恶意页面**，而是将他发送到一个**与真实网页连接的浏览器的 VNC 会话**呢？您将能够看到他所做的事情，窃取密码、使用的 MFA、cookie...\
您可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来做到这一点。

## 检测检测

显然，知道您是否被发现的最佳方法之一是**在黑名单中搜索您的域名**。如果它出现在列表中，您的域名以某种方式被检测为可疑。\
检查您的域名是否出现在任何黑名单的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)。

然而，还有其他方法可以知道受害者是否**在积极寻找可疑的钓鱼活动**，如以下所述：

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

您可以**购买一个与受害者域名非常相似的域名**，**和/或为您控制的域名的**一个**子域名生成证书**，**包含**受害者域名的**关键字**。如果**受害者**与它们进行任何类型的**DNS 或 HTTP 交互**，您将知道**他在积极寻找**可疑域名，您需要非常隐蔽。

### 评估钓鱼

使用 [**Phishious** ](https://github.com/Rices/Phishious) 来评估您的电子邮件是否会进入垃圾邮件文件夹，或者是否会被阻止或成功。

## 参考

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="success" %}
学习和实践 AWS 黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
