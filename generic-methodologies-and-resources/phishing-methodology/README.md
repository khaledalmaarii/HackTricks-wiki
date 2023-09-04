# 钓鱼方法论

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 上看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 方法论

1. 侦查受害者
1. 选择**受害者域名**。
2. 进行一些基本的网络枚举，**搜索受害者使用的登录门户**，并**决定**你将**冒充**哪个门户。
3. 使用一些**OSINT**来**查找电子邮件**。
2. 准备环境
1. **购买**用于钓鱼评估的域名
2. **配置与电子邮件服务相关的记录**（SPF、DMARC、DKIM、rDNS）
3. 配置 VPS 上的 **gophish**
3. 准备攻击活动
1. 准备**电子邮件模板**
2. 准备用于窃取凭据的**网页**
4. 发起攻击活动！

## 生成类似的域名或购买可信任的域名

### 域名变体技术

* **关键词**：域名中包含原始域名的重要**关键词**（例如，zelster.com-management.com）。
* **连字符子域**：将子域的**点**更改为**连字符**（例如，www-zelster.com）。
* **新顶级域**：使用**新的顶级域**相同的域名（例如，zelster.org）
* **同形异义字**：用看起来相似的字母**替换**域名中的字母（例如，zelfser.com）。
* **转位**：在域名中**交换两个字母**（例如，zelster.com）。
* **单复数化**：在域名末尾添加或删除“s”（例如，zeltsers.com）。
* **省略**：从域名中**删除一个**字母（例如，zelser.com）。
* **重复**：在域名中**重复一个**字母（例如，zeltsser.com）。
* **替换**：类似于同形异义字，但不那么隐蔽。它用一个字母替换域名中的一个字母，可能是键盘上与原始字母相邻的字母（例如，zektser.com）。
* **子域**：在域名中**插入一个点**（例如，ze.lster.com）。
* **插入**：在域名中**插入一个字母**（例如，zerltser.com）。
* **缺少点**：将顶级域名附加到域名上。（例如，zelstercom.com）

**自动工具**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### 位翻转

在计算世界中，所有东西都以位（0 和 1）的形式存储在内存中。\
域名也是如此。例如，_windows.com_ 在计算设备的易失性内存中变为 _01110111..._。\
然而，如果其中一个位由于太阳耀斑、宇宙射线或硬件错误而自动翻转会怎样呢？也就是其中的一个 0 变成了 1，反之亦然。\
将这个概念应用到 DNS 请求中，可能发生的情况是，**到达 DNS 服务器的请求域名与最初请求的域名不同**。

例如，对域名 windows.com 进行 1 位修改，可以将其转换为 _windnws.com_。\
**攻击者可能会注册尽可能多与受害者相关的位翻转域名，以将合法用户重定向到他们的基础设施**。

欲了解更多信息，请阅读[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)。
### 购买可信赖的域名

您可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 上搜索一个过期的域名来使用。\
为了确保您要购买的过期域名**已经具有良好的SEO**，您可以查看以下网站对其进行分类：

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100%免费）
* [https://phonebook.cz/](https://phonebook.cz)（100%免费）
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的电子邮件地址或**验证已经发现的**电子邮件地址，您可以尝试对受害者的SMTP服务器进行暴力破解。[在此处了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用**任何网页门户访问他们的邮件**，您可以检查该门户是否容易受到**用户名暴力破解**的攻击，并在可能的情况下利用该漏洞。

## 配置GoPhish

### 安装

您可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载它。

下载并解压缩到 `/opt/gophish` 目录中，然后执行 `/opt/gophish/gophish`。\
您将在输出中获得一个用于端口3333上的管理员用户的密码。因此，请访问该端口并使用这些凭据更改管理员密码。您可能需要将该端口隧道转发到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS证书配置**

在这一步之前，你应该已经**购买了**你要使用的域名，并且它必须**指向**你正在配置**gophish**的**VPS的IP地址**。
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

开始安装：`apt-get install postfix`

然后将域名添加到以下文件中：

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**还要更改/etc/postfix/main.cf中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后修改文件**`/etc/hostname`**和**`/etc/mailname`**为您的域名，并**重新启动您的VPS**。

现在，创建一个**DNS A记录**，将`mail.<domain>`指向VPS的**IP地址**，并创建一个指向`mail.<domain>`的**DNS MX记录**。

现在让我们测试发送一封电子邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish配置**

停止执行gophish并进行配置。\
将`/opt/gophish/config.json`修改为以下内容（注意使用https）：
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
**配置gophish服务**

为了创建gophish服务，使其可以自动启动和管理服务，您可以创建文件`/etc/init.d/gophish`，内容如下：
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
完成配置服务并进行检查：
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

### 等待

域名越旧，被识别为垃圾邮件的可能性就越低。因此，在进行钓鱼评估之前，您应该尽可能地等待一段时间（至少1周）。
请注意，即使您需要等待一周，您现在可以完成所有配置。

### 配置反向DNS（rDNS）记录

设置一个rDNS（PTR）记录，将VPS的IP地址解析为域名。

### 发件人策略框架（SPF）记录

您必须为新域名**配置SPF记录**。如果您不知道什么是SPF记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#spf)。

您可以使用[https://www.spfwizard.net/](https://www.spfwizard.net)生成您的SPF策略（使用VPS机器的IP）

![](<../../.gitbook/assets/image (388).png>)

这是必须在域名的TXT记录中设置的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告和合规性（DMARC）记录

您必须为新域名**配置DMARC记录**。如果您不知道什么是DMARC记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#dmarc)。

您需要创建一个新的DNS TXT记录，将主机名`_dmarc.<domain>`指向以下内容：
```bash
v=DMARC1; p=none
```
### 域名密钥识别邮件（DKIM）

您必须为新域名**配置DKIM**。如果您不知道什么是DMARC记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
您需要将DKIM密钥生成的两个B64值连接起来：
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### 测试您的电子邮件配置分数

您可以使用[https://www.mail-tester.com/](https://www.mail-tester.com)进行测试\
只需访问该页面并向他们提供的地址发送电子邮件：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
您还可以通过向`check-auth@verifier.port25.com`发送电子邮件并阅读响应来检查您的电子邮件配置（为此，您需要打开端口25并在文件`/var/mail/root`中查看响应，如果您以root身份发送电子邮件）。\
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
或者，您可以发送一条消息到您控制的 Gmail 地址，在您的 Gmail 收件箱中查看收到的电子邮件的标头，`Authentication-Results` 标头字段中应该存在 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### 从Spamhouse黑名单中移除

网页www.mail-tester.com可以告诉您您的域名是否被Spamhouse阻止。您可以在以下网址请求将您的域名/IP移除：[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从Microsoft黑名单中移除

您可以在[https://sender.office.com/](https://sender.office.com)请求将您的域名/IP移除。

## 创建并启动GoPhish攻击活动

### 发送配置

* 设置一个用于识别发送者配置的**名称**
* 决定从哪个账户发送钓鱼邮件。建议使用：_noreply, support, servicedesk, salesforce..._
* 您可以将用户名和密码留空，但请确保勾选“忽略证书错误”

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
建议使用“**发送测试邮件**”功能测试一切是否正常。\
我建议将测试邮件发送到10分钟邮件地址，以避免在测试中被列入黑名单。
{% endhint %}

### 邮件模板

* 设置一个用于识别模板的**名称**
* 然后编写一个**主题**（不要太奇怪，只要是您在常规邮件中可能会看到的内容）
* 确保已勾选“**添加跟踪图片**”
* 编写**邮件模板**（您可以使用以下示例中的变量）：
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>

<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
注意，为了增加邮件的可信度，建议使用来自客户的某些签名。建议：

- 发送邮件到一个不存在的地址，并检查回复是否有签名。
- 搜索像info@ex.com或press@ex.com或public@ex.com这样的公共电子邮件，并向它们发送邮件并等待回复。
- 尝试联系一些已发现的有效电子邮件，并等待回复。

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
邮件模板还允许**附加文件进行发送**。如果您还想使用一些特制的文件/文档来窃取NTLM挑战，请阅读此页面。
{% endhint %}

### 登陆页面

- 编写一个**名称**
- **编写网页的HTML代码**。请注意，您可以**导入**网页。
- 标记**捕获提交的数据**和**捕获密码**
- 设置**重定向**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
通常，您需要修改页面的HTML代码，并在本地进行一些测试（可能使用一些Apache服务器）**直到您满意为止**。然后，将HTML代码写入框中。
请注意，如果您需要为HTML使用一些静态资源（例如一些CSS和JS页面），您可以将它们保存在_/opt/gophish/static/endpoint_中，然后从_/static/\<filename>_访问它们。
{% endhint %}

{% hint style="info" %}
对于重定向，您可以将用户**重定向到受害者的合法主网页**，或者将其重定向到_/static/migration.html_，例如，放置一些**旋转的轮子**（[**https://loading.io/**](https://loading.io)**）5秒钟，然后指示过程成功**。
{% endhint %}

### 用户和组

- 设置一个名称
- **导入数据**（请注意，为了使用示例的模板，您需要每个用户的名字、姓氏和电子邮件地址）

![](<../../.gitbook/assets/image (395).png>)

### 活动

最后，创建一个活动，选择一个名称、电子邮件模板、登陆页面、URL、发送配置文件和组。请注意，URL将是发送给受害者的链接。

请注意，**发送配置文件允许发送测试邮件，以查看最终钓鱼邮件的外观**：

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
我建议将测试邮件发送到10分钟邮件地址，以避免在测试中被列入黑名单。
{% endhint %}

一切准备就绪后，启动活动！

## 网站克隆

如果出于任何原因您想克隆网站，请查看以下页面：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## 带后门的文档和文件

在某些钓鱼评估中（主要是为了红队），您还希望**发送包含某种后门的文件**（可能是C2，也可能只是触发身份验证的东西）。
请查看以下页面以获取一些示例：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## 钓鱼多因素认证

### 通过代理中间人攻击

前面的攻击非常聪明，因为您正在伪造一个真实网站并收集用户设置的信息。不幸的是，如果用户没有输入正确的密码，或者如果您伪造的应用程序配置了2FA，**这些信息将无法让您冒充被欺骗的用户**。

这就是[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)和[**muraena**](https://github.com/muraenateam/muraena)等工具有用的地方。这些工具将允许您生成类似于MitM的攻击。基本上，攻击的工作方式如下：

1. 您**冒充**真实网页的**登录**表单。
2. 用户将其凭据发送到您的伪造页面，工具将这些凭据发送到真实网页，**检查凭据是否有效**。
3. 如果帐户配置了**2FA**，MitM页面将要求输入2FA，一旦用户输入2FA，工具将将其发送到真实网页。
4. 一旦用户通过身份验证，您（作为攻击者）将**捕获到凭据、2FA、Cookie和任何与工具执行MitM期间的每次交互相关的信息**。

### 通过VNC

如果您不是将受害者**发送到一个具有与原始网站相同外观的恶意页面**，而是将其发送到一个**连接到真实网页的浏览器的VNC会话**中，会怎么样？您将能够看到他的操作，窃取密码、使用的MFA、Cookie等等。
您可以使用[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)来实现这一点。

## 检测检测

显然，了解自己是否被抓住的最好方法之一是在黑名单中搜索您的域名。如果它出现在列表中，那么您的域名以某种方式被检测为可疑。
检查您的域名是否出现在任何黑名单中的一种简单方法是使用[https://malwareworld.com/](https://malwareworld.com)

然而，还有其他方法可以知道受害者是否在**积极寻找可疑的钓鱼活动**，如下所述：

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

您可以**购买一个与受害者域名非常相似的域名**，并/或为您控制的域名的子域生成一个包含受害者域名关键字的证书。如果受害者与它们进行任何形式的DNS或HTTP交互，您将知道他正在积极寻找可疑的域名，您需要非常隐秘。

### 评估钓鱼

使用[**Phishious**](https://github.com/Rices/Phishious)评估您的电子邮件是否会被放入垃圾邮件文件夹，或者是否会被阻止或成功发送。
## 参考资料

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
