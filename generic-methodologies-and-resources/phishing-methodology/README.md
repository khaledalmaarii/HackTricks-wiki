# 钓鱼方法论

<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 方法论

1. 侦察受害者
1. 选择**受害者域名**。
2. 进行一些基本的网络枚举，**寻找受害者使用的登录门户**，并**决定**你将**模仿**哪一个。
3. 使用一些**OSINT**来**找到电子邮件**。
2. 准备环境
1. **购买域名**，用于钓鱼评估
2. **配置电子邮件服务**相关记录（SPF, DMARC, DKIM, rDNS）
3. 使用**gophish**配置VPS
3. 准备活动
1. 准备**电子邮件模板**
2. 准备**网页**以窃取凭证
4. 启动活动！

## 生成类似的域名或购买受信任的域名

### 域名变体技术

* **关键词**：域名**包含**原始域名的重要**关键词**（例如，zelster.com-management.com）。
* **连字符子域名**：将子域名的**点改为连字符**（例如，www-zelster.com）。
* **新顶级域名**：使用**新的顶级域名**（例如，zelster.org）
* **同形异义字**：将域名中的字母**替换为看起来相似的字母**（例如，zelfser.com）。
* **置换**：在域名中**交换两个字母**（例如，zelster.com）。
* **单数化/复数化**：在域名末尾添加或移除“s”（例如，zeltsers.com）。
* **省略**：从域名中**移除一个字母**（例如，zelser.com）。
* **重复**：在域名中**重复一个字母**（例如，zeltsser.com）。
* **替换**：类似同形异义字，但不那么隐蔽。它替换域名中的一个字母，可能是键盘上原始字母附近的一个字母（例如，zektser.com）。
* **子域化**：在域名中引入一个**点**（例如，ze.lster.com）。
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

在计算领域，一切都以位（零和一）的形式存储在内存中。\
这也适用于域名。例如，_windows.com_ 在计算设备的易失性内存中变成了 _01110111..._。\
然而，如果这些位中的一个因太阳耀斑、宇宙射线或硬件错误而自动翻转了怎么办？即一个0变成了1，反之亦然。\
将这个概念应用于DNS请求，请求到达DNS服务器的**请求域名**可能与最初请求的域名**不同**。

例如，windows.com域名中的1位修改可以将其转换为_windnws.com。_\
**攻击者可能会注册尽可能多的与受害者相关的位翻转域名，以将合法用户重定向到他们的基础设施**。

更多信息请阅读[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买受信任的域名

您可以在[https://www.expireddomains.net/](https://www.expireddomains.net)搜索您可以使用的过期域名。\
为了确保您即将购买的过期域名**已经有良好的SEO**，您可以查询它在以下网站中的分类：

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 免费)
* [https://phonebook.cz/](https://phonebook.cz) (100% 免费)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的电子邮件地址或**验证**您已经发现的电子邮件地址，您可以检查是否可以对受害者的smtp服务器进行暴力破解。[在这里了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用**任何网络门户访问他们的邮件**，您可以检查它是否容易受到**用户名暴力破解**的攻击，并在可能的情况下利用这个漏洞。

## 配置GoPhish

### 安装

您可以从[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)下载

下载并解压到`/opt/gophish`，然后执行`/opt/gophish/gophish`\
您将在输出中获得管理员用户的密码，该用户在3333端口。因此，访问该端口并使用这些凭据更改管理员密码。您可能需要将该端口隧道到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，您应该**已经购买了域名**，并且它必须**指向**您正在配置 **gophish** 的 **VPS 的 IP**。
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

**还要在 /etc/postfix/main.cf 中更改以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后修改文件 **`/etc/hostname`** 和 **`/etc/mailname`** 为您的域名，并**重启您的VPS。**

现在，创建一个 **DNS A 记录** `mail.<domain>` 指向 VPS 的**IP地址**，以及一个指向 `mail.<domain>` 的 **DNS MX** 记录

现在让我们测试发送一封电子邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行，并进行配置。\
修改 `/opt/gophish/config.json` 为以下内容（注意使用了 https）：
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

为了创建gophish服务，以便它可以自动启动并作为一个服务进行管理，你可以创建文件`/etc/init.d/gophish`，内容如下：
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
完成配置服务并通过以下方式进行检查：
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

域名越老，被当作垃圾邮件的可能性越小。因此，在进行网络钓鱼评估之前，您应该等待尽可能长的时间（至少1周）。\
请注意，即使您需要等待一周，现在也可以完成所有配置。

### 配置反向DNS（rDNS）记录

设置一个rDNS（PTR）记录，将VPS的IP地址解析为域名。

### 发件人策略框架（SPF）记录

您必须**为新域名配置SPF记录**。如果您不知道什么是SPF记录[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#spf)。

您可以使用[https://www.spfwizard.net/](https://www.spfwizard.net)来生成您的SPF策略（使用VPS机器的IP）

![](<../../.gitbook/assets/image (388).png>)

这是必须设置在域内TXT记录中的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 域名基础消息认证、报告与合规性 (DMARC) 记录

您必须为新域名**配置 DMARC 记录**。如果您不知道什么是 DMARC 记录[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#dmarc)。

您需要为主机名 `_dmarc.<domain>` 创建一个新的 DNS TXT 记录，内容如下：
```bash
v=DMARC1; p=none
```
### 域名密钥识别邮件 (DKIM)

您必须为新域名**配置DKIM**。如果您不知道DMARC记录是什么，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
您需要将DKIM密钥生成的两个B64值连接起来：
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### 测试您的电子邮件配置得分

您可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com) 来进行测试。\
只需访问该页面，并发送电子邮件到他们提供给您的地址：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过向 `check-auth@verifier.port25.com` 发送电子邮件来**检查你的电子邮件配置**，并**阅读响应**（为此，你需要**打开**端口**25**，并在文件 _/var/mail/root_ 中查看响应，如果你以 root 身份发送电子邮件）。\
检查你是否通过了所有测试：
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
你也可以**向你控制的 Gmail 地址发送一条消息**，在你的 Gmail 收件箱中**查看**收到的**电子邮件头部信息**，`Authentication-Results` 头部字段中应该存在 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### 从Spamhouse黑名单中移除

页面www.mail-tester.com可以指示您的域名是否被spamhouse屏蔽。您可以在以下地址请求移除您的域名/IP：[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从Microsoft黑名单中移除

您可以在[https://sender.office.com/](https://sender.office.com)请求移除您的域名/IP。

## 创建并启动GoPhish活动

### 发送配置文件

* 设置一个**名称以识别**发件人配置文件
* 决定您将使用哪个账户发送钓鱼电子邮件。建议：_noreply, support, servicedesk, salesforce..._
* 您可以留空用户名和密码，但确保勾选忽略证书错误

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
建议使用“**发送测试邮件**”功能来测试一切是否正常工作。\
我建议**将测试邮件发送到10分钟邮箱地址**，以避免在测试时被列入黑名单。
{% endhint %}

### 电子邮件模板

* 设置一个**名称以识别**模板
* 然后编写一个**主题**（没有奇怪的东西，只是您期望在常规电子邮件中阅读的内容）
* 确保您已勾选“**添加追踪图像**”
* 编写**电子邮件模板**（您可以使用变量，如下例所示）：
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
请注意，**为了提高电子邮件的可信度**，建议使用客户端电子邮件中的某些签名。建议：

* 向一个**不存在的地址**发送电子邮件，检查回复中是否有任何签名。
* 搜索**公共电子邮件**，如info@ex.com、press@ex.com或public@ex.com，向它们发送电子邮件并等待回复。
* 尝试联系**一些已发现的有效**电子邮件并等待回复。

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
电子邮件模板还允许**附加文件发送**。如果您还想使用一些特制的文件/文档窃取NTLM挑战，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。
{% endhint %}

### 登陆页面

* 填写一个**名称**
* **编写网页的HTML代码**。请注意，您可以**导入**网页。
* 标记**捕获提交的数据**和**捕获密码**
* 设置一个**重定向**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
通常，您需要修改页面的HTML代码，并在本地进行一些测试（可能使用一些Apache服务器），**直到您满意为止**。然后，在框中写下该HTML代码。\
请注意，如果您需要为HTML使用一些静态资源（可能是一些CSS和JS页面），您可以将它们保存在_**/opt/gophish/static/endpoint**_中，然后从_**/static/\<filename>**_访问它们。
{% endhint %}

{% hint style="info" %}
对于重定向，您可以**将用户重定向到受害者的合法主网页**，或者将他们重定向到_/static/migration.html_，例如，放置一个**旋转轮**（[**https://loading.io/**](https://loading.io)）等待5秒钟，然后指示过程成功。
{% endhint %}

### 用户与组

* 设置一个名称
* **导入数据**（请注意，为了使用示例模板，您需要每个用户的名字、姓氏和电子邮件地址）

![](<../../.gitbook/assets/image (395).png>)

### 活动

最后，创建一个活动，选择一个名称、电子邮件模板、登陆页面、URL、发送配置文件和组。请注意，URL将是发送给受害者的链接。

请注意，**发送配置文件允许发送测试电子邮件，以查看最终的网络钓鱼电子邮件的外观**：

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
我建议**将测试电子邮件发送到10分钟邮件地址**，以避免在测试时被列入黑名单。
{% endhint %}

一切准备就绪后，就可以启动活动了！

## 网站克隆

如果由于某种原因您想克隆网站，请查看以下页面：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## 含后门的文档和文件

在某些网络钓鱼评估中（主要是红队），您还会想要**发送包含某种后门的文件**（可能是C2，或者只是会触发认证的东西）。\
查看以下页面了解一些示例：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## 网络钓鱼MFA

### 通过代理MitM

前面的攻击非常巧妙，因为您伪造了一个真实网站并收集了用户设置的信息。不幸的是，如果用户没有输入正确的密码，或者您伪造的应用程序配置了2FA，**这些信息将不允许您冒充被欺骗的用户**。

这就是像[**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper)和[**muraena**](https://github.com/muraenateam/muraena)这样的工具派上用场的地方。这个工具将允许您生成类似MitM的攻击。基本上，攻击的工作方式如下：

1. 您**冒充真实网页的登录**表单。
2. 用户将他的**凭据发送**到您的假页面，工具将这些发送到真实网页，**检查凭据是否有效**。
3. 如果账户配置了**2FA**，MitM页面将要求它，一旦**用户输入**，工具将其发送到真实网页。
4. 一旦用户通过认证，您（作为攻击者）将**捕获凭据、2FA、cookie以及工具执行MitM期间的任何信息**。

### 通过VNC

如果您不是**将受害者发送到外观相同的恶意页面**，而是将他发送到一个**VNC会话，浏览器连接到真实网页**呢？您将能够看到他做了什么，窃取密码、使用的MFA、cookie等...\
您可以使用[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)来做到这一点。

## 检测检测

显然，知道您是否被发现的最佳方法之一是**在黑名单中搜索您的域名**。如果它被列出，某种方式您的域名被检测为可疑。\
检查您的域名是否出现在任何黑名单中的一种简单方法是使用[https://malwareworld.com/](https://malwareworld.com)

然而，还有其他方法可以知道受害者是否**在野外积极寻找可疑的网络钓鱼活动**，如下所述：

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

您可以**购买一个与受害者域名非常相似的域名**和/或为您控制的域名的**子域名生成证书**，其中**包含**受害者域名的**关键字**。如果**受害者**执行任何类型的**DNS或HTTP交互**，您将知道**他正在积极寻找**可疑域名，您将需要非常隐秘。

### 评估网络钓鱼

使用[**Phishious**](https://github.com/Rices/Phishious)来评估您的电子邮件是否会结束在垃圾邮件文件夹中，或者是否会被阻止或成功。

## 参考资料

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><strong>从零开始学习AWS黑客攻击，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
