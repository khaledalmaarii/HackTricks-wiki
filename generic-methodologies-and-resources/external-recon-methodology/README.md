# 外部侦察方法论

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**赏金漏洞提示**：**注册** Intigriti，一个由黑客创建的高级**赏金漏洞平台**！立即加入我们的[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 资产发现

> 所以你被告知属于某家公司的一切都在范围内，你想弄清楚这家公司实际拥有什么。

这个阶段的目标是获取主要公司拥有的所有**子公司**，然后获取这些公司的**资产**。为此，我们将执行以下操作：

1. 找到主要公司的收购情况，这将给我们提供范围内的公司。
2. 找到每个公司的 ASN（如果有），这将给我们提供每个公司拥有的 IP 范围。
3. 使用反向 whois 查询来搜索与第一个查询相关的其他条目（组织名称、域名等）（可以递归执行此操作）。
4. 使用其他技术，如 shodan 的 `org` 和 `ssl` 过滤器来搜索其他资产（`ssl` 技巧可以递归执行）。

### **收购情况**

首先，我们需要知道主要公司**收购的其他公司**。\
一种选择是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**主要公司，并点击“**acquisitions**”。在那里，你将看到主要公司收购的其他公司。\
另一种选择是访问主要公司的**维基百科**页面并搜索“**acquisitions**”。

> 好的，此时你应该知道范围内的所有公司。让我们弄清楚如何找到它们的资产。

### **ASNs**

自治系统号（**ASN**）是由**互联网分配号码管理局（IANA）**分配给**自治系统**（AS）的**唯一号码**。\
一个**AS**由**IP 地址块**组成，这些块具有明确定义的访问外部网络的策略，并由单个组织管理，但可能由多个运营商组成。

找出公司是否分配了任何 ASN 是有趣的，以找到其**IP 范围**。对范围内的所有**主机**执行**漏洞测试**，并查找这些 IP 内的域名是很有意义的。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net) 中按公司**名称**、**IP** 或 **域名** 进行搜索。\
**根据公司所在地区，这些链接可能对收集更多数据有用：**[**AFRINIC**](https://www.afrinic.net) **（非洲），**[**Arin**](https://www.arin.net/about/welcome/region/) **（北美），**[**APNIC**](https://www.apnic.net) **（亚洲），**[**LACNIC**](https://www.lacnic.net) **（拉丁美洲），**[**RIPE NCC**](https://www.ripe.net) **（欧洲）。无论如何，第一个链接中可能已经包含了所有有用的信息（IP 范围和 Whois）。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
此外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**的**子域名枚举会在扫描结束时自动汇总和总结ASNs。
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
你可以使用[http://asnlookup.com/](http://asnlookup.com)（它有免费的API）来查找组织的IP范围。\
你可以使用[http://ipv4info.com/](http://ipv4info.com)来查找域名的IP和ASN。

### **寻找漏洞**

此时，我们已经知道了**范围内的所有资产**，所以如果允许的话，你可以使用一些**漏洞扫描工具**（如Nessus、OpenVAS）对所有主机进行扫描。\
此外，你还可以进行一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) **或使用像** shodan **这样的服务来查找**开放的端口**，根据你找到的内容，你应该在本书中查找如何对可能运行的多个服务进行渗透测试的方法。\
**另外，值得一提的是，你还可以准备一些**默认的用户名**和**密码**列表，并尝试使用[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)对服务进行暴力破解。

## 域名

> 我们知道范围内的所有公司及其资产，现在是时候找出范围内的域名了。

_请注意，在下面提供的技术中，你还可以找到子域名，这些信息不应被低估。_

首先，你应该寻找每个公司的**主域名**。例如，对于_Tesla Inc._，主域名将是_tesla.com_。

### **反向DNS**

当你找到域名的所有IP范围后，你可以尝试对这些IP进行**反向DNS查找**，以找到范围内的更多域名。尝试使用受害者的某个DNS服务器或一些知名的DNS服务器（1.1.1.1、8.8.8.8）。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
为了使此功能正常工作，管理员必须手动启用PTR。\
您还可以使用在线工具获取此信息：[http://ptrarchive.com/](http://ptrarchive.com)

### **反向Whois（循环）**

在**whois**中，您可以找到许多有趣的**信息**，如**组织名称**、**地址**、**电子邮件**、电话号码等。但更有趣的是，如果您通过这些字段之一执行**反向Whois查找**（例如，其他whois注册表中出现相同的电子邮件），您可以找到与该公司相关的**更多资产**。\
您可以使用在线工具，例如：

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
* [https://www.whoxy.com/](https://www.whoxy.com) - **免费** 网页，不免费API。
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅限**100次免费**搜索）
* [https://www.domainiq.com/](https://www.domainiq.com) - 不免费

您可以使用[**DomLink** ](https://github.com/vysecurity/DomLink)（需要whoxy API密钥）自动化此任务。\
您还可以使用[amass](https://github.com/OWASP/Amass)执行一些自动反向Whois发现：`amass intel -d tesla.com -whois`

**请注意，每次发现新域时，您都可以使用此技术发现更多域名。**

### **跟踪器**

如果在2个不同页面中找到**相同跟踪器的相同ID**，则可以假设**两个页面**都是**由同一团队管理**的。\
例如，如果您在多个页面上看到相同的**Google Analytics ID**或相同的**Adsense ID**。

有一些页面和工具可以让您通过这些跟踪器进行搜索：

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

您知道我们可以通过查找相同的favicon图标哈希来找到与我们的目标相关的域名和子域名吗？这正是[@m4ll0k2](https://twitter.com/m4ll0k2)制作的[favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)工具的用途。以下是如何使用它：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 发现具有相同favicon图标哈希的域名](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash将允许我们发现与我们的目标具有相同favicon图标哈希的域名。

此外，您还可以使用favicon哈希来搜索技术，如[**此博文**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)中所述。这意味着如果您知道易受攻击版本的Web技术的favicon哈希，您可以在shodan中搜索并找到更多易受攻击的地方：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
这是如何计算网页的**favicon哈希值**的方法：
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **版权 / 唯一字符串**

在网页中搜索**可能在同一组织的不同网站之间共享的字符串**。版权字符串可能是一个很好的例子。然后在**Google**、其他**浏览器**甚至**Shodan**中搜索该字符串：`shodan search http.html:"版权字符串"`

### **CRT 时间**

通常会有一个类似于的定时任务
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### **更新服务器上的所有域名证书**

这意味着即使用于此操作的CA在有效期内没有设置生成时间，也可以在证书透明日志中**找到属于同一公司的域名**。

查看[**此文档以获取更多信息**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)。

### **被动接管**

显然，人们常常将子域名分配给属于云提供商的IP，并在某些时候**失去该IP地址，但忘记删除DNS记录**。因此，只需在云中（如Digital Ocean）**生成一个虚拟机**，实际上就可以**接管一些子域名**。

[**这篇文章**](https://kmsec.uk/blog/passive-takeover/)讲述了一个相关的故事，并提出了一个脚本，**在DigitalOcean中生成一个虚拟机**，**获取**新机器的**IPv4地址**，并在Virustotal中**搜索指向该地址的子域名记录**。

### **其他方法**

**请注意，每当发现一个新的域名时，您都可以使用此技术来发现更多的域名。**

**Shodan**

由于您已经知道拥有IP空间的组织的名称，您可以在shodan中使用以下数据进行搜索：`org:"Tesla, Inc."`，检查找到的主机是否有新的意外域名在TLS证书中。

您可以访问主网页的**TLS证书**，获取**组织名称**，然后在**shodan**已知的所有网页的**TLS证书**中搜索该名称，使用过滤器：`ssl:"Tesla Motors"`

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder)是一个查找与主域名相关的**域名**和它们的**子域名**的工具，非常强大。

### **寻找漏洞**

检查是否存在[域接管](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。也许某个公司正在**使用某个域名**，但他们**失去了所有权**。只需注册它（如果便宜），并让公司知道。

如果您发现任何与已发现的资产发现中的IP不同的域名，应进行**基本的漏洞扫描**（使用Nessus或OpenVAS）和一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside)，使用**nmap/masscan/shodan**。根据运行的服务，您可以在**本书中找到一些攻击它们的技巧**。\
请注意，有时域名托管在客户无法控制的IP中，因此不在范围内，请小心。

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug赏金提示**：**注册**Intigriti，这是一个由黑客创建的高级**Bug赏金平台**！立即加入我们，访问[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 子域名

> 我们知道范围内的所有公司，每个公司的所有资产以及与公司相关的所有域名。

现在是时候找到每个发现的域名的所有可能子域名了。

### **DNS**

让我们尝试从**DNS**记录中获取**子域名**。我们还应该尝试进行**区域传输**（如果存在漏洞，应该报告）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名的最快方法是在外部来源中进行搜索。最常用的**工具**如下（为了获得更好的结果，请配置API密钥）：

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/zh-cn)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)

theHarvester是一个用于收集目标公司或个人的电子邮件地址、子域名、主机名和其他相关信息的开源工具。它可以通过搜索引擎、DNS查询和其他公开来源来收集这些信息。theHarvester可以帮助黑客在外部侦察阶段获取有关目标的重要信息，从而为后续攻击提供有用的情报。
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
以下是一些其他有趣的工具/API，即使它们不是直接专门用于查找子域名，也可以用来查找子域名，例如：

* [**Crobat**](https://github.com/cgboal/sonarsearch)**：** 使用API [https://sonar.omnisint.io](https://sonar.omnisint.io) 来获取子域名
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC免费API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 免费API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** 从AlienVault的Open Threat Exchange、Wayback Machine和Common Crawl获取给定域名的已知URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 它们会在网络上进行爬取，寻找JS文件并从中提取子域名。
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys子域名查找器**](https://github.com/christophetd/censys-subdomain-finder)
```
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**securitytrails.com**](https://securitytrails.com/) 提供免费的API，用于搜索子域和IP历史记录
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目免费提供与赏金计划相关的所有子域。您还可以使用[chaospy](https://github.com/dr-0x0x/chaospy)访问这些数据，甚至可以访问该项目使用的范围[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

您可以在此处找到许多这些工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS暴力破解**

让我们尝试使用可能的子域名来对DNS服务器进行暴力破解，以查找新的**子域**。

为此操作，您将需要一些**常见的子域名字典，例如**：

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要好的DNS解析器的IP地址。为了生成可信的DNS解析器列表，您可以从[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)下载解析器，并使用[**dnsvalidator**](https://github.com/vortexau/dnsvalidator)进行筛选。或者您可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS暴力破解最推荐的工具是：

* [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个执行有效的DNS暴力破解的工具。它非常快，但容易产生误报。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 我认为这个工具只使用了一个解析器
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个用Go语言编写的`massdns`的封装工具，它允许您使用主动暴力破解来枚举有效的子域名，同时处理通配符并提供简单的输入输出支持。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): 它也使用 `massdns`。
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步地暴力破解域名。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二轮DNS暴力破解

在使用开放资源和暴力破解找到子域之后，你可以生成子域的变体，以尝试找到更多的子域。有几个工具可以用于此目的：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**：**根据域名和子域生成排列组合。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 给定域名和子域名生成排列组合。
* 您可以在[**这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取goaltdns的排列组合**字典**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 给定域名和子域名生成排列组合。如果没有指定排列组合文件，gotator将使用自己的文件。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): 除了生成子域名的排列组合，它还可以尝试解析它们（但最好使用前面评论的工具）。
* 您可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取altdns的排列组合**字典**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 另一个用于执行子域名的排列、变异和修改的工具。该工具将对结果进行暴力破解（不支持DNS通配符）。
* 您可以在[**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取dmut的排列词表。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**：**根据域名，它会根据指定的模式生成新的潜在子域名，以尝试发现更多子域名。

#### 智能排列生成

* [**regulator**](https://github.com/cramppet/regulator)：有关更多信息，请阅读此[**文章**](https://cramppet.github.io/regulator/index.html)，但基本上它会从发现的子域名中获取**主要部分**并将它们混合以找到更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个子域名暴力破解模糊器，配合一个非常简单但有效的DNS响应引导算法。它利用提供的输入数据集，如定制的字典或历史DNS/TLS记录，准确地合成更多相应的域名，并根据在DNS扫描期间收集到的信息在循环中进一步扩展它们。
```
echo www | subzuf facebook.com
```
### **子域名发现工作流程**

查看我写的关于如何使用**Trickest工作流程自动化子域名发现**的博客文章，这样我就不需要在我的计算机上手动启动一堆工具了：

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **虚拟主机**

如果你找到一个包含**一个或多个网页**的IP地址，属于子域名，你可以尝试通过在**OSINT来源**中查找IP中的域名或通过**暴力破解虚拟主机域名**来找到该IP中的其他子域名。

#### OSINT

你可以使用[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他API**来查找IP中的一些**虚拟主机**。

**暴力破解**

如果你怀疑某个子域名可能隐藏在一个Web服务器中，你可以尝试对其进行暴力破解：
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
使用这种技术，您甚至可以访问内部/隐藏的端点。
{% endhint %}

### **CORS暴力破解**

有时，您会发现只有在_**Origin**_头中设置了有效的域名/子域名时，页面才会返回_**Access-Control-Allow-Origin**_头。在这种情况下，您可以滥用这种行为来**发现**新的**子域名**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **桶强制破解**

在寻找子域名时，要注意是否指向任何类型的桶，并在这种情况下[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。此外，在此时，您将知道范围内的所有域，尝试[**强制破解可能的桶名称并检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

### **监控**

您可以通过监控**证书透明性**日志来监控域的**新子域名**的创建，[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)可以实现此功能。

### **寻找漏洞**

检查可能的[**子域接管**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果子域指向某个**S3桶**，[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

如果您发现任何与资产发现中已找到的IP不同的子域，应进行**基本漏洞扫描**（使用Nessus或OpenVAS）和一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside)（使用nmap/masscan/shodan）。根据运行的服务，您可以在**本书中找到一些攻击它们的技巧**。\
请注意，有时子域托管在客户无法控制的IP中，因此不在范围内，请小心。

## IP地址

在初始步骤中，您可能已经**找到了一些IP范围、域和子域**。\
现在是时候**收集这些范围内的所有IP**和**域名/子域名（DNS查询）**了。

使用以下**免费API服务**，您还可以找到域名和子域名使用过的**先前IP地址**。这些IP地址可能仍然属于客户（并可能允许您找到[**CloudFlare绕过**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

* [**https://securitytrails.com/**](https://securitytrails.com/)

### **寻找漏洞**

**端口扫描所有不属于CDN的IP地址**（因为您很可能在其中找不到任何有趣的东西）。在发现的运行服务中，您可能能够找到漏洞。

查找有关如何扫描主机的[**指南**](../pentesting-network/)。

## Web服务器搜索

> 我们已经找到了所有公司及其资产，并且我们知道范围内的IP范围、域和子域。现在是搜索Web服务器的时候了。

在之前的步骤中，您可能已经对发现的IP和域进行了一些**侦察**，因此您可能已经找到了所有可能的Web服务器。但是，如果您还没有找到，我们现在将看到一些**快速搜索Web服务器的技巧**。

请注意，这将是**面向Web应用程序发现**的，因此您还应该进行**漏洞**和**端口扫描**（如果范围允许）。

使用[**masscan**可以找到此处的**快速方法**，以发现与**Web服务器相关的打开端口**](../pentesting-network/#http-port-discovery)。\
另一个友好的工具是[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)和[**httpx**](https://github.com/projectdiscovery/httpx)。您只需传递一个域名列表，它将尝试连接到端口80（http）和443（https）。此外，您还可以指示尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **截图**

现在，您已经发现了范围内的所有网络服务器（包括公司的IP和所有域名和子域名），您可能不知道从哪里开始。所以，让我们简单点，先对它们进行截图。只需查看主页，您就可以找到更容易受到攻击的奇怪终点。

要执行建议的想法，您可以使用[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)或[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，您还可以使用[**eyeballer**](https://github.com/BishopFox/eyeballer)来查看所有**截图**，以告诉您哪些可能包含漏洞，哪些不包含。

## 公共云资产

为了找到可能属于公司的云资产，您应该从一个能够识别该公司的关键字列表开始。例如，对于加密货币公司，您可以使用诸如："crypto"、"wallet"、"dao"、"<domain_name>"、<"subdomain_names">等词语。

您还需要包含常用桶词的词表：

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，您可以使用这些词语生成**排列组合**（有关更多信息，请查看[**第二轮DNS暴力破解**](./#second-dns-bruteforce-round)）。

使用生成的词表，您可以使用工具，如[**cloud\_enum**](https://github.com/initstring/cloud\_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist)**或**[**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。

请记住，在寻找云资产时，您应该不仅仅寻找AWS中的桶。

### **寻找漏洞**

如果您发现了**公开的桶或公开的云函数**，您应该**访问它们**，并尝试查看它们提供的内容以及是否可以滥用它们。

## 电子邮件

有了范围内的**域名**和**子域名**，您基本上已经具备了开始搜索电子邮件的一切所需。以下是我找到公司电子邮件的最佳**API**和**工具**：

* [**theHarvester**](https://github.com/laramies/theHarvester) - 使用API
* [**https://hunter.io/**](https://hunter.io/)的API（免费版）
* [**https://app.snov.io/**](https://app.snov.io/)的API（免费版）
* [**https://minelead.io/**](https://minelead.io/)的API（免费版）

### **寻找漏洞**

稍后，电子邮件将对**暴力破解网页登录和身份验证服务**（如SSH）非常有用。此外，它们还用于**钓鱼**。此外，这些API还将为您提供有关电子邮件背后的**个人信息**，这对于钓鱼活动非常有用。

## 凭据泄露

有了**域名**、**子域名**和**电子邮件**，您可以开始搜索过去泄露的与这些电子邮件相关的凭据：

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果您找到了**有效的泄露凭据**，那就是一个非常容易的胜利。

## 机密信息泄露

凭据泄露与公司遭受的**泄露并出售敏感信息**的黑客攻击有关。然而，公司可能受到**其他泄露**的影响，这些泄露的信息不在这些数据库中：

### Github泄露

凭据和API可能会泄露在**公司的公共存储库**或**github公司的用户**的存储库中。\
您可以使用**Leakos**工具（https://github.com/carlospolop/Leakos）自动下载一个组织及其开发人员的所有**公共存储库**，然后自动运行**gitleaks**（https://github.com/zricethezav/gitleaks）。

**Leakos**还可以用于对传递给它的**URL提供的所有文本**运行**gitleaks**，因为有时**网页也包含机密信息**。

#### Github Dorks

还可以检查此**页面**，以查找您攻击的组织中可能的**github dorks**。

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes泄露

有时，攻击者或工作人员会在粘贴网站上**发布公司内容**。这可能包含或不包含**敏感信息**，但搜索它非常有趣。\
您可以使用**Pastos**工具（https://github.com/carlospolop/Pastos）同时在80多个粘贴网站上进行搜索。

### Google Dorks

虽然老旧，但黄金谷歌dorks始终有助于找到**不应存在的公开信息**。唯一的问题是，[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)包含数千个可能的查询，您无法手动运行。因此，您可以选择您最喜欢的10个查询，或者您可以使用**Gorks**等工具**运行它们**。

请注意，期望使用常规Google浏览器运行整个数据库的工具将永远无法结束，因为Google会很快阻止您。
### **寻找漏洞**

如果你找到了**有效的泄露**的凭据或API令牌，那就太容易了。

## 公开代码漏洞

如果你发现公司有**开源代码**，你可以**分析**它并搜索其中的**漏洞**。

根据不同的**编程语言**，有不同的**工具**可以使用：

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

还有一些免费的服务可以**扫描公共代码库**，例如：

* [**Snyk**](https://app.snyk.io/)

## [**Web渗透测试方法论**](../../network-services-pentesting/pentesting-web/)

**大多数漏洞**都存在于**Web应用程序**中，所以在这一点上，我想谈谈**Web应用程序测试方法论**，你可以在[**这里找到这些信息**](../../network-services-pentesting/pentesting-web/)。

我还想特别提到[**Web自动化扫描器开源工具**](../../network-services-pentesting/pentesting-web/#automatic-scanners)这一部分，因为尽管你不应该期望它们能找到非常敏感的漏洞，但它们在**工作流程中实施一些初始的Web信息**时非常有用。

## 总结

> 恭喜！到目前为止，你已经执行了**所有基本的枚举**。是的，这只是基本的，因为还可以进行更多的枚举（稍后会介绍更多技巧）。

所以你已经：

1. 找到了范围内的**所有公司**
2. 找到了公司拥有的**所有资产**（如果在范围内进行了一些漏洞扫描）
3. 找到了公司拥有的**所有域名**
4. 找到了域名的**所有子域名**（有没有子域接管的风险？）
5. 找到了范围内的**所有IP地址**（来自CDN和非CDN的）
6. 找到了**Web服务器**并对它们进行了**截图**（有没有什么奇怪的值得深入研究的地方？）
7. 找到了公司拥有的**所有潜在的公共云资产**
8. 找到了可能给你带来**巨大收益**的**电子邮件**、**凭据泄露**和**秘密泄露**
9. 对你找到的所有Web进行了**渗透测试**

## **完整的自动化侦察工具**

市面上有几种工具可以针对给定的范围执行部分建议的操作。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点过时，不再更新

## **参考资料**

* [**@Jhaddix**](https://twitter.com/Jhaddix)的**所有免费课程**（例如[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)）

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**赏金猎人小贴士**：注册**Intigriti**，一个由黑客创建的高级**赏金猎人平台**！立即加入我们，赚取高达**10万美元**的赏金！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
