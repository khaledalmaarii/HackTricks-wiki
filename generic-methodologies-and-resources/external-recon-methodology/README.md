# 外部侦察方法论

<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **注册** **Intigriti**，一个由黑客创建的高级**漏洞赏金平台**！今天就加入[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 资产发现

> 所以你被告知某个公司的所有东西都在范围内，你想弄清楚这个公司实际拥有什么。

这个阶段的目标是获取所有**主公司拥有的公司**，然后是这些公司的所有**资产**。为此，我们将：

1. 查找主公司的收购情况，这将告诉我们范围内的公司。
2. 查找每个公司的ASN（如果有），这将告诉我们每个公司拥有的IP范围。
3. 使用反向whois查找来搜索与第一个条目（组织名称、域名等）相关的其他条目（这可以递归完成）。
4. 使用其他技术，如shodan `org`和`ssl`过滤器来搜索其他资产（`ssl`技巧可以递归完成）。

### **收购**

首先，我们需要知道哪些**其他公司由主公司拥有**。\
一个选择是访问[https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索** **主公司**，然后**点击** "**收购**"。在那里你会看到主公司收购的其他公司。\
另一个选择是访问主公司的**维基百科**页面并搜索**收购**。

> 好的，此时你应该知道范围内的所有公司。让我们弄清楚如何找到他们的资产。

### **ASNs**

自治系统号码（**ASN**）是由**互联网号码分配机构（IANA）**分配给自治系统（AS）的**唯一编号**。\
一个**AS**由**IP地址块**组成，这些地址块有明确定义的策略来访问外部网络，并由单一组织管理，但可能由几个运营商组成。

找到**公司是否分配了任何ASN**以找到其**IP范围**是很有趣的。对范围内的所有**主机**进行**漏洞测试**并**寻找这些IP内的域名**将是有趣的。\
你可以在[**https://bgp.he.net/**](https://bgp.he.net)**上**通过公司**名称**、**IP**或**域名**进行**搜索**。\
**根据公司所在的地区，以下链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **（非洲），** [**Arin**](https://www.arin.net/about/welcome/region/)**（北美），** [**APNIC**](https://www.apnic.net) **（亚洲），** [**LACNIC**](https://www.lacnic.net) **（拉丁美洲），** [**RIPE NCC**](https://www.ripe.net) **（欧洲）。无论如何，可能所有**有用的信息**（IP范围和Whois）**已经出现在第一个链接中了。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**的**子域名枚举在扫描结束时自动聚合并总结ASN。
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
您也可以使用 [http://asnlookup.com/](http://asnlookup.com)（提供免费API）来查找组织的IP范围。
您可以使用 [http://ipv4info.com/](http://ipv4info.com) 查找域名的IP和ASN。

### **寻找漏洞**

此时我们已知**范围内的所有资产**，如果允许的话，您可以对所有主机启动一些**漏洞扫描器**（如Nessus, OpenVAS）。\
此外，您还可以启动一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) **或使用像** shodan **这样的服务来发现**开放端口**，根据您发现的内容，您应该查阅本书了解如何对可能运行的多种服务进行渗透测试。\
**同样值得一提的是，您还可以准备一些**默认用户名**和**密码**列表，尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行暴力破解。**

## 域名

> 我们知道了范围内所有公司及其资产，现在是时候找出范围内的域名了。

_请注意，在以下建议的技术中，您还可以找到子域名，这些信息不应被低估。_

首先，您应该查找每个公司的**主域名**。例如，对于 _Tesla Inc._ 来说，将会是 _tesla.com_。

### **反向DNS**

由于您已经找到了所有域名的IP范围，您可以尝试对这些**IP执行反向DNS查找**，以**发现范围内的更多域名**。尝试使用受害者的某些DNS服务器或一些知名的DNS服务器（1.1.1.1, 8.8.8.8）
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
为了使其工作，管理员必须手动启用PTR。
您也可以使用在线工具获取此信息：[http://ptrarchive.com/](http://ptrarchive.com)

### **反向Whois（循环）**

在**whois**中，您可以找到许多有趣的**信息**，如**组织名称**、**地址**、**电子邮件**、电话号码等。但更有趣的是，如果您通过任何这些字段执行**反向whois查找**（例如，在其他whois注册处出现相同的电子邮件），您可以找到与公司**相关的更多资产**。
您可以使用在线工具，如：

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
* [https://www.whoxy.com/](https://www.whoxy.com) - **免费**网页，API不免费。
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 收费
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 收费（仅**100次免费**搜索）
* [https://www.domainiq.com/](https://www.domainiq.com) - 收费

您可以使用[**DomLink**](https://github.com/vysecurity/DomLink)（需要whoxy API密钥）自动化此任务。
您还可以使用[amass](https://github.com/OWASP/Amass)执行一些自动反向whois发现：`amass intel -d tesla.com -whois`

**请注意，每次发现新域名时，您都可以使用此技术发现更多域名。**

### **追踪器**

如果在两个不同的页面上找到**相同追踪器的相同ID**，您可以假设**两个页面**由**同一团队**管理。
例如，如果您在几个页面上看到相同的**Google Analytics ID**或相同的**Adsense ID**。

有一些页面和工具可以让您搜索这些追踪器及更多：

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

您知道我们可以通过寻找相同的favicon图标哈希来找到与我们目标相关的域名和子域名吗？这正是[@m4ll0k2](https://twitter.com/m4ll0k2)开发的[favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)工具所做的。以下是如何使用它：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
```markdown
![favihash - 发现具有相同favicon图标哈希的域名](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash能够帮助我们发现拥有与我们目标相同favicon图标哈希的域名。

此外，你还可以使用favicon哈希来搜索技术，正如[**这篇博客文章**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)中解释的那样。这意味着，如果你知道**某个易受攻击版本的web技术的favicon的哈希**，你可以在shodan中搜索，**找到更多易受攻击的地方**：
```
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
这是你如何**计算网站的 favicon 哈希**：
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
### **版权 / 独特字符串**

搜索网页中**可能在同一组织的不同网站中共享的字符串**。**版权字符串**可能是一个很好的例子。然后在**谷歌**中搜索该字符串，在其他**浏览器**中搜索，甚至在**shodan**中搜索：`shodan search http.html:"Copyright string"`

### **CRT 时间**

通常会有一个 cron 作业，例如
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### **被动接管**

显然，人们常常会将子域名指向云服务提供商的IP地址，然后在某个时刻**失去该IP地址但忘记移除DNS记录**。因此，只需在云端（如Digital Ocean）**启动一个虚拟机**，你实际上就能**接管一些子域名**。

[**这篇文章**](https://kmsec.uk/blog/passive-takeover/)讲述了一个关于此的故事，并提出了一个脚本，该脚本**在DigitalOcean启动一个虚拟机**，**获取**新机器的**IPv4**地址，并**在Virustotal中搜索**指向该地址的子域名记录。

### **其他方法**

**注意，每当你发现一个新域名时，你都可以使用这种技术来发现更多域名。**

**Shodan**

既然你已经知道拥有IP空间的组织的名称。你可以在shodan中使用该数据进行搜索：`org:"Tesla, Inc."` 检查找到的主机，寻找TLS证书中的新的意外域名。

你可以访问主网页的**TLS证书**，获取**组织名称**，然后在**shodan**已知的所有网页的**TLS证书**中搜索该名称，使用过滤器：`ssl:"Tesla Motors"` 或使用像 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 这样的工具。

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) 是一个查找与主域名**相关的域名**和它们的**子域名**的工具，非常了不起。

### **寻找漏洞**

检查一些[域名接管](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。也许有些公司**正在使用某个域名**，但他们**失去了所有权**。如果价格足够便宜，就注册它，并让公司知道。

如果你发现任何**IP地址与你在资产发现中已找到的不同**的域名，你应该执行**基本的漏洞扫描**（使用Nessus或OpenVAS）和一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) 使用 **nmap/masscan/shodan**。根据运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_注意有时域名托管在客户端无法控制的IP内，因此不在范围内，请小心。_

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty 小贴士**：**注册** **Intigriti**，一个由黑客创建，为黑客服务的高级**bug赏金平台**！立即加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 子域名

> 我们知道范围内所有公司的所有资产和所有与公司相关的域名。

现在是时候找到每个已找到域名的所有可能子域名了。

### **DNS**

让我们尝试从**DNS**记录中获取**子域名**。我们还应该尝试**区域传输**（如果易受攻击，你应该报告它）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

快速获取大量子域的方法是在外部资源中搜索。最常用的**工具**如下（为了获得更好的结果，请配置API密钥）：

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
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
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
有**其他有趣的工具/API**，即使它们不是专门用于查找子域名的，也可能有助于发现子域名，例如：

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 使用API [https://sonar.omnisint.io](https://sonar.omnisint.io) 来获取子域名
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC 免费 API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 免费 API
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
* [**gau**](https://github.com/lc/gau)**:** 为任何给定域名从AlienVault的Open Threat Exchange、Wayback Machine和Common Crawl获取已知URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **和** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们在网上搜索JS文件，并从中提取子域名。
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
* [**Censys 子域名查找器**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) 提供免费 API 用于搜索子域和 IP 历史记录
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目**免费提供与漏洞赏金计划相关的所有子域**。您也可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，或者访问此项目使用的范围 [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

您可以在这里找到许多这些工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 暴力破解**

让我们尝试使用可能的子域名来暴力破解 DNS 服务器，以找到新的**子域**。

对于这项操作，您将需要一些**常见子域词汇表**，例如：

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

同时还需要好的 DNS 解析器的 IP 地址。为了生成可信 DNS 解析器列表，您可以从 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) 下载解析器，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 过滤它们。或者您可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS 暴力破解的工具是：

* [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个执行有效 DNS 暴力破解的工具。它非常快速，但容易出现误报。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 我认为这个只使用1个解析器
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个围绕 `massdns` 编写的 go 语言封装器，它允许您使用主动暴力破解来枚举有效的子域名，以及带有通配符处理和易于输入输出支持的子域名解析。
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

在使用开放源和暴力破解找到子域后，您可以生成找到的子域的变体，尝试发现更多。以下工具对此非常有用：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 根据域名和子域名生成排列组合。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 给定域名和子域名生成排列。
* 您可以在[**这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 排列的**词表**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 给定域名和子域名生成排列。如果没有指定排列文件，gotator将使用其自带的。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): 除了生成子域名排列之外，它还可以尝试解析它们（但最好使用前面评论过的工具）。
* 您可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取 altdns 排列的**词表**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 另一个用于执行子域名的排列、变异和修改的工具。此工具将对结果进行暴力破解（它不支持dns通配符）。
* 您可以在[**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取dmut排列词表。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 根据一个域名，它会**根据指定的模式生成新的潜在子域名**，以尝试发现更多子域名。

#### 智能排列组合生成

* [**regulator**](https://github.com/cramppet/regulator): 想了解更多信息请阅读这篇[**文章**](https://cramppet.github.io/regulator/index.html)，但它基本上会从**已发现的子域名**中获取**主要部分**，并将它们混合以找到更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个子域名暴力猜解模糊器，配合一个极其简单但有效的DNS响应引导算法。它利用提供的输入数据，如定制词表或历史DNS/TLS记录，准确合成更多相应的域名，并根据在DNS扫描期间收集的信息，进一步在循环中扩展它们。
```
echo www | subzuf facebook.com
```
### **子域名发现工作流程**

查看我写的这篇博客文章，了解如何使用 **Trickest 工作流** 从一个域名中**自动化发现子域名**，这样我就不需要在我的电脑上手动启动一堆工具：

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / 虚拟主机**

如果你发现一个IP地址包含**一个或多个属于子域名的网页**，你可以尝试通过在**OSINT资源**中查找一个IP的域名或者在该IP中**暴力破解VHost域名**来**找到该IP中的其他带有网页的子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他APIs**找到IP中的一些**VHosts**。

**暴力破解**

如果你怀疑某个子域名可能隐藏在一个web服务器中，你可以尝试暴力破解它：
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
使用这种技术，你甚至可能访问到内部/隐藏的端点。
{% endhint %}

### **CORS 暴力破解**

有时你会发现，只有当一个有效的域名/子域名在 _**Origin**_ 头中设置时，页面才返回 _**Access-Control-Allow-Origin**_ 头。在这些情况下，你可以利用这种行为来**发现**新的**子域名**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在寻找**子域名**时，留意是否有指向任何类型的**存储桶**，如果是这样的话[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。\
此外，由于此时你将知道范围内的所有域名，尝试[**暴力破解可能的存储桶名称并检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

### **监控**

你可以通过监控**证书透明度**日志来**监控**域名是否创建了**新的子域名**，[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)就是这么做的。

### **寻找漏洞**

检查可能的[**子域名接管**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果**子域名**指向某个**S3存储桶**，[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

如果你发现任何**子域名的IP与你在资产发现中已找到的IP不同**，你应该执行**基本的漏洞扫描**（使用Nessus或OpenVAS）和一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside)与**nmap/masscan/shodan**。根据运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_注意有时子域名托管在客户端无法控制的IP内，因此不在范围内，请小心。_

## IPs

在初始步骤中，你可能已经**找到了一些IP范围、域名和子域名**。\
现在是时候**收集这些范围内的所有IP**以及**域名/子域名的IP（DNS查询）**。

使用以下**免费api**服务，你还可以找到域名和子域名**以前使用的IP**。这些IP可能仍然属于客户端（并可能允许你找到[**CloudFlare绕过**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）

* [**https://securitytrails.com/**](https://securitytrails.com/)

你还可以使用工具[**hakip2host**](https://github.com/hakluke/hakip2host)检查指向特定IP地址的域名。

### **寻找漏洞**

**对所有不属于CDN的IP进行端口扫描**（因为你在那里几乎不可能找到任何有趣的东西）。在发现的运行服务中，你可能会**发现漏洞**。

**找到一个**[**指南**](../pentesting-network/) **关于如何扫描主机。**

## Web服务器狩猎

> 我们已经找到了所有公司及其资产，并且知道了范围内的IP范围、域名和子域名。现在是寻找Web服务器的时候了。

在之前的步骤中，你可能已经执行了一些**对发现的IP和域名的侦察**，所以你可能**已经找到了所有可能的Web服务器**。然而，如果你还没有，我们现在将看到一些**快速技巧来搜索范围内的Web服务器**。

请注意，这将**针对Web应用程序发现**，因此你也应该执行**漏洞**和**端口扫描**（**如果范围允许**）。

一种快速发现与**Web**服务器相关的**开放端口**的方法是使用[**masscan**](../pentesting-network/#http-port-discovery)。\
另一个查找Web服务器的友好工具是[**httprobe**](https://github.com/tomnomnom/httprobe)、[**fprobe**](https://github.com/theblackturtle/fprobe)和[**httpx**](https://github.com/projectdiscovery/httpx)。你只需传递一个域名列表，它将尝试连接到端口80（http）和443（https）。此外，你可以指示尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **屏幕截图**

现在您已经发现了范围内的**所有网页服务器**（包括公司的**IP**以及所有的**域名**和**子域名**），您可能**不知道从哪里开始**。让我们简化流程，从对它们全部进行屏幕截图开始。仅仅通过**查看**主页，您就可以发现更容易**存在漏洞**的**奇怪**端点。

要执行上述想法，您可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，您还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 对所有**屏幕截图**进行分析，以告诉您哪些可能**包含漏洞**，哪些不包含。

## 公共云资产

为了找到属于公司的潜在云资产，您应该**从标识该公司的关键词列表开始**。例如，对于加密货币公司，您可能会使用诸如："crypto"、"wallet"、"dao"、"<domain_name>"、<"subdomain_names"> 等词。

您还需要包含**常用于存储桶的常见词汇**的词表：

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些词汇生成**排列组合**（查看[**第二轮 DNS 暴力破解**](./#second-dns-bruteforce-round)了解更多信息）。

使用生成的词表，您可以使用 [**cloud\_enum**](https://github.com/initstring/cloud\_enum)、[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)、[**cloudlist**](https://github.com/projectdiscovery/cloudlist) 或 [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

记住，在寻找云资产时，您应该**不仅仅在 AWS 中寻找存储桶**。

### **寻找漏洞**

如果您发现诸如**公开的存储桶或暴露的云函数**之类的东西，您应该**访问它们**，尝试了解它们提供了什么，以及您是否可以滥用它们。

## 电子邮件

有了范围内的**域名**和**子域名**，您基本上拥有了**开始搜索电子邮件所需的一切**。以下是我发现公司电子邮件最有效的**API**和**工具**：

* [**theHarvester**](https://github.com/laramies/theHarvester) - 带有 API
* [**https://hunter.io/**](https://hunter.io/) 的 API（免费版本）
* [**https://app.snov.io/**](https://app.snov.io/) 的 API（免费版本）
* [**https://minelead.io/**](https://minelead.io/) 的 API（免费版本）

### **寻找漏洞**

电子邮件稍后将有助于**暴力破解网页登录和认证服务**（如 SSH）。此外，它们对于**网络钓鱼**也是必需的。此外，这些 API 还将为您提供有关电子邮件背后人物的更多**信息**，这对于网络钓鱼活动很有用。

## 凭证泄露

有了**域名**、**子域名**和**电子邮件**，您可以开始寻找过去属于这些电子邮件的泄露凭证：

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果您发现了**有效的泄露**凭证，这是一个非常容易的胜利。

## 秘密泄露

凭证泄露与公司被黑客攻击并**泄露和出售敏感信息**有关。然而，公司可能受到**其他泄露**的影响，这些信息不在那些数据库中：

### Github 泄露

凭证和 API 可能会在**公司**或在该 github 公司工作的**用户**的**公共仓库**中泄露。\
您可以使用**工具** [**Leakos**](https://github.com/carlospolop/Leakos) **下载**一个**组织**及其**开发者**的所有**公共仓库**，并自动运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 也可以用来对提供的所有**文本** **URLs** 运行 **gitleaks**，因为有时**网页也包含秘密**。

#### Github Dorks

还可以查看此**页面**，了解您可能在您正在攻击的组织中搜索的潜在**github dorks**：

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### 粘贴泄露

有时攻击者或工作人员会**在粘贴站点上发布公司内容**。这可能包含或不包含**敏感信息**，但搜索它非常有趣。\
您可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 同时在超过 80 个粘贴站点上进行搜索。

### Google Dorks

老但经典的 google dorks 始终有助于发现**不应该暴露的信息**。唯一的问题是 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数千个您无法手动运行的可能查询。因此，您可以选择您最喜欢的 10 个，或者您可以使用**工具** [**Gorks**](https://github.com/carlospolop/Gorks) **运行它们全部**。

_请注意，使用常规 Google 浏览器运行整个数据库的工具永远不会结束，因为 Google 很快就会阻止您。_

### **寻找漏洞**

如果您发现了**有效的泄露**凭证或 API 令牌，这是一个非常容易的胜利。

## 公共代码漏洞

如果您发现公司有**开源代码**，您可以**分析**它并搜索其中的**漏洞**。

**根据语言**，您可以使用不同的**工具**：

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

还有一些免费服务允许您**扫描公共仓库**，例如：

* [**Snyk**](https://app.snyk.io/)

## [**网页渗透测试方法论**](../../network-services-pentesting/pentesting-web/)

**大多数漏洞**都存在于**网页应用程序**中，所以在这一点上，我想谈谈**网页应用程序测试方法论**，您可以[**在这里找到这些信息**](../../network-services-pentesting/pentesting-web/)。

我还想特别提到[**Web Automated Scanners 开源工具**](../../network-services-pentesting/pentesting-web/#automatic-scanners)部分，因为，如果您不应该期望它们为您找到非常敏感的漏洞，它们在**工作流程中实施一些初始网页信息**时很方便。

## 总结

> 恭喜！此时您已经完成了**所有基本的枚举**。是的，这是基本的，因为可以做更多的枚举（稍后会看到更多技巧）。

所以您已经：

1. 找到了范围内的所有**公司**
2. 找到了所有属于公司的**资产**（如果在范围内，进行一些漏洞扫描）
3. 找到了所有属于公司的**域名**
4. 找到了域名的所有**子域名**（有子域名接管吗？）
5. 找到了范围内的所有**IP**（来自**CDN**和**非 CDN**）。
6. 找到了所有**网页服务器**并对它们进行了**屏幕截图**（有什么奇怪的值得深入研究吗？）
7. 找到了属于公司的所有**潜在公共云资产**。
8. **电子邮件**、**凭证泄露**和**秘密泄露**可能会让您**非常容易地大获全胜**。
9. **渗透测试您发现的所有网页**

## **全面自动化侦察工具**

有几个工具可以对给定范围执行上述部分操作。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点旧，没有更新

## **参考资料**

* [**@Jhaddix**](https://twitter.com/Jhaddix) 的所有免费课程（如 [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)）

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **注册** [**Intigriti**](https://go.intigriti.com/hacktricks)，一个由黑客为黑客创建的优质**漏洞赏金平台**！今天就加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>从零到英雄学习 AWS 黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**The PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
