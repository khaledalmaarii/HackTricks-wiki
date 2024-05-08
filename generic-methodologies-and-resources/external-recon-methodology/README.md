# 外部侦察方法论

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果您对**黑客职业**感兴趣并想要攻破不可攻破的目标 - **我们正在招聘！**（需要流利的波兰语书面和口语表达能力）。

{% embed url="https://www.stmcyber.com/careers" %}

## 资产发现

> 所以你被告知某家公司的所有东西都在范围内，你想弄清楚这家公司实际拥有什么。

这个阶段的目标是获取所有**主公司拥有的公司**，然后获取这些公司的**资产**。为此，我们将执行以下操作：

1. 找到主公司的收购情况，这将给我们范围内的公司。
2. 找到每家公司的**自治系统号（ASN）**（如果有），这将给我们每家公司拥有的IP地址范围。
3. 使用反向whois查找来搜索与第一家公司相关的其他条目（组织名称、域名等）（这可以递归执行）。
4. 使用其他技术，如shodan的`org`和`ssl`过滤器来搜索其他资产（`ssl`技巧可以递归执行）。

### **收购情况**

首先，我们需要知道主公司拥有哪些**其他公司**。\
一种选择是访问[https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**主公司，并点击“**acquisitions**”。在那里，您将看到主公司收购的其他公司。\
另一种选择是访问主公司的**维基百科**页面并搜索**收购情况**。

> 好的，在这一点上，您应该知道所有在范围内的公司。让我们弄清楚如何找到它们的资产。

### **ASN**

自治系统号（**ASN**）是由**互联网数字分配机构（IANA）**分配给**自治系统**（AS）的**唯一编号**。\
**AS**由**IP地址块**组成，具有明确定义的访问外部网络的策略，并由单个组织管理，但可能由多个运营商组成。

找出公司是否分配了任何**ASN**以查找其**IP地址范围**是很有趣的。对范围内的所有**主机**执行**漏洞测试**并查找这些IP地址中的域名将是有趣的。\
您可以在[**https://bgp.he.net/**](https://bgp.he.net)中通过公司**名称**、**IP**或**域名**进行搜索。\
**根据公司所在地区，这些链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **（非洲），** [**Arin**](https://www.arin.net/about/welcome/region/) **（北美），** [**APNIC**](https://www.apnic.net) **（亚洲），** [**LACNIC**](https://www.lacnic.net) **（拉丁美洲），** [**RIPE NCC**](https://www.ripe.net) **（欧洲）。无论如何，可能所有**有用信息**（IP地址范围和Whois）**已经出现在第一个链接中。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
此外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**的**子域枚举会自动在扫描结束时汇总和总结ASNs。
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
您也可以使用[http://asnlookup.com/](http://asnlookup.com)（它有免费API）来查找组织的IP范围。\
您可以使用[http://ipv4info.com/](http://ipv4info.com)来查找域的IP和ASN。

### **寻找漏洞**

此时，我们已经知道**范围内的所有资产**，如果允许，您可以对所有主机启动一些**漏洞扫描器**（Nessus，OpenVAS）。\
此外，您可以启动一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) **或使用像** shodan **这样的服务来查找**开放端口**，根据您找到的内容，您应该**查看本书以了解如何对运行的多种可能服务进行渗透测试**。\
**另外，值得一提的是，您还可以准备一些**默认用户名**和**密码**列表，并尝试使用[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)对服务进行**暴力破解**。

## 域名

> 我们知道范围内的所有公司及其资产，现在是时候找出范围内的域名了。

_请注意，在以下提出的技术中，您还可以找到子域，这些信息不应被低估。_

首先，您应该查找每家公司的**主域名**。例如，对于 _特斯拉公司_，主域名将是 _tesla.com_。

### **反向DNS**

在找到所有域的IP范围后，您可以尝试对这些IP执行**反向DNS查找**，以找到范围内的更多域。尝试使用受害者的某些DNS服务器或一些知名DNS服务器（1.1.1.1，8.8.8.8）。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
### **反向 Whois（循环）**

在 **whois** 中，您可以找到许多有趣的**信息**，如**组织名称**、**地址**、**电子邮件**、电话号码... 但更有趣的是，您可以通过执行**反向 Whois 查找**（例如其他出现相同电子邮件的 whois 注册表）找到与公司相关的**更多资产**。\
您可以使用在线工具，如：

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com) - **免费** 网页，不免费 API。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅**100次免费**搜索）
- [https://www.domainiq.com/](https://www.domainiq.com) - 不免费

您可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 来自动化此任务（需要 whoxy API 密钥）。\
您还可以使用 [amass](https://github.com/OWASP/Amass) 进行一些自动反向 Whois 发现：`amass intel -d tesla.com -whois`

**请注意，您可以使用此技术在每次发现新域时发现更多域名。**

### **跟踪器**

如果在 2 个不同页面中找到**相同跟踪器的相同 ID**，则可以假设**两个页面**由**同一团队管理**。\
例如，如果您在几个页面上看到相同的**Google Analytics ID**或相同的**Adsense ID**。

有一些页面和工具可以让您通过这些跟踪器和更多内容进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

您知道我们可以通过查找相同的 favicon 图标哈希来找到与我们的目标相关的域和子域吗？这正是 [@m4ll0k2](https://twitter.com/m4ll0k2) 制作的 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 工具所做的。以下是如何使用它：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 发现具有相同 favicon 图标哈希的域](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简而言之，favihash 将允许我们发现具有与我们目标相同的 favicon 图标哈希的域。

此外，您还可以使用 favicon 哈希搜索技术，如[**此博客文章**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)中所述。这意味着，如果您知道 Web 技术中易受攻击版本的 favicon 的哈希，您可以在 shodan 中搜索，**找到更多易受攻击的地方**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
这是如何计算网站的**favicon哈希值**：
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

在网页中搜索**可能在同一组织的不同网站之间共享的字符串**。**版权字符串**可能是一个很好的例子。然后在**Google**、其他**浏览器**甚至**Shodan**中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT 时间**

通常会有类似以下的定时任务：
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### 更新服务器上的所有域证书。这意味着即使用于此操作的 CA 在有效期内未设置生成时间，也可以**在证书透明度日志中找到属于同一公司的域**。\
查看这个[**writeup 以获取更多信息**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)。

### 邮件 DMARC 信息

您可以使用网站，例如[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)，或者使用工具，例如[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)来查找**共享相同 dmarc 信息的域和子域**。

### **被动接管**

人们通常会将子域分配给属于云提供商的 IP 地址，然后在某个时候**丢失该 IP 地址但忘记删除 DNS 记录**。因此，只需在云中（如 Digital Ocean）**生成一个虚拟机**，实际上您将**接管一些子域**。

[**这篇文章**](https://kmsec.uk/blog/passive-takeover/)解释了这个情况，并提出了一个**在 DigitalOcean 中生成虚拟机**的脚本，**获取**新机器的**IPv4**，然后在 Virustotal 中搜索指向它的子域记录。

### **其他方法**

**请注意，您可以使用此技术每次发现新域时发现更多域名。**

**Shodan**

由于您已经知道拥有 IP 空间的组织的名称。您可以在 shodan 中使用该数据进行搜索：`org:"Tesla, Inc."` 检查找到的主机，查看 TLS 证书中的新意外域。

您可以访问主网页的**TLS 证书**，获取**组织名称**，然后在**shodan**已知的所有网页的**TLS 证书**中搜索该名称，使用过滤器：`ssl:"Tesla Motors"`，或者使用类似[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)的工具。

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder)是一个查找与主域相关的**域**和它们的**子域**的工具，非常惊人。

### **寻找漏洞**

检查一下[域接管](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。也许某些公司**正在使用某个域**，但他们**失去了所有权**。只需注册它（如果足够便宜），然后通知该公司。

如果您发现任何**具有不同 IP 的域**，则应执行**基本漏洞扫描**（使用 Nessus 或 OpenVAS）和一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside)，使用**nmap/masscan/shodan**。根据正在运行的服务，您可以在**本书中找到一些“攻击”它们的技巧**。\
_请注意，有时域托管在客户无法控制的 IP 内，因此不在范围内，请小心。_

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**漏洞赏金提示**：**注册** Intigriti，这是一家由黑客创建的高级**漏洞赏金平台**！立即加入我们，访问[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达**$100,000**的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 子域

> 我们知道范围内的所有公司，每家公司的所有资产以及与公司相关的所有域。

现在是时候找到每个找到的域的所有可能子域了。

{% hint style="success" %}
请注意，一些用于查找域的工具和技术也可以帮助查找子域！
{% endhint %}

### **DNS**

让我们尝试从**DNS**记录中获取**子域**。我们还应尝试进行**区域传送**（如果存在漏洞，应该报告）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域的最快方法是在外部来源中搜索。最常用的**工具**如下（为了获得更好的结果，请配置API密钥）：

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
有**其他有趣的工具/API**，即使不是直接专门用于查找子域的，也可以用来查找子域，比如：

* [**Crobat**](https://github.com/cgboal/sonarsearch)**：** 使用API [https://sonar.omnisint.io](https://sonar.omnisint.io) 来获取子域
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC免费API**](https://jldc.me/anubis/subdomains/google.com)
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
* [**gau**](https://github.com/lc/gau)**:** 从AlienVault的Open Threat Exchange，Wayback Machine和Common Crawl中获取给定域的已知URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 它们会在网络上进行爬取，寻找JS文件并从中提取子域。
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
* [**Censys子域名查找工具**](https://github.com/christophetd/censys-subdomain-finder)
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

该项目免费提供与赏金计划相关的所有子域。您还可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，或者访问该项目使用的范围 [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

您可以在这里找到许多这些工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 暴力破解**

让我们尝试使用可能的子域名在 DNS 服务器上进行暴力破解以查找新的**子域**。

对于此操作，您将需要一些**常见的子域名字典，例如**：

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要良好 DNS 解析器的 IP 地址。为了生成可信 DNS 解析器列表，您可以从 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) 下载解析器并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 进行过滤。或者您可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS 暴力破解最推荐的工具有：

* [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个执行有效 DNS 暴力破解的工具。它非常快，但容易产生误报。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 我认为这个工具只使用了一个解析器
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个围绕`massdns`编写的Go语言封装工具，允许您使用主动暴力破解枚举有效子域名，同时解析具有通配符处理和简单输入输出支持的子域名。
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

在利用公开资源和暴力破解找到子域之后，您可以生成已找到的子域的变体，以尝试找到更多信息。有几种工具可用于此目的：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**：** 给定域和子域生成排列。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 给定域名和子域名生成排列组合。
* 您可以在[**这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 排列组合**词表**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 给定域和子域生成排列。如果未指定排列文件，gotator 将使用自己的文件。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns)：除了生成子域名排列外，它还可以尝试解析它们（但最好使用前面评论过的工具）。
* 您可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取altdns排列**词表**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 另一个用于执行子域的排列、变异和修改的工具。该工具将对结果进行暴力破解（不支持DNS通配符）。
* 您可以在[**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取dmut排列词表。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 基于一个域名，根据指定的模式生成新的潜在子域名，以尝试发现更多子域名。

#### 智能排列生成

* [**regulator**](https://github.com/cramppet/regulator): 有关更多信息，请阅读此[**文章**](https://cramppet.github.io/regulator/index.html)，但基本上它将从**发现的子域名**中获取**主要部分**，并将它们混合以找到更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个子域名暴力破解工具，配备了一个极其简单但有效的DNS响应引导算法。它利用提供的一组输入数据，如定制的单词列表或历史DNS/TLS记录，准确地合成更多对应的域名，并根据在DNS扫描过程中收集的信息进一步扩展它们。
```
echo www | subzuf facebook.com
```
### **子域发现工作流程**

查看我写的关于如何使用**Trickest工作流程自动化子域发现**的博客文章，这样我就不需要在计算机上手动启动一堆工具了：

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **虚拟主机**

如果你发现一个包含**一个或多个网页**的IP地址属于子域，你可以尝试通过在**OSINT来源**中查找该IP上的域名或者**通过在该IP上暴力破解VHost域名**来**查找其他具有网页的子域**。

#### OSINT

您可以使用[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他API**来查找一些**IP中的VHosts**。

**暴力破解**

如果您怀疑某个子域可能隐藏在一个Web服务器中，您可以尝试暴力破解它：
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

有时您会发现只有在_**Origin**_标头中设置有效的域名/子域名时，页面才会返回_**Access-Control-Allow-Origin**_标头。在这些情况下，您可以滥用这种行为来**发现**新的**子域名**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **存储桶暴力破解**

在寻找**子域**的同时，要留意是否指向任何类型的**存储桶**，如果是的话，[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)**。**\
此外，由于此时您将了解范围内的所有域，尝试[**暴力破解可能的存储桶名称并检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

### **监控**

您可以通过监控**证书透明度**日志来**监控**域名的**新子域**创建情况，[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)可以实现此功能。

### **寻找漏洞**

检查可能存在的[**子域接管**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果**子域**指向某个**S3存储桶**，[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

如果发现任何**IP与资产发现中已发现的IP不同**的**子域**，应执行**基本漏洞扫描**（使用Nessus或OpenVAS）和一些[**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside)使用**nmap/masscan/shodan**。根据运行的服务，您可以在**本书中找到一些“攻击”它们的技巧**。\
_请注意，有时子域托管在客户不控制的IP内，因此不在范围内，请小心。_

## IPs

在初始步骤中，您可能已经**找到了一些IP范围、域和子域**。\
现在是时候**收集所有这些范围内的IP**和**域/子域（DNS查询）**。

使用以下**免费API服务**，您还可以找到域和子域使用过的**先前IP**。这些IP可能仍然归客户所有（并且可能允许您找到[**CloudFlare绕过**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

* [**https://securitytrails.com/**](https://securitytrails.com/)

您还可以使用工具[**hakip2host**](https://github.com/hakluke/hakip2host)检查指向特定IP地址的域。

### **寻找漏洞**

**端口扫描所有不属于CDN的IP**（因为您很可能在那里找不到任何有趣的内容）。在发现的运行服务中，您可能**能够找到漏洞**。

**查找**[**关于如何扫描主机的指南**](../pentesting-network/)。

## Web服务器搜索

> 我们已经找到了所有公司及其资产，知道了IP范围、域和子域在范围内。现在是搜索Web服务器的时候了。

在之前的步骤中，您可能已经执行了一些**对发现的IP和域的侦察**，因此您可能已经找到了所有可能的Web服务器。但是，如果没有，我们现在将看到一些**快速搜索Web服务器的技巧**。

请注意，这将**针对Web应用程序发现**，因此您应该**执行漏洞**和**端口扫描**（**如果范围允许**）。

使用[**masscan可以找到与Web服务器相关的**开放端口的**快速方法**](../pentesting-network/#http-port-discovery)。\
另一个友好的工具用于查找Web服务器是[**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe)和[**httpx**](https://github.com/projectdiscovery/httpx)。您只需传递一个域列表，它将尝试连接到端口80（http）和443（https）。此外，您可以指示尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **截图**

现在你已经发现了**在范围内的所有Web服务器**（包括公司的**IP地址**和所有**域名**和**子域名**），你可能**不知道从哪里开始**。所以，让我们简单点，开始截取它们的屏幕。只需**查看****主页**，你就可以找到更**容易****受攻击**的**奇怪**端点。

要执行建议的想法，你可以使用[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)或[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你可以使用[**eyeballer**](https://github.com/BishopFox/eyeballer)来查看所有**截图**，告诉你**可能包含漏洞**的内容，以及哪些不包含。

## 公共云资产

为了找到属于公司的潜在云资产，你应该**从能够识别该公司的关键字列表开始**。例如，对于加密公司，你可以使用诸如："crypto"、"wallet"、"dao"、"<domain_name>"、<"subdomain_names">等词语。

你还需要**常用的存储桶词汇表**：

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些词语生成**排列组合**（查看[**第二轮DNS暴力破解**](./#second-dns-bruteforce-round)获取更多信息）。

使用生成的词汇表，你可以使用工具，如[**cloud\_enum**](https://github.com/initstring/cloud\_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist)**或**[**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

请记住，在寻找云资产时，应该**不仅仅寻找AWS中的存储桶**。

### **寻找漏洞**

如果发现**公开的存储桶或暴露的云功能**等内容，你应该**访问它们**，尝试查看它们提供了什么，以及是否可以滥用它们。

## 电子邮件

有了范围内的**域名**和**子域名**，基本上你已经有了开始搜索电子邮件的所有**必要信息**。以下是我发现的用于查找公司电子邮件的**API**和**工具**：

* [**theHarvester**](https://github.com/laramies/theHarvester) - 带有API
* [**https://hunter.io/**](https://hunter.io/)（免费版）的API
* [**https://app.snov.io/**](https://app.snov.io/)（免费版）的API
* [**https://minelead.io/**](https://minelead.io/)（免费版）的API

### **寻找漏洞**

稍后，电子邮件将有助于**暴力破解Web登录和身份验证服务**（如SSH）。此外，它们也是**钓鱼**所必需的。此外，这些API将为你提供更多关于电子邮件背后的人的**信息**，这对于钓鱼活动很有用。

## 凭证泄漏

有了**域名**、**子域名**和**电子邮件**，你可以开始搜索过去泄漏的属于这些电子邮件的凭证：

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果找到**有效的泄漏**凭证，这将是一个非常容易的胜利。

## 机密信息泄漏

凭证泄漏涉及公司被泄露并出售的**敏感信息**的黑客攻击。然而，公司可能受到**其他泄漏**的影响，这些信息不在这些数据库中：

### Github泄漏

凭证和API可能会泄漏在**公司**或**那个github公司的用户**的**公共存储库**中。\
你可以使用**工具**[**Leakos**](https://github.com/carlospolop/Leakos)来**下载**一个**组织**及其**开发人员**的所有**公共存储库**，并自动运行[**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos**也可用于对其提供的**URL传递的所有文本**运行**gitleaks**，因为有时**网页也包含机密信息**。

#### Github Dorks

还要检查这个**页面**，以查找你攻击的组织中可能还可以搜索的潜在**github dorks**：

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### 粘贴泄漏

有时攻击者或工作人员会在粘贴网站上**发布公司内容**。这可能包含或不包含**敏感信息**，但搜索它非常有趣。\
你可以使用工具[**Pastos**](https://github.com/carlospolop/Pastos)同时在80多个粘贴网站中搜索。

### Google Dorks

虽然老旧但实用的Google Dorks始终有助于找到**不应存在的暴露信息**。唯一的问题是[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)包含数千种可能的查询，你无法手动运行。因此，你可以选择你最喜欢的10个查询，或者你可以使用**工具，如**[**Gorks**](https://github.com/carlospolop/Gorks)**来运行它们**。

_请注意，期望使用常规Google浏览器运行整个数据库的工具将永远无法结束，因为Google会很快阻止你。_

### **寻找漏洞**

如果找到**有效的泄漏**凭证或API令牌，这将是一个非常容易的胜利。

## 公共代码漏洞

如果发现公司有**开源代码**，你可以对其进行**分析**并搜索其中的**漏洞**。

根据**语言**的不同，你可以使用不同的**工具**：

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

还有一些允许你**扫描公共存储库**的免费服务，例如：

* [**Snyk**](https://app.snyk.io/)
## [**网络渗透测试方法论**](../../network-services-pentesting/pentesting-web/)

**大多数漏洞**都存在于**Web应用程序**中，因此我想谈一下**Web应用程序测试方法论**，您可以在[**此处找到此信息**](../../network-services-pentesting/pentesting-web/)。

我还想特别提及[**Web自动化扫描器开源工具**](../../network-services-pentesting/pentesting-web/#automatic-scanners)，因为尽管不应指望它们发现非常敏感的漏洞，但它们对于在**工作流程中实施一些初始Web信息**非常有用。

## 总结

> 恭喜！到目前为止，您已经执行了**所有基本枚举**。是的，这是基本的，因为还可以进行更多的枚举（稍后将看到更多技巧）。

因此，您已经：

1. 找到了**范围内的所有公司**
2. 找到了属于这些公司的所有**资产**（并对其进行了一些漏洞扫描，如果在范围内）
3. 找到了属于这些公司的所有**域**
4. 找到了这些域的所有**子域**（有任何子域接管吗？）
5. 找到了范围内所有**IP地址**（来自和**不来自CDN**）
6. 找到了所有**Web服务器**并对它们进行了**屏幕截图**（有任何值得深入研究的奇怪情况吗？）
7. 找到了属于公司的所有**潜在公共云资产**
8. 可能会为您带来**轻松大收获的电子邮件**、**凭据泄漏**和**秘密泄漏**。
9. **对您找到的所有网站进行渗透测试**

## **全面侦察自动化工具**

有几种工具可以针对给定范围执行所提议的部分操作。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点陈旧，未更新

## **参考资料**

* 所有[**@Jhaddix**](https://twitter.com/Jhaddix)的免费课程，如[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果您对**黑客职业**感兴趣并想要黑入不可黑入的系统 - **我们正在招聘！**（需要流利的波兰语书面和口语能力）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
