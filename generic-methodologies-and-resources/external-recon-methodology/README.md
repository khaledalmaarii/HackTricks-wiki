# 외부 탐색 방법론

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**버그 바운티 팁**: 해커들이 만든 프리미엄 버그 바운티 플랫폼 **Intigriti**에 **가입**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 가입하고 최대 **$100,000**의 바운티를 받으세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## 자산 발견

> 어떤 회사에 속한 모든 것이 범위 내에 있다고 말려고 했고, 실제로 이 회사가 무엇을 소유하고 있는지 알고 싶습니다.

이 단계의 목표는 **주요 회사가 소유한 모든 회사**와 이러한 회사의 **자산**을 얻는 것입니다. 이를 위해 다음을 수행합니다:

1. 주요 회사의 인수를 찾아서 범위 내에 있는 회사를 얻습니다.
2. 각 회사의 ASN(있는 경우)을 찾아서 각 회사가 소유한 IP 범위를 얻습니다.
3. 반대로 whois 조회를 사용하여 첫 번째 항목과 관련된 다른 항목(조직 이름, 도메인 등)을 검색합니다(이는 재귀적으로 수행될 수 있음).
4. shodan `org` 및 `ssl` 필터와 같은 다른 기술을 사용하여 다른 자산을 검색합니다(`ssl` 트릭은 재귀적으로 수행될 수 있음).

### **인수**

먼저, **주요 회사가 소유한 다른 회사**를 알아야 합니다.\
[https://www.crunchbase.com/](https://www.crunchbase.com)에 방문하여 **주요 회사**를 **검색**하고 "**인수**"를 **클릭**할 수 있습니다. 거기에서 주요 회사가 인수한 다른 회사를 볼 수 있습니다.\
다른 옵션은 주요 회사의 **Wikipedia** 페이지를 방문하고 **인수**를 검색하는 것입니다.

> 이 시점에서 범위 내에 있는 모든 회사를 알아야 합니다. 이제 자산을 찾는 방법을 알아보겠습니다.

### **ASNs**

자율 시스템 번호(**ASN**)는 **인터넷 할당 번호 관리 기관 (IANA)**에 의해 **자율 시스템** (AS)에 할당된 **고유한 번호**입니다.\
**AS**는 외부 네트워크에 대한 액세스 정책이 명확하게 정의된 **IP 주소 블록**으로 구성되며 단일 조직에 의해 관리되지만 여러 운영자로 구성될 수 있습니다.

**회사가 할당한 ASN**이 있는지 알아보는 것은 **IP 범위**를 찾기 위해 흥미로울 수 있습니다. 범위 내의 모든 **호스트**에 대해 **취약성 테스트**를 수행하고 이러한 IP 내의 도메인을 찾습니다.\
[**https://bgp.he.net/**](https://bgp.he.net)**에서** 회사 **이름**, **IP** 또는 **도메인**으로 검색할 수 있습니다.\
**회사의 지역에 따라 이 링크들은 더 많은 데이터를 수집하는 데 유용할 수 있습니다:** [**AFRINIC**](https://www.afrinic.net) **(아프리카),** [**Arin**](https://www.arin.net/about/welcome/region/)**(북미),** [**APNIC**](https://www.apnic.net) **(아시아),** [**LACNIC**](https://www.lacnic.net) **(라틴 아메리카),** [**RIPE NCC**](https://www.ripe.net) **(유럽). 그러나 아마도 모든** 유용한 정보 **(IP 범위 및 Whois)**는 이미 첫 번째 링크에 나와 있을 것입니다.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한, [**BBOT**](https://github.com/blacklanternsecurity/bbot)은 하위 도메인 열거를 자동으로 수행하며 스캔 종료 시 ASNs를 집계하고 요약합니다.
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
조직의 IP 범위를 찾을 수도 있습니다. [http://asnlookup.com/](http://asnlookup.com) (무료 API를 제공합니다)를 사용하여.\
도메인의 IP와 ASN을 찾으려면 [http://ipv4info.com/](http://ipv4info.com)을 사용할 수 있습니다.

### **취약점 찾기**

이 시점에서 우리는 **범위 내의 모든 자산을 알고 있습니다**. 따라서 허용된 경우 모든 호스트에 대해 **취약점 스캐너**(Nessus, OpenVAS)를 실행할 수 있습니다.\
또한, [**포트 스캔**](../pentesting-network/#discovering-hosts-from-the-outside)을 실행하거나 shodan과 같은 서비스를 사용하여 열린 포트를 찾을 수 있으며, 찾은 내용에 따라 이 책에서 여러 가능한 서비스를 펜테스트하는 방법을 확인해야 합니다.\
**또한, 기본 사용자 이름과 암호 목록을 준비하고 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)를 사용하여 서비스를 브루트포스할 수도 있습니다.**

## 도메인

> 우리는 범위 내의 모든 회사와 그들의 자산을 알고 있으며, 이제 범위 내의 도메인을 찾아야 합니다.

_다음에 제안된 기술에서도 서브도메인을 찾을 수 있으며, 이 정보를 과소평가해서는 안 됩니다._

먼저 각 회사의 **주요 도메인**(들)을 찾아야 합니다. 예를 들어, _Tesla Inc._의 경우 _tesla.com_이 될 것입니다.

### **Reverse DNS**

도메인의 IP 범위를 모두 찾았으므로 해당 **IP에 대해 역 DNS 조회**를 시도하여 범위 내의 더 많은 도메인을 찾을 수 있습니다. 피해자의 DNS 서버나 잘 알려진 DNS 서버(1.1.1.1, 8.8.8.8)를 사용해 보세요.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
이 작업을 수행하려면 관리자가 수동으로 PTR을 활성화해야 합니다.\
또한 온라인 도구를 사용하여 이 정보를 얻을 수도 있습니다: [http://ptrarchive.com/](http://ptrarchive.com)

### **역 Whois (루프)**

**whois** 내부에서는 **조직 이름**, **주소**, **이메일**, 전화번호와 같은 많은 흥미로운 **정보**를 찾을 수 있습니다. 그러나 더 흥미로운 것은 이러한 필드 중 하나로 **역 whois 조회**를 수행하면 **회사와 관련된 더 많은 자산**을 찾을 수 있다는 것입니다 (예: 동일한 이메일이 나타나는 다른 whois 레지스트리).\
다음과 같은 온라인 도구를 사용할 수 있습니다:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
* [https://www.whoxy.com/](https://www.whoxy.com) - **무료** 웹, 무료 API 아님.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 유료
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 유료 (무료 검색 100회)
* [https://www.domainiq.com/](https://www.domainiq.com) - 유료

[**DomLink** ](https://github.com/vysecurity/DomLink)를 사용하여 이 작업을 자동화할 수 있습니다(whoxy API 키 필요).\
또한 [amass](https://github.com/OWASP/Amass)를 사용하여 일부 자동 역 whois 검색을 수행할 수 있습니다: `amass intel -d tesla.com -whois`

**새 도메인을 찾을 때마다 이 기술을 사용하여 더 많은 도메인 이름을 발견할 수 있다는 점을 유의하세요.**

### **트래커**

2개의 다른 페이지에서 **동일한 트래커 ID**를 찾으면 **두 페이지가 동일한 팀에 의해 관리된다고 가정**할 수 있습니다.\
예를 들어, 여러 페이지에서 동일한 **Google Analytics ID** 또는 동일한 **Adsense ID**를 볼 경우입니다.

이러한 트래커 및 기타 정보로 검색할 수 있는 몇 가지 페이지와 도구가 있습니다:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **파비콘**

같은 파비콘 아이콘 해시를 찾아 우리의 대상과 관련된 도메인 및 하위 도메인을 찾을 수 있다는 사실을 알고 계셨나요? 이것이 바로 [@m4ll0k2](https://twitter.com/m4ll0k2)가 만든 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구입니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 동일한 파비콘 아이콘 해시를 가진 도메인 찾기](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해서, favihash를 사용하면 대상과 동일한 파비콘 아이콘 해시를 가진 도메인을 찾을 수 있습니다.

또한, [**이 블로그 포스트**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에서 설명한대로 파비콘 해시를 사용하여 기술을 검색할 수도 있습니다. 즉, 취약한 버전의 웹 기술의 파비콘 해시를 알고 있다면 shodan에서 검색하여 **더 많은 취약한 위치를 찾을 수 있습니다**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
다음은 웹의 **파비콘 해시를 계산하는 방법**입니다:
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
### **저작권 / 고유 문자열**

같은 조직의 다른 웹 사이트에서 공유될 수 있는 문자열을 웹 페이지에서 검색합니다. 저작권 문자열은 좋은 예일 수 있습니다. 그런 다음 해당 문자열을 Google, 다른 브라우저 또는 심지어 Shodan에서 검색합니다: `shodan search http.html:"저작권 문자열"`

### **CRT 시간**

일반적으로 cron 작업에는 다음과 같은 것이 있습니다.
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
서버의 모든 도메인 인증서를 갱신합니다. 이는 이를 위해 사용된 CA가 유효 기간에 생성된 시간을 설정하지 않더라도, **인증서 투명성 로그에서 동일한 회사에 속하는 도메인을 찾을 수 있다는 것을 의미**합니다.\
자세한 정보는 [**이 문서를 확인하세요**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **수동적인 탈취**

사람들이 클라우드 공급자에 속하는 IP에 하위 도메인을 할당하고, 언젠가는 **그 IP 주소를 잃어버리지만 DNS 레코드를 제거하는 것을 잊어버리는 것이 흔하다고 합니다**. 따라서, Digital Ocean과 같은 클라우드에서 **가상 머신을 생성**하면 실제로 **일부 하위 도메인을 탈취**할 수 있습니다.

[**이 게시물**](https://kmsec.uk/blog/passive-takeover/)은 이에 대한 이야기를 설명하고, **DigitalOcean에서 가상 머신을 생성**하고, 새로운 머신의 **IPv4**를 가져와서 그것을 가리키는 하위 도메인 레코드를 Virustotal에서 검색하는 스크립트를 제안합니다.

### **다른 방법들**

**새로운 도메인을 찾을 때마다 이 기술을 사용하여 더 많은 도메인 이름을 발견할 수 있다는 점을 유의하세요.**

**Shodan**

이미 IP 공간을 소유한 조직의 이름을 알고 있다면, `org:"Tesla, Inc."`와 같은 데이터로 Shodan에서 검색할 수 있습니다. 발견된 호스트에서 TLS 인증서에 새로운 예상치 못한 도메인을 확인하세요.

주요 웹 페이지의 **TLS 인증서**에 액세스하여 **조직 이름**을 얻은 다음, **shodan**에서 알려진 모든 웹 페이지의 **TLS 인증서**에서 해당 이름을 검색하거나 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch)와 같은 도구를 사용할 수 있습니다.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder)는 주 도메인과 그들의 **하위 도메인**과 관련된 **도메인을 찾는 도구**로, 매우 훌륭합니다.

### **취약점 찾기**

[도메인 탈취](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)를 확인하세요. 어떤 회사가 **도메인을 사용**하지만 **소유권을 잃어버렸을 수도** 있습니다. 저렴하다면 등록하고 회사에 알려주세요.

자산 탐지에서 이미 찾은 자산과 다른 IP를 가진 **도메인을 찾으면**, 기본적인 취약점 스캔(Nessus 또는 OpenVAS 사용)과 [**포트 스캔**](../pentesting-network/#discovering-hosts-from-the-outside)을 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 몇 가지 트릭을 찾을 수 있습니다**.\
_도메인이 때로는 클라이언트가 제어하지 않는 IP 내에 호스팅되므로 범위에 포함되지 않을 수 있으므로 주의하세요._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**버그 바운티 팁**: 해커들에 의해 만들어진 프리미엄 버그 바운티 플랫폼인 **Intigriti**에 가입하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 가입하고 최대 **$100,000**의 바운티를 받으세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## 하위 도메인

> 우리는 스코프 내의 모든 회사, 각 회사의 자산 및 회사와 관련된 모든 도메인을 알고 있습니다.

이제 찾은 각 도메인의 가능한 모든 하위 도메인을 찾아보는 시간입니다.

### **DNS**

**DNS** 레코드에서 **하위 도메인**을 가져오려고 해봅시다. **Zone Transfer**도 시도해보아야 합니다(취약하다면 보고해야 합니다).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

많은 하위 도메인을 얻는 가장 빠른 방법은 외부 소스에서 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다 (더 나은 결과를 위해 API 키를 구성하세요):

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/ko-kr)
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

* [**theHarvester**](https://github.com/laramies/theHarvester)는 정보 수집 도구로, 이메일 주소, 하위 도메인, IP 주소, 호스트 이름 등과 같은 공개 정보를 수집하는 데 사용됩니다. 이 도구는 여러 개의 검색 엔진과 데이터베이스를 쿼리하여 정보를 수집하며, 이를 통해 대상 조직에 대한 외부 공격 표면을 식별할 수 있습니다. theHarvester는 OSINT(Open Source Intelligence) 기법을 사용하여 정보를 수집하므로, 대상에 대한 사전 조사 및 외부 탐색에 유용합니다.
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
다른 흥미로운 도구/API가 있습니다. 이 도구/API는 직접적으로 서브도메인을 찾는 데 특화되어 있지는 않지만 서브도메인을 찾는 데 유용할 수 있습니다. 예를 들어:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** [https://sonar.omnisint.io](https://sonar.omnisint.io) API를 사용하여 서브도메인을 얻습니다.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC 무료 API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 무료 API
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
* [**gau**](https://github.com/lc/gau)**:** 특정 도메인에서 AlienVault의 Open Threat Exchange, Wayback Machine 및 Common Crawl에서 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹을 스크랩하여 JS 파일을 찾고 거기에서 하위 도메인을 추출합니다.
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
* [**Censys 하위 도메인 찾기 도구**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/)은 하위 도메인과 IP 기록을 검색하기 위한 무료 API를 제공합니다.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)는 버그 바운티 프로그램과 관련된 모든 하위 도메인을 무료로 제공합니다. 이 데이터에 접근하려면 [chaospy](https://github.com/dr-0x0x/chaospy)를 사용하거나 이 프로젝트에서 사용하는 범위에 접근할 수도 있습니다. [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

다양한 도구들의 **비교**는 여기에서 확인할 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 브루트 포스**

가능한 하위 도메인 이름을 사용하여 DNS 서버를 브루트 포스하여 새로운 **하위 도메인**을 찾아보겠습니다.

이 작업을 위해 다음과 같은 **일반적인 하위 도메인 워드리스트**가 필요합니다:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

또한 좋은 DNS 리졸버의 IP도 필요합니다. 신뢰할 수 있는 DNS 리졸버 목록을 생성하기 위해 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)에서 리졸버를 다운로드하고 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용하여 필터링할 수 있습니다. 또는 다음을 사용할 수도 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS 브루트 포스에 가장 권장되는 도구는 다음과 같습니다:

* [**massdns**](https://github.com/blechschmidt/massdns): 이 도구는 효과적인 DNS 브루트 포스를 수행한 최초의 도구입니다. 매우 빠르지만 잘못된 양성 결과가 발생할 수 있습니다.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 이것은 1개의 리졸버를 사용하는 것 같습니다.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns)은 go로 작성된 `massdns`를 감싼 래퍼입니다. 이 도구를 사용하여 액티브한 브루트포스를 통해 유효한 하위 도메인을 열거하고, 와일드카드 처리 및 쉬운 입출력 지원을 통해 하위 도메인을 해결할 수 있습니다.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): 이것도 `massdns`를 사용합니다.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 무차별 대입(brute force)합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 두 번째 DNS 브루트포스 라운드

오픈 소스와 브루트포스를 사용하여 하위 도메인을 찾은 후, 찾은 하위 도메인의 변형을 생성하여 더 많은 도메인을 찾아볼 수 있습니다. 이를 위해 다음과 같은 여러 도구들이 유용합니다:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 도메인과 하위 도메인을 주어진 도구를 사용하여 순열을 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 서브도메인을 주어진 단어들의 조합으로 생성합니다.
* goaltdns의 조합 단어 목록은 [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 서브도메인을 주어진 순열로 생성합니다. 순열 파일이 지정되지 않은 경우 gotator는 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): 서브도메인 순열을 생성하는 것 외에도, 이 도구는 그들을 해결해보려고 시도할 수도 있습니다 (하지만 이전에 언급된 도구를 사용하는 것이 더 좋습니다).
* altdns 순열 **단어 목록**은 [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 하위 도메인의 순열, 변형 및 변경을 수행하는 또 다른 도구입니다. 이 도구는 결과를 무차별 대입 공격으로 찾아냅니다 (dns 와일드카드를 지원하지 않습니다).
* [**여기**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 dmut 순열 단어 목록을 얻을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 하여, 추가적인 하위 도메인을 발견하기 위해 지정된 패턴에 따라 새로운 잠재적인 하위 도메인 이름을 생성합니다.

#### 스마트한 순열 생성

* [**regulator**](https://github.com/cramppet/regulator): 자세한 내용은 이 [**포스트**](https://cramppet.github.io/regulator/index.html)를 참조하십시오. 기본적으로, 발견된 하위 도메인에서 **주요 부분**을 가져와 섞어 더 많은 하위 도메인을 찾습니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 서브도메인 브루트 포스 퍼저와 매우 간단하지만 효과적인 DNS 응답 가이드 알고리즘을 결합한 도구입니다. _subzuf_는 특정한 워드리스트나 과거의 DNS/TLS 레코드와 같은 입력 데이터 세트를 활용하여 더 많은 해당 도메인 이름을 정확하게 합성하고 DNS 스캔 중에 수집된 정보를 기반으로 루프를 통해 더 확장합니다.
```
echo www | subzuf facebook.com
```
### **하위 도메인 탐색 워크플로우**

이 블로그 포스트를 확인하세요. 여기에는 **Trickest 워크플로우**를 사용하여 도메인에서 **하위 도메인 탐색을 자동화하는 방법**에 대해 설명되어 있습니다. 이렇게 하면 컴퓨터에서 수동으로 여러 도구를 실행할 필요가 없습니다:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / 가상 호스트**

하위 도메인에 속한 **하나 이상의 웹 페이지를 포함하는 IP 주소**를 찾았다면, 해당 IP에서 **다른 하위 도메인을 찾아볼 수 있습니다**. 이를 위해 **OSINT 소스**에서 IP에 대한 도메인을 찾거나, 해당 IP에서 **VHost 도메인 이름을 무차별 대입(brute-force)하여 찾아볼 수 있습니다**.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 API**를 사용하여 일부 **IP에서 VHost를 찾을 수 있습니다**.

**무차별 대입(brute force)**

웹 서버에 숨겨진 하위 도메인이 있는 것으로 의심되는 경우, 무차별 대입(brute force)을 시도해 볼 수 있습니다:
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
이 기술을 사용하면 내부/숨겨진 엔드포인트에 접근할 수도 있습니다.
{% endhint %}

### **CORS 브루트 포스**

가끔 유효한 도메인/하위 도메인이 _**Origin**_ 헤더에 설정되어 있을 때만 헤더 _**Access-Control-Allow-Origin**_을 반환하는 페이지를 찾을 수 있습니다. 이러한 시나리오에서 이 동작을 악용하여 새로운 **하위 도메인**을 **발견**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **버킷 브루트 포스**

**서브도메인**을 찾을 때, **버킷**으로 연결되어 있는지 확인하고 그 경우에는 [**권한을 확인**](../../network-services-pentesting/pentesting-web/buckets/)하세요.\
또한, 이 시점에서 범위 내의 모든 도메인을 알게 되었으므로 [**가능한 버킷 이름을 브루트 포스하고 권한을 확인**](../../network-services-pentesting/pentesting-web/buckets/)해보세요.

### **모니터링**

도메인의 **새로운 서브도메인**이 생성되는지 **Certificate Transparency** 로그를 모니터링하여 확인할 수 있습니다. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)를 사용하세요.

### **취약점 탐색**

가능한 [**서브도메인 탈취**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)을 확인하세요.\
**서브도메인**이 **S3 버킷**을 가리키고 있다면, [**권한을 확인**](../../network-services-pentesting/pentesting-web/buckets/)하세요.

자산 탐색에서 이미 찾은 IP와 다른 IP를 가진 **서브도메인**을 발견하면, **기본적인 취약점 스캔**(Nessus 또는 OpenVAS 사용)과 **포트 스캔**(nmap/masscan/shodan)을 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 방법**을 찾을 수 있습니다.\
_참고로, 때로는 서브도메인이 클라이언트가 제어하지 않는 IP에 호스팅되어 있어 범위에 포함되지 않을 수 있으므로 주의하세요._

## IP

초기 단계에서 **IP 범위, 도메인 및 서브도메인**을 찾았을 수 있습니다.\
이제 **해당 범위의 모든 IP**와 **도메인/서브도메인(DNS 쿼리)**을 수집해야 합니다.

다음 **무료 API 서비스**를 사용하여 도메인 및 서브도메인이 사용한 이전 IP를 찾을 수도 있습니다. 이러한 IP는 여전히 클라이언트가 소유하고 있을 수 있으며 [**CloudFlare 우회**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾을 수 있게 해줄 수 있습니다.

* [**https://securitytrails.com/**](https://securitytrails.com/)

도메인이 특정 IP 주소를 가리키는지 확인하기 위해 [**hakip2host**](https://github.com/hakluke/hakip2host) 도구를 사용할 수도 있습니다.

### **취약점 탐색**

**CDN에 속하지 않는 모든 IP에 대해 포트 스캔**을 수행하세요(거기에는 흥미로운 내용이 거의 없을 것입니다). 발견한 실행 중인 서비스에서 **취약점을 찾을 수 있을 수 있습니다**.

**호스트 스캔 방법에 대한** [**가이드**](../pentesting-network/) **을 찾으세요.**

## 웹 서버 탐색

> 모든 회사와 그들의 자산을 찾았으며, IP 범위, 도메인 및 서브도메인을 알고 있습니다. 이제 웹 서버를 찾아보는 시간입니다.

이전 단계에서 이미 발견한 IP와 도메인의 **정보 수집**을 수행했을 가능성이 높으므로 이미 **가능한 모든 웹 서버**를 찾았을 수 있습니다. 그러나 아직 찾지 못했다면, 이제 범위 내에서 웹 서버를 찾기 위한 **빠른 트릭**을 살펴보겠습니다.

참고로, 이는 **웹 앱 탐색을 위한 것**이므로 범위에 따라 **취약점 스캔**과 **포트 스캔**도 수행해야 합니다(**허용되는 경우**).

[**masscan을 사용하여 웹 서버와 관련된 열린 포트**를 빠르게 찾는 방법은 여기에서 찾을 수 있습니다](../pentesting-network/#http-port-discovery).\
웹 서버를 찾기 위한 또 다른 유용한 도구로 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)가 있습니다. 도메인 목록을 전달하면 포트 80 (http) 및 443 (https)에 연결을 시도합니다. 추가로 다른 포트를 시도할 수도 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **스크린샷**

이제 스코프 내에 있는 모든 웹 서버(회사의 IP 및 모든 도메인 및 하위 도메인)를 발견했으므로 어디서부터 시작해야 할지 아마도 모를 것입니다. 그래서 간단하게 시작하고 모든 웹 서버의 스크린샷을 찍는 것으로 시작합시다. **메인 페이지**를 살펴보면 취약점이 더 많이 발생할 수 있는 이상한 엔드포인트를 찾을 수 있습니다.

제안된 아이디어를 수행하기 위해 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)를 사용할 수 있습니다.

또한, [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용하여 모든 스크린샷을 실행하여 취약점이 포함될 가능성이 있는 것과 그렇지 않은 것을 알려줄 수 있습니다.

## 공용 클라우드 자산

회사에 속하는 잠재적인 클라우드 자산을 찾으려면 해당 회사를 식별하는 키워드 목록으로 시작해야 합니다. 예를 들어, 암호화폐 회사의 경우 "crypto", "wallet", "dao", "<도메인_이름>", "<하위_도메인_이름>"과 같은 단어를 사용할 수 있습니다.

또한, 버킷에서 사용되는 일반적인 단어들의 단어 목록이 필요합니다:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그런 다음, 해당 단어들로 **순열**을 생성해야 합니다(자세한 내용은 [**두 번째 DNS 브루트 포스 라운드**](./#second-dns-bruteforce-round)를 참조).

생성된 단어 목록을 사용하여 [**cloud\_enum**](https://github.com/initstring/cloud\_enum), [**CloudScraper**](https://github.com/jordanpotti/CloudScraper), [**cloudlist**](https://github.com/projectdiscovery/cloudlist) 또는 [**S3Scanner**](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용할 수 있습니다.

클라우드 자산을 찾을 때는 AWS의 버킷 이상을 찾아야 합니다.

### **취약점 찾기**

오픈 버킷이나 노출된 클라우드 함수와 같은 것을 찾으면 해당 자산에 액세스하여 제공되는 내용을 확인하고 악용할 수 있는지 확인해야 합니다.

## 이메일

스코프 내의 도메인 및 하위 도메인을 사용하면 기업의 이메일을 검색하기 위해 필요한 모든 것을 갖추게 됩니다. 기업의 이메일을 찾기 위해 가장 잘 작동한 **API** 및 **도구**는 다음과 같습니다:

* [**theHarvester**](https://github.com/laramies/theHarvester) - API 사용
* [**https://hunter.io/**](https://hunter.io/)의 API (무료 버전)
* [**https://app.snov.io/**](https://app.snov.io/)의 API (무료 버전)
* [**https://minelead.io/**](https://minelead.io/)의 API (무료 버전)

### **취약점 찾기**

이메일은 나중에 웹 로그인 및 인증 서비스(예: SSH)를 브루트 포스하는 데 유용하게 사용될 수 있습니다. 또한, 피싱에 필요합니다. 또한, 이러한 API를 사용하면 피싱 캠페인에 유용한 이메일 주소 뒤에 있는 사람에 대한 더 많은 정보를 얻을 수 있습니다.

## 자격 증명 유출

도메인, 하위 도메인 및 이메일을 사용하여 이메일에 속한 과거에 유출된 자격 증명을 찾을 수 있습니다:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **취약점 찾기**

유효한 유출된 자격 증명을 찾으면 매우 쉽게 성공할 수 있습니다.

## 비밀 유출

자격 증명 유출은 민감한 정보가 유출되고 판매된 회사의 해킹과 관련이 있습니다. 그러나 회사는 그러한 데이터베이스에 정보가 없는 다른 유출에도 영향을 받을 수 있습니다.

### Github 유출

자격 증명 및 API는 회사의 공개 저장소나 해당 github 회사에서 작업하는 사용자의 공개 저장소에서 유출될 수 있습니다.\
[**Leakos**](https://github.com/carlospolop/Leakos) 도구를 사용하여 조직 및 해당 개발자의 모든 공개 저장소를 다운로드하고 자동으로 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 실행할 수 있습니다.

**Leakos**는 때로는 웹 페이지에도 비밀이 포함되어 있기 때문에 제공된 URL을 통해 **텍스트**를 실행하는 **gitleaks**를 실행하는 데에도 사용할 수 있습니다.

#### Github Dorks

공격 대상 조직에서 검색할 수 있는 잠재적인 **github dorks**에 대해서도 검토해보세요:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes 유출

때로는 공격자나 작업자가 회사 콘텐츠를 페이스트 사이트에 게시할 수 있습니다. 이는 민감한 정보를 포함할 수도 있고 그렇지 않을 수도 있지만 검색해 보는 것이 매우 흥미로울 수 있습니다.\
[**Pastos**](https://github.com/carlospolop/Pastos) 도구를 사용하여 80개 이상의 페이스트 사이트에서 동시에 검색할 수 있습니다.

### Google Dorks

오래된 Google Dorks는 노출되지 않아야 할 정보를 찾는 데 항상 유용합니다. 유일한 문제는 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 가능한 쿼리가 포함되어 있어 수동으로 실행할 수 없다는 것입니다. 따라서 가장 좋아하는 10개의 쿼리를 선택하거나 [**Gorks**](https://github.com/carlospolop/Gorks)와 같은 도구를 사용하여 모두 실행할 수 있습니다.

_일반 Google 브라우저를 사용하여 데이터베이스 전체를 실행하는 도구는 Google이 매우 빨리 차단하기 때문에 결코 종료되지 않을 것입니다._

### **취약점 찾기**

유효한 유출된 자격 증명이나 API 토큰을 찾으면 매우 쉽게 성공할 수 있습니다.

## 공개 코드 취약점

회사가 **오픈 소스 코드**를 가지고 있다면 해당 코드를 분석하여 취약점을 찾을 수 있습니다.

**언어에 따라** 사용할 수 있는 다른 **도구**가 있습니다:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

또한, 다음과 같이 **공개 저장소를 스캔**할 수 있는 무료 서비스도 있습니다:

* [**Snyk**](https://app.snyk.io/)
## [**웹 펜테스팅 방법론**](../../network-services-pentesting/pentesting-web/)

버그 헌터들이 발견한 **취약점의 대부분**은 **웹 애플리케이션**에 존재하므로, 이 시점에서 **웹 애플리케이션 테스트 방법론**에 대해 이야기하고 싶습니다. [**이 정보는 여기에서 찾을 수 있습니다**](../../network-services-pentesting/pentesting-web/).

또한, [**웹 자동 스캐너 오픈 소스 도구**](../../network-services-pentesting/pentesting-web/#automatic-scanners) 섹션에 특별한 언급을 하고 싶습니다. 이 도구들은 매우 민감한 취약점을 찾을 것으로 기대하지 않아도 되지만, **일부 초기 웹 정보를 수집하는 데 유용**합니다.

## 요약

> 축하합니다! 이 시점에서 이미 **기본적인 열거 작업**을 수행했습니다. 네, 이것은 기본적인 작업입니다. 더 많은 열거 작업을 수행할 수 있습니다(나중에 더 많은 트릭을 볼 것입니다).

따라서 다음을 이미 수행했습니다:

1. 범위 내의 **회사**를 모두 찾았습니다.
2. 회사에 속한 **자산**을 모두 찾았습니다(범위 내에서 취약점 스캔 수행).
3. 회사에 속한 **도메인**을 모두 찾았습니다.
4. 도메인의 **모든 하위 도메인**을 찾았습니다(하위 도메인 탈취 여부 확인).
5. 범위 내의 **CDN이 아닌 IP**를 모두 찾았습니다.
6. **웹 서버**를 모두 찾았고, 그들의 **스크린샷**을 찍었습니다(더 깊이 들여다볼 가치가 있는 이상한 점이 있나요?).
7. 회사에 속한 **잠재적인 공용 클라우드 자산**을 모두 찾았습니다.
8. **이메일**, **자격증명 유출**, 그리고 **비밀 유출**을 찾았습니다. 이들은 당신에게 **쉽게 큰 이득**을 줄 수 있습니다.
9. 찾은 모든 웹을 **펜테스팅**했습니다.

## **전체 자동화된 Recon 도구**

주어진 범위에 대해 제안된 작업 중 일부를 수행하는 여러 도구가 있습니다.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 조금 오래되었고 업데이트되지 않음

## **참고 자료**

* [**@Jhaddix**](https://twitter.com/Jhaddix)의 모든 무료 강좌, [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**버그 바운티 팁**: 해커들이 만든 프리미엄 버그 바운티 플랫폼인 **Intigriti에 가입**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 가입하고 최대 **$100,000**의 바운티를 받으세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹을 배워보세요**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **자신의 해킹 트릭을 공유**하세요.

</details>
