# 외부 탐색 방법론

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 처음부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **채용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

## 자산 발견

> 어떤 회사에 속한 모든 것이 범위 내에 있다고 말받고, 실제로 이 회사가 무엇을 소유하고 있는지 알고 싶습니다.

이 단계의 목표는 **주요 회사가 소유한 회사** 및 이러한 회사의 **모든 자산**을 획득하는 것입니다. 이를 위해 우리는 다음을 수행할 것입니다:

1. 주요 회사의 인수를 찾아 범위 내의 회사를 얻습니다.
2. 각 회사의 **ASN**을 찾아 해당 회사가 소유한 **IP 범위**를 얻습니다.
3. 다른 항목(조직 이름, 도메인 등)을 검색하기 위해 역 whois 조회를 사용하여 첫 번째 항목과 관련된 항목을 검색합니다(이를 재귀적으로 수행할 수 있음).
4. 다른 기술(예: shodan `org` 및 `ssl` 필터)을 사용하여 다른 자산을 검색합니다(`ssl` 트릭은 재귀적으로 수행할 수 있음).

### **인수**

우선, **주요 회사가 소유한 다른 회사**를 알아야 합니다.\
[https://www.crunchbase.com/](https://www.crunchbase.com)를 방문하여 **주요 회사**를 **검색**하고 "**인수**"를 **클릭**합니다. 거기에서 주요 회사가 인수한 다른 회사를 볼 수 있습니다.\
다른 옵션은 주요 회사의 **위키피디아** 페이지를 방문하여 **인수**를 검색하는 것입니다.

> 이 시점에서 범위 내의 모든 회사를 알아야 합니다. 이제 그들의 자산을 찾는 방법을 알아봅시다.

### **ASNs**

자율 시스템 번호(**ASN**)는 **인터넷 할당 번호 기관(IANA)**에 의해 **자율 시스템(AS)**에 할당된 **고유한 번호**입니다.\
**AS**는 외부 네트워크에 액세스하기 위한 명확히 정의된 정책을 가진 **IP 주소 블록**으로 구성되며 단일 조직에 의해 관리되지만 여러 운영자로 구성될 수 있습니다.

**회사가 할당한 ASN**을 찾아 해당 **IP 범위**를 찾는 것이 흥미로울 수 있습니다. **범위 내의 모든 호스트에 대한 취약성 테스트**를 수행하고 해당 IP 내의 도메인을 찾는 것이 유익할 것입니다.\
[**https://bgp.he.net/**](https://bgp.he.net)에서 회사 **이름**, **IP**, 또는 **도메인**으로 검색할 수 있습니다.\
**회사의 지역에 따라 이 링크가 더 많은 데이터를 수집하는 데 유용할 수 있습니다:** [**AFRINIC**](https://www.afrinic.net) **(아프리카),** [**Arin**](https://www.arin.net/about/welcome/region/)**(북미),** [**APNIC**](https://www.apnic.net) **(아시아),** [**LACNIC**](https://www.lacnic.net) **(중남미),** [**RIPE NCC**](https://www.ripe.net) **(유럽). 그러나 아마도 모든** 유용한 정보 **(IP 범위 및 Whois)**가 이미 첫 번째 링크에 나와 있을 것입니다.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**은** 하위 도메인 열거를 자동으로 수행하며 스캔 종료 시 ASNs를 집계 및 요약합니다.
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
조직의 IP 범위를 찾을 수도 있습니다. [http://asnlookup.com/](http://asnlookup.com) (무료 API 제공).\
도메인의 IP 및 ASN을 찾을 수 있습니다. [http://ipv4info.com/](http://ipv4info.com).

### **취약점 찾기**

이 시점에서 **범위 내의 모든 자산을 알고 있으므로**, 허용된다면 모든 호스트에 대해 **취약점 스캐너**(Nessus, OpenVAS)를 실행할 수 있습니다.\
또한, [**포트 스캔**](../pentesting-network/#discovering-hosts-from-the-outside)을 실행하거나 shodan과 같은 서비스를 사용하여 **열린 포트를 찾을 수 있으며 발견한 내용에 따라** 이 책에서 여러 가능한 서비스를 펜테스트하는 방법을 확인해야 합니다.\
**또한, 기본 사용자 이름 및** 암호 목록을 준비하고 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)를 사용하여 서비스를 브루트포스할 수도 있습니다.

## 도메인

> 우리는 범위 내의 모든 회사와 그 자산을 알고 있습니다. 이제 범위 내의 도메인을 찾아야 합니다.

_다음으로 제안된 기술을 사용하여 하위 도메인을 찾을 수도 있으며 이 정보를 과소평가해서는 안 됩니다._

먼저 각 회사의 **주요 도메인**(들)을 찾아야 합니다. 예를 들어, _Tesla Inc._의 경우 _tesla.com_이 될 것입니다.

### **Reverse DNS**

도메인의 IP 범위를 모두 찾았다면 해당 **IP에 대한 역 DNS 조회**를 수행하여 범위 내의 더 많은 도메인을 찾아볼 수 있습니다. 피해자의 DNS 서버 또는 잘 알려진 DNS 서버(1.1.1.1, 8.8.8.8)를 사용해보세요.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
### **역 Whois (루프)**

**Whois** 내부에는 **조직 이름**, **주소**, **이메일**, 전화번호 등과 같은 많은 흥미로운 **정보**가 포함되어 있습니다. 그러나 더 흥미로운 것은 **회사와 관련된 더 많은 자산을 찾을 수 있다는 것**입니다. 이를 위해 해당 필드 중 하나로 **역 Whois 조회를 수행**하면 됩니다(예: 동일한 이메일이 나타나는 다른 whois 레지스트리).\
다음과 같은 온라인 도구를 사용할 수 있습니다:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
* [https://www.whoxy.com/](https://www.whoxy.com) - **무료** 웹, 무료 API 아님.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 유료
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 유료 (무료 **100회** 검색)
* [https://www.domainiq.com/](https://www.domainiq.com) - 유료

[**DomLink** ](https://github.com/vysecurity/DomLink)를 사용하여 이 작업을 자동화할 수 있습니다(whoxy API 키 필요).\
또한 [amass](https://github.com/OWASP/Amass)를 사용하여 일부 자동 역 Whois 검색을 수행할 수 있습니다: `amass intel -d tesla.com -whois`

**새로운 도메인을 발견할 때마다 이 기술을 사용하여 더 많은 도메인 이름을 발견할 수 있다는 점을 유의하십시오.**

### **트래커**

2개의 다른 페이지에서 **동일한 트래커의 동일한 ID**를 찾으면 **두 페이지가 동일한 팀에 의해 관리된다고 가정**할 수 있습니다.\
예를 들어, 여러 페이지에서 **동일한 Google Analytics ID** 또는 **동일한 Adsense ID**를 볼 때입니다.

이러한 트래커 및 기타 정보로 검색할 수 있는 페이지 및 도구가 있습니다:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **파비콘**

우리의 대상과 관련된 도메인 및 하위 도메인을 찾을 수 있다는 것을 알고 계셨습니까? 동일한 파비콘 아이콘 해시를 찾아주는 것이 바로 [@m4ll0k2](https://twitter.com/m4ll0k2)가 만든 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구입니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 동일한 파비콘 아이콘 해시를 가진 도메인 발견](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해서, favihash를 사용하면 대상과 동일한 파비콘 아이콘 해시를 가진 도메인을 발견할 수 있습니다.

또한, [**이 블로그 게시물**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에서 설명한대로 파비콘 해시를 사용하여 기술을 검색할 수도 있습니다. 즉, 취약한 버전의 웹 기술의 파비콘 해시를 알고 있다면 shodan에서 검색하여 **더 많은 취약한 위치를 찾을 수 있습니다**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
다음은 웹 사이트의 **파비콘 해시를 계산하는 방법**입니다:
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

동일 조직 내 다른 웹 사이트에서 공유될 수 있는 **문자열을 웹 페이지 내에서 검색**합니다. **저작권 문자열**이 좋은 예가 될 수 있습니다. 그런 다음 해당 문자열을 **Google**, 다른 **브라우저** 또는 심지어 **Shodan**에서 검색합니다: `shodan search http.html:"Copyright string"`

### **CRT 시간**

다음과 같은 cron 작업이 있는 것이 일반적입니다.
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### 외부 탐색 방법론

서버의 모든 도메인 인증서를 갱신합니다. 이는 이를 위해 사용된 CA가 발급 시간을 유효 기간에 설정하지 않더라도 **인증서 투명성 로그에서 동일 회사에 속한 도메인을 찾을 수 있습니다**.\
자세한 정보는 [**여기의 설명서**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)를 확인하세요.

### 메일 DMARC 정보

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)와 같은 웹 또는 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)와 같은 도구를 사용하여 **동일한 dmarc 정보를 공유하는 도메인 및 하위 도메인을 찾을 수 있습니다**.

### **수동 인수**

사람들이 하위 도메인을 클라우드 제공업체에 속하는 IP에 할당하고 어느 순간에는 **해당 IP 주소를 잃어버리지만 DNS 레코드를 제거하는 것을 잊는 것이 흔합니다**. 따라서, 클라우드(예: Digital Ocean)에 VM을 생성하기만 하면 실제로 **일부 하위 도메인을 인수**할 수 있습니다.

[**이 게시물**](https://kmsec.uk/blog/passive-takeover/)은 이에 대한 이야기를 설명하고, **DigitalOcean에서 VM을 생성**하고, 새로운 기계의 **IPv4**를 **얻은 다음 Virustotal에서 해당 기계를 가리키는 하위 도메인 레코드를 검색**하는 스크립트를 제안합니다.

### **기타 방법**

**새로운 도메인을 발견할 때마다이 기술을 사용하여 더 많은 도메인 이름을 발견할 수 있다는 점을 유의하십시오.**

**Shodan**

이미 IP 공간을 소유한 조직의 이름을 알고 있습니다. 이 데이터로 Shodan에서 다음과 같이 검색할 수 있습니다: `org:"Tesla, Inc."` TLS 인증서에서 새로운 예상치 못한 도메인을 찾으십시오.

주요 웹 페이지의 **TLS 인증서**에 액세스하여 **조직 이름**을 얻은 다음, Shodan에서 알려진 모든 웹 페이지의 **TLS 인증서**에서 해당 이름을 검색하십시오. 필터 : `ssl:"Tesla Motors"` 또는 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch)와 같은 도구를 사용할 수 있습니다.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder)는 주요 도메인과 해당 **하위 도메인**을 찾는 도구로 매우 놀라운 도구입니다.

### **취약점 찾기**

[도메인 인수](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)를 확인하십시오. 어떤 회사가 **도메인을 사용 중**이지만 **소유권을 잃었을 수 있습니다**. 저렴하다면 등록하고 회사에 알려주세요.

자산 발견에서 찾은 IP와 다른 **도메인을 발견하면**, 기본 취약점 스캔(네스러스 또는 OpenVAS 사용) 및 **nmap/masscan/shodan**을 사용한 [**포트 스캔**](../pentesting-network/#discovering-hosts-from-the-outside)을 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 데 사용할 수 있는 몇 가지 요령을 찾을 수 있습니다**.\
_도메인이 클라이언트가 제어하지 않는 IP 내에 호스팅되어 있을 수 있으므로 범위에 포함되지 않을 수 있습니다. 주의하세요._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**버그 바운티 팁**: **해커들에 의해 만들어진 프리미엄 버그 바운티 플랫폼인 Intigriti에 가입**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 참여하여 최대 **$100,000**의 바운티를 받아보세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## 하위 도메인

> 우리는 범위 내의 모든 회사, 각 회사의 모든 자산 및 회사와 관련된 모든 도메인을 알고 있습니다.

이제 찾은 각 도메인의 모든 가능한 하위 도메인을 찾아야 합니다.

{% hint style="success" %}
일부 도메인을 찾는 도구 및 기술은 하위 도메인을 찾는 데도 도움이 될 수 있습니다!
{% endhint %}

### **DNS**

**DNS** 레코드에서 **하위 도메인**을 가져오려고 합니다. 취약하다면 **Zone Transfer**도 시도해보세요(취약하다면 보고해야 합니다).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

다량의 하위 도메인을 얻는 가장 빠른 방법은 외부 소스에서 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다 (더 나은 결과를 얻으려면 API 키를 구성하세요):

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
다른 흥미로운 도구/API가 있습니다. 하위 도메인을 직접적으로 찾는 데 특화되지 않았더라도 하위 도메인을 찾는 데 유용할 수 있습니다. 예를 들어:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 하위 도메인을 얻기 위해 [https://sonar.omnisint.io](https://sonar.omnisint.io) API를 사용합니다.
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
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹을 스크랩하여 JS 파일을 찾고 거기서 하위 도메인을 추출합니다.
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
* [**Censys 하위 도메인 찾기**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/)은 하위 도메인 및 IP 기록을 검색하기 위한 무료 API를 제공합니다.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

이 프로젝트는 **버그 바운티 프로그램과 관련된 모든 하위 도메인을 무료로 제공**합니다. 이 데이터에 접근하려면 [chaospy](https://github.com/dr-0x0x/chaospy)를 사용하거나 이 프로젝트에서 사용하는 범위에도 접근할 수 있습니다. [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

다양한 도구들의 **비교**를 여기에서 찾을 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 브루트 포스**

가능한 하위 도메인 이름을 사용하여 DNS 서버를 브루트 포스하여 새로운 **하위 도메인**을 찾아봅시다.

이 작업을 위해 몇 가지 **일반적인 하위 도메인 워드리스트가 필요**합니다:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

그리고 좋은 DNS 리졸버의 IP도 필요합니다. 신뢰할 수 있는 DNS 리졸버 목록을 생성하려면 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)에서 리졸버를 다운로드하고 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용하여 필터링할 수 있습니다. 또는 [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)를 사용할 수도 있습니다.

DNS 브루트 포스에 가장 권장되는 도구들은 다음과 같습니다:

* [**massdns**](https://github.com/blechschmidt/massdns): 이 도구는 효과적인 DNS 브루트 포스를 수행한 최초의 도구였습니다. 매우 빠르지만 잘못된 양성 결과가 발생할 수 있습니다.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 이것은 제 생각에는 1개의 resolver만 사용하는 것 같습니다.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns)은 `massdns`를 감싼 것으로, 유효한 서브도메인을 활성 브루트포스를 사용하여 나열하고, 와일드카드 처리 및 쉬운 입출력 지원을 통해 서브도메인을 해결할 수 있습니다.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): `massdns`도 사용합니다.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 무차별 대입 공격합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 두 번째 DNS 브루트포스 라운드

오픈 소스 및 브루트포스를 사용하여 하위 도메인을 찾은 후, 찾은 하위 도메인의 변형을 생성하여 더 많은 도메인을 찾아볼 수 있습니다. 이를 위해 다음과 같은 여러 도구가 유용합니다:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 도메인 및 하위 도메인을 주어진 경우 순열을 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 주어진 도메인 및 서브도메인에서 순열을 생성합니다.
* goaltdns 순열 **wordlist**를 [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 도메인 및 서브도메인을 제공하여 순열을 생성합니다. 순열 파일이 지정되지 않은 경우 gotator는 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): 하위 도메인 순열을 생성하는 것 외에도 해결을 시도할 수 있지만 (이전에 설명된 도구를 사용하는 것이 더 좋음).
* altdns 순열 **wordlist**를 [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 하위 도메인의 순열, 변형 및 변경을 수행하는 또 다른 도구입니다. 이 도구는 결과를 무차별 대입할 것입니다 (DNS 와일드카드를 지원하지 않음).
* [**여기**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 dmut 순열 워드리스트를 얻을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 하여 **지정된 패턴에 따라 새로운 잠재적인 하위 도메인 이름을 생성**하여 더 많은 하위 도메인을 발견하려고 시도합니다.

#### 스마트 순열 생성

* [**regulator**](https://github.com/cramppet/regulator): 자세한 내용은 이 [**포스트**](https://cramppet.github.io/regulator/index.html)를 참조하십시오. 그러나 기본적으로 **발견된 하위 도메인**에서 **주요 부분**을 가져와 섞어 더 많은 하위 도메인을 찾을 것입니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_은 서브도메인 브루트포스 퍼저로, 극도로 간단하지만 효과적인 DNS 응답 안내 알고리즘과 결합되어 있습니다. 사용자 지정 워드리스트나 과거 DNS/TLS 레코드와 같은 입력 데이터 세트를 활용하여 더 많은 해당 도메인 이름을 정확하게 합성하고 DNS 스캔 중 수집된 정보를 기반으로 루프를 통해 더 확장합니다.
```
echo www | subzuf facebook.com
```
### **서브도메인 발견 워크플로우**

도메인에서 **Trickest 워크플로우**를 사용하여 **서브도메인 발견을 자동화**하는 방법에 대해 작성한 블로그 포스트를 확인하세요. 이를 통해 컴퓨터에서 수동으로 여러 도구를 실행할 필요가 없습니다:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / 가상 호스트**

하나 이상의 웹 페이지를 포함하는 IP 주소를 발견했다면, 해당 IP에서 **다른 서브도메인을 찾아볼 수 있습니다**. 이를 위해 IP에서 도메인을 찾거나 **해당 IP의 VHost 도메인 이름을 무차별 대입**하여 찾아볼 수 있습니다.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 API**를 사용하여 **IP에서 VHosts를 찾을 수 있습니다**.

**무차별 대입**

웹 서버에 숨겨진 서브도메인이 있을 것으로 의심된다면, 무차별 대입을 시도할 수 있습니다:
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
이 기술을 사용하면 내부/숨겨진 엔드포인트에 액세스할 수도 있습니다.
{% endhint %}

### **CORS 브루트 포스**

가끔 유효한 도메인/서브도메인이 _**Origin**_ 헤더에 설정될 때에만 헤더 _**Access-Control-Allow-Origin**_을 반환하는 페이지를 발견할 수 있습니다. 이러한 시나리오에서 이러한 동작을 남용하여 **새로운 서브도메인**을 **발견**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **버킷 브루트 포스**

**서브도메인**을 찾을 때 **버킷**으로 **포인팅**되는지 확인하고, 그 경우에는 [**권한을 확인**](../../network-services-pentesting/pentesting-web/buckets/)**하세요**.\
또한, 이 시점에서 범위 내의 모든 도메인을 알게 되었으므로 [**가능한 버킷 이름을 브루트 포스하고 권한을 확인**](../../network-services-pentesting/pentesting-web/buckets/)**하세요**.

### **모니터링**

**도메인**의 **새로운 서브도메인**이 생성되는지 **모니터링**하여 **Certificate Transparency** 로그를 통해 확인할 수 있습니다. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)를 사용하세요.

### **취약점 탐색**

가능한 [**서브도메인 탈취**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)을 확인하세요.\
**서브도메인**이 **S3 버킷**을 가리키는 경우, [**권한을 확인**](../../network-services-pentesting/pentesting-web/buckets/)**하세요**.

자산 발견에서 이미 찾은 IP와 다른 **IP를 가리키는 서브도메인**을 찾으면 **기본 취약점 스캔**을 수행해야 합니다 (Nessus 또는 OpenVAS 사용) 및 **nmap/masscan/shodan**을 사용한 [**포트 스캔**](../pentesting-network/#discovering-hosts-from-the-outside)을 수행하세요. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 방법을 찾을 수 있습니다**.\
_가끔 서브도메인이 클라이언트가 제어하지 않는 IP에 호스팅되어 있어 범위에 포함되지 않을 수 있으니 주의하세요._

## IPs

초기 단계에서 **일부 IP 범위, 도메인 및 서브도메인을 찾았을 수 있습니다**.\
이제 **해당 범위에서 모든 IP**와 **도메인/서브도메인 (DNS 쿼리)**을 **재수집**할 시간입니다.

다음 **무료 API 서비스**를 사용하여 **도메인 및 서브도메인이 사용한 이전 IP**를 찾을 수도 있습니다. 이러한 IP는 여전히 클라이언트가 소유하고 있을 수 있으며 [**CloudFlare 우회**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾을 수 있습니다.

* [**https://securitytrails.com/**](https://securitytrails.com/)

도메인이 특정 IP 주소를 가리키는지 확인할 수 있는 도구 [**hakip2host**](https://github.com/hakluke/hakip2host)를 사용할 수도 있습니다.

### **취약점 탐색**

**CDN에 속하지 않는 모든 IP에 대해 포트 스캔**을 수행하세요 (거기에 흥미로운 것을 찾을 가능성이 높지 않습니다). 발견된 실행 중인 서비스에서 **취약점을 찾을 수 있습니다**.

**호스트를 스캔하는 방법에 대한** [**가이드**](../pentesting-network/) **를 찾으세요**.

## 웹 서버 탐색

> 모든 기업과 그 자산을 찾았으며 범위 내의 IP 범위, 도메인 및 서브도메인을 알고 있습니다. 이제 웹 서버를 찾아보는 시간입니다.

이전 단계에서 이미 발견된 IP 및 도메인의 **정찰**을 수행했을 가능성이 높으므로 **모든 가능한 웹 서버를 이미 찾았을 수 있습니다**. 그러나 아직 찾지 못했다면 이제 범위 내의 웹 서버를 찾는 **빠른 트릭**을 살펴보겠습니다.

이것은 **웹 앱 발견을 위해 지향**되므로 **취약점** 및 **포트 스캔**도 수행해야 합니다 (**범위 내에서 허용되는 경우**).

[**masscan을 사용하여 웹 서버와 관련된 열린 포트를 빠르게 찾을 수 있는 빠른 방법**은 여기에서 찾을 수 있습니다](../pentesting-network/#http-port-discovery).\
다른 웹 서버를 찾는 데 유용한 도구로 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)가 있습니다. 도메인 목록을 전달하면 포트 80 (http) 및 443 (https)에 연결을 시도합니다. 추가로 다른 포트를 시도할 수도 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **스크린샷**

이제 스코프 내에 있는 모든 웹 서버(회사의 IP 및 모든 도메인 및 서브도메인의 IP 중)를 발견했으므로 아마도 **어디서부터 시작해야 할지 모를 것**입니다. 그래서 간단하게 시작하고 그 모든 것의 스크린샷을 찍는 것부터 시작합시다. **메인 페이지**를 살펴보기만 해도 **취약할 가능성이 높은** 이상한 엔드포인트를 찾을 수 있습니다.

제안된 아이디어를 수행하기 위해 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)를 사용할 수 있습니다.

또한, 그런 다음 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용하여 **스크린샷**을 모두 실행하여 **취약점을 포함할 가능성이 높은 것**과 그렇지 않은 것을 알려줄 수 있습니다.

## 퍼블릭 클라우드 자산

회사에 속한 잠재적인 클라우드 자산을 찾으려면 해당 회사를 식별하는 키워드 목록부터 시작해야 합니다. 예를 들어, 암호화폐 회사의 경우 "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">와 같은 단어를 사용할 수 있습니다.

또한 **버킷에 사용되는 일반 단어들의 단어 목록**이 필요합니다:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그런 다음 해당 단어들로 **순열을 생성**해야 합니다(자세한 내용은 [**두 번째 라운드 DNS 브루트포스**](./#second-dns-bruteforce-round)를 확인하십시오).

생성된 단어 목록을 사용하여 [**cloud\_enum**](https://github.com/initstring/cloud\_enum), [**CloudScraper**](https://github.com/jordanpotti/CloudScraper), [**cloudlist**](https://github.com/projectdiscovery/cloudlist) 또는 [**S3Scanner**](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용할 수 있습니다.

클라우드 자산을 찾을 때 **AWS 버킷 이상을 찾아야** 한다는 것을 기억하십시오.

### **취약점 찾기**

**오픈 버킷이나 노출된 클라우드 함수**와 같은 것을 발견하면 **접근**하여 제공되는 내용을 확인하고 악용할 수 있는지 확인해야 합니다.

## 이메일

스코프 내의 **도메인** 및 **서브도메인**을 통해 기업의 이메일을 검색하기 시작할 필요가 있습니다. 이는 회사의 이메일을 찾는 데 가장 잘 작동한 **API** 및 **도구**입니다:

* [**theHarvester**](https://github.com/laramies/theHarvester) - APIs와 함께
* [**https://hunter.io/**](https://hunter.io/)의 API(무료 버전)
* [**https://app.snov.io/**](https://app.snov.io/)의 API(무료 버전)
* [**https://minelead.io/**](https://minelead.io/)의 API(무료 버전)

### **취약점 찾기**

나중에 이메일은 웹 로그인 및 인증 서비스(예: SSH)를 브루트 포스하거나 **피싱**에 필요합니다. 또한, 이러한 API는 이메일 뒤에 있는 **사람에 대한 더 많은 정보**를 제공하여 피싱 캠페인에 유용합니다.

## 자격 증명 유출

**도메인**, **서브도메인** 및 **이메일**로 해당 이메일에 속한 과거에 유출된 자격 증명을 찾을 수 있습니다:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **취약점 찾기**

유효한 유출된 자격 증명을 찾으면 매우 쉬운 승리입니다.

## 비밀 유출

자격 증명 유출은 **민감한 정보가 유출되고 판매된** 회사의 해킹과 관련이 있습니다. 그러나 회사는 **그 데이터베이스에 없는 정보**로 영향을 받을 수 있습니다.

### Github 유출

자격 증명 및 API는 **회사의 공개 저장소**나 해당 github 회사에서 일하는 **사용자**의 공개 저장소에 유출될 수 있습니다.\
**Leakos** 도구를 사용하여 **조직** 및 **개발자**의 모든 **공개 저장소**를 **다운로드**하고 자동으로 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 실행할 수 있습니다.

**Leakos**는 때로는 **웹 페이지에도 비밀이 포함**되어 있기 때문에 **URL을 전달**받은 **텍스트**에 대해 **gitleaks**를 다시 실행하는 데 사용할 수 있습니다.

#### Github Dorks

공격 중인 조직에서 검색할 수 있는 잠재적인 **github dorks**를 찾을 수 있는 이 **페이지**도 확인하십시오:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes 유출

가끔 공격자나 작업자가 **회사 콘텐츠를 붙여넣기 사이트에 게시**할 수 있습니다. 이는 **민감한 정보**를 포함할 수도 있고 그렇지 않을 수도 있지만 검색해 보는 것이 매우 흥미로울 수 있습니다.\
80개 이상의 붙여넣기 사이트에서 검색하는 데 사용할 수 있는 [**Pastos**](https://github.com/carlospolop/Pastos) 도구를 사용할 수 있습니다.

### Google Dorks

오래된 Google Dorks는 **노출되지 않아야 할 정보를 찾는 데 항상 유용**합니다. 유일한 문제는 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 가능한 쿼리가 포함되어 있어 수동으로 실행할 수 없다는 것입니다. 따라서 좋아하는 10개를 선택하거나 [**Gorks**](https://github.com/carlospolop/Gorks)와 같은 도구를 사용하여 모두 실행할 수 있습니다.

_일반 Google 브라우저를 사용하여 데이터베이스 전체를 실행하는 도구는 Google이 매우 빨리 차단할 것이므로 종료되지 않을 것입니다._

### **취약점 찾기**

유효한 유출된 자격 증명이나 API 토큰을 찾으면 매우 쉬운 승리입니다.

## 공개 코드 취약점

회사에 **오픈 소스 코드**가 있다면 해당 코드를 **분석**하고 그 안에 **취약점**을 찾을 수 있습니다.

**언어에 따라** 사용할 수 있는 다양한 **도구**가 있습니다:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

또한 다음과 같은 무료 서비스를 사용하여 **공개 저장소를 스캔**할 수 있습니다:

* [**Snyk**](https://app.snyk.io/)
## [**웹 펜테스팅 방법론**](../../network-services-pentesting/pentesting-web/)

**버그 헌터들이 발견한 취약점의 대다수**는 **웹 애플리케이션** 내에 존재하기 때문에, 이 시점에서 **웹 애플리케이션 테스트 방법론**에 대해 이야기하고 있습니다. [**이 정보를 여기에서 찾을 수 있습니다**](../../network-services-pentesting/pentesting-web/).

또한, [**웹 자동화 스캐너 오픈 소스 도구**](../../network-services-pentesting/pentesting-web/#automatic-scanners) 섹션에 특별히 언급하고 싶습니다. 이 도구들은 매우 민감한 취약점을 찾지는 못할지라도, **일부 초기 웹 정보를 얻기 위해 워크플로에 구현하는 데 유용**합니다.

## 요약

> 축하합니다! 이 시점에서 이미 **모든 기본 열거**를 수행했습니다. 네, 이것은 기본적인 것이며 (나중에 더 많은 트릭을 볼 것입니다).

따라서 이미 다음을 수행했습니다:

1. 범위 내의 **모든 회사**를 찾았습니다.
2. 회사에 속한 **모든 자산**을 찾았으며 (범위 내에 있다면 취약성 스캔 수행)
3. 회사에 속한 **모든 도메인**을 찾았습니다.
4. 도메인의 **모든 서브도메인**을 찾았습니다 (서브도메인 탈취가 있었나요?)
5. 범위 내의 **모든 IP** (CDN에서 **아닌 것** 포함)를 찾았습니다.
6. **웹 서버**를 모두 찾아 **스크린샷**을 찍었습니다 (더 깊게 살펴볼 가치 있는 이상한 것이 있나요?)
7. 회사에 속한 **모든 잠재적인 공개 클라우드 자산**을 찾았습니다.
8. **큰 승리를 쉽게 가져다 줄 수 있는** **이메일**, **자격 증명 누출**, **비밀 누출**을 찾았습니다.
9. 찾은 모든 웹을 **펜테스팅**했습니다.

## **전체 Recon 자동 도구**

주어진 범위에 대해 제안된 작업의 일부를 수행할 수 있는 여러 도구가 있습니다.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 조금 오래되었고 업데이트되지 않음

## **참고 자료**

* [**@Jhaddix**](https://twitter.com/Jhaddix)의 모든 무료 강좌, [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)와 같은 것들

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **저희가 채용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>제로부터 히어로가 되기까지의 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
