# Njia za Kupata Taarifa za Nje

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) **na** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repos za github.**

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Mshauri wa tuzo ya mdudu**: **jiandikishe** kwa **Intigriti**, jukwaa la tuzo za mdudu la malipo lililoanzishwa na wadukuzi, kwa wadukuzi! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Ugunduzi wa Mali

> Kwa hiyo umeelezwa kuwa kila kitu kinachomilikiwa na kampuni fulani kipo ndani ya wigo, na unataka kujua kampuni hii inamiliki nini kwa kweli.

Lengo la hatua hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu** na kisha kupata **mali** za kampuni hizi. Ili kufanya hivyo, tutafanya yafuatayo:

1. Tafuta ununuzi wa kampuni kuu, hii itatupa kampuni zilizo ndani ya wigo.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni, hii itatupa safu za IP zinazomilikiwa na kila kampuni.
3. Tumia utafutaji wa reverse whois kutafuta kuingia nyingine (majina ya shirika, kikoa...) yanayohusiana na ya kwanza (hii inaweza kufanywa kwa njia ya kurudia).
4. Tumia njia nyingine kama shodan `org` na `ssl`filters kutafuta mali nyingine (njia ya `ssl` inaweza kufanywa kwa njia ya kurudia).

### **Ununuzi**

Kwanza kabisa, tunahitaji kujua ni **kampuni gani nyingine zinamilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** kwa **kampuni kuu**, na **bonyeza** "**ununuzi**". Hapo utaona kampuni nyingine zilizonunuliwa na kampuni kuu.\
Chaguo lingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **ununuzi**.

> Sawa, kwa wakati huu unapaswa kujua kampuni zote zilizo ndani ya wigo. Hebu tujue jinsi ya kupata mali zao.

### **ASNs**

Nambari ya mfumo huru (**ASN**) ni **nambari ya kipekee** inayotolewa kwa **mfumo huru** (AS) na **Mamlaka ya Nambari za Mtandao wa Intaneti (IANA)**.\
**AS** inajumuisha **vifungu** vya **anwani za IP** ambazo zina sera maalum ya kupata mitandao ya nje na zinasimamiwa na shirika moja lakini inaweza kuwa na waendeshaji kadhaa.

Ni muhimu kujua ikiwa **kampuni imetengeneza ASN yoyote** ili kupata **safu za IP** zake. Itakuwa muhimu kufanya **jaribio la udhaifu** dhidi ya **watumishi** wote ndani ya **wigo** na kutafuta **vipelekaji** ndani ya IP hizo.\
Unaweza **kutafuta** kwa jina la kampuni, kwa **IP** au kwa **kikoa** kwenye [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Kulingana na eneo la kampuni, viungo hivi vinaweza kuwa na manufaa katika kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amerika Kaskazini),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Amerika ya Kusini),** [**RIPE NCC**](https://www.ripe.net) **(Ulaya). Hata hivyo, labda taarifa muhimu zote (safu za IP na Whois)** tayari zinaonekana kwenye kiungo cha kwanza.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, utambuzi wa subdomain wa [**BBOT**](https://github.com/blacklanternsecurity/bbot) hukusanya na kuhitimisha ASNs kiotomatiki mwishoni mwa uchunguzi.
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
Unaweza kupata safu za IP za shirika pia kwa kutumia [http://asnlookup.com/](http://asnlookup.com) (ina API ya bure). Unaweza kupata IP na ASN ya kikoa kwa kutumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta udhaifu**

Kwa wakati huu tunajua **mali zote ndani ya wigo**, kwa hivyo ikiwa unaruhusiwa unaweza kuzindua **skana ya udhaifu** (Nessus, OpenVAS) kwenye seva zote. Pia, unaweza kuzindua [**skana ya bandari**](../pentesting-network/#discovering-hosts-from-the-outside) **au kutumia huduma kama** shodan **kutafuta** bandari zilizofunguliwa **na kulingana na unachokipata unapaswa** angalia kitabu hiki jinsi ya kufanya pentest kwenye huduma kadhaa zinazowezekana zinazoendesha. Pia, inaweza kuwa na maana kutaja kwamba unaweza pia kuandaa orodha za **majina ya mtumiaji na nywila** na kujaribu **kuvunja nguvu huduma** na [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Vikoa

> Tunajua makampuni yote ndani ya wigo na mali zao, ni wakati wa kupata vikoa ndani ya wigo.

_Tafadhali, kumbuka kuwa katika mbinu zilizopendekezwa zifuatazo unaweza pia kupata vikoa vya pili na habari hiyo isipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **kikoa kikuu**(s) cha kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **DNS ya Nyuma**

Baada ya kupata safu zote za IP za vikoa unaweza kujaribu kufanya **utafutaji wa DNS ya nyuma** kwenye **IP hizo ili kupata vikoa zaidi ndani ya wigo**. Jaribu kutumia seva ya DNS ya mwathirika au seva maarufu ya DNS (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Ili hii ifanye kazi, msimamizi lazima aamrishe PTR kwa mkono.\
Unaweza pia kutumia chombo cha mtandaoni kwa habari hii: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (mzunguko)**

Ndani ya **whois** unaweza kupata habari nyingi za kuvutia kama jina la **shirika**, **anwani**, **barua pepe**, namba za simu... Lakini zaidi ya hayo, unaweza kupata **mali zaidi zinazohusiana na kampuni** ikiwa utafanya **utafutaji wa reverse whois kwa kutumia mojawapo ya hizo taarifa** (kwa mfano, usajili mwingine wa whois ambapo anwani ya barua pepe inaonekana).\
Unaweza kutumia zana za mtandaoni kama:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bure**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bure**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bure**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Bure** wavuti, sio API ya bure.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Sio bure
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Sio Bure (utafutaji **100 bure** tu)
* [https://www.domainiq.com/](https://www.domainiq.com) - Sio Bure

Unaweza kiotomatisha kazi hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji ufunguo wa API ya whoxy).\
Unaweza pia kufanya ugunduzi wa reverse whois kiotomatiki na [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Tambua kuwa unaweza kutumia mbinu hii kugundua majina zaidi ya kikoa kila wakati unapopata kikoa kipya.**

### **Trackers**

Ikiwa unapata **kitambulisho kimoja cha tracker kimoja** kwenye kurasa 2 tofauti, unaweza kudhani kuwa **kurasa zote** zinasimamiwa na timu moja.\
Kwa mfano, ikiwa unaona **kitambulisho kimoja cha Google Analytics** au **kitambulisho kimoja cha Adsense** kwenye kurasa kadhaa.

Kuna kurasa na zana ambazo zinakuwezesha kutafuta kwa kutumia trackers hizi na zingine:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Je, ulijua kwamba tunaweza kupata kikoa na subdomain zinazohusiana na lengo letu kwa kutafuta alama sawa ya favicon? Hii ndio hasa kile chombo cha [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) kilichotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2) kinachofanya. Hapa ni jinsi ya kutumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - gundua kikoa chenye alama sawa ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa ufupi, favihash itaturuhusu kugundua vikoa ambavyo vina alama sawa ya favicon kama lengo letu.

Zaidi ya hayo, unaweza pia kutafuta teknolojia kwa kutumia hash ya favicon kama ilivyoelezwa katika [**chapisho hili la blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hii inamaanisha kwamba ikiwa unajua **hash ya favicon ya toleo lenye udhaifu wa teknolojia ya wavuti**, unaweza kutafuta ikiwa ipo kwenye shodan na **kupata maeneo zaidi yenye udhaifu**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Hii ndiyo jinsi unavyoweza **kukadiria hash ya favicon** ya wavuti:
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
### **Hati ya Hakimiliki / Uniq string**

Tafuta ndani ya kurasa za wavuti **maneno ambayo yanaweza kushirikiwa kwenye tovuti tofauti ndani ya shirika moja**. Kamba ya **hati ya hakimiliki** inaweza kuwa mfano mzuri. Kisha tafuta kamba hiyo kwenye **google**, kwenye **vivinjari vingine** au hata kwenye **shodan**: `shodan search http.html:"Kamba ya Hati ya Hakimiliki"`

### **Wakati wa CRT**

Ni kawaida kuwa na kazi ya cron kama vile
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Kuwezesha upya vyeti vyote vya kikoa kwenye seva. Hii inamaanisha kwamba hata kama CA iliyotumiwa kwa hii haioni wakati ilizalishwa kwenye Muda wa Uhalali, ni **inawezekana kupata vikoa vinavyomilikiwa na kampuni hiyo hiyo katika kumbukumbu za usahihi wa vyeti**.\
Angalia [**makala hii kwa maelezo zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Kuchukua Udhibiti kwa Njia ya Kupita**

Inaonekana ni kawaida kwa watu kuweka subdomains kwa IP ambazo zinamilikiwa na watoa huduma wa wingu na wakati mwingine **kupoteza anwani ya IP lakini kusahau kuondoa rekodi ya DNS**. Kwa hivyo, tu **kuzindua VM** katika wingu (kama Digital Ocean) utakuwa **ukichukua udhibiti wa baadhi ya subdomain(s)**.

[**Makala hii**](https://kmsec.uk/blog/passive-takeover/) inaelezea hadithi kuhusu hilo na inapendekeza hati ambayo **inazindua VM katika DigitalOcean**, **inapata** IPv4 **ya mashine mpya**, na **inatafuta katika Virustotal kwa rekodi za subdomain** zinazoelekeza kwake.

### **Njia Nyingine**

**Tafadhali kumbuka kuwa unaweza kutumia mbinu hii ili kugundua majina zaidi ya kikoa kila wakati unapopata kikoa kipya.**

**Shodan**

Kwa kuwa tayari unajua jina la shirika linalomiliki nafasi ya IP. Unaweza kutafuta kwa data hiyo katika shodan kwa kutumia: `org:"Tesla, Inc."` Angalia watumishi uliopatikana kwa vikoa visivyotarajiwa katika cheti cha TLS.

Unaweza kupata **cheti cha TLS** cha ukurasa wa wavuti kuu, kupata **jina la Shirika** na kisha kutafuta jina hilo ndani ya **vyeti vya TLS** vya kurasa zote za wavuti zinazojulikana na **shodan** kwa kutumia kichujio: `ssl:"Tesla Motors"` au tumia chombo kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) ni chombo kinachotafuta **vikoa vinavyohusiana** na kikoa kikuu na **subdomains** zake, ni cha kushangaza sana.

### **Kutafuta Uvumbuzi**

Angalia kwa [kuchukua udhibiti wa kikoa](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Labda kuna kampuni ina **tumia kikoa fulani** lakini wame **poteza umiliki**. Jiandikishe tu (ikiwa ni rahisi) na ujulishe kampuni hiyo.

Ikiwa unapata **kikoa chenye IP tofauti** na zile ulizopata tayari katika ugunduzi wa mali, unapaswa kufanya uchunguzi wa msingi wa udhaifu (kwa kutumia Nessus au OpenVAS) na [**uchunguzi wa bandari**](../pentesting-network/#discovering-hosts-from-the-outside) na **nmap/masscan/shodan**. Kulingana na huduma zipi zinazotumika, unaweza kupata katika **kitabu hiki mbinu za "kuwashambulia"**.\
_Tafadhali kumbuka kuwa mara nyingine kikoa kinaandaliwa ndani ya IP ambayo haijachukuliwa na mteja, kwa hivyo sio sehemu ya wigo, kuwa mwangalifu._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Mshauri wa tuzo ya mdudu**: **Jisajili** kwa **Intigriti**, jukwaa la tuzo la mdudu la **kulipwa la juu lililoundwa na wadukuzi, kwa wadukuzi**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomains

> Tunajua kampuni zote zilizo ndani ya wigo, mali zote za kila kampuni na vikoa vyote vinavyohusiana na kampuni hizo.

Ni wakati wa kupata vikoa vyote vya chini vinavyowezekana kwa kila kikoa kilichopatikana.

### **DNS**

Hebu jaribu kupata **vikoa vya chini** kutoka kwa rekodi za **DNS**. Pia tunapaswa kujaribu **Uhamisho wa Eneo** (Ikiwa ni dhaifu, unapaswa kuripoti hilo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka ya kupata idadi kubwa ya subdomains ni kutafuta katika vyanzo vya nje. **Zana** zinazotumiwa sana ni zifuatazo (kwa matokeo bora, sanidi funguo za API):

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/sw-tz)
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
Kuna **zana/API nyingine za kuvutia** ambazo ingawa hazijaspecializwa moja kwa moja katika kupata subdomains zinaweza kuwa na manufaa katika kupata subdomains, kama vile:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Inatumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) kupata subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC API ya bure**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API ya bure
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
* [**gau**](https://github.com/lc/gau)**:** inapata URL zinazojulikana kutoka AlienVault's Open Threat Exchange, Wayback Machine, na Common Crawl kwa kikoa chochote kilichotolewa.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Wanachunguza wavuti kutafuta faili za JS na kuchambua vikoa vidogo kutoka hapo.
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
* [**Censys kugundua subdomain**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) ina API ya bure ya kutafuta subdomains na historia ya IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Mradi huu unatoa **bure subdomains zote zinazohusiana na programu za bug-bounty**. Unaweza kupata data hii pia kwa kutumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kupata wigo uliotumiwa na mradi huu [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **ulinganisho** wa zana nyingi za aina hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu jaribu kupata **subdomains** mpya kwa kufanya brute-force kwenye seva za DNS kwa kutumia majina ya subdomain yanayowezekana.

Kwa hatua hii utahitaji orodha za maneno ya kawaida ya subdomains kama vile:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IP za wapatanishi bora wa DNS. Ili kuunda orodha ya wapatanishi wa DNS wenye uaminifu unaweza kupakua wapatanishi kutoka [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

* [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza ambayo ilifanya DNS brute-force kwa ufanisi. Ni haraka sana ingawa inaweza kuwa na matokeo sahihi ya uwongo.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Hii nadhani inatumia resolver 1 tu
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni kifuniko kinachozunguka `massdns`, kilichoandikwa kwa lugha ya Go, kinachokuwezesha kutambua anwani za chini halali kwa kutumia nguvu ya kubashiri, pamoja na kutatua anwani za chini na kushughulikia alama za jokeri na msaada rahisi wa kuingiza na kutoa.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kufanya nguvu za lazima za majina ya kikoa kwa njia isiyofungamana.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Raundi ya Pili ya Kuvunja Nguvu ya DNS

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na kuvunja nguvu, unaweza kuzalisha mabadiliko ya subdomains yaliyopatikana ili kujaribu kupata zaidi. Zana kadhaa ni muhimu kwa lengo hili:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Ikitolewa kwa kikoa na subdomains, inazalisha mabadiliko.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Kwa kuzingatia kikoa na subdomains, tengeneza mchanganyiko.
* Unaweza kupata mchanganyiko wa goaltdns **wordlist** [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Kwa kuzingatia kikoa na subdomain, tengeneza mchanganyiko. Ikiwa hakuna faili ya mchanganyiko iliyotajwa, gotator itatumia yake mwenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Mbali na kuzalisha mabadiliko ya subdomains, pia inaweza kujaribu kuzitatua (lakini ni bora kutumia zana zilizotajwa hapo awali).
* Unaweza kupata orodha ya mabadiliko ya subdomains ya altdns **wordlist** [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya mabadiliko, mabadiliko na ubadilishaji wa subdomains. Zana hii itafanya jaribio la nguvu kwenye matokeo (haitoi msaada wa dns wild card).
* Unaweza kupata orodha ya maneno ya dmut permutations [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kwa kutumia kikoa, **inazalisha majina mapya ya subdomains** kulingana na mifano iliyotolewa ili kujaribu kupata subdomains zaidi.

#### Uzalishaji wa permutesheni za akili

* [**regulator**](https://github.com/cramppet/regulator): Kwa maelezo zaidi soma [**chapisho**](https://cramppet.github.io/regulator/index.html) hii lakini kimsingi itapata **sehemu kuu** kutoka kwa **subdomains zilizogunduliwa** na kuzichanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni zana ya kufanya jaribio la nguvu kwenye subdomain ambayo inatumia algorithmu rahisi lakini yenye ufanisi ya kujibu maelekezo ya DNS. Inatumia seti ya data iliyotolewa, kama orodha ya maneno iliyoboreshwa au rekodi za DNS/TLS za kihistoria, ili kuzalisha majina zaidi ya kikoa yanayohusiana na data hiyo na kuyapanua zaidi kwa kutumia maelezo yaliyokusanywa wakati wa uchunguzi wa DNS.
```
echo www | subzuf facebook.com
```
### **Mchakato wa Kugundua Subdomain**

Angalia chapisho hili la blogi nililoandika kuhusu jinsi ya **kutomatisha ugunduzi wa subdomain** kutoka kwa kikoa kwa kutumia **mchakato wa Trickest** ili nisiwe na haja ya kuzindua zana nyingi kwa mkono kwenye kompyuta yangu:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtual Hosts**

Ikiwa umepata anwani ya IP inayohusisha **ukurasa mmoja au zaidi** unaomilikiwa na subdomains, unaweza kujaribu **kupata subdomains nyingine na tovuti kwenye IP hiyo** kwa kutafuta katika vyanzo vya **OSINT** kwa kikoa kwenye IP au kwa **kuvunja nguvu majina ya kikoa ya VHost kwenye IP hiyo**.

#### OSINT

Unaweza kupata **VHosts kwenye IPs kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Kuvunja Nguvu**

Ikiwa una shaka kuwa kuna subdomain fulani inaweza kuwa imefichwa kwenye seva ya wavuti, unaweza kujaribu kuvunja nguvu:
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
Kwa njia hii, huenda ukaweza kupata ufikiaji wa ndani/maeneo yaliyofichwa.
{% endhint %}

### **CORS Brute Force**

Maranyingi utakutana na kurasa ambazo zinarudisha kichwa cha habari _**Access-Control-Allow-Origin**_ tu wakati kikoa/kidogo halali kimewekwa kwenye kichwa cha habari cha _**Origin**_. Katika hali hizi, unaweza kutumia tabia hii kwa **kugundua** kidogo **kipya**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Kuvunja Nguvu Kwa Mifuko**

Wakati unatafuta **subdomains**, angalia ikiwa inaonyesha aina yoyote ya **mifuko**, na katika kesi hiyo [**angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Pia, kwa kuwa kwa sasa utajua uwanja wote ndani ya wigo, jaribu [**kuvunja nguvu majina ya mifuko inayowezekana na angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/).

### **Ufuatiliaji**

Unaweza **kufuatilia** ikiwa **subdomains mpya** ya kikoa yameundwa kwa kufuatilia **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)inayofanya.

### **Kutafuta Udhaifu**

Angalia [**uchukuzi wa subdomain**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) unaowezekana.\
Ikiwa **subdomain** inaonyesha kwenye **mifuko ya S3**, [**angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/).

Ikiwa unapata **subdomain na anwani ya IP tofauti** na zile ulizopata tayari katika ugunduzi wa mali, unapaswa kufanya **uchunguzi wa msingi wa udhaifu** (kwa kutumia Nessus au OpenVAS) na [**uchunguzi wa bandari**](../pentesting-network/#discovering-hosts-from-the-outside) na **nmap/masscan/shodan**. Kulingana na huduma zipi zinazotumika, unaweza kupata katika **kitabu hiki mbinu za "kuwashambulia"**.\
_Tafadhali kumbuka kuwa mara nyingine subdomain inahifadhiwa ndani ya anwani ya IP ambayo haijachukuliwa na mteja, kwa hivyo haiko katika wigo, kuwa mwangalifu._

## Anwani za IP

Katika hatua za awali unaweza kuwa umepata **aina fulani za anwani za IP, vikoa na subdomains**.\
Ni wakati wa **kukusanya tena anwani za IP kutoka kwa hizo anuwani** na kwa **vikoa/subdomains (kutafuta DNS).**

Kwa kutumia huduma kutoka kwa **apis za bure** zifuatazo, unaweza pia kupata **anwani za IP zilizotumiwa hapo awali na vikoa na subdomains**. Anwani hizi za IP bado zinaweza kuwa mali ya mteja (na inaweza kukuruhusu kupata [**njia za kuzunguka CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia vikoa vinavyoelekeza kwenye anwani ya IP maalum kwa kutumia zana [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Kutafuta Udhaifu**

**Chunguza bandari zote za IP ambazo sio za CDNs** (kwa kuwa kuna uwezekano mkubwa hautapata kitu cha kuvutia hapo). Katika huduma zinazotumika ulizogundua, unaweza **kupata udhaifu**.

**Pata** [**mwongozo**](../pentesting-network/) **kuhusu jinsi ya kuchunguza wenyewe.**

## Uwindaji wa Seva za Wavuti

> Tumepata kampuni zote na mali zao na tunajua anwani za IP, vikoa na subdomains ndani ya wigo. Ni wakati wa kutafuta seva za wavuti.

Katika hatua za awali, labda tayari umefanya **uchunguzi wa anwani za IP na vikoa ulivyogundua**, kwa hivyo labda tayari umepata **seva zote za wavuti zinazowezekana**. Walakini, ikiwa haujafanya hivyo, sasa tutatazama **mbinu za haraka za kutafuta seva za wavuti** ndani ya wigo.

Tafadhali, kumbuka kuwa hii itakuwa **imeelekezwa kwa ugunduzi wa programu za wavuti**, kwa hivyo unapaswa **kufanya uchunguzi wa udhaifu** na **uchunguzi wa bandari** pia (**ikiwa inaruhusiwa** na wigo).

**Njia ya haraka** ya kugundua **bandari zilizofunguliwa** zinazohusiana na **seva za wavuti** kwa kutumia [**masscan inaweza kupatikana hapa**](../pentesting-network/#http-port-discovery).\
Zana nyingine rafiki ya kutafuta seva za wavuti ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unapitisha orodha ya vikoa na itajaribu kuunganisha kwenye bandari 80 (http) na 443 (https). Kwa kuongezea, unaweza kuonyesha kujaribu bandari zingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Picha za Skrini**

Sasa baada ya kugundua **seva zote za wavuti** zilizopo katika wigo (kati ya **IPs** za kampuni na **domaini** na **subdomaini** zote), labda **hujui wapi kuanza**. Basi, hebu tufanye iwe rahisi na tuanze kwa kuchukua picha za skrini za zote. Kwa tu **kutazama** ukurasa **mkuu** unaweza kupata **sehemu za ajabu** ambazo zina uwezekano mkubwa wa kuwa **hatarini**.

Kutekeleza wazo lililopendekezwa unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuendesha juu ya **picha za skrini** zote ili kukwambia **nini kinaweza kuwa na udhaifu**, na nini sio.

## Mali za Wingu za Umma

Ili kupata mali za wingu zinazomilikiwa na kampuni, unapaswa **kuanza na orodha ya maneno yanayotambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya sarafu ya sarafu unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<jina_la_kikoa>", <"majina_ya_subdomain">`.

Pia utahitaji orodha ya maneno ya **kawaida yanayotumiwa katika vikapu**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa maneno hayo unapaswa kuzalisha **permutations** (angalia [**Raundi ya Pili ya Brute-Force ya DNS**](./#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa orodha ya maneno iliyopatikana unaweza kutumia zana kama [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kuwa unapotafuta Mali za Wingu unapaswa **kutafuta zaidi ya vikapu tu katika AWS**.

### **Kutafuta udhaifu**

Ikiwa unapata vitu kama **vikapu wazi au kazi za wingu zilizofichuliwa**, unapaswa **kuzifikia** na jaribu kuona wanakupa nini na ikiwa unaweza kuzitumia vibaya.

## Barua pepe

Ukiwa na **domaini** na **subdomaini** ndani ya wigo, kimsingi una kila kitu unachohitaji kuanza kutafuta barua pepe. Hizi ni **API** na **zana** ambazo zimefanya kazi vizuri kwangu kupata barua pepe ya kampuni:

* [**theHarvester**](https://github.com/laramies/theHarvester) - na APIs
* API ya [**https://hunter.io/**](https://hunter.io/) (toleo la bure)
* API ya [**https://app.snov.io/**](https://app.snov.io/) (toleo la bure)
* API ya [**https://minelead.io/**](https://minelead.io/) (toleo la bure)

### **Kutafuta udhaifu**

Barua pepe zitakuwa muhimu baadaye kwa **brute-force wa kuingia kwenye wavuti na huduma za uthibitishaji** (kama vile SSH). Pia, zinahitajika kwa **phishing**. Zaidi ya hayo, APIs hizi zitakupa habari zaidi juu ya **mtu nyuma ya barua pepe**, ambayo ni muhimu kwa kampeni ya phishing.

## Kutiririka kwa Vitambulisho

Ukiwa na **domaini**, **subdomaini**, na **barua pepe** unaweza kuanza kutafuta vitambulisho vilivyovuja hapo awali vinavyomilikiwa na barua pepe hizo:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta udhaifu**

Ikiwa unapata vitambulisho vilivyovuja **vilivyothibitishwa**, hii ni ushindi rahisi sana.

## Kutiririka kwa Siri

Kuvuja kwa vitambulisho kunahusiana na kuvunjika kwa kampuni ambapo **habari nyeti ilivuja na kuuzwa**. Walakini, kampuni zinaweza kuathiriwa na **uvujaji mwingine** ambao habari yake haipo kwenye hizo database:

### Kutiririka kwa Github

Vitambulisho na APIs zinaweza kuvuja katika **hifadhidata za umma** za **kampuni** au za **watumiaji** wanaofanya kazi kwa kampuni hiyo ya github.\
Unaweza kutumia **zana** [**Leakos**](https://github.com/carlospolop/Leakos) kwa **kupakua** **hifadhidata za umma** za **shirika** na wa **watengenezaji** wake na kukimbia [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yao kiotomatiki.

**Leakos** inaweza pia kutumika kukimbia **gitleaks** kwenye **maandishi** yote yaliyotolewa **URL zilizopitishwa** kwake kwani mara nyingi **kurasa za wavuti pia zina siri**.

#### Github Dorks

Angalia pia **ukurasa** huu kwa **github dorks** za uwezekano ambazo unaweza pia kutafuta katika shirika unaloshambulia:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Kutiririka kwa Paste

Wakati mwingine wadukuzi au wafanyakazi tu wataweza **kuchapisha yaliyomo ya kampuni kwenye tovuti ya paste**. Hii inaweza au isiyoweza kuwa na **habari nyeti**, lakini ni ya kuvutia sana kutafuta.\
Unaweza kutumia zana [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta katika zaidi ya tovuti 80 za paste kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini nzuri zinafaa siku zote kupata **habari zilizofichuliwa ambazo hazipaswi kuwepo**. Shida pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu kadhaa ya maswali yanayowezekana ambayo huwezi kukimbia kwa mikono. Kwa hivyo, unaweza kupata 10 yako pendwa au unaweza kutumia **zana kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuzikimbia zote**.

_Tafadhali kumbuka kuwa zana ambazo zinatarajia kukimbia hifadhidata nzima kwa kutumia kivinjari cha Kawaida cha Google hazitamalizika kamwe kwani Google itakuzuia haraka sana._

### **Kutafuta udhaifu**

Ikiwa unapata **vitambulisho vilivyovuja** vilivyothibitishwa au alama za API, hii ni ushindi rahisi sana.

## Udhaifu wa Kanuni ya Umma

Ikiwa umegundua kuwa kampuni ina **kanuni ya chanzo wazi**, unaweza **kuianaliza** na kutafuta **udhaifu** ndani yake.

**Kulingana na lugha** kuna zana tofauti unazoweza kutumia:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Pia kuna huduma za bure ambazo zinakuwezesha **kuchunguza hifadhidata za umma**, kama vile:

* [**Snyk**](https://app.snyk.io/)
## [**Utaratibu wa Pentesting wa Wavuti**](../../network-services-pentesting/pentesting-web/)

**Wengi wa udhaifu** uliopatikana na wawindaji wa kasoro uko ndani ya **programu za wavuti**, kwa hivyo kwa wakati huu ningependa kuzungumzia **utaratibu wa kupima programu za wavuti**, na unaweza [**kupata habari hii hapa**](../../network-services-pentesting/pentesting-web/).

Ningependa pia kutoa maelezo maalum kwa sehemu [**Zana za chanzo wazi za Skana za Wavuti za Kiotomatiki**](../../network-services-pentesting/pentesting-web/#automatic-scanners), kwani, ingawa hutegemei kupata udhaifu unaohusiana na usalama sana, zinakuja kwa manufaa katika **mchakato wa kupata habari ya awali kuhusu wavuti.**

## Kurudia

> Hongera! Kwa wakati huu tayari umefanya **uchunguzi wa msingi wote**. Ndiyo, ni msingi kwa sababu unaweza kufanya uchunguzi zaidi (tutaona mbinu zaidi baadaye).

Kwa hivyo tayari umefanya yafuatayo:

1. Kupata **kampuni zote** zilizo ndani ya wigo
2. Kupata **mali zote** zinazomilikiwa na kampuni (na kufanya uchunguzi wa udhaifu ikiwa ni sehemu ya wigo)
3. Kupata **kikoa zote** zinazomilikiwa na kampuni
4. Kupata **kikoa ndogo zote** za kikoa (kuna kuchukua kikoa chochote?)
5. Kupata **IP zote** (kutoka na **sio kutoka kwa CDNs**) ndani ya wigo.
6. Kupata **seva za wavuti** zote na kuchukua **picha skrini** yao (kuna kitu kisicho cha kawaida kinachostahili kuangaliwa kwa undani?)
7. Kupata **mali zote za wingu la umma** zinazomilikiwa na kampuni.
8. **Barua pepe**, **vuja vya vibali**, na **vuja vya siri** ambavyo vinaweza kukupa **ushindi mkubwa kwa urahisi**.
9. **Kupima usalama wa wavuti zote ulizopata**

## **Zana za Uchunguzi wa Kiotomatiki Kamili**

Kuna zana kadhaa huko nje ambazo zitafanya sehemu ya hatua zilizopendekezwa dhidi ya wigo uliopewa.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Kidogo cha zamani na hakijasasishwa

## **Marejeo**

* Kozi zote za bure za [**@Jhaddix**](https://twitter.com/Jhaddix) kama [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Ncha ya bug bounty**: **Jisajili** kwa **Intigriti**, jukwaa la bug bounty la malipo ya juu lililoanzishwa na wawindaji wa kasoro, kwa wawindaji wa kasoro! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata zawadi hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
