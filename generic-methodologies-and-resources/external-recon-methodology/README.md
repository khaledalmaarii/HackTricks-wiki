# Mbinu ya Uchunguzi wa Nje

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ikiwa una nia ya **kazi ya udukuzi** na kudukua yasiyodukuzika - **tunakupa kazi!** (_inahitajika uwezo wa kuandika na kuzungumza Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

## Ugunduzi wa Mali

> Kwa hivyo uliambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kipo ndani ya wigo, na unataka kugundua kile kampuni hii kwa kweli inamiliki.

Lengo la hatua hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu** na kisha mali zote za **kampuni hizi**. Ili kufanya hivyo, tutafanya yafuatayo:

1. Tafuta ununuzi wa kampuni kuu, hii itatupa kampuni zilizo ndani ya wigo.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni, hii itatupa safu za IP zinazomilikiwa na kila kampuni.
3. Tumia utafutaji wa whois uliorejea nyuma kutafuta viingilio vingine (majina ya shirika, uwanja...) unayohusiana na la kwanza (hii inaweza kufanywa kwa njia ya kurudia).
4. Tumia mbinu nyingine kama shodan `org`na `ssl`filters kutafuta mali zingine (mbinu ya `ssl` inaweza kufanywa kwa njia ya kurudia).

### **Ununuzi**

Kwanza kabisa, tunahitaji kujua ni **kampuni gani zingine zinamilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** **kampuni kuu**, na **bonyeza** "**ununuzi**". Huko utaona kampuni zingine zilizonunuliwa na ile kuu.\
Chaguo lingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **ununuzi**.

> Sawa, kufikia hatua hii unapaswa kujua kampuni zote zilizo ndani ya wigo. Hebu tujaribu kugundua jinsi ya kupata mali zao.

### **ASNs**

Namba ya mfumo huru (**ASN**) ni **namba ya kipekee** inayotolewa kwa **mfumo huru** (AS) na **Mamlaka ya Namba za Mtandao (IANA)**.\
**AS** inajumuisha **vifungu** vya **anwani za IP** ambazo zina sera iliyowekwa wazi kwa kupata mitandao ya nje na inasimamiwa na shirika moja lakini inaweza kuundwa na waendeshaji kadhaa.

Ni muhimu kujua ikiwa **kampuni imetengewa ASN yoyote** ili kupata **safu zake za IP**. Itakuwa muhimu kufanya **jaribio la udhaifu** dhidi ya **mashine zote** ndani ya **wigo** na **kutafuta uwanja** ndani ya IP hizi.\
Unaweza **kutafuta** kwa jina la kampuni, kwa **IP** au kwa **uwanja** kwenye [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Kulingana na eneo la kampuni viungo hivi vinaweza kuwa vya manufaa kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amerika Kaskazini),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Amerika ya Kusini),** [**RIPE NCC**](https://www.ripe.net) **(Ulaya). Hata hivyo, labda taarifa zote muhimu (safu za IP na Whois)** tayari zinaonekana kwenye kiungo cha kwanza.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, uchambuzi wa subdomain wa [**BBOT**](https://github.com/blacklanternsecurity/bbot) hukusanya na kufupisha ASNs mwishoni mwa uchunguzi.
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
Unaweza kupata safu za IP za shirika pia kwa kutumia [http://asnlookup.com/](http://asnlookup.com) (ina API ya bure).\
Unaweza kupata IP na ASN ya kikoa kwa kutumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta Udhaifu**

Kufikia hatua hii tunajua **mali zote ndani ya eneo la kuzingatia**, hivyo ikiwa unaruhusiwa unaweza kuzindua baadhi ya **skana za udhaifu** (Nessus, OpenVAS) kwenye mwenyeji wote.\
Pia, unaweza kuzindua baadhi ya [**skani za bandari**](../pentesting-network/#discovering-hosts-from-the-outside) **au kutumia huduma kama** shodan **kupata** bandari zilizofunguliwa **na kulingana na unachopata unapaswa** kutazama kitabu hiki jinsi ya kupima uwezekano wa huduma kadhaa zinazoendeshwa.\
**Pia, Inaweza kuwa na maana kutaja kwamba unaweza pia kuandaa baadhi ya** majina ya mtumiaji ya msingi **na** orodha za nywila **na kujaribu** kuvunja nguvu huduma na [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Viko

> Tunajua makampuni yote ndani ya eneo la kuzingatia na mali zao, ni wakati wa kupata viko ndani ya eneo la kuzingatia.

_Tafadhali, elewa kwamba katika mbinu zilizopendekezwa zifuatazo unaweza pia kupata viko vya pili na habari hiyo isipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **viko vikuu** vya kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **DNS ya Nyuma**

Baada ya kupata safu zote za IP za viko unaweza kujaribu kufanya **utafutaji wa DNS ya nyuma** kwenye **IP hizo ili kupata viko zaidi ndani ya eneo la kuzingatia**. Jaribu kutumia seva fulani ya dns ya mwathiriwa au seva ya dns inayojulikana (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Kwa hili kufanya kazi, msimamizi lazima awezeshe PTR kwa mkono.\
Unaweza pia kutumia chombo mtandaoni kwa habari hii: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (mzunguko)**

Ndani ya **whois** unaweza kupata habari nyingi za kuvutia kama **jina la shirika**, **anwani**, **barua pepe**, namba za simu... Lakini jambo linalovutia zaidi ni kwamba unaweza kupata **mali zaidi zinazohusiana na kampuni** ikiwa utafanya **utafutaji wa reverse whois kwa kutumia mojawapo ya hizo taarifa** (kwa mfano, rekodi nyingine za whois ambapo anwani ya barua pepe inaonekana).\
Unaweza kutumia zana mtandaoni kama:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bure**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bure**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bure**
* [https://www.whoxy.com/](https://www.whoxy.com) - Tovuti **Bure**, sio API bure.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Sio bure
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Sio Bure (tafuta **100 bure** tu)
* [https://www.domainiq.com/](https://www.domainiq.com) - Sio Bure

Unaweza kiotomatiki kazi hii kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji ufunguo wa API ya whoxy).\
Unaweza pia kufanya ugunduzi wa reverse whois kiotomatiki na [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Tambua kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya kikoa kila wakati unapopata kikoa kipya.**

### **Trackers**

Ukiona **kitambulisho kimoja cha kufuatilia** cha kufuatilia kimoja kwenye kurasa 2 tofauti unaweza kudhani kwamba **kurasa zote** zinasimamiwa na timu ile ile.\
Kwa mfano, ikiwa unaona **kitambulisho kimoja cha Google Analytics** au **kitambulisho kimoja cha Adsense** kwenye kurasa kadhaa.

Kuna kurasa na zana zinazoruhusu utafutaji kwa kutumia hizi trackers na zaidi:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Je! Ulijua kwamba tunaweza kupata vikoa vinavyohusiana na lengo letu kwa kutafuta hash sawa ya picha ya favicon? Hii ndio hasa kile [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) zana iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2) inafanya. Hivi ndivyo unavyoweza kutumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - pata uwanja wenye alama sawa ya favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa maneno rahisi, favihash itaturuhusu kupata uwanja ambao una alama sawa ya favicon icon hash kama lengo letu.

Zaidi ya hayo, unaweza pia kutafuta teknolojia kwa kutumia favicon hash kama ilivyoelezwa katika [**chapisho hili la blogi**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hii inamaanisha kwamba ukijua **hash ya favicon ya toleo lenye kasoro la teknolojia ya wavuti** unaweza kutafuta kama ipo kwenye shodan na **kupata maeneo zaidi yenye kasoro**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Hii ndio jinsi unavyoweza **kukadiria hash ya favicon** ya wavuti:
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
### **Haki miliki / String ya kipekee**

Tafuta ndani ya kurasa za wavuti **maneno ambayo yanaweza kushirikishwa kote kwenye wavuti tofauti ndani ya shirika moja**. **String ya haki miliki** inaweza kuwa mfano mzuri. Kisha tafuta string hiyo kwenye **google**, kwenye **vibonyezo vingine** au hata kwenye **shodan**: `shodan search http.html:"String ya haki miliki"`

### **Muda wa CRT**

Ni kawaida kuwa na kazi ya cron kama vile
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### Kufanya upya vyeti vyote vya kikoa kwenye seva. Hii inamaanisha hata kama CA iliyotumiwa kwa hili haioni wakati ilizalishwa katika Muda wa Kuthibitisha, ni **inawezekana kupata vikoa vinavyomilikiwa na kampuni ileile katika magogo ya uwazi ya cheti**.\
Angalia hii [**makala kwa maelezo zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Taarifa za DMARC za Barua pepe

Unaweza kutumia wavuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au chombo kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) kupata **vikoa na subdomain zinazoshiriki taarifa sawa za dmarc**.

### **Kuchukua Udhibiti kwa Njia ya Kupita**

Inaonekana ni kawaida kwa watu kuweka subdomains kwa IPs zinazomilikiwa na watoa huduma wa wingu na wakati mwingine **kupoteza anwani hiyo ya IP lakini kusahau kuondoa rekodi ya DNS**. Kwa hiyo, tu **kuzindua VM** katika wingu (kama Digital Ocean) utakuwa **ukichukua udhibiti wa baadhi ya subdomains**.

[**Makala hii**](https://kmsec.uk/blog/passive-takeover/) inaelezea hadithi kuhusu hilo na kupendekeza script ambayo **inazindua VM katika DigitalOcean**, **inapata** anwani ya **IPv4** ya mashine mpya, na **kutafuta kwenye Virustotal rekodi za subdomain** zinazoashiria hiyo.

### **Njia Nyingine**

**Tambua kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya kikoa kila unapopata kikoa kipya.**

**Shodan**

Kwa kuwa tayari unajua jina la shirika linalomiliki nafasi ya IP. Unaweza kutafuta kwa data hiyo kwenye shodan ukitumia: `org:"Tesla, Inc."` Angalia mwenyeji waliopatikana kwa vikoa visivyotarajiwa vipya kwenye cheti cha TLS.

Unaweza kupata **cheti cha TLS** cha ukurasa wa wavuti kuu, kupata **jina la Shirika** na kisha kutafuta jina hilo ndani ya **vyeti vya TLS** vya kurasa zote zinazojulikana na **shodan** kwa kutumia kichujio: `ssl:"Tesla Motors"` au tumia chombo kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ni chombo kinachotafuta **vikoa vinavyohusiana** na kikoa kuu na **subdomains** zao, ni nzuri sana.

### **Kutafuta Udhaifu**

Angalia kwa [uchukuzi wa kikoa](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Labda kuna kampuni ina **tumia kikoa fulani** lakini wame **poteza umiliki**. Jiandikishe tu (ikiwa ni rahisi) na ujulishe kampuni.

Ikiwa unapata **kikoa na IP tofauti** na zile ulizopata tayari katika ugunduzi wa mali, unapaswa kufanya uchunguzi wa **msingi wa udhaifu** (ukitumia Nessus au OpenVAS) na [uchunguzi wa **bandari**](../pentesting-network/#discovering-hosts-from-the-outside) na **nmap/masscan/shodan**. Kulingana na huduma zipi zinazoendeshwa unaweza kupata katika **kitabu hiki mbinu za "kuishambulia"**.\
_Tambua kwamba mara nyingine kikoa kinaandaliwa ndani ya IP ambayo haikudhibitiwa na mteja, kwa hivyo sio sehemu ya kazi, kuwa mwangalifu._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Siri ya tuzo ya mdudu**: **jiandikishe** kwa **Intigriti**, jukwaa la **tuzo za mdudu za malipo lililoundwa na wadukuzi, kwa wadukuzi**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomains

> Tunajua makampuni yote ndani ya wigo, mali zote za kila kampuni na vikoa vyote vinavyohusiana na makampuni.

Ni wakati wa kupata subdomains zote zinazowezekana za kila kikoa kilichopatikana.

{% hint style="success" %}
Tambua kwamba baadhi ya zana na mbinu za kupata vikoa zinaweza pia kusaidia kupata subdomains!
{% endhint %}

### **DNS**

Hebu jaribu kupata **subdomains** kutoka kwa rekodi za **DNS**. Pia tunapaswa kujaribu kwa **Uhamisho wa Eneo** (Ikiwa ina kasoro, unapaswa kuripoti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka ya kupata idadi kubwa ya subdomains ni kutafuta katika vyanzo vya nje. **Zana** zinazotumiwa sana ni zifuatazo (kwa matokeo bora configure funguo za API):

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
Kuna **zana/API nyingine za kuvutia** ambazo hata kama hazijataalamika moja kwa moja katika kupata subdomains zinaweza kuwa na manufaa katika kupata subdomains, kama:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Hutumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) kupata subdomains
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
* [**gau**](https://github.com/lc/gau)**:** inapata URL zinazojulikana kutoka kwa AlienVault's Open Threat Exchange, Wayback Machine, na Common Crawl kwa kikoa chochote kilichotolewa.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Wanachimba mtandao kutafuta faili za JS na kuchambua subdomains kutoka hapo.
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
* [**Censys kugundua kikoa cha pili**](https://github.com/christophetd/censys-subdomain-finder)
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

Unaweza kupata **ulinganifu** wa zana nyingi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu jaribu kupata **subdomains** mpya kwa kufanya nguvu ya DNS kwa kutumia majina ya subdomains yanayowezekana.

Kwa hatua hii utahitaji **orodha za maneno ya kawaida ya subdomains kama**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IPs za wapangishaji bora wa DNS. Ili kuzalisha orodha ya wapangishaji wa DNS walioaminika unaweza kupakua wapangishaji kutoka [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzifuta. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zilizopendekezwa zaidi kwa nguvu ya DNS ni:

* [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza iliyofanya nguvu ya DNS kwa ufanisi. Ni haraka sana hata hivyo inaweza kuwa na matokeo sahihi ya uwongo.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Hii nadhani inatumia 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni kifuniko cha `massdns`, kilichoandikwa kwa lugha ya go, kinachokuwezesha kutambua anwani sahihi za subdomains kwa kutumia nguvu ya bruteforce, pamoja na kutatua subdomains na usindikaji rahisi wa pembejeo-na-pato.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kuvamia majina ya uwanja kwa njia isiyo ya moja kwa moja.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Raundi ya Pili ya Kudukua DNS kwa Nguvu

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na kudukua kwa nguvu, unaweza kuzalisha mabadiliko ya subdomains zilizopatikana kujaribu kupata zaidi. Zana kadhaa ni muhimu kwa lengo hili:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Ikitolewa kwa vikoa na subdomains, huzalisha mabadiliko.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Kutoa upeo wa uwanja na subdomains kuzalisha mabadiliko.
* Unaweza kupata mabadiliko ya goaltdns **wordlist** [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Kutoa uwanja na subdomains kuzalisha mchanganyiko. Ikiwa hakuna faili ya mchanganyiko inaonyeshwa gotator itatumia yake mwenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Mbali na kuzalisha mabadiliko ya subdomains, inaweza pia kujaribu kuzitatua (ingawa ni bora kutumia zana zilizotajwa hapo awali).
* Unaweza kupata orodha ya maneno ya mabadiliko ya altdns **hapa** (https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya mabadiliko, mabadiliko na ubadilishaji wa subdomains. Zana hii itafanya nguvu ya matokeo (haitoi msaada wa dns wild card).
* Unaweza kupata orodha ya maneno ya dmut permutations [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kulingana na kikoa, **inazalisha majina mapya ya subdomains** kulingana na mifano iliyotajwa kujaribu kugundua subdomains zaidi.

#### Uzalishaji wa permutasi za akili

* [**regulator**](https://github.com/cramppet/regulator): Kwa habari zaidi soma hii [**chapisho**](https://cramppet.github.io/regulator/index.html) lakini kimsingi itapata **sehemu kuu** kutoka kwa **subdomains zilizogunduliwa** na kuzichanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer inayohusishwa na algorithm ya DNS ya kujibu kwa urahisi lakini yenye ufanisi mkubwa. Inatumia seti iliyotolewa ya data ya kuingiza, kama orodha iliyoboreshwa ya maneno au rekodi za DNS/TLS za kihistoria, kusintezesha majina zaidi ya kikoa yanayohusiana na kupanua zaidi katika mzunguko kulingana na habari iliyokusanywa wakati wa uchunguzi wa DNS.
```
echo www | subzuf facebook.com
```
### **Mchakato wa Kugundua Subdomain**

Angalia chapisho hili la blogi nililoandika kuhusu jinsi ya **kutuza kugundua subdomain** kutoka kwa kikoa kwa kutumia **Mchakato wa Trickest** ili nisiitaji kuzindua zana nyingi kwa mkono kwenye kompyuta yangu:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Wenyeji Bandia**

Ikiwa umepata anwani ya IP inayoitwa **ukurasa mmoja au kadhaa** unaomilikiwa na subdomains, unaweza kujaribu **kupata subdomains nyingine zenye kurasa kwenye IP hiyo** kwa kutafuta kwenye **vyanzo vya OSINT** kwa mifumo ya kikoa kwenye IP au kwa **kufanya nguvu ya kutafuta majina ya kikoa ya VHost kwenye IP hiyo**.

#### OSINT

Unaweza kupata **VHosts kwenye IPs kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Nguvu ya Kutafuta**

Ikiwa una shaka kwamba baadhi ya subdomains zinaweza kuwa zimefichwa kwenye seva ya wavuti unaweza kujaribu kuzitafuta kwa nguvu:
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
Kwa kutumia mbinu hii, unaweza hata kupata ufikiaji wa vituo vya ndani/vilivyofichwa.
{% endhint %}

### **CORS Brute Force**

Wakati mwingine utakutana na kurasa ambazo hurudisha kichwa cha _**Access-Control-Allow-Origin**_ pekee wakati kikoa/kidogo halali kimewekwa kwenye kichwa cha _**Origin**_. Katika hali hizi, unaweza kutumia tabia hii kugundua **kidogo mpya**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Kuforce Brute ya Buckets**

Wakati unatafuta **subdomains** angalia kuona kama inaelekeza kwa aina yoyote ya **bucket**, na katika kesi hiyo [**angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Pia, kwa wakati huu utajua uwanja wote ndani ya eneo, jaribu [**kuforce majina ya bucket yanayowezekana na angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/).

### **Ufuatiliaji**

Unaweza **kufuatilia** ikiwa **subdomains mpya** ya uwanja unatengenezwa kwa kufuatilia **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)inavyofanya.

### **Kutafuta mapungufu**

Angalia kwa [**uchukuzi wa subdomain**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) unaowezekana.\
Ikiwa **subdomain** inaelekeza kwa **bucket ya S3**, [**angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/).

Ikiwa unapata **subdomain na anwani ya IP tofauti** na zile ulizopata tayari katika ugunduzi wa mali, unapaswa kufanya **uchunguzi wa msingi wa mapungufu** (ukitumia Nessus au OpenVAS) na [**uchunguzi wa bandari**](../pentesting-network/#discovering-hosts-from-the-outside) na **nmap/masscan/shodan**. Kulingana na huduma zipi zinazoendeshwa unaweza kupata katika **kitabu hiki mbinu za "kuishambulia"**.\
_Tahadhari kwamba mara kwa mara subdomain inahifadhiwa ndani ya anwani ya IP ambayo haikudhibitiwa na mteja, kwa hivyo sio sehemu ya eneo, kuwa mwangalifu._

## Anwani za IP

Katika hatua za awali unaweza kuwa umepata **aina fulani za anwani za IP, uwanja na subdomains**.\
Ni wakati wa **kukusanya upya anwani zote za IP kutoka kwa hizo anwani** na kwa **uwanja/subdomains (mipangilio ya DNS).**

Kwa kutumia huduma kutoka kwa **apis za bure** zifuatazo unaweza pia kupata **anwani za IP zilizotumiwa hapo awali na uwanja na subdomains**. Anwani hizi za IP zinaweza bado kuwa mali ya mteja (na inaweza kukuruhusu kupata [**njia za kuzunguka CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia uwanja unaoelekeza kwa anwani fulani ya IP kwa kutumia zana [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Kutafuta mapungufu**

**Chunguza bandari zote za IP ambazo sio sehemu ya CDNs** (kwa sababu kwa uwezekano mkubwa hautapata kitu cha kuvutia hapo). Katika huduma zinazoendeshwa zilizogunduliwa unaweza **kupata mapungufu**.

**Pata** [**mwongozo**](../pentesting-network/) **kuhusu jinsi ya kuchunguza wenyeji.**

## Uwindaji wa seva za Wavuti

> Tumeona makampuni yote na mali zao na tunajua anwani za IP, uwanja na subdomains ndani ya eneo. Ni wakati wa kutafuta seva za wavuti.

Katika hatua za awali labda tayari umefanya **uchunguzi wa IPs na uwanja uliogunduliwa**, kwa hivyo unaweza kuwa tayari umepata **seva zote za wavuti zinazowezekana**. Walakini, ikiwa hujafanya hivyo sasa tutatazama baadhi ya **mbinu za haraka za kutafuta seva za wavuti** ndani ya eneo.

Tafadhali, kumbuka kuwa hii itakuwa **ililenga ugunduzi wa programu za wavuti**, kwa hivyo unapaswa **kufanya uchunguzi wa mapungufu** na **uchunguzi wa bandari** pia (**ikiwa kuruhusiwa** na eneo).

**Mbinu ya haraka** ya kugundua **bandari zilizofunguliwa** zinazohusiana na **seva za wavuti** kwa kutumia [**masscan inaweza kupatikana hapa**](../pentesting-network/#http-port-discovery).\
Zana nyingine rafiki ya kutafuta seva za wavuti ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unapitisha orodha ya uwanja na itajaribu kuunganisha kwenye bandari 80 (http) na 443 (https). Kwa kuongezea, unaweza kuonyesha kujaribu bandari zingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Picha za Skrini**

Sasa baada ya kugundua **seva zote za wavuti** zilizopo katika eneo la tafiti (miongoni mwa **IPs** za kampuni na **mamia** yote na **subdomains**) labda **hujui pa kuanza**. Kwa hivyo, hebu tuifanye iwe rahisi na tuanze kwa kuchukua picha za skrini za zote. Kwa tu **kutazama** ukurasa **wa kwanza** unaweza kupata **malengo** ya ajabu ambayo ni zaidi **ya kuwa hatarini**.

Ili kutekeleza wazo lililopendekezwa unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kukimbia juu ya **picha za skrini** zote kukwambia **ni nini kinachoweza kuwa na udhaifu**, na ni nini siyo.

## Mali za Wingu za Umma

Ili kupata mali za wingu za uwezekano zinazomilikiwa na kampuni unapaswa **kuanza na orodha ya maneno muhimu yanayotambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "mkoba", "dao", "<jina_la_kikoa>", <"majina_ya_subdomain">`.

Pia utahitaji orodha za maneno ya **kawaida yanayotumiwa katika vikapu**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa maneno hayo unapaswa kuzalisha **permutations** (angalia [**Raundi ya Pili ya Brute-Force ya DNS**](./#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa orodha za maneno zilizopatikana unaweza kutumia zana kama [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Mali za Wingu unapaswa **kutafuta zaidi ya vikapu tu katika AWS**.

### **Kutafuta Udhaifu**

Ikiwa unapata mambo kama **vikapu wazi au kazi za wingu zilizofichuliwa** unapaswa **kuzifikia** na jaribu kuona wanakupa nini na ikiwa unaweza kuzitumia vibaya.

## Barua pepe

Kwa **mamia** na **subdomains** ndani ya eneo la tafiti kimsingi una kila kitu unachohitaji kuanza kutafuta barua pepe. Hizi ni **APIs** na **zana** ambazo zimefanya kazi vizuri kwangu kupata barua pepe ya kampuni:

* [**theHarvester**](https://github.com/laramies/theHarvester) - na APIs
* API ya [**https://hunter.io/**](https://hunter.io/) (toleo la bure)
* API ya [**https://app.snov.io/**](https://app.snov.io/) (toleo la bure)
* API ya [**https://minelead.io/**](https://minelead.io/) (toleo la bure)

### **Kutafuta Udhaifu**

Barua pepe zitakuja muhimu baadaye kwa **brute-force wa kuingia kwenye wavuti na huduma za uthibitishaji** (kama vile SSH). Pia, zinahitajika kwa **phishing**. Zaidi ya hayo, APIs hizi zitakupa hata zaidi **habari kuhusu mtu** nyuma ya barua pepe, ambayo ni muhimu kwa kampeni ya phishing.

## Kuvuja kwa Vitambulisho

Kwa **mamia,** **subdomains,** na **barua pepe** unaweza kuanza kutafuta vitambulisho vilivyovuja hapo awali vinavyomilikiwa na barua pepe hizo:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta Udhaifu**

Ikiwa unapata vitambulisho vilivyovuja **vilivyothibitishwa**, hii ni ushindi rahisi sana.

## Kuvuja kwa Siri

Kuvuja kwa vitambulisho kunahusiana na kuvuja kwa kampuni ambapo **habari nyeti ilivuja na kuuzwa**. Walakini, kampuni zinaweza kuathiriwa na **uvujaji mwingine** ambao habari yake haipo katika hizo databases:

### Kuvuja kwa Github

Vitambulisho na APIs zinaweza kuvuja katika **makusanyo ya umma** ya **kampuni** au ya **watumiaji** wanaofanya kazi na kampuni hiyo ya github.\
Unaweza kutumia **zana** [**Leakos**](https://github.com/carlospolop/Leakos) kudownload **repos za umma** za **shirika** na ya **wabunifu** wake na kukimbia [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yao kiotomatiki.

**Leakos** inaweza pia kutumika kukimbia **gitleaks** tena kwenye **maandishi** yote yaliyotolewa **URLs zilizopitishwa** kwake kwa sababu mara nyingi **kurasa za wavuti pia zina siri**.

#### Dorks za Github

Angalia pia **ukurasa** huu kwa **dorks za github** za uwezekano unaweza pia kutafuta katika shirika unaloshambulia:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Kuvuja kwa Pastes

Wakati mwingine wadukuzi au wafanyakazi wataweza **kuchapisha maudhui ya kampuni kwenye tovuti ya kubandika**. Hii inaweza au isiyoweza kuwa na **habari nyeti**, lakini ni ya kuvutia sana kutafuta.\
Unaweza kutumia zana [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya tovuti 80 za kubandika kwa wakati mmoja.

### Dorks za Google

Dorks za zamani lakini dhahabu zinafaa siku zote kwa kutafuta **habari zilizofichuliwa ambazo hazipaswi kuwepo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu ya matakwa yanayowezekana ambayo huwezi kukimbia kwa mikono. Kwa hivyo, unaweza kupata zako 10 zinazopendwa au unaweza kutumia **zana kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuzikimbia zote**.

_Taarifa kwamba zana zinatarajia kukimbia database yote kwa kutumia kivinjari cha kawaida cha Google haitamaliza kamwe kwani google itakuzuia haraka sana._

### **Kutafuta Udhaifu**

Ikiwa unapata **vitambulisho vilivyovuja** au vivuli vya API, hii ni ushindi rahisi sana.

## Udhaifu wa Kodi ya Umma

Ikiwa umegundua kuwa kampuni ina **msimbo wa chanzo wazi** unaweza **kuuchambua** na kutafuta **udhaifu** ndani yake.

**Kulingana na lugha** kuna zana tofauti unazoweza kutumia:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Pia kuna huduma za bure zinazokuwezesha **kutafuta makusanyo ya umma**, kama vile:

* [**Snyk**](https://app.snyk.io/)
## [**Mbinu ya Kupima Usalama wa Wavuti**](../../network-services-pentesting/pentesting-web/)

**Ukubwa wa kasoro** zilizopatikana na wawindaji wa makosa zinapatikana ndani ya **maombi ya wavuti**, kwa hivyo kwa sasa ningependa kuzungumzia **mfumo wa kupima maombi ya wavuti**, na unaweza [**kupata habari hii hapa**](../../network-services-pentesting/pentesting-web/).

Pia ningependa kufanya marejeleo maalum kwa sehemu [**Zana za Kufanya Uchunguzi wa Wavuti kiotomatiki za chanzo wazi**](../../network-services-pentesting/pentesting-web/#automatic-scanners), kwani, ingawa hutegemei kupata kasoro zenye hisia sana, zinaweza kusaidia kutekeleza **hatua za awali za kupata habari za wavuti.**

## Muhtasari

> Hongera! Kufikia hatua hii tayari umefanya **uchunguzi wa msingi wote**. Ndiyo, ni msingi kwa sababu uchunguzi zaidi unaweza kufanywa (tutaona mbinu zaidi baadaye).

Kwa hivyo tayari umefanya yafuatayo:

1. Kupata **makampuni yote** ndani ya eneo la uchunguzi
2. Kupata **mali zote** zinazomilikiwa na makampuni (na kufanya uchunguzi wa kasoro ikiwa ni sehemu ya uchunguzi)
3. Kupata **kikoa zote** zinazomilikiwa na makampuni
4. Kupata **subdomain zote** za vikoa (kuna uwezekano wa kuchukua subdomain?)
5. Kupata **IPs zote** (kutoka na **si kutoka kwa CDNs**) ndani ya eneo la uchunguzi.
6. Kupata **seva za wavuti** zote na kuchukua **picha ya skrini** yao (kuna kitu cha ajabu kinachostahili kuangaliwa kwa undani zaidi?)
7. Kupata **mali zote za wingu la umma** zinazomilikiwa na kampuni.
8. **Barua pepe**, **vuja vya siri**, na **vuja vya siri** ambavyo vinaweza kukupa **ushindi mkubwa kwa urahisi sana**.
9. **Kupima usalama wa wavuti zote ulizopata**

## **Zana za Uchunguzi wa Kiotomatiki Kamili**

Kuna zana kadhaa huko nje ambazo zitafanya sehemu ya hatua zilizopendekezwa dhidi ya eneo lililopewa.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Kidogo zaidi na haifanyiwa marekebisho

## **Vyanzo**

* Kozi zote za bure za [**@Jhaddix**](https://twitter.com/Jhaddix) kama [**Mbinu ya Mwindaji wa Makosa v4.0 - Toleo la Uchunguzi**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ikiwa una nia ya **kazi ya udukuzi** na kudukua yasiyoweza kudukuliwa - **tunakupa kazi!** (_inahitajika uwezo wa kuzungumza na kuandika Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
