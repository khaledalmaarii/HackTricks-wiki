# Eksterne Recon Metodologie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Indien jy belangstel in 'n **hackingsloopbaan** en die onhackbare wil hack - **ons is aan die aanstel!** (_vloeiende Pools geskrewe en gesproke vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Bate-ontdekkings

> So jy is gesê dat alles wat aan 'n maatskappy behoort binne die omvang is, en jy wil uitvind wat hierdie maatskappy eintlik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te verkry en dan al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Vind die verkrygings van die hoofmaatskappy, dit sal ons die maatskappye binne die omvang gee.
2. Vind die ASN (indien enige) van elke maatskappy, dit sal ons die IP-reeks besit deur elke maatskappy gee
3. Gebruik omgekeerde whois-opsoeke om te soek na ander inskrywings (organisasienames, domeine...) wat verband hou met die eerste een (dit kan rekursief gedoen word)
4. Gebruik ander tegnieke soos shodan `org`en `ssl`filters om te soek na ander bates (die `ssl`truk kan rekursief gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, **soek** vir die **hoofmaatskappy**, en **klik** op "**verkrygings**". Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
'n Ander opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en te soek na **verkrygings**.

> Ok, op hierdie punt behoort jy al die maatskappye binne die omvang te ken. Laat ons uitvind hoe om hul bates te vind.

### **ASNs**

'n Outonome stelselnommer (**ASN**) is 'n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan 'n **outonome stelsel** (AS) toegeken word.\
'n **AS** bestaan uit **blokke** van **IP-adresse** wat 'n duidelik gedefinieerde beleid vir die toegang tot eksterne netwerke het en deur 'n enkele organisasie geadministreer word, maar uit verskeie operateurs kan bestaan.

Dit is interessant om te vind of die **maatskappy enige ASN toegewys het** om sy **IP-reeks** te vind. Dit sal interessant wees om 'n **kwesbaarheidstoets** uit te voer teen al die **gasheer** binne die **omvang** en te soek na domeine binne hierdie IP's.\
Jy kan soek op maatskappy **naam**, op **IP** of op **domein** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Afhanklik van die streek van die maatskappy kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Hoe dan ook, waarskynlik verskyn alle** nuttige inligting **(IP-reeks en Whois)** reeds in die eerste skakel.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** subdomeinversameling konsolideer outomaties en sommeer ASNs aan die einde van die skandering.
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
### **Op soek na kwesbaarhede**

Op hierdie punt weet ons **al die bates binne die omvang**, so as jy toegelaat word, kan jy 'n paar **kwesbaarheidsskanderings** (Nessus, OpenVAS) oor al die gasheerservers uitvoer.\
Ook kan jy 'n paar [**poortskanderings**](../pentesting-network/#discovering-hosts-from-the-outside) **uitvoer of dienste soos** shodan **gebruik om** oop poorte **te vind en afhangende van wat jy vind, moet jy** hierdie boek deursoek om te sien hoe om verskeie moontlike dienste te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy ook 'n paar** standaard gebruikersnaam **en** wagwoorde **lyste kan voorberei en probeer om dienste te** bruteforce met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeine

> Ons ken al die maatskappye binne die omvang en hul bates, dit is tyd om die domeine binne die omvang te vind.

_Geliewe daarop te let dat in die volgende voorgestelde tegnieke jy ook subdomeine kan vind en daardie inligting moet nie onderskat word nie._

Eerstens moet jy soek na die **hoofdomein**(e) van elke maatskappy. Byvoorbeeld, vir _Tesla Inc._ gaan dit wees _tesla.com_.

### **Omgekeerde DNS**

Nadat jy al die IP-reeks van die domeine gevind het, kan jy probeer om **omgekeerde DNS-opsoeke** op daardie **IP's uit te voer om meer domeine binne die omvang te vind**. Probeer om 'n paar dns-bedieners van die slagoffer of 'n paar bekende dns-bedieners (1.1.1.1, 8.8.8.8) te gebruik.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Vir hierdie om te werk, moet die administrateur handmatig die PTR aktiveer.\
Jy kan ook 'n aanlyn gereedskap gebruik vir hierdie inligting: [http://ptrarchive.com/](http://ptrarchive.com)

### **Omgekeerde Whois (lus)**

Binne 'n **whois** kan jy baie interessante **inligting** vind soos **organisasienaam**, **adres**, **e-posse**, telefoonnommers... Maar wat selfs meer interessant is, is dat jy **meer bates wat verband hou met die maatskappy** kan vind as jy **omgekeerde whois-opsoeke uitvoer deur enige van daardie velde** (byvoorbeeld ander whois-registre waar dieselfde e-pos verskyn).\
Jy kan aanlyn gereedskappe gebruik soos:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** web, nie gratis API nie.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis nie
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie Gratis (slegs **100 gratis** soektogte)
* [https://www.domainiq.com/](https://www.domainiq.com) - Nie Gratis nie

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis 'n whoxy API-sleutel).\
Jy kan ook enkele outomatiese omgekeerde whois-ontdekkings doen met [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer as jy 'n nuwe domein vind.**

### **Opvolgers**

As jy dieselfde ID van dieselfde opvolger op 2 verskillende bladsye vind, kan jy aanneem dat **beide bladsye** deur dieselfde span **bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is 'n paar bladsye en gereedskappe wat jou toelaat om te soek na hierdie opvolgers en meer:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine aan ons teiken kan vind deur te soek na dieselfde favicon-ikoon-hash? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) gereedskap gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2) doen. Hier is hoe om dit te gebruik:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ontdek domeine met dieselfde favicon-ikoon-hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, favihash sal ons in staat stel om domeine te ontdek wat dieselfde favicon-ikoon-hash as ons teiken het.

Verder kan jy ook tegnologieë soek deur die favicon-hash te gebruik soos verduidelik in [**hierdie blogpos**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Dit beteken dat as jy die **hash van die favicon van 'n kwesbare weergawe van 'n webtegnologie** ken, kan jy soek of dit in shodan is en **meer kwesbare plekke vind**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Dit is hoe jy die **favicon hash** van 'n webwerf kan **bereken**:
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
### **Auteursreg / Unieke string**

Soek binne die webbladsye na **strings wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **auteursregstring** kan 'n goeie voorbeeld wees. Soek dan vir daardie string in **Google**, in ander **blaaier** of selfs in **Shodan**: `shodan search http.html:"Auteursregstring"`

### **CRT-tyd**

Dit is algemeen om 'n cron-werk soos dit te hê
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### **Hernuwe van domeinsertifikate**

Om al die domeinsertifikate op die bediener te hernu, beteken dit selfs as die CA wat hiervoor gebruik word nie die tyd waarop dit gegenereer is in die Geldigheidstyd instel nie, is dit moontlik om **domeine wat aan dieselfde maatskappy behoort in die sertifikaattransparantielogboeke te vind**.\
Kyk na hierdie [**verslag vir meer inligting**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Pos DMARC-inligting

Jy kan 'n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of 'n instrument soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine te vind wat dieselfde dmarc-inligting deel**.

### **Passiewe Oorname**

Dit is blykbaar algemeen vir mense om subdomeine aan IP-adresse toe te ken wat aan wolkverskaffers behoort en op 'n stadium daardie IP-adres te **verloor maar vergeet om die DNS-rekord te verwyder**. Daarom, deur net 'n VM te **begin in 'n wolk (soos Digital Ocean)**, sal jy eintlik **sekere subdomeine oorneem**.

[**Hierdie pos**](https://kmsec.uk/blog/passive-takeover/) verduidelik 'n storie daaroor en stel 'n skripsie voor wat **'n VM in DigitalOcean begin**, die **IPv4** van die nuwe masjien **kry**, en in Virustotal vir subdomeinrekords wat daarna verwys, **soek**.

### **Ander maniere**

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer as jy 'n nuwe domein vind**.

**Shodan**

Aangesien jy reeds die naam van die organisasie wat die IP-ruimte besit, ken. Jy kan daarna soek in shodan deur hierdie data te gebruik: `org:"Tesla, Inc."` Kyk na die gevonde gasheer vir nuwe onverwagte domeine in die TLS-sertifikaat.

Jy kan die **TLS-sertifikaat** van die hoofwebwerf besoek, die **Organisasienaam** verkry, en dan soek na daardie naam binne die **TLS-sertifikate** van al die webwerwe wat deur **shodan** bekend is met die filter: `ssl:"Tesla Motors"` of gebruik 'n instrument soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) is 'n instrument wat soek na **domeine wat verband hou** met 'n hoofdomein en **subdomeine** daarvan, baie indrukwekkend.

### **Op soek na kwesbaarhede**

Soek na 'n [domeinoorneem](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Dalk gebruik 'n maatskappy **'n domein** maar hulle **het die eienaarskap verloor**. Registreer dit net (as dit goedkoop genoeg is) en laat die maatskappy weet.

As jy enige **domein met 'n ander IP** as diegene wat jy reeds in die batesontdekking gevind het, vind, moet jy 'n **basiese kwesbaarheidsskandering** uitvoer (met behulp van Nessus of OpenVAS) en 'n [**poortskandering**](../pentesting-network/#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangende van watter dienste besig is, kan jy in **hierdie boek 'n paar truuks vind om hulle te "aanval"**.\
_Merk op dat die domein soms gehuisves word binne 'n IP wat nie deur die klient beheer word nie, so dit val nie binne die bestek nie, wees versigtig._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bugsbounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bugsbountyplatform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om belonings te verdien tot **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomeine

> Ons ken al die maatskappye binne die bestek, al die bates van elke maatskappy en al die domeine wat verband hou met die maatskappye.

Dit is tyd om al die moontlike subdomeine van elke gevonde domein te vind.

{% hint style="success" %}
Merk op dat sommige van die gereedskap en tegnieke om domeine te vind, ook kan help om subdomeine te vind!
{% endhint %}

### **DNS**

Laat ons probeer om **subdomeine** van die **DNS**-rekords te kry. Ons moet ook probeer vir **Zone-oordrag** (As dit kwesbaar is, moet jy dit rapporteer).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om 'n groot aantal subdomeine te verkry, is deur in eksterne bronne te soek. Die mees gebruikte **hulpmiddels** is die volgende (om beter resultate te kry, stel die API-sleutels in):

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
* [**lewe**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Daar is **ander interessante gereedskap/API's** wat selfs al is hulle nie direk gespesialiseer in die vind van subdomeine nie, nuttig kan wees om subdomeine te vind, soos:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Gebruik die API [https://sonar.omnisint.io](https://sonar.omnisint.io) om subdomeine te verkry
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC gratis API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) gratis API
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
* [**gau**](https://github.com/lc/gau)**:** haal bekende URL's op van AlienVault se Open Threat Exchange, die Wayback Machine, en Common Crawl vir enige gegewe domein.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle skraap die web vir JS-lêers en onttrek subdomeine daaruit.
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
* [**Censys subdomeinsoeker**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) het 'n gratis API om te soek na subdomeine en IP-geskiedenis
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Hierdie projek bied **gratis al die subdomeine wat verband hou met foutjagprogramme** aan. Jy kan ook toegang tot hierdie data kry deur [chaospy](https://github.com/dr-0x0x/chaospy) te gebruik of selfs die omvang wat deur hierdie projek gebruik word, te besoek [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan 'n **vergelyking** van baie van hierdie gereedskap hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Laat ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners te kragtig te gebruik met moontlike subdomeinname.

Vir hierdie aksie sal jy 'n paar **gewone subdomeinwoordlyste soos** nodig hê:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP-adresse van goeie DNS-oplossers. Om 'n lys van vertroude DNS-oplossers te genereer, kan jy die oplossers aflaai van [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan gebruik maak van: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole gereedskap vir DNS-kragtige aksies is:

* [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste gereedskap wat 'n effektiewe DNS-kragtige aksie uitgevoer het. Dit is baie vinnig, maar vatbaar vir vals positiewe resultate.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Hierdie een dink ek gebruik net 1 oplosser
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is 'n omhulsel rondom `massdns`, geskryf in go, wat jou toelaat om geldige subdomeine op te som deur aktiewe bruteforce te gebruik, asook om subdomeine op te los met wildkaart-hantering en maklike in- en uitset-ondersteuning.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Dit maak ook gebruik van `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) maak gebruik van asyncio om domeinnames asynchroon te brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Tweede DNS Brute-Force Ronde

Nadat subdomeine gevind is deur oop bronne en brute-forcings, kan jy veranderings van die gevonde subdomeine genereer om selfs meer te vind. Verskeie gereedskap is nuttig vir hierdie doel:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Gee die domeine en subdomeine permutasies.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Gegee die domeine en subdomeine genereer permutasies.
* Jy kan die goaltdns permutasies **woordelys** kry **hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Gee die domeine en subdomeine om permutasies te genereer. As geen permutasie lêer aangedui word nie, sal gotator sy eie een gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Afgesien van die generering van subdomein-permutasies, kan dit ook probeer om hulle op te los (maar dit is beter om die vorige gekommenteerde gereedskap te gebruik).
* Jy kan altdns-permutasies **woordelys** kry in [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 'n Ander instrument om permutasies, mutasies en verandering van subdomeine uit te voer. Hierdie instrument sal die resultaat kragtig afdwing (dit ondersteun nie dns wild card nie).
* Jy kan die dmut permutasies woordelys kry [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op 'n domein **genereer nuwe potensiële subdomeinname** gebaseer op aangeduide patrone om te probeer om meer subdomeine te ontdek.

#### Slim permutasie generasie

* [**regulator**](https://github.com/cramppet/regulator): Vir meer inligting lees hierdie [**pos**](https://cramppet.github.io/regulator/index.html) maar dit sal basies die **hoofdele** van die **ontdekte subdomeine** kry en hulle meng om meer subdomeine te vind.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is 'n subdomein-brute-force fuzzer gekoppel met 'n immens eenvoudige maar effektiewe DNS-antwoord-geleide algoritme. Dit maak gebruik van 'n voorsiene stel insetdata, soos 'n op maat gemaakte woordelys of historiese DNS/TLS-rekords, om akkuraat meer ooreenstemmende domeinname te sintetiseer en hulle selfs verder uit te brei in 'n lus gebaseer op inligting wat tydens die DNS-scan ingesamel is.
```
echo www | subzuf facebook.com
```
### **Subdomein Ontdekking Werkvloei**

Kyk na hierdie blogpos wat ek geskryf het oor hoe om die **subdomein ontdekking te outomatiseer** van 'n domein deur die gebruik van **Trickest-werkvloei** sodat ek nie handmatig 'n klomp gereedskap op my rekenaar hoef te begin nie:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / Virtuele Gasheer**

As jy 'n IP-adres gevind het wat **een of verskeie webbladsye** bevat wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webblaaie op daardie IP te vind** deur in **OSINT-bronne** te kyk vir domeine in 'n IP of deur **VHost-domeinname in daardie IP te brute force**.

#### OSINT

Jy kan sommige **VHosts in IP's vind deur** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API's te gebruik**.

**Brute Force**

As jy vermoed dat 'n subdomein dalk weggesteek kan wees op 'n webbediener, kan jy probeer om dit met geweld te ontsluit:
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
Met hierdie tegniek kan jy selfs moontlik toegang verkry tot interne/verborge eindpunte.
{% endhint %}

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die _**Access-Control-Allow-Origin**_ kop soek wanneer 'n geldige domein/subdomein in die _**Origin**_ kop ingestel is. In hierdie scenarios kan jy hierdie gedrag misbruik om nuwe **subdomeine** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Emmersie Kragaanval**

Terwyl jy op soek is na **subdomeine**, hou 'n oog dop om te sien of dit na enige soort **emmer** wys, en in daardie geval [**kontroleer die regte**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Ook, aangesien jy op hierdie punt al die domeine binne die omvang sal ken, probeer om [**moontlike emmernaamkragaanvalle uit te voer en die regte te kontroleer**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitering**

Jy kan **moniter** of **nuwe subdomeine** van 'n domein geskep word deur die **Sertifikaat Transparantie** Logboeke te monitor met [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Op soek na kwesbaarhede**

Kyk vir moontlike [**subdomein-oorneemaksies**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomein** na 'n **S3-emmer** wys, [**kontroleer die regte**](../../network-services-pentesting/pentesting-web/buckets/).

As jy enige **subdomein met 'n IP wat verskil** van die een wat jy reeds in die batesontdekking gevind het, vind, moet jy 'n **basiese kwesbaarheidsskandering** uitvoer (met behulp van Nessus of OpenVAS) en 'n paar [**poortskandering**](../pentesting-network/#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangende van watter dienste besig is, kan jy in **hierdie boek 'n paar truuks vind om hulle te "aanval"**.\
_Merk op dat die subdomein soms gehuisves word binne 'n IP wat nie deur die klient beheer word nie, so dit is nie in die omvang nie, wees versigtig._

## IP's

In die aanvanklike stappe het jy dalk **'n paar IP-reekse, domeine en subdomeine gevind**.\
Dit is tyd om **al die IP's van daardie reekse te versamel** en vir die **domeine/subdomeine (DNS-navrae).**

Deur dienste van die volgende **gratis API's** te gebruik, kan jy ook **vorige IP's wat deur domeine en subdomeine gebruik is, vind**. Hierdie IP's mag steeds deur die klient besit word (en mag jou in staat stel om [**CloudFlare-omleidings**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind)

* [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook vir domeine wat na 'n spesifieke IP-adres wys, kyk met die hulpmiddel [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Op soek na kwesbaarhede**

**Skandeer alle IP's wat nie aan CDN's behoort nie** (aangesien jy waarskynlik niks interessants daar sal vind nie). In die lopende dienste wat ontdek is, kan jy **kwesbaarhede vind**.

**Vind 'n** [**gids**](../pentesting-network/) **oor hoe om gasheer te skandeer.**

## Webbedieners jag

> Ons het al die maatskappye en hul bates gevind en ons ken IP-reekse, domeine en subdomeine binne die omvang. Dit is tyd om vir webbedieners te soek.

In die vorige stappe het jy waarskynlik al 'n bietjie **rekognisering van die IP's en domeine wat ontdek is** uitgevoer, sodat jy dalk **al die moontlike webbedieners al gevind het**. Indien nie, gaan ons nou sien na 'n paar **vinnige truuks om vir webbedieners te soek** binne die omvang.

Let asseblief daarop dat dit **georiënteer sal wees vir die ontdekking van webtoepassings**, sodat jy ook die **kwesbaarheid** en **poortskandering** moet uitvoer (**indien toegelaat** deur die omvang).

'n **Vinnige metode** om **oophawens verband houend met webbedieners** te ontdek met [**masscan** kan hier gevind word](../pentesting-network/#http-port-discovery).\
'n Ander vriendelike hulpmiddel om vir webbedieners te soek is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy stuur net 'n lys domeine en dit sal probeer om aan te sluit by poort 80 (http) en 443 (https). Daarbenewens kan jy aandui om ander poorte te probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Skermgrepe**

Nou dat jy **alle webbedieners** wat teenwoordig is in die omvang (onder die **IP's** van die maatskappy en al die **domeine** en **subdomeine**) ontdek het, weet jy waarskynlik **nie waar om te begin nie**. Dus, laat ons dit eenvoudig maak en begin net deur skermskote van almal te neem. Deur net 'n blik te werp op die **hoofbladsy** kan jy **vreemde** eindpunte vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.

Verder kan jy dan [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om deur al die **skermskote** te hardloop om jou te vertel **wat waarskynlik kwesbaarhede bevat**, en wat nie.

## Openbare Wolkmiddels

Om potensiële wolkbates wat aan 'n maatskappy behoort te vind, moet jy **begin met 'n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir 'n kriptomaatskappy kan jy woorde soos: `"krypto", "beursie", "dao", "<domein_naam>", <"subdomein_name">` gebruik.

Jy sal ook woordlyste van **gewone woorde wat in houers gebruik word** benodig:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Daarna moet jy met daardie woorde **permutasies genereer** (kyk na die [**Tweede Ronde DNS-Brute-Force**](./#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordlyste kan jy gereedskap soos [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**, [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**, [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.

Onthou dat wanneer jy na Wolkbates soek, jy **meer as net houers in AWS** moet soek.

### **Op soek na kwesbaarhede**

As jy dinge soos **oophouers of blootgestelde wolkfunksies** vind, moet jy **hulle toegang** en probeer sien wat hulle jou bied en of jy dit kan misbruik.

## E-posse

Met die **domeine** en **subdomeine** binne die omvang het jy basies alles wat jy **nodig het om te begin soek na e-posse**. Dit is die **API's** en **gereedskap** wat vir my die beste gewerk het om e-posse van 'n maatskappy te vind:

* [**theHarvester**](https://github.com/laramies/theHarvester) - met API's
* API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
* API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
* API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Op soek na kwesbaarhede**

E-posse sal later van pas kom om **webaanmeldings en outentifikasiedienste te brute force** (soos SSH). Ook is hulle nodig vir **hengel**. Verder sal hierdie API's jou selfs meer **inligting oor die persoon** agter die e-pos gee, wat nuttig is vir die hengelveldtog.

## Gelêkte Gelde

Met die **domeine**, **subdomeine**, en **e-posse** kan jy begin soek na gelêkte gelde wat in die verlede aan daardie e-posse behoort het:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Op soek na kwesbaarhede**

As jy **geldige gelêkte** gelde vind, is dit 'n baie maklike wen.

## Geheim Gelde

Gelêkte gelde is verwant aan hacks van maatskappye waar **sensitiewe inligting gelekte en verkoop** is. Maatskappye kan egter geraak word deur **ander lekke** waarvan die inligting nie in daardie databasisse is nie:

### Github Gelde

Gelde en API's kan gelekteer word in die **openbare bewaarplekke** van die **maatskappy** of van die **gebruikers** wat vir daardie github-maatskappy werk.\
Jy kan die **gereedskap** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **openbare bewaarplekke** van 'n **organisasie** en van sy **ontwikkelaars** af te **laai** en [**gitleaks**](https://github.com/zricethezav/gitleaks) outomaties daaroor te hardloop.

**Leakos** kan ook gebruik word om **gitleaks** weer te hardloop teen al die **teks** wat aan hom **deurgegee URL's** is, aangesien soms **webbladsye ook geheime bevat**.

#### Github Dorks

Kyk ook na hierdie **bladsy** vir potensiële **github dorks** wat jy ook in die organisasie wat jy aanval, kan soek:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Paste Gelde

Soms sal aanvallers of net werkers **maatskappy-inhoud op 'n plakwebwerf publiseer**. Dit mag of mag nie **sensitiewe inligting** bevat nie, maar dit is baie interessant om daarvoor te soek.\
Jy kan die gereedskap [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om in meer as 80 plakwebwerwe gelyktydig te soek.

### Google Dorks

Ou maar goeie google dorks is altyd nuttig om **blootgestelde inligting wat nie daar behoort te wees nie** te vind. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) verskeie **duisende** moontlike navrae bevat wat jy nie handmatig kan hardloop nie. So, jy kan jou gunsteling 10 kry of jy kan 'n **gereedskap soos** [**Gorks**](https://github.com/carlospolop/Gorks) **gebruik om hulle almal te hardloop**.

_Merk op dat die gereedskappe wat verwag om die hele databasis te hardloop deur die gewone Google-blaaier te gebruik, nooit sal eindig nie, aangesien Google jou baie baie gou sal blokkeer._

### **Op soek na kwesbaarhede**

As jy **geldige gelêkte** gelde of API-tokens vind, is dit 'n baie maklike wen.

## Openbare Kodekwesbaarhede

As jy vind dat die maatskappy **open-source kode** het, kan jy dit **ontleed** en soek na **kwesbaarhede** daarin.

**Afhanklik van die taal** is daar verskillende **gereedskappe** wat jy kan gebruik:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Daar is ook gratis dienste wat jou toelaat om **openbare bewaarplekke te skandeer**, soos:

* [**Snyk**](https://app.snyk.io/)
## [**Pentesting Web Metodologie**](../../network-services-pentesting/pentesting-web/)

Die **meerderheid van die kwesbaarhede** wat deur foutjagters gevind word, is binne **webtoepassings** geleë, dus op hierdie punt wil ek graag praat oor 'n **webtoepassingstoetsmetodologie**, en jy kan hierdie inligting [**hier vind**](../../network-services-pentesting/pentesting-web/).

Ek wil ook 'n spesiale vermelding maak van die afdeling [**Web Geoutomatiseerde Skandeerders oopbronhulpmiddels**](../../network-services-pentesting/pentesting-web/#automatic-scanners), aangesien hulle handig is om te implementeer op **werkstrome om 'n paar aanvanklike webinligting te hê**, al moet jy nie verwag dat hulle baie sensitiewe kwesbaarhede vir jou sal vind nie.

## Opsomming

> Gelukwens! Op hierdie punt het jy reeds **alle basiese opname** uitgevoer. Ja, dit is basies omdat baie meer opname gedoen kan word (ons sal later meer truuks sien).

Jy het reeds:

1. Al die **maatskappye** binne die omvang gevind
2. Al die **bates** wat aan die maatskappye behoort, gevind (en 'n paar kwesbaarheidsskanderings uitgevoer indien in die omvang)
3. Al die **domeine** wat aan die maatskappye behoort, gevind
4. Al die **subdomeine** van die domeine gevind (enige subdomeinoorname?)
5. Al die **IP's** (van en **nie van CDNs**) binne die omvang gevind.
6. Al die **webbedieners** gevind en 'n **skermkiekie** van hulle geneem (enigiets vreemds wat 'n dieper kykie werd is?)
7. Al die **potensiële openbare wolkbatesse** wat aan die maatskappy behoort, gevind.
8. **E-posse**, **geloofsbriewe-lekke**, en **geheimlekkasies** wat jou 'n **groot wen baie maklik** kan gee.
9. **Pentesting van al die webwerwe wat jy gevind het**

## **Volledige Opname Outomatiese Gereedskap**

Daar is verskeie gereedskap daar buite wat deel van die voorgestelde aksies teen 'n gegewe omvang sal uitvoer.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 'n Bietjie oud en nie opgedateer nie

## **Verwysings**

* Alle gratis kursusse van [**@Jhaddix**](https://twitter.com/Jhaddix) soos [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Indien jy belangstel in 'n **hackingsloopbaan** en die onhackbare wil hack - **ons is aan die aanstel!** (_vloeiende Pools geskrewe en gesproke vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Leer AWS-hacking van niks tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
