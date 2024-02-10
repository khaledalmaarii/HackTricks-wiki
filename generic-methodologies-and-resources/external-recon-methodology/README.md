# Metodologija spoljašnjeg istraživanja

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty savet**: **registrujte se** za **Intigriti**, premium **platformu za bug bounty kreiranu od strane hakera, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Otkrivanje resursa

> Rečeno vam je da sve što pripada određenoj kompaniji spada u opseg, i želite da saznate šta ta kompanija zapravo poseduje.

Cilj ove faze je da se dobiju sve **kompanije koje pripadaju glavnoj kompaniji**, a zatim i svi **resursi** ovih kompanija. Da bismo to postigli, uradićemo sledeće:

1. Pronaći akvizicije glavne kompanije, to će nam dati kompanije koje spadaju u opseg.
2. Pronaći ASN (ako postoji) svake kompanije, to će nam dati IP opsege koje svaka kompanija poseduje.
3. Koristiti pretragu obrnutog whois-a da bismo pronašli druge unose (nazive organizacija, domene...) povezane sa prvom (ovo se može raditi rekurzivno).
4. Koristiti druge tehnike poput shodan `org` i `ssl` filtera da bismo pronašli druge resurse (tri trick se može raditi rekurzivno).

### **Akvizicije**

Prvo, trebamo znati koje **druge kompanije pripadaju glavnoj kompaniji**.\
Jedna opcija je posetiti [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražiti** glavnu kompaniju i **kliknuti** na "**akvizicije**". Tamo ćete videti druge kompanije koje je glavna kompanija akvizirala.\
Druga opcija je posetiti **Wikipedia** stranicu glavne kompanije i pretražiti **akvizicije**.

> Ok, do ovog trenutka trebali biste znati sve kompanije koje spadaju u opseg. Hajde da saznamo kako pronaći njihove resurse.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstven broj** dodeljen autonomnom sistemu (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
AS se sastoji od **blokova** IP adresa koji imaju jasno definisanu politiku za pristupanje spoljnim mrežama i upravljaju se od strane jedne organizacije, ali mogu biti sastavljeni od nekoliko operatera.

Interesantno je saznati da li **kompanija ima dodeljen ASN** kako bismo pronašli njene **IP opsege**. Bilo bi korisno izvršiti **test ranjivosti** na sve **hostove** koji spadaju u **opseg** i potražiti domene unutar tih IP adresa.\
Možete **pretraživati** po imenu kompanije, po **IP** adresi ili po **domeni** na [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Zavisno od regiona u kojem se nalazi kompanija, ovi linkovi mogu biti korisni za prikupljanje više podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se svi** korisni podaci **(IP opsezi i Whois)** već pojavljuju na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-ova** enumeracija poddomena automatski agregira i sažima ASN-ove na kraju skeniranja.
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
Možete pronaći IP opsege organizacije koristeći [http://asnlookup.com/](http://asnlookup.com) (ima besplatnu API).\
Možete pronaći IP i ASN domena koristeći [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sve resurse unutar opsega**, pa ako vam je dozvoljeno, možete pokrenuti neki **skener ranjivosti** (Nessus, OpenVAS) na svim hostovima.\
Takođe, možete pokrenuti neke [**port skenove**](../pentesting-network/#discovering-hosts-from-the-outside) **ili koristiti usluge kao što je** shodan **da biste pronašli** otvorene portove **i, u zavisnosti od onoga što pronađete, trebali biste** pogledati u ovoj knjizi kako biste testirali nekoliko mogućih pokrenutih usluga.\
**Takođe, vredno je pomenuti da možete pripremiti neke** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati** probiti usluge sa [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar opsega i njihove resurse, vreme je da pronađemo domene unutar opsega.

_Molimo, imajte na umu da u sledećim predloženim tehnikama takođe možete pronaći poddomene i te informacije ne treba potcenjivati._

Prvo biste trebali potražiti **glavni domen(e)** svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Kada ste pronašli sve IP opsege domena, možete pokušati izvršiti **obrnute DNS upite** na tim **IP adresama kako biste pronašli više domena unutar opsega**. Pokušajte koristiti neki DNS server žrtve ili neki dobro poznati DNS server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Da bi ovo funkcionisalo, administrator mora ručno omogućiti PTR.\
Takođe možete koristiti online alat za ove informacije: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (petlja)**

Unutar **whois** informacija možete pronaći mnogo interesantnih **podataka** kao što su **ime organizacije**, **adresa**, **emailovi**, telefonski brojevi... Ali ono što je još interesantnije je da možete pronaći **više resursa povezanih sa kompanijom** ako izvršite **pretragu reverse whois-om koristeći bilo koja od tih polja** (na primer, drugi whois registri gde se isti email pojavljuje).\
Možete koristiti online alate kao što su:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatno** web, nije besplatno API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
* [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno

Možete automatizovati ovaj zadatak koristeći [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Takođe možete izvršiti automatsko otkrivanje reverse whois-a sa [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da možete koristiti ovu tehniku da biste otkrili više domena svaki put kada pronađete novu domenu.**

### **Pratitelji**

Ako pronađete **isti ID istog pratioca** na 2 različite stranice, možete pretpostaviti da **obe stranice** upravlja **isti tim**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na nekoliko stranica.

Postoje neke stranice i alati koji vam omogućavaju pretragu po ovim pratiocima i još mnogo toga:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tako što ćemo tražiti isti hash ikone favicona? To je upravo ono što alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) napravljen od strane [@m4ll0k2](https://twitter.com/m4ll0k2) radi. Evo kako ga koristiti:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrijte domene sa istim hešom ikone favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koje imaju isti heš ikone favicon kao naš cilj.

Osim toga, možete takođe pretraživati tehnologije koristeći heš favicon-a kako je objašnjeno u [**ovom blog postu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da ako znate **heš favicon-a ranjive verzije web tehnologije**, možete pretražiti da li se nalazi na shodan-u i **pronaći više ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ovako možete **izračunati heš favicona** veb stranice:
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
### **Autorsko pravo / Unikatni niz**

Pretražite unutar web stranica **nizove koji se mogu deliti između različitih web stranica u istoj organizaciji**. Niz koji predstavlja **autorsko pravo** može biti dobar primer. Zatim pretražite taj niz na **Google-u**, u drugim **pregledačima** ili čak na **Shodan-u**: `shodan search http.html:"Niz autorskog prava"`

### **CRT vreme**

Uobičajeno je imati cron posao kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Da biste obnovili sve sertifikate domena na serveru. To znači da čak i ako CA koji se koristi za ovo ne postavlja vreme kada je generisan u vremenskom periodu važnosti, moguće je **pronaći domene koje pripadaju istoj kompaniji u logovima transparentnosti sertifikata**.\
Pogledajte ovaj [**članak za više informacija**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Pasivno preuzimanje**

Izgleda da je uobičajeno da ljudi dodeljuju poddomene IP adresama koje pripadaju provajderima oblaka i u nekom trenutku **izgube tu IP adresu, ali zaborave da uklone DNS zapis**. Stoga, samo **pokretanjem virtuelne mašine** u oblaku (kao što je Digital Ocean), zapravo ćete **preuzeti neke poddomene**.

[**Ovaj post**](https://kmsec.uk/blog/passive-takeover/) objašnjava priču o tome i predlaže skriptu koja **pokreće virtuelnu mašinu u DigitalOcean-u**, **dobija** IPv4 **nove mašine** i **pretražuje Virustotal za poddomene** koje na nju upućuju.

### **Drugi načini**

**Imajte na umu da možete koristiti ovu tehniku da biste otkrili više naziva domena svaki put kada pronađete novu domenu.**

**Shodan**

Kako već znate ime organizacije koja je vlasnik IP prostora, možete pretraživati po tim podacima u Shodan-u koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove za nove neočekivane domene u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne veb stranice, dobiti **ime organizacije** i zatim pretražiti to ime unutar **TLS sertifikata** svih veb stranica poznatih **Shodan-u** sa filterom: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) je alat koji traži **povezane domene** sa glavnim domenom i **poddomene** od njih, prilično neverovatno.

### **Traženje ranjivosti**

Proverite da li postoji [preuzimanje domena](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali su **izgubili vlasništvo** nad njim. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa drugačijom IP adresom** od onih koje ste već pronašli u otkrivanju resursa, trebali biste izvršiti **osnovno skeniranje ranjivosti** (koristeći Nessus ili OpenVAS) i neko [**skeniranje porta**](../pentesting-network/#discovering-hosts-from-the-outside) sa **nmap/masscan/shodan**. Zavisno od toga koje usluge se izvršavaju, možete pronaći u **ovoj knjizi neke trikove za "napad" na njih**.\
Imajte na umu da se ponekad domen nalazi na IP adresi kojom ne upravlja klijent, pa nije u opsegu, budite oprezni.

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Savet za bug bounty**: **Prijavite se** za **Intigriti**, premium **platformu za bug bounty kreiranu od strane hakera, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas i počnite da zarađujete nagrade do **100.000 dolara**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Poddomeni

> Znamo sve kompanije u opsegu, sve resurse svake kompanije i sve domene povezane sa kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

### **DNS**

Pokušajmo da dobijemo **poddomene** iz **DNS** zapisa. Takođe bismo trebali pokušati sa **Zone Transferom** (Ako je ranjiv, trebali biste to prijaviti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da se dobije veliki broj poddomena je pretraživanje eksternih izvora. Najčešće **alatke** koje se koriste su sledeće (za bolje rezultate konfigurišite API ključeve):

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/sr-latn)
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
Postoje **drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za tu svrhu, kao što su:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za dobijanje poddomena.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC besplatni API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) besplatni API
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
* [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove sa AlienVault-ove Open Threat Exchange, Wayback Machine-a i Common Crawl-a za bilo koji zadati domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Oni pretražuju web u potrazi za JS fajlovima i iz njih izvlače poddomene.
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
* [**Censys pronalazač poddomena**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) ima besplatnu API za pretragu poddomena i istoriju IP adresa
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat nudi **besplatno sve poddomene vezane za bug-bounty programe**. Možete pristupiti ovim podacima i koristeći [chaospy](https://github.com/dr-0x0x/chaospy) ili pristupiti opsegu koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Možete pronaći **poređenje** mnogih ovih alata ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomene** brute-forcing DNS servere koristeći moguća imena poddomena.

Za ovu akciju će vam biti potrebne neke **uobičajene liste reči za poddomene kao što su**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

I takođe IP adrese dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

* [**massdns**](https://github.com/blechschmidt/massdns): Ovo je prvi alat koji je izveo efikasan DNS brute-force. Veoma je brz, ali je podložan lažnim pozitivima.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač oko `massdns`, napisan u go jeziku, koji vam omogućava da nabrojite validne poddomene korišćenjem aktivnog bruteforce-a, kao i da rešite poddomene sa rukovanjem sa džoker znakom i jednostavnom podrškom za unos i izlaz.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhrono brute force napad na domenska imena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS Brute-Force napada

Nakon što ste pronašli poddomene korišćenjem otvorenih izvora i brute-force tehnike, možete generisati varijacije pronađenih poddomena kako biste pokušali pronaći još više. Za tu svrhu korisne su nekoliko alata:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Generiše permutacije na osnovu domena i poddomena.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dati domeni i poddomeni generišu permutacije.
* Možete dobiti goaltdns permutacije **wordlist** [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dati domeni i poddomeni generišu permutacije. Ako nije naznačena datoteka permutacija, gotator će koristiti svoju sopstvenu.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može pokušati i da ih razreši (ali bolje je koristiti prethodno komentarisane alate).
* Možete dobiti altdns permutacije **wordlist** [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će grubom silom dobiti rezultat (ne podržava dns wild card).
* Možete preuzeti dmut listu reči za permutacije [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena, **generiše nove potencijalne poddomene** na osnovu naznačenih obrazaca kako bi otkrio više poddomena.

#### Pametno generisanje permutacija

* [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovaj [**post**](https://cramppet.github.io/regulator/index.html), ali u osnovi će uzeti **glavne delove** otkrivenih poddomena i mešati ih kako bi pronašao više poddomena.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je alat za brute-force napad na poddomene koji je uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi pruženi set ulaznih podataka, poput prilagođene liste reči ili istorijskih DNS/TLS zapisa, kako bi tačno sintetisao više odgovarajućih imena domena i dalje ih proširio u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Radni tok otkrivanja poddomena**

Proverite ovaj blog post koji sam napisao o tome kako **automatizovati otkrivanje poddomena** sa domena koristeći **Trickest radne tokove** tako da ne moram ručno pokretati gomilu alata na svom računaru:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtuelni hostovi**

Ako pronađete IP adresu koja sadrži **jednu ili više veb stranica** koje pripadaju poddomenima, možete pokušati **pronaći druge poddomene sa veb stranicama na toj IP adresi** tako što ćete pretražiti **OSINT izvore** za domene na određenoj IP adresi ili **brute-forcing VHost imena domena na toj IP adresi**.

#### OSINT

Možete pronaći neke **VHostove na IP adresama koristeći** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili druge API-je**.

**Brute Force**

Ako sumnjate da se neki poddomen može sakriti na veb serveru, možete pokušati da ga brute-forceujete:
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
Sa ovom tehnikom možda čak možete pristupiti internim/skrivenim endpointima.
{% endhint %}

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju samo zaglavlje _**Access-Control-Allow-Origin**_ kada je validna domena/poddomena postavljena u zaglavlju _**Origin**_. U ovim scenarijima, možete zloupotrebiti ovu funkcionalnost da **otkrijete** nove **poddomene**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force za Buckets**

Dok tražite **poddomene**, obratite pažnju da li se **upućuje** na neku vrstu **bucket-a**, i u tom slučaju [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Takođe, s obzirom da ćete u ovom trenutku znati sve domene unutar opsega, pokušajte [**brute force-ovati moguća imena bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorisanje**

Možete **pratiti** da li su **kreirane nove poddomene** domena praćenjem **Certificate Transparency** Logova [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) radi toga.

### **Traženje ranjivosti**

Proverite moguće [**preuzimanje poddomene**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako se **poddomena** upućuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/).

Ako pronađete bilo koju **poddomenu sa drugačijom IP adresom** od onih koje ste već pronašli u otkrivanju resursa, trebali biste izvršiti **osnovno skeniranje ranjivosti** (korišćenjem Nessus-a ili OpenVAS-a) i neko [**skeniranje porta**](../pentesting-network/#discovering-hosts-from-the-outside) sa **nmap/masscan/shodan**. Zavisno od toga koje usluge se izvršavaju, možete pronaći u **ovoj knjizi neke trikove za "napad" na njih**.\
Napomena da se ponekad poddomena nalazi na IP adresi koja nije pod kontrolom klijenta, pa nije u opsegu, budite oprezni.

## IP adrese

U početnim koracima možda ste **pronašli neke opsege IP adresa, domene i poddomene**.\
Vreme je da **sakupite sve IP adrese iz tih opsega** i za **domene/poddomene (DNS upiti)**.

Korišćenjem usluga sledećih **besplatnih API-ja** možete takođe pronaći **prethodno korišćene IP adrese od strane domena i poddomena**. Ove IP adrese još uvek mogu biti u vlasništvu klijenta (i mogu vam omogućiti pronalaženje [**CloudFlare zaobilaznica**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koje upućuju na određenu IP adresu koristeći alat [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte sve IP adrese koje ne pripadaju CDN-ovima** (jer verovatno nećete pronaći ništa zanimljivo tamo). U otkrivenim pokrenutim uslugama možda ćete **moći pronaći ranjivosti**.

Pronađite [**vodič**](../pentesting-network/) **o tome kako skenirati hostove**.

## Lov na veb servere

> Pronašli smo sve kompanije i njihove resurse i znamo opsege IP adresa, domene i poddomene unutar opsega. Vreme je da tražimo veb servere.

U prethodnim koracima verovatno ste već izvršili neko **istraživanje IP adresa i otkrili domene**, tako da možda već imate **sve moguće veb servere**. Međutim, ako nemate, sada ćemo videti neke **brze trikove za traženje veb servera** unutar opsega.

Molim vas, imajte na umu da će ovo biti **usmereno na otkrivanje veb aplikacija**, pa biste trebali **izvršiti skeniranje ranjivosti** i **skeniranje porta** takođe (**ako je dozvoljeno** u opsegu).

**Brz metod** za otkrivanje **otvorenih portova** koji se odnose na **veb** servere koristeći [**masscan** možete pronaći ovde](../pentesting-network/#http-port-discovery).\
Još jedan koristan alat za traženje veb servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Samo prosledite listu domena i pokušaće da se poveže na port 80 (http) i 443 (https). Dodatno, možete naznačiti da pokušate i druge portove:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve veb servere** prisutne u opsegu (među **IP adresama** kompanije i svim **domenima** i **poddomenima**), verovatno **ne znate odakle da počnete**. Dakle, učinimo to jednostavnim i počnimo tako što ćemo napraviti snimke ekrana svih njih. Samo **pogledom** na **glavnu stranicu** možete pronaći **čudne** endpointe koji su više **podložni** ranjivostima.

Da biste izvršili predloženu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Osim toga, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da pregledate sve **snimke ekrana** i da vam kaže šta je verovatno **ranjivo**, a šta nije.

## Javna Cloud Sredstva

Da biste pronašli potencijalna cloud sredstva koja pripadaju kompaniji, trebali biste **početi sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za kripto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<ime_domena>", <"ime_poddomena">`.

Takođe će vam biti potrebne liste reči koje se **često koriste u bucketima**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, sa tim rečima trebali biste generisati **permutacije** (proverite [**Second Round DNS Brute-Force**](./#second-dns-bruteforce-round) za više informacija).

Sa rezultirajućim listama reči možete koristiti alate kao što su [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da prilikom traženja Cloud Sredstava trebate **tražiti više od samo bucketa u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete stvari kao što su **otvoreni bucketi ili izložene cloud funkcije**, trebali biste im **pristupiti** i pokušati videti šta vam nude i da li ih možete zloupotrebiti.

## E-mailovi

Sa **domenima** i **poddomenima** unutar opsega, imate sve što vam je **potrebno da počnete tražiti e-mailove**. Ovo su **API-ji** i **alati** koji su mi najbolje funkcionisali za pronalaženje e-mailova kompanije:

* [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-ima
* API od [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
* API od [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
* API od [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

E-mailovi će vam kasnije biti korisni za **brute-force web prijave i autentifikacijske servise** (kao što je SSH). Takođe, potrebni su za **phishing**. Osim toga, ovi API-ji će vam pružiti još više **informacija o osobi** iza e-maila, što je korisno za kampanju phishinga.

## Curenje akreditacija

Sa **domenima**, **poddomenima** i **e-mailovima** možete početi tražiti procurele akreditacije iz prošlosti koje pripadaju tim e-mailovima:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** akreditacije, to je veoma jednostavna pobeda.

## Curenje tajni

Curenje akreditacija je povezano sa hakovanjem kompanija gde je **osetljive informacije procurele i prodavane**. Međutim, kompanije mogu biti pogođene i drugim curenjima čije informacije nisu u tim bazama podataka:

### Github Curenja

Akreditacije i API-ji mogu biti procureli u **javnom repozitorijumu** **kompanije** ili **korisnika** koji rade za tu github kompaniju.\
Možete koristiti alat [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** jedne **organizacije** i njenih **razvijača** i automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** nad svim **tekstualnim** **URL-ovima** koje mu prosledite, jer se ponekad **veb stranice takođe sadrže tajne**.

#### Github Dorks

Proverite takođe ovu **stranicu** za potencijalne **github dorks** koje takođe možete pretraživati u organizaciji koju napadate:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Curenja Pasteova

Ponekad napadači ili samo radnici će **objaviti sadržaj kompanije na sajtu za paste**. To može ili ne mora sadržati **osetljive informacije**, ali je veoma interesantno za pretragu.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da pretražujete više od 80 sajtova za paste istovremeno.

### Google Dorks

Stari, ali zlatni google dorks uvek su korisni za pronalaženje **izloženih informacija koje ne bi trebale biti tamo**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete pokrenuti ručno. Dakle, možete odabrati svojih 10 omiljenih ili možete koristiti alat kao što je [**Gorks**](https://github.com/carlospolop/Gorks) da ih sve pokrenete.

Napomena da alati koji očekuju da pokrenu celu bazu podataka koristeći redovni Google pretraživač nikada neće završiti jer će vas Google vrlo brzo blokirati.

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** akreditacije ili API tokene, to je veoma jednostavna pobeda.

## Ranjivosti javnog koda

Ako ste otkrili da kompanija ima **otvoren kod**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**Zavisno o jeziku**, postoje različiti **alati** koje možete koristiti:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Postoje i besplatne usluge koje vam omogućavaju da **skenirate javne repozitorijume**, kao što su:

* [**Snyk**](https://app.snyk.io/)
## [**Metodologija testiranja penetracije veb aplikacija**](../../network-services-pentesting/pentesting-web/)

**Većina ranjivosti** koje pronalaze lovci na bagove nalaze se unutar **veb aplikacija**, pa bih ovde želeo da govorim o **metodologiji testiranja veb aplikacija**, a vi možete [**pronaći ove informacije ovde**](../../network-services-pentesting/pentesting-web/).

Takođe želim da posebno pomenem sekciju [**Alati za automatsko skeniranje veb aplikacija otvorenog koda**](../../network-services-pentesting/pentesting-web/#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma osetljive ranjivosti, korisni su za implementaciju u **radne tokove kako bi se dobile neke početne informacije o vebu**.

## Rekapitulacija

> Čestitam! Do ovog trenutka ste već obavili **svu osnovnu enumeraciju**. Da, osnovnu, jer se može obaviti mnogo više enumeracije (videćemo više trikova kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** u okviru opsega
2. Pronašli sve **resurse** koji pripadaju kompanijama (i obavili neko skeniranje ranjivosti ako je u opsegu)
3. Pronašli sve **domene** koje pripadaju kompanijama
4. Pronašli sve **poddomene** domena (ima li preuzimanja poddomena?)
5. Pronašli sve **IP adrese** (izvan i **izvan CDN-a**) u okviru opsega.
6. Pronašli sve **veb servere** i napravili **screenshot** (ima li nešto čudno što vredi detaljnije pogledati?)
7. Pronašli sve **potencijalne javne resurse u oblaku** koji pripadaju kompaniji.
8. **Emailove**, **curenja podataka o akreditivima** i **curenja tajni** koja vam mogu **lako doneti veliku dobit**.
9. **Testirali penetraciju svih veb lokacija koje ste pronašli**

## **Alati za automatsku potpunu rekonstrukciju**

Postoji nekoliko alata koji će izvršiti deo predloženih radnji u okviru određenog opsega.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo zastareo i nije ažuriran

## **Reference**

* Svi besplatni kursevi [**@Jhaddix**](https://twitter.com/Jhaddix) kao što je [**Metodologija lovca na bagove v4.0 - Recon izdanje**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Savet za lov na bagove**: **Prijavite se** za **Intigriti**, premium **platformu za lov na bagove kreiranu od strane hakera, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas i počnite da zarađujete nagrade do **100.000 dolara**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
