# Externe Recherche-Methodik

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Wenn Sie an einer **Hackerkarriere** interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

## Entdeckung von Vermögenswerten

> Ihnen wurde gesagt, dass alles, was einem Unternehmen gehört, im Rahmen liegt, und Sie möchten herausfinden, was dieses Unternehmen tatsächlich besitzt.

Das Ziel dieser Phase ist es, alle **Unternehmen, die dem Hauptunternehmen gehören**, zu erhalten und dann alle **Vermögenswerte** dieser Unternehmen. Dazu werden wir:

1. Die Übernahmen des Hauptunternehmens finden, dies gibt uns die Unternehmen im Rahmen.
2. Die ASN (falls vorhanden) jedes Unternehmens finden, dies gibt uns die IP-Bereiche, die von jedem Unternehmen besessen werden.
3. Reverse-Whois-Suchen verwenden, um nach anderen Einträgen (Organisationsnamen, Domains...) im Zusammenhang mit dem ersten zu suchen (dies kann rekursiv durchgeführt werden).
4. Andere Techniken wie Shodan `org`und `ssl`-Filter verwenden, um nach anderen Vermögenswerten zu suchen (der `ssl`-Trick kann rekursiv durchgeführt werden).

### **Übernahmen**

Zunächst müssen wir wissen, welche **anderen Unternehmen dem Hauptunternehmen gehören**.\
Eine Möglichkeit besteht darin, [https://www.crunchbase.com/](https://www.crunchbase.com) zu besuchen, nach dem **Hauptunternehmen zu suchen** und auf "**Übernahmen**" zu klicken. Dort sehen Sie andere Unternehmen, die vom Hauptunternehmen übernommen wurden.\
Eine andere Möglichkeit besteht darin, die **Wikipedia**-Seite des Hauptunternehmens zu besuchen und nach **Übernahmen** zu suchen.

> Ok, zu diesem Zeitpunkt sollten Sie alle Unternehmen im Rahmen kennen. Lassen Sie uns herausfinden, wie man ihre Vermögenswerte findet.

### **ASNs**

Eine autonome Systemnummer (**ASN**) ist eine **eindeutige Nummer**, die einem **autonomen System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, die eine klar definierte Richtlinie für den Zugriff auf externe Netzwerke haben und von einer einzigen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant zu erfahren, ob das **Unternehmen eine ASN zugewiesen hat**, um seine **IP-Bereiche zu finden**. Es wird interessant sein, einen **Vulnerabilitätstest** gegen alle **Hosts** im **Rahmen** durchzuführen und nach Domains innerhalb dieser IPs zu suchen.\
Sie können nach Unternehmensnamen, nach **IP** oder nach **Domain** unter [**https://bgp.he.net/**](https://bgp.he.net)** suchen.**\
**Je nach Region des Unternehmens könnten diese Links nützlich sein, um mehr Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Wie auch immer, wahrscheinlich erscheinen bereits alle** nützlichen Informationen **(IP-Bereiche und Whois)** im ersten Link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Auch die Subdomain-Enumeration von [**BBOT**](https://github.com/blacklanternsecurity/bbot) aggregiert und fasst automatisch ASNs am Ende des Scans zusammen.
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
Sie können die IP-Bereiche einer Organisation auch unter Verwendung von [http://asnlookup.com/](http://asnlookup.com) (es hat eine kostenlose API) finden.\
Sie können die IP und ASN einer Domain unter Verwendung von [http://ipv4info.com/](http://ipv4info.com) finden.

### **Suche nach Schwachstellen**

Zu diesem Zeitpunkt kennen wir **alle Assets im Umfang**, daher könnten Sie, wenn Sie dazu berechtigt sind, einen **Vulnerability Scanner** (Nessus, OpenVAS) über alle Hosts starten.\
Außerdem könnten Sie einige [**Portscans**](../pentesting-network/#discovering-hosts-from-the-outside) durchführen **oder Dienste wie** Shodan **verwenden, um** offene Ports **zu finden, und je nachdem, was Sie finden, sollten Sie** in diesem Buch nachsehen, wie Sie verschiedene mögliche Dienste pentesten können.\
**Außerdem könnte es sich lohnen zu erwähnen, dass Sie auch einige** Standardbenutzername **und** Passwortlisten **vorbereiten und versuchen können, Dienste mit [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) zu brute-forcen.

## Domains

> Wir kennen alle Unternehmen im Umfang und ihre Assets, es ist Zeit, die Domains im Umfang zu finden.

_Bitte beachten Sie, dass Sie in den folgenden vorgeschlagenen Techniken auch Subdomains finden können und diese Informationen nicht unterschätzt werden sollten._

Zunächst sollten Sie nach den **Hauptdomains** jedes Unternehmens suchen. Zum Beispiel ist für _Tesla Inc._ wird es _tesla.com_ sein.

### **Reverse DNS**

Da Sie alle IP-Bereiche der Domains gefunden haben, könnten Sie versuchen, **Reverse-DNS-Lookups** auf diesen **IPs durchzuführen, um mehr Domains im Umfang zu finden**. Versuchen Sie, einige DNS-Server des Opfers oder einige bekannte DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
### **Rückwärtssuche Whois (Schleife)**

Innerhalb eines **whois** können Sie viele interessante **Informationen** wie **Organisationsname**, **Adresse**, **E-Mails**, Telefonnummern finden... Aber noch interessanter ist, dass Sie **weitere Assets im Zusammenhang mit dem Unternehmen** finden können, wenn Sie **Rückwärtssuchen Whois nach einem dieser Felder durchführen** (zum Beispiel in anderen Whois-Registern, in denen dieselbe E-Mail erscheint).\
Sie können Online-Tools wie folgt verwenden:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Kostenlos** web, nicht kostenloses API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht kostenlos
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Suchen)
* [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos

Sie können diese Aufgabe automatisieren, indem Sie [**DomLink** ](https://github.com/vysecurity/DomLink)verwenden (erfordert einen Whoxy-API-Schlüssel).\
Sie können auch einige automatische Rückwärtssuchen Whois-Entdeckungen mit [amass](https://github.com/OWASP/Amass) durchführen: `amass intel -d tesla.com -whois`

**Beachten Sie, dass Sie diese Technik verwenden können, um jedes Mal, wenn Sie eine neue Domain finden, weitere Domainnamen zu entdecken.**

### **Tracker**

Wenn Sie die **gleiche ID des gleichen Trackers** auf 2 verschiedenen Seiten finden, können Sie davon ausgehen, dass **beide Seiten** vom selben Team **verwaltet werden**.\
Zum Beispiel, wenn Sie dieselbe **Google Analytics ID** oder dieselbe **Adsense ID** auf mehreren Seiten sehen.

Es gibt einige Seiten und Tools, mit denen Sie nach diesen Trackern und mehr suchen können:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Wussten Sie, dass wir verwandte Domains und Subdomains zu unserem Ziel finden können, indem wir nach demselben Favicon-Symbol-Hash suchen? Genau das macht das [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)-Tool von [@m4ll0k2](https://twitter.com/m4ll0k2). So verwenden Sie es:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - Domains mit demselben Favicon-Symbol-Hash entdecken](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach ausgedrückt ermöglicht es uns favihash, Domains zu entdecken, die denselben Favicon-Symbol-Hash wie unser Ziel haben.

Darüber hinaus können Sie auch Technologien mithilfe des Favicon-Hash suchen, wie in [**diesem Blog-Beitrag**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erklärt. Das bedeutet, dass Sie, wenn Sie den **Hash des Favicons einer verwundbaren Version einer Web-Technologie** kennen, in Shodan danach suchen können und **mehr verwundbare Stellen finden**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Das ist, wie du den **Favicon-Hash** einer Webseite berechnen kannst:
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
### **Urheberrecht / Eindeutiger String**

Suchen Sie in den Webseiten nach **Zeichenfolgen, die in verschiedenen Websites derselben Organisation geteilt werden könnten**. Die **Urheberrechtszeichenfolge** könnte ein gutes Beispiel sein. Suchen Sie dann nach dieser Zeichenfolge in **Google**, in anderen **Browsern** oder sogar in **Shodan**: `shodan search http.html:"Urheberrechtszeichenfolge"`

### **CRT-Zeit**

Es ist üblich, einen Cron-Job wie folgt zu haben:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### Externe Recherche-Methodik

Um alle Domain-Zertifikate auf dem Server zu erneuern. Dies bedeutet, dass selbst wenn die CA, die für dies verwendet wird, die Zeit, zu der sie generiert wurde, nicht im Gültigkeitszeitraum festlegt, es möglich ist, **Domains, die demselben Unternehmen gehören, in den Zertifikatstransparenz-Logs zu finden**.\
Schauen Sie sich dieses [**Writeup für weitere Informationen**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/) an.

### Mail DMARC-Informationen

Sie können eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen teilen**.

### **Passive Übernahme**

Es ist anscheinend üblich, dass Personen Subdomains IPs zuweisen, die Cloud-Anbietern gehören, und irgendwann **diese IP-Adresse verlieren, aber vergessen, den DNS-Eintrag zu entfernen**. Daher wird durch das **Starten einer VM** in einer Cloud (wie Digital Ocean) tatsächlich **die Kontrolle über einige Subdomains übernommen**.

[**Dieser Beitrag**](https://kmsec.uk/blog/passive-takeover/) erklärt eine Geschichte darüber und schlägt ein Skript vor, das **eine VM in DigitalOcean startet**, die **IPv4** des neuen Geräts **abruft** und in Virustotal nach Subdomain-Einträgen sucht, die darauf verweisen.

### **Andere Methoden**

**Beachten Sie, dass Sie diese Technik verwenden können, um jedes Mal, wenn Sie eine neue Domain finden, weitere Domainnamen zu entdecken.**

**Shodan**

Da Sie bereits den Namen der Organisation kennen, die den IP-Bereich besitzt, können Sie in Shodan nach diesen Daten suchen: `org:"Tesla, Inc."` Überprüfen Sie die gefundenen Hosts auf neue unerwartete Domains im TLS-Zertifikat.

Sie könnten auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisationsnamen** erhalten und dann nach diesem Namen in den **TLS-Zertifikaten** aller Webseiten suchen, die von **Shodan** bekannt sind, mit dem Filter: `ssl:"Tesla Motors"` oder verwenden Sie ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **mit einer Hauptdomain verbundenen Domains** und **Subdomains** von ihnen sucht, ziemlich erstaunlich.

### **Suche nach Schwachstellen**

Überprüfen Sie auf [Domain-Übernahmen](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Möglicherweise verwendet ein Unternehmen **eine Domain**, hat aber **die Eigentümerschaft verloren**. Registrieren Sie sie einfach (wenn sie billig genug ist) und informieren Sie das Unternehmen.

Wenn Sie eine **Domain mit einer anderen IP** als denjenigen finden, die Sie bereits in der Assets-Entdeckung gefunden haben, sollten Sie einen **grundlegenden Schwachstellen-Scan** durchführen (mit Nessus oder OpenVAS) und einen [**Port-Scan**](../pentesting-network/#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste ausgeführt werden, können Sie in **diesem Buch einige Tricks finden, um sie "anzugreifen"**.\
_Beachten Sie, dass die Domain manchmal in einer IP gehostet wird, die nicht vom Kunden kontrolliert wird, daher nicht im Scope liegt. Seien Sie vorsichtig._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns noch heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und beginnen Sie, Prämien von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomains

> Wir kennen alle Unternehmen im Scope, alle Vermögenswerte jedes Unternehmens und alle mit den Unternehmen verbundenen Domains.

Es ist an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu finden.

{% hint style="success" %}
Beachten Sie, dass einige der Tools und Techniken zur Auffindung von Domains auch zur Auffindung von Subdomains beitragen können!
{% endhint %}

### **DNS**

Lassen Sie uns versuchen, **Subdomains** aus den **DNS**-Einträgen zu erhalten. Wir sollten auch nach **Zone Transfer** suchen (Wenn anfällig, sollten Sie es melden).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Der schnellste Weg, um viele Subdomains zu erhalten, besteht darin, in externen Quellen zu suchen. Die am häufigsten verwendeten **Tools** sind die folgenden (für bessere Ergebnisse konfigurieren Sie die API-Schlüssel):

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
Es gibt **andere interessante Tools/APIs**, die zwar nicht direkt auf die Suche nach Subdomains spezialisiert sind, aber dennoch nützlich sein können, um Subdomains zu finden, wie:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um Subdomains zu erhalten
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC kostenlose API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) kostenlose API
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
* [**gau**](https://github.com/lc/gau)**:** ruft bekannte URLs von AlienVault's Open Threat Exchange, der Wayback Machine und Common Crawl für eine beliebige Domain ab.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Sie durchsuchen das Web nach JS-Dateien und extrahieren Subdomains daraus.
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
* [**Censys Subdomain Finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) bietet eine kostenlose API zur Suche nach Subdomains und IP-Verlauf
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle mit Bug-Bounty-Programmen verbundenen Subdomains** an. Sie können auch auf diese Daten zugreifen, indem Sie [chaospy](https://github.com/dr-0x0x/chaospy) verwenden oder sogar auf den Umfang zugreifen, der von diesem Projekt verwendet wird [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Sie finden hier einen **Vergleich** vieler dieser Tools: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS-Brute-Force**

Versuchen wir, neue **Subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen brute-forcen.

Für diese Aktion benötigen Sie einige **übliche Subdomain-Wordlists wie**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Und auch IPs von guten DNS-Resolvern. Um eine Liste vertrauenswürdiger DNS-Resolver zu generieren, können Sie die Resolver von [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) herunterladen und [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) verwenden, um sie zu filtern. Oder Sie könnten verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die empfohlensten Tools für DNS-Brute-Force sind:

* [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das einen effektiven DNS-Brute-Force durchführte. Es ist sehr schnell, jedoch anfällig für falsche Positiven.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Ich glaube, dieser verwendet nur 1 Resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, der es ermöglicht, gültige Subdomains mittels aktiver Bruteforce aufzulisten, sowie Subdomains mit Wildcard-Handling aufzulösen und eine einfache Ein- und Ausgabesteuerung zu ermöglichen.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Es verwendet auch `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron zu brute-forcen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS-Brute-Force-Runde

Nachdem Sie Subdomains mithilfe von Open-Quellen und Brute-Force gefunden haben, könnten Sie Variationen der gefundenen Subdomains generieren, um noch mehr zu finden. Mehrere Tools sind für diesen Zweck nützlich:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Generiert Permutationen von Domains und Subdomains.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Angenommen die Domains und Subdomains generieren Permutationen.
* Du kannst die goaltdns Permutationen **Wortliste** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) erhalten.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Angesichts der Domains und Subdomains generieren Sie Permutationen. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Neben der Generierung von Subdomain-Permutationen kann es auch versuchen, sie aufzulösen (aber es ist besser, die zuvor kommentierten Tools zu verwenden).
* Du kannst die altdns Permutationen **Wortliste** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) bekommen.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zur Durchführung von Permutationen, Mutationen und Änderungen von Subdomains. Dieses Tool wird das Ergebnis per Bruteforce erzwingen (es unterstützt keine DNS-Wildcards).
* Sie können die dmut-Permutationswortliste [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) erhalten.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es neue potenzielle Subdomain-Namen** basierend auf angegebenen Mustern, um mehr Subdomains zu entdecken.

#### Intelligente Permutationserzeugung

* [**regulator**](https://github.com/cramppet/regulator): Für weitere Informationen lesen Sie diesen [**Beitrag**](https://cramppet.github.io/regulator/index.html), aber es wird im Wesentlichen die **Hauptteile** der **entdeckten Subdomains** erhalten und sie mischen, um mehr Subdomains zu finden.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven DNS-Antwort-geführten Algorithmus gekoppelt ist. Er nutzt einen bereitgestellten Satz von Eingabedaten, wie z.B. eine maßgeschneiderte Wortliste oder historische DNS/TLS-Einträge, um genauere entsprechende Domänennamen zu synthetisieren und sie basierend auf den während des DNS-Scans gesammelten Informationen weiter zu erweitern.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Überprüfen Sie diesen Blog-Beitrag, den ich darüber geschrieben habe, wie Sie die **automatische Entdeckung von Subdomains** von einer Domain mithilfe von **Trickest-Workflows** durchführen können, sodass ich nicht manuell eine Vielzahl von Tools auf meinem Computer starten muss:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtuelle Hosts**

Wenn Sie eine IP-Adresse gefunden haben, die **eine oder mehrere Webseiten** von Subdomains enthält, könnten Sie versuchen, **andere Subdomains mit Websites auf dieser IP zu finden**, indem Sie in **OSINT-Quellen** nach Domains in einer IP suchen oder indem Sie **VHost-Domänennamen auf dieser IP durch Brute-Force erzwingen**.

#### OSINT

Sie können einige **VHosts in IPs finden, indem Sie** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder andere APIs verwenden**.

**Brute Force**

Wenn Sie vermuten, dass sich eine Subdomain auf einem Webserver verstecken könnte, könnten Sie versuchen, diese durch Brute-Force zu erzwingen:
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
Mit dieser Technik können Sie möglicherweise sogar auf interne/versteckte Endpunkte zugreifen.
{% endhint %}

### **CORS-Brute-Force**

Manchmal finden Sie Seiten, die nur den Header _**Access-Control-Allow-Origin**_ zurückgeben, wenn eine gültige Domain/Unterdomäne im _**Origin**_-Header festgelegt ist. In solchen Szenarien können Sie dieses Verhalten missbrauchen, um neue **Subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Eimer-Brute-Force**

Beim Suchen nach **Subdomains** achten Sie darauf, ob diese auf einen **Eimer** verweisen, und in diesem Fall [**überprüfen Sie die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Außerdem, da Sie zu diesem Zeitpunkt alle Domains im Scope kennen, versuchen Sie, [**mögliche Eimernamen zu brute-forcen und die Berechtigungen zu überprüfen**](../../network-services-pentesting/pentesting-web/buckets/).

### **Überwachung**

Sie können **überwachen**, ob **neue Subdomains** einer Domain erstellt werden, indem Sie die **Certificate Transparency**-Logs überwachen, was [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) tut.

### **Suche nach Schwachstellen**

Überprüfen Sie mögliche [**Subdomain-Übernahmen**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3-Eimer** verweist, [**überprüfen Sie die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/).

Wenn Sie eine **Subdomain mit einer anderen IP** als denjenigen finden, die Sie bereits bei der Assets-Erkennung gefunden haben, sollten Sie einen **grundlegenden Schwachstellen-Scan** durchführen (mit Nessus oder OpenVAS) und einen [**Port-Scan**](../pentesting-network/#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste ausgeführt werden, können Sie in **diesem Buch einige Tricks finden, um sie "anzugreifen"**.\
_Beachten Sie, dass die Subdomain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird, daher nicht im Scope liegt. Seien Sie vorsichtig._

## IPs

In den ersten Schritten haben Sie möglicherweise **einige IP-Bereiche, Domains und Subdomains gefunden**.\
Es ist an der Zeit, **alle IPs aus diesen Bereichen zu sammeln** und für die **Domains/Subdomains (DNS-Abfragen)**.

Mit Diensten der folgenden **kostenlosen APIs** können Sie auch **frühere IPs finden, die von Domains und Subdomains verwendet wurden**. Diese IPs könnten immer noch im Besitz des Kunden sein (und könnten es Ihnen ermöglichen, [**CloudFlare-Bypasses zu finden**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Sie können auch nach Domains suchen, die auf eine bestimmte IP-Adresse verweisen, mithilfe des Tools [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Suche nach Schwachstellen**

**Scannen Sie alle IPs, die nicht zu CDNs gehören** (da Sie höchstwahrscheinlich nichts Interessantes finden werden). In den entdeckten laufenden Diensten könnten Sie **Schwachstellen finden**.

**Finden Sie einen** [**Leitfaden**](../pentesting-network/) **zum Scannen von Hosts.**

## Webserver-Suche

> Wir haben alle Unternehmen und ihre Vermögenswerte gefunden und kennen die IP-Bereiche, Domains und Subdomains im Scope. Es ist Zeit, nach Webservern zu suchen.

In den vorherigen Schritten haben Sie wahrscheinlich bereits einige **Rekognoszierungen der entdeckten IPs und Domains** durchgeführt, sodass Sie möglicherweise **bereits alle möglichen Webserver gefunden haben**. Wenn nicht, werden wir jetzt einige **schnelle Tricks zum Suchen von Webservern** im Scope sehen.

Bitte beachten Sie, dass dies auf die **Entdeckung von Webanwendungen ausgerichtet sein wird**, daher sollten Sie auch die **Schwachstellen** und **Port-Scans** durchführen (**falls im Scope erlaubt**).

Eine **schnelle Methode** zum Entdecken von **offenen Ports** in Bezug auf **Webserver** mit [**masscan finden Sie hier**](../pentesting-network/#http-port-discovery).\
Ein weiteres benutzerfreundliches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Sie geben einfach eine Liste von Domains ein und es wird versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Darüber hinaus können Sie angeben, auch andere Ports zu versuchen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Nun, da Sie **alle Webserver** im Umfang entdeckt haben (unter den **IPs** des Unternehmens und allen **Domains** und **Subdomains**), wissen Sie wahrscheinlich **nicht, wo Sie anfangen sollen**. Also, machen wir es einfach und fangen einfach an, Screenshots von allen zu machen. Schon beim **Blick auf die Hauptseite** können Sie **seltsame** Endpunkte finden, die anfälliger für **Schwachstellen** sind.

Um die vorgeschlagene Idee umzusetzen, können Sie [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** verwenden.

Darüber hinaus könnten Sie dann [**eyeballer**](https://github.com/BishopFox/eyeballer) verwenden, um alle **Screenshots** zu durchsuchen und Ihnen mitzuteilen, **was wahrscheinlich Schwachstellen enthält** und was nicht.

## Öffentliche Cloud-Ressourcen

Um potenzielle Cloud-Ressourcen eines Unternehmens zu finden, sollten Sie mit einer Liste von Schlüsselwörtern beginnen, die dieses Unternehmen identifizieren. Zum Beispiel könnten Sie für ein Krypto-Unternehmen Wörter wie: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Sie benötigen auch Wortlisten von **üblichen Wörtern, die in Buckets verwendet werden**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dann sollten Sie mit diesen Wörtern **Permutationen generieren** (überprüfen Sie die [**Second Round DNS Brute-Force**](./#second-dns-bruteforce-round) für weitere Informationen).

Mit den resultierenden Wortlisten könnten Sie Tools wie [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**, [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**, [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.

Denken Sie daran, dass Sie bei der Suche nach Cloud-Ressourcen **mehr als nur Buckets in AWS** suchen sollten.

### **Suche nach Schwachstellen**

Wenn Sie auf Dinge wie **offene Buckets oder freigegebene Cloud-Funktionen** stoßen, sollten Sie **darauf zugreifen** und versuchen zu sehen, was sie Ihnen bieten und ob Sie sie missbrauchen können.

## E-Mails

Mit den **Domains** und **Subdomains** im Umfang haben Sie im Grunde alles, was Sie brauchen, um nach E-Mails zu suchen. Dies sind die **APIs** und **Tools**, die für mich am besten funktioniert haben, um E-Mails eines Unternehmens zu finden:

* [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
* API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
* API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
* API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Suche nach Schwachstellen**

E-Mails werden später nützlich sein, um **Web-Logins und Authentifizierungsdienste per Brute-Force anzugreifen** (wie z. B. SSH). Außerdem sind sie für **Phishing** erforderlich. Darüber hinaus geben Ihnen diese APIs noch mehr **Informationen über die Person** hinter der E-Mail, was für die Phishing-Kampagne nützlich ist.

## Zugangsdaten-Leaks

Mit den **Domains**, **Subdomains** und **E-Mails** können Sie damit beginnen, nach in der Vergangenheit geleakten Zugangsdaten zu suchen, die diesen E-Mails gehören:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Suche nach Schwachstellen**

Wenn Sie **gültige geleakte** Zugangsdaten finden, ist dies ein sehr einfacher Erfolg.

## Geheimnis-Leaks

Zugangsdaten-Leaks stehen im Zusammenhang mit Hacks von Unternehmen, bei denen **sensible Informationen geleakt und verkauft** wurden. Unternehmen könnten jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken enthalten sind:

### Github-Leaks

Zugangsdaten und APIs könnten in den **öffentlichen Repositories** des **Unternehmens** oder der **Benutzer** geleakt werden, die für dieses Github-Unternehmen arbeiten.\
Sie können das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** herunterzuladen und automatisch [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber laufen zu lassen.

**Leakos** kann auch verwendet werden, um **gitleaks** gegen alle **übergebenen URLs** auszuführen, da manchmal **Webseiten auch Geheimnisse enthalten**.

#### Github-Dorks

Überprüfen Sie auch diese **Seite** nach potenziellen **Github-Dorks**, nach denen Sie in der angegriffenen Organisation suchen könnten:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes-Leaks

Manchmal veröffentlichen Angreifer oder einfach Mitarbeiter Unternehmensinhalte auf einer Paste-Seite. Dies könnte sensible Informationen enthalten oder auch nicht, aber es ist sehr interessant, danach zu suchen.\
Sie können das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 Paste-Seiten zu suchen.

### Google-Dorks

Alte, aber bewährte Google-Dorks sind immer nützlich, um **exponierte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausende** möglicher Abfragen enthält, die Sie nicht manuell ausführen können. Sie können also Ihre Lieblings-10 auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Beachten Sie, dass die Tools, die erwarten, die gesamte Datenbank mit dem regulären Google-Browser auszuführen, niemals enden werden, da Google Sie sehr bald blockieren wird._

### **Suche nach Schwachstellen**

Wenn Sie **gültige geleakte** Zugangsdaten oder API-Token finden, ist dies ein sehr einfacher Erfolg.

## Öffentliche Code-Schwachstellen

Wenn Sie feststellen, dass das Unternehmen **Open-Source-Code** hat, können Sie diesen **analysieren** und nach **Schwachstellen** suchen.

Je nach Sprache gibt es verschiedene **Tools**, die Sie verwenden können:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Es gibt auch kostenlose Dienste, die es Ihnen ermöglichen, **öffentliche Repositories zu scannen**, wie:

* [**Snyk**](https://app.snyk.io/)
## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

Die **Mehrheit der Schwachstellen**, die von Bug Bounty Jägern gefunden werden, befindet sich in **Webanwendungen**, daher möchte ich an dieser Stelle über eine **Webanwendungstestmethodik** sprechen, die Sie [**hier finden können**](../../network-services-pentesting/pentesting-web/).

Ich möchte auch einen speziellen Hinweis auf den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/#automatic-scanners) geben, da sie zwar nicht unbedingt sehr sensible Schwachstellen finden, aber nützlich sind, um sie in **Workflows zur Erstellung von anfänglichen Webinformationen zu implementieren**.

## Zusammenfassung

> Herzlichen Glückwunsch! Zu diesem Zeitpunkt haben Sie bereits **alle grundlegenden Enumerationen** durchgeführt. Ja, es ist grundlegend, da noch viel mehr Enumerationen durchgeführt werden können (weitere Tricks werden später besprochen).

Sie haben also bereits:

1. Alle **Unternehmen** im Scope gefunden
2. Alle **Assets** der Unternehmen gefunden (und bei Bedarf einen Schwachstellenscan durchgeführt)
3. Alle **Domains** der Unternehmen gefunden
4. Alle **Subdomains** der Domains gefunden (gibt es eine Möglichkeit zur Übernahme von Subdomains?)
5. Alle **IPs** (von und **nicht von CDNs**) im Scope gefunden.
6. Alle **Webserver** gefunden und von ihnen einen **Screenshot** gemacht (gibt es etwas Seltsames, das genauer betrachtet werden sollte?)
7. Alle **potenziellen öffentlichen Cloud-Ressourcen** des Unternehmens gefunden.
8. **E-Mails**, **Zugangsdaten-Leaks** und **Geheimnis-Leaks**, die Ihnen einen **großen Gewinn sehr einfach** ermöglichen könnten.
9. **Pentesting aller von Ihnen gefundenen Websites**

## **Vollständige automatische Recon-Tools**

Es gibt mehrere Tools, die einen Teil der vorgeschlagenen Aktionen gegen einen bestimmten Scope durchführen werden.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ein wenig veraltet und nicht aktualisiert

## **Referenzen**

* Alle kostenlosen Kurse von [**@Jhaddix**](https://twitter.com/Jhaddix) wie [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Wenn Sie an einer **Hackerkarriere** interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
