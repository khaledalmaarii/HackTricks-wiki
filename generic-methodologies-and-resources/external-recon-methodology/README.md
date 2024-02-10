# Externe Recherche-Methodik

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug-Bounty-Tipp**: **Registrieren** Sie sich für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns noch heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und verdienen Sie Prämien von bis zu **100.000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Entdeckung von Assets

> Man hat Ihnen gesagt, dass alles, was einem Unternehmen gehört, zum Umfang gehört, und Sie möchten herausfinden, was dieses Unternehmen tatsächlich besitzt.

Das Ziel dieser Phase ist es, alle **Unternehmen, die dem Hauptunternehmen gehören**, und dann alle **Assets** dieser Unternehmen zu erhalten. Dazu gehen wir folgendermaßen vor:

1. Finden Sie die Übernahmen des Hauptunternehmens, dies gibt uns die Unternehmen im Umfang.
2. Finden Sie die ASN (falls vorhanden) jedes Unternehmens, dies gibt uns die IP-Bereiche, die von jedem Unternehmen besessen werden.
3. Verwenden Sie Reverse Whois-Lookups, um nach anderen Einträgen (Organisationsnamen, Domains usw.) im Zusammenhang mit dem ersten Eintrag zu suchen (dies kann rekursiv erfolgen).
4. Verwenden Sie andere Techniken wie Shodan `org` und `ssl`-Filter, um nach anderen Assets zu suchen (der `ssl`-Trick kann rekursiv durchgeführt werden).

### **Übernahmen**

Zunächst müssen wir wissen, welche **anderen Unternehmen dem Hauptunternehmen gehören**.\
Eine Möglichkeit besteht darin, [https://www.crunchbase.com/](https://www.crunchbase.com) zu besuchen, nach dem **Hauptunternehmen zu suchen** und auf "**Übernahmen**" zu klicken. Dort sehen Sie andere Unternehmen, die vom Hauptunternehmen übernommen wurden.\
Eine andere Möglichkeit besteht darin, die **Wikipedia**-Seite des Hauptunternehmens zu besuchen und nach **Übernahmen** zu suchen.

> Ok, zu diesem Zeitpunkt sollten Sie alle Unternehmen im Umfang kennen. Lassen Sie uns herausfinden, wie wir ihre Assets finden können.

### **ASNs**

Eine autonome Systemnummer (**ASN**) ist eine **eindeutige Nummer**, die einem **autonomen System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, die eine klar definierte Richtlinie für den Zugriff auf externe Netzwerke haben und von einer einzigen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant zu wissen, ob das **Unternehmen einer ASN zugewiesen hat**, um seine **IP-Bereiche** zu finden. Es ist interessant, einen **Schwachstellentest** gegen alle **Hosts** im **Umfang** durchzuführen und nach Domains innerhalb dieser IPs zu suchen.\
Sie können nach dem **Firmennamen**, nach **IP** oder nach **Domain** in [**https://bgp.he.net/**](https://bgp.he.net)** suchen.**\
**Je nach Region des Unternehmens könnten diese Links nützlich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Wahrscheinlich erscheinen jedoch bereits in dem ersten Link alle** nützlichen Informationen **(IP-Bereiche und Whois)**.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Außerdem aggregiert und fasst die Subdomain-Ermittlung von [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatisch ASNs am Ende des Scans zusammen.
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
Sie können die IP-Bereiche einer Organisation auch mit [http://asnlookup.com/](http://asnlookup.com) (es hat eine kostenlose API) finden.\
Sie können die IP und ASN einer Domain mit [http://ipv4info.com/](http://ipv4info.com) finden.

### **Suche nach Schwachstellen**

An diesem Punkt kennen wir **alle Assets im Umfang**, daher können Sie, sofern erlaubt, einen **Schwachstellenscanner** (Nessus, OpenVAS) auf allen Hosts starten.\
Sie können auch einige [**Portscans**](../pentesting-network/#discovering-hosts-from-the-outside) durchführen **oder Dienste wie** Shodan **verwenden, um** offene Ports **zu finden und je nachdem, was Sie finden, sollten Sie in diesem Buch nachsehen, wie Sie verschiedene mögliche Dienste pentesten können.\
**Es könnte auch sinnvoll sein zu erwähnen, dass Sie auch einige** Standard-Benutzernamen **und** Passwortlisten **vorbereiten und versuchen können, Dienste mit [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) zu brute-forcen.

## Domains

> Wir kennen alle Unternehmen im Umfang und ihre Assets, es ist Zeit, die Domains im Umfang zu finden.

_Beachten Sie bitte, dass Sie in den folgenden vorgeschlagenen Techniken auch Subdomains finden können und diese Informationen nicht unterschätzt werden sollten._

Zunächst sollten Sie nach der **Hauptdomain**(en) jedes Unternehmens suchen. Zum Beispiel ist es für _Tesla Inc._ _tesla.com_.

### **Reverse DNS**

Da Sie alle IP-Bereiche der Domains gefunden haben, können Sie versuchen, **Reverse DNS-Lookups** auf diesen IPs durchzuführen, um weitere Domains im Umfang zu finden. Versuchen Sie, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit dies funktioniert, muss der Administrator PTR manuell aktivieren.\
Sie können auch ein Online-Tool für diese Informationen verwenden: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (Schleife)**

In einem **Whois** können Sie viele interessante **Informationen** wie den **Organisationsnamen**, die **Adresse**, **E-Mails**, Telefonnummern usw. finden. Aber noch interessanter ist, dass Sie **weitere Assets im Zusammenhang mit dem Unternehmen** finden können, wenn Sie **Reverse Whois-Lookups nach einem dieser Felder** durchführen (zum Beispiel andere Whois-Register, in denen dieselbe E-Mail erscheint).\
Sie können Online-Tools wie folgt verwenden:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Kostenlos** (Web, nicht kostenloses API).
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht kostenlos
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Suchanfragen)
* [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos

Sie können diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (erfordert einen Whoxy-API-Schlüssel).\
Sie können auch mit [amass](https://github.com/OWASP/Amass) eine automatische Reverse-Whois-Entdeckung durchführen: `amass intel -d tesla.com -whois`

**Beachten Sie, dass Sie diese Technik verwenden können, um jedes Mal, wenn Sie eine neue Domain finden, weitere Domainnamen zu entdecken.**

### **Tracker**

Wenn Sie dieselbe ID des gleichen Trackers auf 2 verschiedenen Seiten finden, können Sie davon ausgehen, dass **beide Seiten vom selben Team verwaltet werden**.\
Zum Beispiel, wenn Sie dieselbe **Google Analytics ID** oder dieselbe **Adsense ID** auf mehreren Seiten sehen.

Es gibt einige Seiten und Tools, mit denen Sie nach diesen Trackern und mehr suchen können:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Wussten Sie, dass wir durch die Suche nach demselben Favicon-Icon-Hash verwandte Domains und Subdomains zu unserem Ziel finden können? Genau das macht das Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) von [@m4ll0k2](https://twitter.com/m4ll0k2). So verwenden Sie es:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - Domains mit demselben Favicon-Icon-Hash entdecken](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt ermöglicht es uns favihash, Domains zu entdecken, die denselben Favicon-Icon-Hash wie unser Ziel haben.

Darüber hinaus können Sie auch Technologien suchen, indem Sie den Favicon-Hash verwenden, wie in [**diesem Blog-Beitrag**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erklärt. Das bedeutet, dass Sie, wenn Sie den **Hash des Favicon einer verwundbaren Version einer Web-Technologie** kennen, in Shodan suchen können und **weitere verwundbare Orte finden**.
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
So berechnen Sie den **Favicon-Hash** einer Webseite:

1. Laden Sie das Favicon der Webseite herunter.
2. Konvertieren Sie das Favicon-Bild in das PNG-Format, falls es nicht bereits in diesem Format vorliegt.
3. Verwenden Sie einen Hash-Algorithmus wie MD5 oder SHA-256, um den Hash-Wert des Favicon-Bildes zu berechnen.
4. Der berechnete Hash-Wert ist der Favicon-Hash der Webseite.

Beispiel für die Berechnung des Favicon-Hashes mit dem MD5-Algorithmus:

```bash
$ wget http://example.com/favicon.ico -O favicon.ico
$ convert favicon.ico favicon.png
$ md5sum favicon.png
```

Beispiel für die Berechnung des Favicon-Hashes mit dem SHA-256-Algorithmus:

```bash
$ wget http://example.com/favicon.ico -O favicon.ico
$ convert favicon.ico favicon.png
$ sha256sum favicon.png
```

Bitte beachten Sie, dass der Favicon-Hash dazu verwendet werden kann, um nach ähnlichen oder identischen Favicons auf anderen Webseiten zu suchen. Dies kann bei der Identifizierung von verwandten Webseiten oder bei der Erkennung von Phishing-Versuchen hilfreich sein.
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

Suchen Sie in den Webseiten nach **Zeichenketten, die in verschiedenen Websites derselben Organisation geteilt werden könnten**. Die **Urheberrechtszeichenkette** könnte ein gutes Beispiel sein. Suchen Sie dann nach dieser Zeichenkette in **Google**, in anderen **Browsern** oder sogar in **Shodan**: `shodan search http.html:"Urheberrechtszeichenkette"`

### **CRT-Zeit**

Es ist üblich, einen Cron-Job wie folgt zu haben:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Um alle Domain-Zertifikate auf dem Server zu erneuern. Dies bedeutet, dass selbst wenn die CA, die dafür verwendet wird, die Zeit, zu der es generiert wurde, nicht in der Gültigkeitszeit angibt, es möglich ist, **Domains, die zu derselben Firma gehören, in den Zertifikatstransparenz-Logs zu finden**.\
Schauen Sie sich diese [**Informationen für weitere Informationen**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/) an.

### **Passive Übernahme**

Es ist anscheinend üblich, dass Personen Subdomains IP-Adressen zuweisen, die zu Cloud-Anbietern gehören, und zu einem bestimmten Zeitpunkt **diese IP-Adresse verlieren, aber vergessen, den DNS-Eintrag zu entfernen**. Daher wird durch das **Starten einer VM** in einer Cloud (wie Digital Ocean) tatsächlich **einige Subdomains übernommen**.

[**Dieser Beitrag**](https://kmsec.uk/blog/passive-takeover/) erklärt eine Geschichte darüber und schlägt ein Skript vor, das eine VM in DigitalOcean **startet**, die **IPv4** der neuen Maschine **erhält** und in Virustotal nach Subdomain-Einträgen sucht, die darauf verweisen.

### **Andere Möglichkeiten**

**Beachten Sie, dass Sie diese Technik verwenden können, um jedes Mal, wenn Sie eine neue Domain finden, weitere Domainnamen zu entdecken**.

**Shodan**

Da Sie bereits den Namen der Organisation kennen, die den IP-Bereich besitzt, können Sie in Shodan danach suchen, indem Sie Folgendes verwenden: `org:"Tesla, Inc."` Überprüfen Sie die gefundenen Hosts auf neue unerwartete Domains im TLS-Zertifikat.

Sie könnten auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisationsnamen** erhalten und dann nach diesem Namen in den **TLS-Zertifikaten** aller von **Shodan** bekannten Webseiten suchen, die den Filter verwenden: `ssl:"Tesla Motors"` oder verwenden Sie ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **mit einer Hauptdomain zusammenhängenden Domains** und **Subdomains** von ihnen sucht, ziemlich erstaunlich.

### **Nach Schwachstellen suchen**

Überprüfen Sie auf [Domain-Übernahme](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Möglicherweise verwendet ein Unternehmen eine Domain, hat jedoch das Eigentum daran verloren. Registrieren Sie sie einfach (wenn sie billig genug ist) und informieren Sie das Unternehmen.

Wenn Sie eine **Domain mit einer anderen IP** als denjenigen finden, die Sie bereits in der Assets-Erkennung gefunden haben, sollten Sie einen **grundlegenden Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**Portscan**](../pentesting-network/#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste ausgeführt werden, können Sie in **diesem Buch einige Tricks finden, um sie "anzugreifen"**.\
Beachten Sie, dass die Domain manchmal in einer IP gehostet wird, die nicht vom Client kontrolliert wird, daher nicht im Scope liegt. Seien Sie vorsichtig.

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug-Bounty-Tipp**: **Melden Sie sich** bei **Intigriti** an, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker** entwickelt wurde! Treten Sie uns noch heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und verdienen Sie Prämien von bis zu **100.000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomains

> Wir kennen alle Unternehmen im Scope, alle Assets jedes Unternehmens und alle mit den Unternehmen verbundenen Domains.

Es ist an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu finden.

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Einträgen zu erhalten. Wir sollten auch nach **Zone Transfer** suchen (Wenn verwundbar, sollten Sie es melden).
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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/de-de)
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
Es gibt **weitere interessante Tools/APIs**, die zwar nicht direkt auf das Auffinden von Subdomains spezialisiert sind, aber dennoch nützlich sein können, um Subdomains zu finden, wie:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um Subdomains zu erhalten.
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
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Sie durchsuchen das Web nach JS-Dateien und extrahieren von dort aus Subdomains.
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

Dieses Projekt bietet **kostenlos alle mit Bug-Bounty-Programmen verbundenen Subdomains** an. Sie können auch auf diese Daten zugreifen, indem Sie [chaospy](https://github.com/dr-0x0x/chaospy) verwenden oder sogar auf den von diesem Projekt verwendeten Umfang zugreifen [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Eine **Vergleich** vieler dieser Tools finden Sie hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS-Brute-Force**

Versuchen wir, neue **Subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen brute-forcen.

Für diese Aktion benötigen Sie einige **gängige Subdomain-Wordlists wie**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Und auch IPs von guten DNS-Resolvern. Um eine Liste vertrauenswürdiger DNS-Resolver zu generieren, können Sie die Resolver von [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) herunterladen und [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) verwenden, um sie zu filtern. Oder Sie könnten verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die empfohlensten Tools für DNS-Brute-Force sind:

* [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das einen effektiven DNS-Brute-Force durchführte. Es ist sehr schnell, aber anfällig für falsch positive Ergebnisse.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Ich denke, dieser verwendet nur 1 Resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, der in Go geschrieben ist und es ermöglicht, gültige Subdomains durch aktives Brute-Force zu ermitteln. Außerdem können Subdomains mit Wildcard-Handling aufgelöst werden und es gibt eine einfache Ein- und Ausgabesteuerung.
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

Nachdem Sie Subdomains mithilfe von öffentlichen Quellen und Brute-Force gefunden haben, können Sie Variationen der gefundenen Subdomains generieren, um noch mehr zu finden. Mehrere Tools sind für diesen Zweck nützlich:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Generiert Permutationen basierend auf Domains und Subdomains.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Gegeben die Domains und Subdomains, generiere Permutationen.
* Du kannst die Permutationen für goaltdns **Wortliste** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) erhalten.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Gegeben die Domains und Subdomains generiert gotator Permutationen. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Neben der Generierung von Subdomain-Permutationen kann es auch versuchen, sie aufzulösen (aber es ist besser, die zuvor kommentierten Tools zu verwenden).
* Sie können die altdns-Permutationen **Wortliste** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) erhalten.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zur Durchführung von Permutationen, Mutationen und Änderungen von Subdomains. Dieses Tool wird das Ergebnis per Brute-Force-Methode ermitteln (es unterstützt keine DNS-Wildcards).
* Die dmut-Permutations-Wortliste können Sie [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) erhalten.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es neue potenzielle Subdomain-Namen** basierend auf angegebenen Mustern, um weitere Subdomains zu entdecken.

#### Intelligente Permutationserzeugung

* [**regulator**](https://github.com/cramppet/regulator): Für weitere Informationen lesen Sie diesen [**Beitrag**](https://cramppet.github.io/regulator/index.html), aber im Wesentlichen werden die **Hauptteile** der **entdeckten Subdomains** extrahiert und gemischt, um weitere Subdomains zu finden.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven DNS-Antwort-gesteuerten Algorithmus gekoppelt ist. Er verwendet eine bereitgestellte Menge an Eingabedaten, wie z.B. eine maßgeschneiderte Wortliste oder historische DNS/TLS-Einträge, um genauere entsprechende Domänennamen zu synthetisieren und sie basierend auf den während des DNS-Scans gesammelten Informationen weiter zu erweitern.
```
echo www | subzuf facebook.com
```
### **Subdomain-Entdeckungsworkflow**

Lesen Sie diesen Blogbeitrag, den ich darüber geschrieben habe, wie Sie die Subdomain-Entdeckung automatisieren können, indem Sie Trickiest-Workflows verwenden, damit ich nicht manuell eine Reihe von Tools auf meinem Computer starten muss:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtuelle Hosts**

Wenn Sie eine IP-Adresse gefunden haben, die **eine oder mehrere Webseiten** von Subdomains enthält, können Sie versuchen, **andere Subdomains mit Webseiten in dieser IP-Adresse zu finden**, indem Sie in OSINT-Quellen nach Domains in einer IP-Adresse suchen oder **VHost-Domänennamen in dieser IP-Adresse durch Brute-Force ausprobieren**.

#### OSINT

Sie können einige **VHosts in IPs finden**, indem Sie [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder andere APIs** verwenden.

**Brute Force**

Wenn Sie vermuten, dass sich eine Subdomain auf einem Webserver verstecken kann, können Sie versuchen, diese durch Brute-Force zu erzwingen:
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

Manchmal finden Sie Seiten, die nur den Header _**Access-Control-Allow-Origin**_ zurückgeben, wenn eine gültige Domain/Subdomain im Header _**Origin**_ festgelegt ist. In solchen Szenarien können Sie dieses Verhalten missbrauchen, um neue **Subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Bei der Suche nach **Subdomains** sollten Sie darauf achten, ob diese auf einen **Bucket** verweisen, und in diesem Fall die **Berechtigungen überprüfen**.\
Außerdem sollten Sie, da Sie zu diesem Zeitpunkt alle Domains im Umfang kennen, versuchen, mögliche Bucket-Namen zu **brute-forcen und die Berechtigungen zu überprüfen**.

### **Überwachung**

Sie können überwachen, ob neue **Subdomains** einer Domain erstellt werden, indem Sie die **Certificate Transparency**-Logs überwachen, wie es [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) tut.

### **Suche nach Schwachstellen**

Überprüfen Sie mögliche **Subdomain-Übernahmen**.\
Wenn die **Subdomain** auf einen **S3-Bucket** verweist, **überprüfen Sie die Berechtigungen**.

Wenn Sie eine **Subdomain mit einer anderen IP** als denjenigen, die Sie bereits bei der Assets-Erkennung gefunden haben, finden, sollten Sie einen **grundlegenden Schwachstellenscan** (mit Nessus oder OpenVAS) und einen **Portscan** (mit nmap/masscan/shodan) durchführen. Je nachdem, welche Dienste ausgeführt werden, finden Sie in **diesem Buch einige Tricks, um sie "anzugreifen"**.\
Beachten Sie, dass die Subdomain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht im Umfang liegt. Seien Sie vorsichtig.

## IPs

In den ersten Schritten haben Sie möglicherweise **IP-Bereiche, Domains und Subdomains gefunden**.\
Es ist an der Zeit, **alle IPs aus diesen Bereichen** und für die **Domains/Subdomains (DNS-Abfragen)** zu sammeln.

Mit den Diensten der folgenden **kostenlosen APIs** können Sie auch **frühere von Domains und Subdomains verwendete IPs** finden. Diese IPs könnten immer noch dem Kunden gehören (und könnten Ihnen ermöglichen, [**CloudFlare-Bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

* [**https://securitytrails.com/**](https://securitytrails.com/)

Sie können auch nach Domains suchen, die auf eine bestimmte IP-Adresse verweisen, indem Sie das Tool [**hakip2host**](https://github.com/hakluke/hakip2host) verwenden.

### **Suche nach Schwachstellen**

**Scannen Sie alle IPs, die nicht zu CDNs gehören** (da Sie dort höchstwahrscheinlich nichts Interessantes finden werden). In den entdeckten laufenden Diensten könnten Sie **Schwachstellen finden**.

**Finden Sie eine** [**Anleitung**](../pentesting-network/) **zum Scannen von Hosts**.

## Jagd auf Webserver

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen die IP-Bereiche, Domains und Subdomains im Umfang. Es ist an der Zeit, nach Webservern zu suchen.

In den vorherigen Schritten haben Sie wahrscheinlich bereits einige **Recherchen zu den entdeckten IPs und Domains** durchgeführt, sodass Sie möglicherweise bereits alle möglichen Webserver gefunden haben. Wenn nicht, werden wir nun einige **schnelle Tricks zur Suche nach Webservern** im Umfang sehen.

Bitte beachten Sie, dass dies auf die **Entdeckung von Webanwendungen ausgerichtet ist**, daher sollten Sie auch die **Schwachstellen-** und **Portscans** durchführen (**sofern im Umfang erlaubt**).

Eine **schnelle Methode**, um **offene Ports** in Bezug auf **Webserver** mit [**masscan zu entdecken, finden Sie hier**](../pentesting-network/#http-port-discovery).\
Ein weiteres hilfreiches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe), [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Sie geben einfach eine Liste von Domains ein und es wird versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich können Sie angeben, auch andere Ports zu versuchen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Nun, da Sie alle Webserver im Umfang entdeckt haben (unter den IP-Adressen des Unternehmens sowie allen Domains und Subdomains), wissen Sie wahrscheinlich nicht, wo Sie anfangen sollen. Machen wir es also einfach und nehmen Sie einfach Screenshots von allen. Allein durch einen Blick auf die Hauptseite können Sie seltsame Endpunkte finden, die anfälliger für Schwachstellen sind.

Um die vorgeschlagene Idee umzusetzen, können Sie [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness), [HttpScreenshot](https://github.com/breenmachine/httpscreenshot), [Aquatone](https://github.com/michenriksen/aquatone), [Shutter](https://shutter-project.org/downloads/third-party-packages/) oder [webscreenshot](https://github.com/maaaaz/webscreenshot) verwenden.

Darüber hinaus könnten Sie dann [eyeballer](https://github.com/BishopFox/eyeballer) verwenden, um alle Screenshots zu überprüfen und Ihnen mitzuteilen, was wahrscheinlich Schwachstellen enthält und was nicht.

## Öffentliche Cloud-Ressourcen

Um potenzielle Cloud-Ressourcen eines Unternehmens zu finden, sollten Sie mit einer Liste von Schlüsselwörtern beginnen, die dieses Unternehmen identifizieren. Zum Beispiel könnten Sie für ein Kryptounternehmen Wörter wie "crypto", "wallet", "dao", "<domain_name>", "<subdomain_names>" verwenden.

Sie benötigen auch Wortlisten mit häufig verwendeten Wörtern in Buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dann sollten Sie mit diesen Wörtern **Permutationen** generieren (siehe [Second Round DNS Brute-Force](./#second-dns-bruteforce-round) für weitere Informationen).

Mit den resultierenden Wortlisten können Sie Tools wie [cloud_enum](https://github.com/initstring/cloud_enum), [CloudScraper](https://github.com/jordanpotti/CloudScraper), [cloudlist](https://github.com/projectdiscovery/cloudlist) oder [S3Scanner](https://github.com/sa7mon/S3Scanner) verwenden.

Denken Sie daran, dass Sie bei der Suche nach Cloud-Ressourcen nicht nur nach Buckets in AWS suchen sollten.

### **Suche nach Schwachstellen**

Wenn Sie offene Buckets oder freigegebene Cloud-Funktionen finden, sollten Sie darauf zugreifen und versuchen herauszufinden, was sie Ihnen bieten und ob Sie sie missbrauchen können.

## E-Mails

Mit den Domains und Subdomains im Umfang haben Sie im Grunde alles, was Sie brauchen, um nach E-Mails zu suchen. Dies sind die APIs und Tools, die für mich am besten funktioniert haben, um E-Mails eines Unternehmens zu finden:

* [theHarvester](https://github.com/laramies/theHarvester) - mit APIs
* API von [https://hunter.io/](https://hunter.io/) (kostenlose Version)
* API von [https://app.snov.io/](https://app.snov.io/) (kostenlose Version)
* API von [https://minelead.io/](https://minelead.io/) (kostenlose Version)

### **Suche nach Schwachstellen**

E-Mails werden später nützlich sein, um Web-Logins und Authentifizierungsdienste (wie SSH) per Brute-Force anzugreifen. Außerdem werden sie für Phishing-Angriffe benötigt. Darüber hinaus geben Ihnen diese APIs noch mehr Informationen über die Person hinter der E-Mail, was für die Phishing-Kampagne nützlich ist.

## Zugangsdaten-Leaks

Mit den Domains, Subdomains und E-Mails können Sie nach in der Vergangenheit geleakten Zugangsdaten suchen, die diesen E-Mails gehören:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Suche nach Schwachstellen**

Wenn Sie gültige geleakte Zugangsdaten finden, ist dies ein sehr einfacher Erfolg.

## Geheimnis-Leaks

Zugangsdaten-Leaks beziehen sich auf Hacks von Unternehmen, bei denen sensible Informationen geleakt und verkauft wurden. Unternehmen können jedoch auch von anderen Leaks betroffen sein, deren Informationen nicht in diesen Datenbanken enthalten sind:

### Github-Leaks

Zugangsdaten und APIs können in den öffentlichen Repositories des Unternehmens oder der Benutzer, die für dieses Github-Unternehmen arbeiten, geleakt werden.\
Sie können das Tool [Leakos](https://github.com/carlospolop/Leakos) verwenden, um alle öffentlichen Repositories einer Organisation und ihrer Entwickler herunterzuladen und automatisch [gitleaks](https://github.com/zricethezav/gitleaks) darauf auszuführen.

Leakos kann auch verwendet werden, um gitleaks gegen alle übergebene Text-URLs auszuführen, da manchmal auch Webseiten Geheimnisse enthalten.

#### Github-Dorks

Überprüfen Sie auch diese Seite nach potenziellen Github-Dorks, nach denen Sie in der angegriffenen Organisation suchen könnten:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes-Leaks

Manchmal veröffentlichen Angreifer oder Mitarbeiter Unternehmensinhalte auf einer Paste-Site. Dies kann sensible Informationen enthalten oder auch nicht, aber es ist sehr interessant, danach zu suchen.\
Sie können das Tool [Pastos](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 Paste-Sites zu suchen.

### Google-Dorks

Alte, aber bewährte Google-Dorks sind immer nützlich, um Informationen zu finden, die nicht öffentlich zugänglich sein sollten. Das einzige Problem ist, dass die [google-hacking-database](https://www.exploit-db.com/google-hacking-database) mehrere Tausend mögliche Abfragen enthält, die Sie nicht manuell ausführen können. Sie können also Ihre 10 Favoriten auswählen oder ein Tool wie [Gorks](https://github.com/carlospolop/Gorks) verwenden, um sie alle auszuführen.

Beachten Sie, dass Tools, die erwarten, die gesamte Datenbank mit dem regulären Google-Browser auszuführen, niemals enden werden, da Google Sie sehr bald blockieren wird.

### **Suche nach Schwachstellen**

Wenn Sie gültige geleakte Zugangsdaten oder API-Token finden, ist dies ein sehr einfacher Erfolg.

## Öffentliche Code-Schwachstellen

Wenn Sie feststellen, dass das Unternehmen Open-Source-Code hat, können Sie diesen analysieren und nach Schwachstellen suchen.

Je nach Sprache gibt es verschiedene Tools, die Sie verwenden können:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Es gibt auch kostenlose Dienste, mit denen Sie öffentliche Repositories scannen können, wie zum Beispiel:

* [Snyk](https://app.snyk.io/)
## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

Die **Mehrheit der Schwachstellen**, die von Bug Bounty-Huntern gefunden werden, befindet sich in **Webanwendungen**. An dieser Stelle möchte ich daher über eine **Methodik zur Prüfung von Webanwendungen** sprechen, die Sie [**hier finden können**](../../network-services-pentesting/pentesting-web/).

Ich möchte auch besonders auf den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/#automatic-scanners) hinweisen, da sie zwar nicht in der Lage sind, sehr sensible Schwachstellen zu finden, aber nützlich sind, um sie in **Workflows zur Gewinnung erster Informationen über Webanwendungen** zu implementieren.

## Zusammenfassung

> Herzlichen Glückwunsch! Zu diesem Zeitpunkt haben Sie bereits **alle grundlegenden Enumerationen** durchgeführt. Ja, es handelt sich um grundlegende Enumerationen, da noch viel mehr Enumerationen durchgeführt werden können (später werden wir weitere Tricks sehen).

Sie haben also bereits:

1. Alle **Unternehmen** im Umfang gefunden.
2. Alle **Assets**, die den Unternehmen gehören, gefunden (und bei Bedarf eine Schwachstellenprüfung durchgeführt).
3. Alle **Domains**, die den Unternehmen gehören, gefunden.
4. Alle **Subdomains** der Domains gefunden (gibt es eine Übernahme von Subdomains?).
5. Alle **IP-Adressen** (von und **nicht von CDNs**) im Umfang gefunden.
6. Alle **Webserver** gefunden und einen **Screenshot** von ihnen gemacht (gibt es etwas Seltsames, das genauer betrachtet werden sollte?).
7. Alle **potenziellen öffentlichen Cloud-Ressourcen**, die dem Unternehmen gehören, gefunden.
8. **E-Mails**, **geleakte Zugangsdaten** und **geheime Leaks**, die Ihnen einen **großen Gewinn sehr einfach** ermöglichen könnten.
9. **Pentesting aller gefundenen Webanwendungen**

## **Vollständige automatische Tools für die Aufklärung**

Es gibt mehrere Tools, die einen Teil der vorgeschlagenen Aktionen gegen einen bestimmten Umfang durchführen.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ein wenig veraltet und nicht aktualisiert

## **Referenzen**

* Alle kostenlosen Kurse von [**@Jhaddix**](https://twitter.com/Jhaddix) wie [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug Bounty-Tipp**: **Melden Sie sich bei Intigriti an**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker** entwickelt wurde! Treten Sie uns noch heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und verdienen Sie Prämien von bis zu **100.000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
