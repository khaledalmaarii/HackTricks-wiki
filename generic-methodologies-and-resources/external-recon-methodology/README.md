# Metodologia zewnętrznego rozpoznania

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Wskazówka dotycząca bug bounty**: **zarejestruj się** na platformie **Intigriti**, premium **platformie bug bounty stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Odkrywanie zasobów

> Powiedziano ci, że wszystko należące do pewnej firmy znajduje się w zakresie, i chcesz dowiedzieć się, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie wszystkich **firm należących do głównej firmy**, a następnie wszystkich **zasobów** tych firm. Aby to zrobić, wykonamy następujące czynności:

1. Znajdź przejęcia głównej firmy, co pozwoli nam poznać firmy w zakresie.
2. Znajdź ASN (jeśli istnieje) każdej firmy, co pozwoli nam poznać zakresy IP posiadane przez każdą firmę.
3. Użyj odwróconego wyszukiwania whois, aby wyszukać inne wpisy (nazwy organizacji, domeny...) powiązane z pierwszym (można to zrobić rekurencyjnie).
4. Użyj innych technik, takich jak filtry `org` i `ssl` w Shodan, aby wyszukać inne zasoby (szczególnie trik z `ssl` można wykonać rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy dowiedzieć się, które **inne firmy należą do głównej firmy**.\
Jedną opcją jest odwiedzenie strony [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukanie** głównej firmy i **kliknięcie** na "**przejęcia**". Tam zobaczysz inne firmy przejęte przez główną firmę.\
Inną opcją jest odwiedzenie strony **Wikipedia** głównej firmy i wyszukanie **przejęć**.

> W tym momencie powinieneś znać wszystkie firmy w zakresie. Teraz dowiedzmy się, jak znaleźć ich zasoby.

### **ASNs**

Numer autonomicznego systemu (**ASN**) to **unikalny numer** przypisany do **autonomicznego systemu** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
AS składa się z bloków adresów IP, które mają wyraźnie zdefiniowaną politykę dostępu do sieci zewnętrznych i są administrowane przez jedną organizację, ale mogą składać się z kilku operatorów.

Warto sprawdzić, czy **firma ma przypisany jakiś ASN**, aby znaleźć jej **zakresy IP**. Warto przeprowadzić test podatności na wszystkich **hostach** w **zakresie** i szukać domen w tych adresach IP.\
Możesz **wyszukiwać** według **nazwy firmy**, według **IP** lub według **domeny** na stronie [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**W zależności od regionu, w którym znajduje się firma, te linki mogą być przydatne do zebrania większej ilości danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie, prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** już się pojawiają w pierwszym linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ponadto, automatyczne wyliczanie poddomen [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatycznie agreguje i podsumowuje ASNs na końcu skanowania.
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
Możesz znaleźć zakresy IP organizacji również za pomocą [http://asnlookup.com/](http://asnlookup.com) (ma darmowe API).\
Możesz znaleźć IP i ASN domeny za pomocą [http://ipv4info.com/](http://ipv4info.com).

### **Wyszukiwanie podatności**

W tym momencie znamy **wszystkie zasoby w zakresie**, więc jeśli masz na to zgodę, możesz uruchomić **skaner podatności** (Nessus, OpenVAS) na wszystkich hostach.\
Możesz również uruchomić [**skanowanie portów**](../pentesting-network/#discovering-hosts-from-the-outside) **lub skorzystać z usług takich jak** shodan **, aby znaleźć** otwarte porty **i w zależności od tego, co znajdziesz, powinieneś** zapoznać się z tą książką, aby dowiedzieć się, jak przetestować kilka możliwych uruchomionych usług.\
**Warto również wspomnieć, że możesz przygotować listy** domyślnych nazw użytkowników **i** haseł **i spróbować** przeprowadzić atak brute force na usługi za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy wszystkie firmy w zakresie i ich zasoby, czas znaleźć domeny w zakresie.

_Proszę zauważyć, że w poniższych proponowanych technikach można również znaleźć subdomeny i ta informacja nie powinna być niedoceniana._

Przede wszystkim powinieneś szukać **głównej domeny**(y) każdej firmy. Na przykład, dla _Tesla Inc._ będzie to _tesla.com_.

### **Odwrócone DNS**

Po znalezieniu wszystkich zakresów IP domen możesz spróbować wykonać **odwrócone wyszukiwanie DNS** na tych **IP, aby znaleźć więcej domen w zakresie**. Spróbuj użyć serwera DNS ofiary lub znanego serwera DNS (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Aby to działało, administrator musi ręcznie włączyć PTR.\
Możesz również skorzystać z narzędzia online do uzyskania tych informacji: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (pętla)**

Wewnątrz **whois** można znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **adresy e-mail**, numery telefonów... Ale co jeszcze bardziej interesujące, to że można znaleźć **więcej zasobów związanych z firmą**, jeśli wykonasz **odwrotne wyszukiwanie whois według dowolnego z tych pól** (na przykład inne rejestry whois, w których występuje ten sam adres e-mail).\
Możesz skorzystać z narzędzi online, takich jak:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Darmowe**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Darmowe**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Darmowe**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Darmowe** (strona internetowa), płatne API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Płatne
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Płatne (tylko **100 darmowych** wyszukiwań)
* [https://www.domainiq.com/](https://www.domainiq.com) - Płatne

Możesz zautomatyzować to zadanie za pomocą [**DomLink** ](https://github.com/vysecurity/DomLink)(wymaga klucza API whoxy).\
Możesz również wykonać automatyczne odkrywanie odwrotnego whois za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Zauważ, że możesz użyć tej techniki, aby odkrywać więcej nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackery**

Jeśli znajdziesz **ten sam identyfikator tego samego trackera** na dwóch różnych stronach, możesz przypuszczać, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli zobaczysz ten sam **identyfikator Google Analytics** lub ten sam **identyfikator Adsense** na kilku stronach.

Istnieją strony i narzędzia, które pozwalają wyszukiwać te trackery i wiele więcej:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, szukając tego samego skrótu ikony favicon? Dokładnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto, jak go użyć:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - odkrywanie domen o tym samym skrócie ikony favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

W skrócie, favihash pozwoli nam odkryć domeny, które mają ten sam skrót ikony favicon co nasz cel.

Ponadto, możesz również wyszukiwać technologie za pomocą skrótu favicon, jak wyjaśniono w [**tym wpisie na blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Oznacza to, że jeśli znasz **skrót favicon wrażliwej wersji technologii internetowej**, możesz wyszukać go w shodan i **znaleźć więcej podatnych miejsc**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Oto jak możesz **obliczyć skrót favicon** strony internetowej:
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
### **Prawa autorskie / Unikalny ciąg znaków**

Wyszukaj wewnątrz stron internetowych **ciągi znaków, które mogą być udostępniane na różnych stronach w tej samej organizacji**. Dobrym przykładem może być **ciąg znaków praw autorskich**. Następnie wyszukaj ten ciąg znaków w **Google**, w innych **przeglądarkach** lub nawet w **Shodan**: `shodan search http.html:"Ciąg znaków praw autorskich"`

### **CRT Time**

Często spotyka się zadania cron, takie jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Aby odnowić wszystkie certyfikaty domenowe na serwerze. Oznacza to, że nawet jeśli CA używane do tego nie ustawia czasu generacji w czasie ważności, możliwe jest **znalezienie domen należących do tej samej firmy w dziennikach przejrzystości certyfikatów**.\
Sprawdź ten [**artykuł, aby uzyskać więcej informacji**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Pasywne przejęcie**

Okazuje się, że ludzie często przypisują subdomeny do adresów IP należących do dostawców chmur i w pewnym momencie **tracą ten adres IP, ale zapominają usunąć rekord DNS**. Dlatego, po prostu **uruchamiając maszynę wirtualną** w chmurze (np. Digital Ocean), faktycznie **przejmujesz niektóre subdomeny**.

[**Ten post**](https://kmsec.uk/blog/passive-takeover/) opisuje historię na ten temat i proponuje skrypt, który **uruchamia maszynę wirtualną w DigitalOcean**, **pobiera** jej **IPv4**, a następnie **wyszukuje w Virustotal rekordy subdomen** wskazujące na ten adres IP.

### **Inne sposoby**

**Zauważ, że możesz użyć tej techniki, aby odkrywać więcej nazw domen za każdym razem, gdy znajdziesz nową domenę.**

**Shodan**

Ponieważ już znasz nazwę organizacji posiadającej przestrzeń adresową IP, możesz wyszukać te dane w Shodan, używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz uzyskać dostęp do **certyfikatu TLS** głównej strony internetowej, uzyskać **nazwę organizacji** i następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron internetowych znanych przez **Shodan** z filtrem: `ssl:"Tesla Motors"` lub użyć narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) to narzędzie, które wyszukuje **powiązane domeny** z główną domeną i **subdomeny** z nimi, naprawdę niesamowite.

### **Wyszukiwanie podatności**

Sprawdź, czy istnieje możliwość [przejęcia domeny](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **używa pewnej domeny**, ale **straciła jej własność**. Wystarczy ją zarejestrować (jeśli jest wystarczająco tania) i poinformować firmę.

Jeśli znajdziesz jakąś **domenę z innym adresem IP** niż te, które już znalazłeś w odkrywaniu zasobów, powinieneś przeprowadzić **podstawowe skanowanie podatności** (za pomocą Nessusa lub OpenVAS) oraz [**skan portów**](../pentesting-network/#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od tego, jakie usługi są uruchomione, możesz znaleźć w **tej książce kilka sztuczek do "atakowania" ich**.\
Zauważ, że czasami domena jest hostowana wewnątrz adresu IP, który nie jest kontrolowany przez klienta, więc nie jest w zakresie, bądź ostrożny.

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Wskazówka dotycząca bug bounty**: **Zarejestruj się** na platformie **Intigriti**, premium platformie **bug bounty stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomeny

> Znamy wszystkie firmy w zakresie, wszystkie zasoby każdej firmy i wszystkie powiązane z nimi domeny.

Nadszedł czas, aby znaleźć wszystkie możliwe subdomeny dla każdej znalezionej domeny.

### **DNS**

Spróbujmy uzyskać **subdomeny** z rekordów **DNS**. Powinniśmy również spróbować **Transferu Strefy** (jeśli jest podatny, powinieneś to zgłosić).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najszybszym sposobem na uzyskanie dużej liczby subdomen jest wyszukiwanie w zewnętrznych źródłach. Najczęściej używanymi **narzędziami** są następujące (dla lepszych wyników skonfiguruj klucze API):

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/pl-pl)
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
Istnieją **inne interesujące narzędzia/API**, które mogą być przydatne do znalezienia subdomen, nawet jeśli nie są bezpośrednio specjalizowane w tym celu, takie jak:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Wykorzystuje API [https://sonar.omnisint.io](https://sonar.omnisint.io) do uzyskania subdomen.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**Darmowe API JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) darmowe API
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
* [**gau**](https://github.com/lc/gau)**:** pobiera znane adresy URL z AlienVault's Open Threat Exchange, Wayback Machine i Common Crawl dla dowolnej domeny.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Przeszukują sieć w poszukiwaniu plików JS i wyodrębniają z nich subdomeny.
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
* [**Censys narzędzie do znajdowania poddomen**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) ma darmowe API do wyszukiwania subdomen i historii IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ten projekt oferuje **darmowo wszystkie subdomeny związane z programami bug bounty**. Możesz uzyskać dostęp do tych danych również za pomocą [chaospy](https://github.com/dr-0x0x/chaospy) lub uzyskać dostęp do zakresu używanego przez ten projekt [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Możesz znaleźć **porównanie** wielu z tych narzędzi tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomeny** poprzez brutalne atakowanie serwerów DNS za pomocą możliwych nazw subdomen.

Do tego działania będziesz potrzebować kilku **wspólnych list słów subdomen, takich jak**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

A także adresy IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać resolverów z [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) do ich filtrowania. Lub możesz użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do brutalnego atakowania DNS to:

* [**massdns**](https://github.com/blechschmidt/massdns): To było pierwsze narzędzie, które skutecznie przeprowadzało brutalny atak na DNS. Jest bardzo szybkie, ale podatne na fałszywe wyniki.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Ten, myślę, że używa tylko 1 resolvera
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to nakładka na `massdns`, napisana w języku go, która umożliwia wyliczenie prawidłowych subdomen za pomocą aktywnego bruteforce, a także rozwiązywanie subdomen z obsługą wildcardów i łatwe wsparcie wejścia-wyjścia.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Korzysta również z `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do asynchronicznego brute force'owania nazw domenowych.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda brutalnego ataku DNS

Po znalezieniu subdomen za pomocą publicznie dostępnych źródeł i brutalnego ataku, można wygenerować zmiany znalezionych subdomen, aby spróbować znaleźć jeszcze więcej. Kilka narzędzi jest przydatnych w tym celu:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Generuje permutacje na podstawie domen i subdomen.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dla podanych domen i subdomen generuje permutacje.
* Możesz pobrać listę permutacji goaltdns **wordlist** [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dla podanych domen i subdomen generuje permutacje. Jeśli nie podano pliku z permutacjami, gotator użyje własnego.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen, może również próbować je rozwiązać (ale lepiej używać wcześniej skomentowanych narzędzi).
* Możesz pobrać listę permutacji **altdns** [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutacji, mutacji i zmiany subdomen. To narzędzie przeprowadzi brutalny atak na wynik (nie obsługuje dzikich kart DNS).
* Możesz pobrać listę słów permutacji dmut [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nowe potencjalne nazwy poddomen** na podstawie wskazanych wzorców, aby odkryć więcej poddomen.

#### Generowanie inteligentnych permutacji

* [**regulator**](https://github.com/cramppet/regulator): Aby uzyskać więcej informacji, przeczytaj ten [**post**](https://cramppet.github.io/regulator/index.html), ale w zasadzie pobierze **główne części** z **odkrytych poddomen** i połączy je, aby znaleźć więcej poddomen.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to narzędzie do brutalnego ataku na subdomeny, połączone z niezwykle prostym, ale skutecznym algorytmem opartym na odpowiedziach DNS. Wykorzystuje dostarczony zestaw danych wejściowych, takich jak spersonalizowana lista słów lub historyczne rekordy DNS/TLS, aby dokładnie syntetyzować więcej odpowiadających im nazw domen i dalej je rozwijać w pętli na podstawie informacji zebranych podczas skanowania DNS.
```
echo www | subzuf facebook.com
```
### **Przepływ pracy odkrywania subdomen**

Sprawdź ten wpis na blogu, który napisałem na temat **automatyzacji odkrywania subdomen** z domeny za pomocą **najbardziej skomplikowanych przepływów pracy**, dzięki czemu nie muszę ręcznie uruchamiać wielu narzędzi na swoim komputerze:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Wirtualne hosty**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami na tym IP**, szukając w **źródłach OSINT** domen na danym IP lub **przez próbę brutalnego przełamywania nazw domen VHost na tym IP**.

#### OSINT

Możesz znaleźć niektóre **VHosty w IP za pomocą** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych interfejsów API**.

**Brute Force**

Jeśli podejrzewasz, że pewna subdomena może być ukryta na serwerze WWW, możesz spróbować jej brutalnego przełamania:
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
Z tą techniką możesz nawet uzyskać dostęp do wewnętrznych/ukrytych punktów końcowych.
{% endhint %}

### **CORS Brute Force**

Czasami natrafisz na strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiony jest prawidłowy domena/poddomena. W takich scenariuszach możesz wykorzystać to zachowanie do **odkrywania** nowych **poddomen**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force Buckets**

Podczas szukania **subdomen** zwróć uwagę, czy nie wskazuje ona na jakiekolwiek **bucket**, a w takim przypadku [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Ponadto, mając już wszystkie domeny w zakresie, spróbuj [**przeprowadzić atak brute force na możliwe nazwy bucketów i sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorowanie**

Możesz **monitorować**, czy są tworzone **nowe subdomeny** dla danej domeny, monitorując **logi Certificate Transparency**. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)robi to.

### **Wyszukiwanie podatności**

Sprawdź możliwość [**przejęcia subdomeny**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomena** wskazuje na **bucket S3**, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/).

Jeśli znajdziesz jakąś **subdomenę z innym adresem IP** niż te, które już znalazłeś podczas odkrywania zasobów, powinieneś przeprowadzić **podstawowe skanowanie podatności** (za pomocą Nessusa lub OpenVAS) oraz [**skan portów**](../pentesting-network/#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług, w **tej książce znajdziesz kilka sztuczek, jak je "zaatakować"**.\
Należy zauważyć, że czasami subdomena jest hostowana na adresie IP, który nie jest kontrolowany przez klienta, więc nie jest w zakresie, bądź ostrożny.

## Adresy IP

W początkowych krokach możesz **znaleźć pewne zakresy adresów IP, domeny i subdomeny**.\
Nadszedł czas, aby **zbierać wszystkie adresy IP z tych zakresów** oraz dla **domen/subdomen (zapytania DNS)**.

Korzystając z usług poniższych **darmowych API**, możesz również znaleźć **poprzednie adresy IP używane przez domeny i subdomeny**. Te adresy IP mogą nadal należeć do klienta (i mogą umożliwić znalezienie [**obejść CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

* [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz również sprawdzić domeny wskazujące na określony adres IP za pomocą narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Wyszukiwanie podatności**

**Skanuj porty wszystkich adresów IP, które nie należą do CDN** (ponieważ prawdopodobnie nie znajdziesz tam nic interesującego). W odkrytych uruchomionych usługach możesz **znaleźć podatności**.

**Znajdź** [**przewodnik**](../pentesting-network/) **o skanowaniu hostów**.

## Poszukiwanie serwerów WWW

> Znaleźliśmy wszystkie firmy i ich zasoby, znamy zakresy adresów IP, domeny i subdomeny w zakresie. Czas poszukać serwerów WWW.

W poprzednich krokach prawdopodobnie już przeprowadziłeś **rekonesans adresów IP i odkrytych domen**, więc możesz już **znaleźć wszystkie możliwe serwery WWW**. Jeśli jednak tego nie zrobiłeś, teraz zobaczymy kilka **szybkich sztuczek do wyszukiwania serwerów WWW** w zakresie.

Należy zauważyć, że będzie to **skierowane na odkrywanie aplikacji internetowych**, więc powinieneś również **przeprowadzić skan podatności** i **portów** (**jeśli jest to dozwolone** w zakresie).

**Szybka metoda** do odkrywania **otwartych portów** związanych z serwerami **WWW** za pomocą [**masscan** można znaleźć tutaj](../pentesting-network/#http-port-discovery).\
Innym przyjaznym narzędziem do wyszukiwania serwerów WWW jest [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy podać listę domen, a narzędzie spróbuje połączyć się z portem 80 (http) i 443 (https). Dodatkowo można wskazać, aby spróbowało innych portów:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Zrzuty ekranu**

Teraz, gdy odkryłeś **wszystkie serwery WWW** obecne w zakresie (wśród **adresów IP** firmy oraz wszystkich **domen** i **poddomen**), prawdopodobnie **nie wiesz, od czego zacząć**. Więc zróbmy to prosto i zacznijmy od zrobienia zrzutów ekranu wszystkich z nich. Już tylko **spojrzenie** na **stronę główną** może ujawnić **dziwne** punkty końcowe, które są bardziej **podatne** na **zagrożenia**.

Aby wykonać zaproponowany pomysł, możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ponadto, możesz użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przejrzeć wszystkie **zrzuty ekranu** i dowiedzieć się, co **najprawdopodobniej zawiera podatności**, a co nie.

## Zasoby publiczne w chmurze

Aby znaleźć potencjalne zasoby w chmurze należące do firmy, powinieneś **zacząć od listy słów kluczowych identyfikujących tę firmę**. Na przykład, dla firmy kryptograficznej możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<nazwa_domeny>", <"nazwy_poddomen">`.

Będziesz również potrzebować list słów **często używanych w kubełkach**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie, z tymi słowami powinieneś wygenerować **permutacje** (sprawdź [**Drugą rundę brutalnego ataku DNS**](./#second-dns-bruteforce-round) dla więcej informacji).

Z uzyskanych list słów możesz użyć narzędzi takich jak [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając zasobów w chmurze powinieneś **szukać czegoś więcej niż tylko kubełków w AWS**.

### **Szukanie podatności**

Jeśli znajdziesz takie rzeczy jak **otwarte kubełki lub wystawione funkcje w chmurze**, powinieneś się do nich **dostać** i sprawdzić, co oferują i czy można je wykorzystać.

## E-maile

Dzięki **domenom** i **poddomenom** w zakresie masz praktycznie wszystko, czego potrzebujesz, aby rozpocząć wyszukiwanie adresów e-mail. Oto **API** i **narzędzia**, które najlepiej sprawdziły się w wyszukiwaniu adresów e-mail firmy:

* [**theHarvester**](https://github.com/laramies/theHarvester) - z wykorzystaniem API
* API [**https://hunter.io/**](https://hunter.io/) (wersja darmowa)
* API [**https://app.snov.io/**](https://app.snov.io/) (wersja darmowa)
* API [**https://minelead.io/**](https://minelead.io/) (wersja darmowa)

### **Szukanie podatności**

Adresy e-mail przydadzą się później do **brute-force'owania logowania do stron internetowych i usług uwierzytelniania** (takich jak SSH). Są również potrzebne do **phishingu**. Ponadto, te API dostarczą Ci jeszcze więcej **informacji o osobie** za adresem e-mail, co jest przydatne w kampanii phishingowej.

## Wycieki poświadczeń

Dzięki **domenom**, **poddomenom** i **adresom e-mail** możesz rozpocząć poszukiwanie wycieków poświadczeń przecieknących w przeszłości i należących do tych adresów e-mail:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie podatności**

Jeśli znajdziesz **ważne wycieknięte** poświadczenia, to jest bardzo łatwe zwycięstwo.

## Wycieki poufnych informacji

Wycieki poświadczeń są związane z atakami na firmy, w których **poufne informacje zostały ujawnione i sprzedane**. Jednak firmy mogą być dotknięte również przez **inne wycieki**, których informacje nie znajdują się w tych bazach danych:

### Wycieki na Githubie

Poświadczenia i interfejsy API mogą być ujawnione w **publicznych repozytoriach** **firmy** lub **użytkowników** pracujących dla tej firmy na Githubie.\
Możesz użyć narzędzia [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** organizacji i jej **programistów** oraz automatycznie uruchomić [**gitleaks**](https://github.com/zricethezav/gitleaks) na nich.

**Leakos** może również być używany do uruchamiania **gitleaks** na wszystkich **tekstach** dostarczonych jako **przekazane adresy URL**, ponieważ czasami **strony internetowe również zawierają poufne informacje**.

#### Github Dorks

Sprawdź również tę **stronę**, aby znaleźć potencjalne **github dorks**, których możesz również szukać w atakowanej organizacji:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Wycieki wklejek

Czasami atakujący lub po prostu pracownicy **publikują treści firmy na stronach do wklejania**. Mogą one zawierać lub nie zawierać **poufnych informacji**, ale jest bardzo interesujące ich poszukiwanie.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby jednocześnie przeszukiwać ponad 80 stron do wklejania.

### Google Dorks

Stare, ale złote google dorks zawsze są przydatne do znalezienia **ujawnionych informacji, które tam nie powinny być**. Jedynym problemem jest to, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie można uruchomić ręcznie. Możesz więc wybrać swoje ulubione 10 lub skorzystać z narzędzia takiego jak [**Gorks**](https://github.com/carlospolop/Gorks), aby uruchomić je wszystkie.

Zauważ, że narzędzia, które oczekują uruchomienia całej bazy danych za pomocą zwykłej przeglądarki Google, nigdy się nie zakończą, ponieważ Google bardzo szybko zablokuje dostęp.

### **Szukanie podatności**

Jeśli znajdziesz **ważne wycieknięte** poświadczenia lub tokeny API, to jest bardzo łatwe zwycięstwo.

## Publiczne podatności kodu

Jeśli odkryłeś, że firma ma **kod open-source**, możesz go **analizować** i szukać w nim **podatności**.

**W zależności od języka** istnieją różne **narzędzia**, których możesz użyć:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Istnieją również bezpłatne usługi, które pozwalają **skanować publiczne repozytoria**, takie jak:

* [**Snyk**](https://app.snyk.io/)
## [**Metodologia testowania penetracyjnego aplikacji internetowych**](../../network-services-pentesting/pentesting-web/)

**Większość podatności**, które znajdują łowcy błędów, znajduje się w **aplikacjach internetowych**, dlatego w tym momencie chciałbym omówić **metodologię testowania aplikacji internetowych**, którą można [**znaleźć tutaj**](../../network-services-pentesting/pentesting-web/).

Chciałbym również wspomnieć o sekcji [**Narzędzia open source do automatycznego skanowania sieci Web**](../../network-services-pentesting/pentesting-web/#automatic-scanners), ponieważ, choć nie należy oczekiwać, że znajdą one bardzo wrażliwe podatności, są one przydatne do implementacji w **przepływach pracy w celu uzyskania początkowych informacji o sieci Web**.

## Podsumowanie

> Gratulacje! W tym momencie już przeprowadziłeś **wszystkie podstawowe operacje wyliczania**. Tak, to podstawowe, ponieważ można wykonać znacznie więcej operacji wyliczania (zobaczymy więcej sztuczek później).

Więc już:

1. Znalazłeś wszystkie **firmy** w zakresie
2. Znalazłeś wszystkie **zasoby** należące do firm (i przeprowadziłeś skanowanie podatności, jeśli jest to w zakresie)
3. Znalazłeś wszystkie **domeny** należące do firm
4. Znalazłeś wszystkie **poddomeny** domen (czy jest możliwość przejęcia poddomeny?)
5. Znalazłeś wszystkie **adresy IP** (z i **bez CDN**) w zakresie.
6. Znalazłeś wszystkie **serwery WWW** i zrobiłeś **zrzut ekranu** z nich (czy coś dziwnego, co warto dokładniej przyjrzeć?)
7. Znalazłeś wszystkie **potencjalne publiczne zasoby w chmurze** należące do firmy.
8. **Adresy e-mail**, **wycieki poświadczeń** i **wycieki tajemnic**, które mogą dać ci **duże zwycięstwo bardzo łatwo**.
9. **Testowanie penetracyjne wszystkich znalezionych stron internetowych**

## **Pełne narzędzia automatycznego wywiadu**

Istnieje wiele narzędzi, które wykonają część z proponowanych działań w określonym zakresie.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Trochę przestarzałe i nieaktualizowane

## **Odnośniki**

* Wszystkie darmowe kursy [**@Jhaddix**](https://twitter.com/Jhaddix), takie jak [**Metodologia łowcy błędów v4.0 - Edycja wywiadu**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Wskazówka dotycząca nagród za znalezienie błędów**: **Zarejestruj się** na platformie **Intigriti**, premium platformie **nagród za znalezienie błędów stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
