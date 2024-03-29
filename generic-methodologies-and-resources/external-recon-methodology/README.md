# Metodologia di Ricognizione Esterna

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato alla **carriera dell'hacking** e vuoi hackerare l'inviolabile - **stiamo assumendo!** (_richiesta competenza polacca scritta e parlata_).

{% embed url="https://www.stmcyber.com/careers" %}

## Scoperta degli Asset

> Ti è stato detto che tutto ciò che appartiene a un'azienda è nel perimetro, e vuoi capire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è ottenere tutte le **aziende possedute dall'azienda principale** e quindi tutti gli **asset** di queste aziende. Per farlo, faremo quanto segue:

1. Trovare le acquisizioni dell'azienda principale, questo ci darà le aziende nel perimetro.
2. Trovare l'ASN (se presente) di ogni azienda, questo ci darà gli intervalli IP posseduti da ciascuna azienda.
3. Utilizzare ricerche whois inverse per cercare altre voci (nomi di organizzazioni, domini...) correlati al primo (questo può essere fatto in modo ricorsivo).
4. Utilizzare altre tecniche come i filtri shodan `org` e `ssl` per cercare altri asset (il trucco `ssl` può essere fatto in modo ricorsivo).

### **Acquisizioni**

Innanzitutto, dobbiamo sapere quali **altre aziende sono possedute dall'azienda principale**.\
Un'opzione è visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** l'**azienda principale**, e **cliccare** su "**acquisizioni**". Lì vedrai altre aziende acquisite dalla principale.\
Un'altra opzione è visitare la pagina **Wikipedia** dell'azienda principale e cercare **acquisizioni**.

> Ok, a questo punto dovresti conoscere tutte le aziende nel perimetro. Scopriamo come trovare i loro asset.

### **ASN**

Un numero di sistema autonomo (**ASN**) è un **numero univoco** assegnato a un **sistema autonomo** (AS) dall'**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste in **blocchi** di **indirizzi IP** che hanno una politica definita per l'accesso alle reti esterne e sono amministrati da un'unica organizzazione ma possono essere composti da diversi operatori.

È interessante scoprire se l'**azienda ha assegnato un qualsiasi ASN** per trovare i suoi **intervalli IP**. Sarà interessante eseguire un **test di vulnerabilità** contro tutti gli **host** all'interno del **perimetro** e cercare **domini** all'interno di questi IP.\
Puoi **cercare** per nome dell'azienda, per **IP** o per **dominio** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**A seconda della regione dell'azienda questi link potrebbero essere utili per raccogliere più dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(America del Nord),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(America Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Comunque, probabilmente tutte le** informazioni utili **(intervalli IP e Whois)** appaiono già nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Inoltre, l'enumerazione dei sottodomini di [**BBOT**](https://github.com/blacklanternsecurity/bbot) aggrega automaticamente e riassume gli ASN alla fine della scansione.
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
Puoi trovare gli intervalli di IP di un'organizzazione anche utilizzando [http://asnlookup.com/](http://asnlookup.com) (ha un'API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio utilizzando [http://ipv4info.com/](http://ipv4info.com).

### **Ricerca di vulnerabilità**

A questo punto conosciamo **tutte le risorse all'interno del perimetro**, quindi se ti è consentito potresti avviare uno **scanner di vulnerabilità** (Nessus, OpenVAS) su tutti gli host.\
Inoltre, potresti eseguire alcuni [**scansione delle porte**](../pentesting-network/#discovering-hosts-from-the-outside) **o utilizzare servizi come** shodan **per trovare** porte aperte **e in base a ciò che trovi dovresti** consultare questo libro su come testare la sicurezza di diversi servizi in esecuzione.\
**Inoltre, potrebbe valere la pena menzionare che puoi anche preparare alcuni elenchi di** nomi utente predefiniti **e** password **e provare a** forzare l'accesso ai servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende all'interno del perimetro e le loro risorse, è ora di trovare i domini all'interno del perimetro.

_Per favore, nota che nelle tecniche proposte di seguito è possibile trovare anche sottodomini e tali informazioni non dovrebbero essere sottovalutate._

Innanzitutto dovresti cercare il/i **dominio principale** di ciascuna azienda. Ad esempio, per _Tesla Inc._ sarà _tesla.com_.

### **DNS inverso**

Dato che hai trovato tutti gli intervalli di IP dei domini, potresti provare a eseguire **ricerche DNS inverse** su quegli **IP per trovare altri domini all'interno del perimetro**. Prova a utilizzare alcuni server DNS della vittima o alcuni server DNS ben noti (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Per far funzionare questo, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche utilizzare un tool online per queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

All'interno di un **whois** puoi trovare molte informazioni interessanti come il **nome dell'organizzazione**, l'**indirizzo**, gli **indirizzi email**, i numeri di telefono... Ma ciò che è ancora più interessante è che puoi trovare **altri asset correlati all'azienda** se esegui **ricerche reverse whois per uno qualsiasi di quei campi** (ad esempio altri registri whois in cui compare lo stesso indirizzo email).\
Puoi utilizzare strumenti online come:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuito**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
* [https://www.whoxy.com/](https://www.whoxy.com) - Sito web **gratuito**, API a pagamento.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - A pagamento
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - A pagamento (solo **100 ricerche gratuite**)
* [https://www.domainiq.com/](https://www.domainiq.com) - A pagamento

Puoi automatizzare questo compito utilizzando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una chiave API whoxy).\
Puoi anche eseguire una scoperta automatica reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi utilizzare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.**

### **Tracker**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse, puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Ad esempio, se vedi lo stesso **ID di Google Analytics** o lo stesso **ID di Adsense** su diverse pagine.

Ci sono alcune pagine e strumenti che ti permettono di cercare tramite questi tracker e altri:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro obiettivo cercando lo stesso hash dell'icona favicon? Questo è esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - scoprire domini con lo stesso hash dell'icona favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In poche parole, favihash ci permetterà di scoprire domini che hanno lo stesso hash dell'icona favicon del nostro obiettivo.

Inoltre, è possibile cercare tecnologie utilizzando l'hash del favicon come spiegato in [**questo post sul blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Ciò significa che se si conosce l'**hash del favicon di una versione vulnerabile di una tecnologia web**, è possibile cercare in shodan e **trovare più luoghi vulnerabili**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ecco come puoi **calcolare l'hash della favicon** di un sito web:
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
### **Diritti d'autore / Stringa univoca**

Cerca all'interno delle pagine web **stringhe che potrebbero essere condivise tra diversi siti web nella stessa organizzazione**. La **stringa di copyright** potrebbe essere un buon esempio. Successivamente cerca quella stringa su **Google**, su altri **browser** o addirittura su **Shodan**: `shodan search http.html:"Stringa di copyright"`

### **Ora CRT**

È comune avere un lavoro pianificato come
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### **Metodologia di Ricognizione Esterna**

Per rinnovare tutti i certificati di dominio sul server. Ciò significa che anche se l'AC utilizzato per questo non imposta l'ora in cui è stato generato nel tempo di Validità, è possibile **trovare domini appartenenti alla stessa azienda nei log di trasparenza del certificato**.\
Consulta questo [**articolo per ulteriori informazioni**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Assunzione Passiva**

Apparentemente è comune che le persone assegnino sottodomini a IP che appartengono a fornitori di servizi cloud e a un certo punto **perdano quel IP ma dimentichino di rimuovere il record DNS**. Pertanto, semplicemente **creando una VM** in un cloud (come Digital Ocean) in realtà **assumerai alcuni sottodomini**.

[**Questo post**](https://kmsec.uk/blog/passive-takeover/) spiega una storia a riguardo e propone uno script che **crea una VM in DigitalOcean**, **ottiene** l'**IPv4** della nuova macchina e **cerca in Virustotal i record dei sottodomini** che vi puntano.

### **Altri metodi**

**Nota che puoi utilizzare questa tecnica per scoprire più nomi di dominio ogni volta che ne trovi uno nuovo.**

**Shodan**

Poiché conosci già il nome dell'organizzazione che possiede lo spazio IP, puoi cercare quei dati in shodan usando: `org:"Tesla, Inc."` Controlla gli host trovati per nuovi domini inaspettati nel certificato TLS.

Potresti accedere al **certificato TLS** della pagina web principale, ottenere il **nome dell'organizzazione** e quindi cercare quel nome all'interno dei **certificati TLS** di tutte le pagine web conosciute da **shodan** con il filtro: `ssl:"Tesla Motors"` o utilizzare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) è uno strumento che cerca **domini correlati** a un dominio principale e i relativi **sottodomini**, davvero sorprendente.

### **Ricerca di vulnerabilità**

Controlla per eventuali [acquisizioni di dominio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Forse un'azienda **sta utilizzando un dominio** ma ha **perso la proprietà**. Registratelo (se abbastanza economico) e informa l'azienda.

Se trovi un **dominio con un IP diverso** da quelli già trovati nella scoperta degli asset, dovresti eseguire una **scansione di vulnerabilità di base** (utilizzando Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il dominio è ospitato all'interno di un IP che non è controllato dal cliente, quindi non è nell'ambito, fai attenzione._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Suggerimento per bug bounty**: **iscriviti** a **Intigriti**, una piattaforma premium di **bug bounty creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi e inizia a guadagnare taglie fino a **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Sottodomini

> Conosciamo tutte le aziende nell'ambito, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È ora di trovare tutti i possibili sottodomini di ciascun dominio trovato.

### **DNS**

Proviamo a ottenere i **sottodomini** dai **record DNS**. Dovremmo anche provare per il **Trasferimento di Zona** (Se vulnerabile, dovresti segnalarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più veloce per ottenere molti sottodomini è cercare in fonti esterne. Gli **strumenti** più utilizzati sono i seguenti (per ottenere risultati migliori, configurare le chiavi API):

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
Ci sono **altri strumenti/API interessanti** che, anche se non sono direttamente specializzati nel trovare sottodomini, potrebbero essere utili per trovarli, come:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilizza l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere sottodomini
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**API gratuita JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API gratuito
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
* [**gau**](https://github.com/lc/gau)**:** recupera gli URL conosciuti da AlienVault's Open Threat Exchange, il Wayback Machine e Common Crawl per un determinato dominio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Effettuano lo scraping del web alla ricerca di file JS ed estraggono i sottodomini da essi.
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
* [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) offre una API gratuita per cercare sottodomini e la cronologia degli IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre gratuitamente tutti i sottodomini relativi ai programmi di bug bounty. Puoi accedere a questi dati anche utilizzando [chaospy](https://github.com/dr-0x0x/chaospy) o accedere allo scope utilizzato da questo progetto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare un confronto di molti di questi strumenti qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi sottodomini forzando i server DNS utilizzando possibili nomi di sottodomini.

Per questa azione avrai bisogno di alcune liste di parole comuni per i sottodomini come:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche gli IP dei buoni risolutori DNS. Per generare un elenco di risolutori DNS affidabili, puoi scaricare i risolutori da [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e utilizzare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. Oppure potresti utilizzare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più raccomandati per il brute-force DNS sono:

* [**massdns**](https://github.com/blechschmidt/massdns): Questo è stato il primo strumento che ha eseguito un efficace brute-force DNS. È molto veloce, tuttavia è soggetto a falsi positivi.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Penso che questo utilizzi solo 1 risolutore
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper attorno a `massdns`, scritto in go, che ti permette di enumerare sottodomini validi utilizzando la forza bruta attiva, oltre a risolvere sottodomini con gestione dei wildcard e supporto facile input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Utilizza anche `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilizza asyncio per forzare in modo asincrono i nomi di dominio.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Secondo Round di Brute-Force DNS

Dopo aver trovato sottodomini utilizzando fonti aperte e brute-forcing, potresti generare variazioni dei sottodomini trovati per cercarne ancora di più. Diversi strumenti sono utili a questo scopo:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dato il dominio e i sottodomini, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Date i domini e i sottodomini generano permutazioni.
* Puoi ottenere la lista di permutazioni di **wordlist** di goaltdns [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Date i domini e i sottodomini generano permutazioni. Se non viene indicato un file di permutazioni, gotator utilizzerà il proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di sottodomini, può anche provare a risolverli (ma è meglio utilizzare gli strumenti precedentemente commentati).
* È possibile ottenere la **wordlist** delle permutazioni di altdns [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per eseguire permutazioni, mutazioni e alterazioni dei sottodomini. Questo strumento forzerà il risultato (non supporta il wild card dns).
* Puoi ottenere la lista di parole per le permutazioni di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basato su un dominio, **genera nuovi potenziali nomi di sottodomini** basati su pattern indicati per cercare di scoprire più sottodomini.

#### Generazione intelligente di permutazioni

* [**regulator**](https://github.com/cramppet/regulator): Per ulteriori informazioni leggi questo [**post**](https://cramppet.github.io/regulator/index.html) ma fondamentalmente otterrà le **parti principali** dai **sottodomini scoperti** e le mescolerà per trovare più sottodomini.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un fuzzer di forza bruta per subdomini abbinato a un algoritmo guidato dalle risposte DNS estremamente semplice ma efficace. Utilizza un insieme di dati di input forniti, come un elenco di parole personalizzato o record storici DNS/TLS, per sintetizzare con precisione più nomi di dominio corrispondenti ed espanderli ulteriormente in un ciclo basato sulle informazioni raccolte durante la scansione DNS.
```
echo www | subzuf facebook.com
```
### **Flusso di scoperta dei sottodomini**

Controlla questo post sul blog che ho scritto su come **automatizzare la scoperta dei sottodomini** da un dominio utilizzando **i workflow di Trickest** in modo da non dover avviare manualmente una serie di strumenti sul mio computer:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtual Hosts**

Se hai trovato un indirizzo IP contenente **una o più pagine web** appartenenti a sottodomini, potresti provare a **trovare altri sottodomini con pagine web in quell'IP** cercando in **fonti OSINT** per domini in un IP o **forzando i nomi di dominio VHost in quell'IP**.

#### OSINT

Puoi trovare alcuni **VHost in IP utilizzando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altri API**.

**Forza Bruta**

Se sospetti che alcuni sottodomini possano essere nascosti in un server web, potresti provare a forzarli:
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
Con questa tecnica potresti persino essere in grado di accedere a endpoint interni/nascosti.
{% endhint %}

### **Forza Bruta CORS**

A volte troverai pagine che restituiscono solo l'intestazione _**Access-Control-Allow-Origin**_ quando un dominio/sottodominio valido è impostato nell'intestazione _**Origin**_. In questi scenari, puoi abusare di questo comportamento per **scoprire** nuovi **sottodomini**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Forza bruta sui Bucket**

Mentre cerchi **sottodomini**, fai attenzione se sta **puntando** a qualche tipo di **bucket**, e in tal caso [**controlla le autorizzazioni**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Inoltre, a questo punto, saprai tutti i domini all'interno del perimetro, prova a [**forzare possibili nomi di bucket e controllare le autorizzazioni**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitoraggio**

Puoi **monitorare** se vengono creati **nuovi sottodomini** di un dominio monitorando i **log di Certificate Transparency** che [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) fa.

### **Ricerca di vulnerabilità**

Controlla possibili [**takeover di sottodomini**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **sottodominio** punta a un **bucket S3**, [**controlla le autorizzazioni**](../../network-services-pentesting/pentesting-web/buckets/).

Se trovi un **sottodominio con un IP diverso** da quelli che hai già trovato nella scoperta degli asset, dovresti eseguire una **scansione di vulnerabilità di base** (usando Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il sottodominio è ospitato all'interno di un IP che non è controllato dal cliente, quindi non è nel perimetro, fai attenzione._

## IP

Nei passaggi iniziali potresti aver **trovato alcuni intervalli di IP, domini e sottodomini**.\
È ora di **raccogliere tutti gli IP da quei range** e per i **domini/sottodomini (query DNS).**

Utilizzando servizi delle seguenti **API gratuite** puoi trovare anche **IP precedenti utilizzati da domini e sottodomini**. Questi IP potrebbero ancora essere di proprietà del cliente (e potrebbero consentirti di trovare [**bypass di CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche verificare i domini che puntano a un indirizzo IP specifico utilizzando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Ricerca di vulnerabilità**

**Scansiona tutte le porte degli IP che non appartengono a CDN** (poiché molto probabilmente non troverai nulla di interessante lì). Nei servizi in esecuzione scoperti potresti essere **in grado di trovare vulnerabilità**.

**Trova una** [**guida**](../pentesting-network/) **su come scansionare gli host.**

## Caccia ai server web

> Abbiamo trovato tutte le aziende e i loro asset e conosciamo gli intervalli di IP, i domini e i sottodomini all'interno del perimetro. È ora di cercare i server web.

Nei passaggi precedenti probabilmente hai già eseguito un **riconoscimento degli IP e dei domini scoperti**, quindi potresti **già aver trovato tutti i possibili server web**. Tuttavia, se non lo hai fatto, vedremo ora alcuni **trucchi veloci per cercare server web** all'interno del perimetro.

Si noti che questo sarà **orientato alla scoperta delle app web**, quindi dovresti **eseguire la scansione di vulnerabilità** e **delle porte** anche (**se consentito** dal perimetro).

Un **metodo rapido** per scoprire le **porte aperte** relative ai **server web** utilizzando [**masscan può essere trovato qui**](../pentesting-network/#http-port-discovery).\
Un altro strumento utile per cercare server web è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Basta passare un elenco di domini e cercherà di connettersi alla porta 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshot**

Ora che hai scoperto **tutti i server web** presenti nel perimetro (tra gli **IP** dell'azienda e tutti i **domini** e **sottodomini**) probabilmente **non sai da dove cominciare**. Quindi, semplifichiamoci e iniziamo semplicemente facendo degli screenshot di tutti loro. Già **dando un'occhiata** alla **pagina principale** puoi trovare **endpoint strani** che sono più **suscettibili** di essere **vulnerabili**.

Per eseguire l'idea proposta puoi utilizzare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, potresti poi utilizzare [**eyeballer**](https://github.com/BishopFox/eyeballer) per esaminare tutti gli **screenshots** e dirti **cosa è probabile che contenga vulnerabilità**, e cosa no.

## Risorse Cloud Pubbliche

Per trovare potenziali risorse cloud appartenenti a un'azienda dovresti **iniziare con un elenco di parole chiave che identificano quell'azienda**. Ad esempio, per una crypto company potresti usare parole come: `"crypto", "wallet", "dao", "<nome_dominio>", <"nomi_sottodomini">`.

Avrai anche bisogno di liste di parole **comuni usate nei bucket**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Quindi, con quelle parole dovresti generare **permutazioni** (controlla il [**Secondo Round di Brute-Force DNS**](./#second-dns-bruteforce-round) per ulteriori informazioni).

Con le liste di parole risultanti potresti utilizzare strumenti come [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che quando cerchi Risorse Cloud dovresti **cercare più che solo bucket in AWS**.

### **Ricerca di vulnerabilità**

Se trovi cose come **bucket aperti o funzioni cloud esposte** dovresti **accedervi** e cercare di capire cosa offrono e se puoi abusarne.

## Email

Con i **domini** e i **sottodomini** all'interno del perimetro hai praticamente tutto ciò di cui **hai bisogno per iniziare a cercare email**. Questi sono gli **API** e gli **strumenti** che hanno funzionato meglio per me per trovare le email di un'azienda:

* [**theHarvester**](https://github.com/laramies/theHarvester) - con API
* API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
* API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
* API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Ricerca di vulnerabilità**

Le email saranno utili in seguito per **forzare l'accesso ai log e ai servizi di autenticazione web** (come SSH). Inoltre, sono necessarie per i **phishing**. Inoltre, questi API ti daranno ancora più **informazioni sulla persona** dietro l'email, che è utile per la campagna di phishing.

## Fughe di Credenziali

Con i **domini**, i **sottodomini** e le **email** puoi iniziare a cercare credenziali trapelate in passato appartenenti a quelle email:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Ricerca di vulnerabilità**

Se trovi **credenziali trapelate valide**, è una vittoria molto facile.

## Fughe di Segreti

Le fughe di credenziali sono correlate a hack di aziende in cui è stata **trapelata e venduta informazione sensibile**. Tuttavia, le aziende potrebbero essere colpite da **altre fughe** le cui informazioni non sono in quei database:

### Fughe su Github

Credenziali e API potrebbero essere trapelati nei **repository pubblici** dell'**azienda** o degli **utenti** che lavorano per quella azienda su github.\
Puoi utilizzare lo **strumento** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repo pubblici** di un'**organizzazione** e dei suoi **sviluppatori** ed eseguire [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi automaticamente.

**Leakos** può anche essere utilizzato per eseguire **gitleaks** su tutti i **testi** forniti tramite **URL passati** ad esso poiché a volte le **pagine web contengono anche segreti**.

#### Dork su Github

Controlla anche questa **pagina** per potenziali **dork su github** che potresti cercare anche nell'organizzazione che stai attaccando:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Fughe su Paste

A volte gli attaccanti o semplicemente i lavoratori **pubblicheranno contenuti aziendali in un sito di paste**. Questo potrebbe o potrebbe non contenere **informazioni sensibili**, ma è molto interessante cercarlo.\
Puoi utilizzare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare contemporaneamente in più di 80 siti di paste.

### Dork di Google

I vecchi ma d'oro dork di Google sono sempre utili per trovare **informazioni esposte che non dovrebbero esserci**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di possibili query che non puoi eseguire manualmente. Quindi, puoi prendere i tuoi preferiti 10 o potresti utilizzare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirli tutti**.

_Nota che gli strumenti che si aspettano di eseguire l'intero database utilizzando il normale browser di Google non finiranno mai poiché Google ti bloccherà molto presto._

### **Ricerca di vulnerabilità**

Se trovi **credenziali trapelate valide o token API**, è una vittoria molto facile.

## Vulnerabilità del Codice Pubblico

Se hai scoperto che l'azienda ha del **codice open-source** puoi **analizzarlo** e cercare **vulnerabilità** al suo interno.

**A seconda del linguaggio** ci sono diversi **strumenti** che puoi utilizzare:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Ci sono anche servizi gratuiti che ti consentono di **scansionare i repository pubblici**, come:

* [**Snyk**](https://app.snyk.io/)
## [**Metodologia di Pentesting Web**](../../network-services-pentesting/pentesting-web/)

La **maggior parte delle vulnerabilità** trovate dai cacciatori di bug risiede all'interno delle **applicazioni web**, quindi a questo punto vorrei parlare di una **metodologia di test delle applicazioni web**, e puoi [**trovare queste informazioni qui**](../../network-services-pentesting/pentesting-web/).

Vorrei anche fare una menzione speciale alla sezione [**Strumenti open source di scannerizzazione automatica web**](../../network-services-pentesting/pentesting-web/#automatic-scanners), poiché, se non ci si deve aspettare che trovino vulnerabilità molto sensibili, sono utili per implementarle nei **workflow per avere alcune informazioni web iniziali.**

## Riepilogo

> Congratulazioni! A questo punto hai già eseguito **tutta l'enumerazione di base**. Sì, è di base perché si possono fare molte altre enumerazioni (vedremo più trucchi in seguito).

Quindi hai già:

1. Trovato tutte le **aziende** all'interno del perimetro
2. Trovato tutti gli **asset** appartenenti alle aziende (e eseguito una scansione delle vulnerabilità se nel perimetro)
3. Trovato tutti i **domini** appartenenti alle aziende
4. Trovato tutti i **sottodomini** dei domini (possibile takeover di sottodomini?)
5. Trovato tutti gli **IP** (da e **non da CDN**) all'interno del perimetro.
6. Trovato tutti i **server web** e ne hai preso uno **screenshot** (qualcosa di strano che merita un'analisi più approfondita?)
7. Trovato tutti i **potenziali asset pubblici cloud** appartenenti all'azienda.
8. **Email**, **leak di credenziali**, e **leak di segreti** che potrebbero portarti a una **grande vittoria molto facilmente**.
9. **Pentesting di tutti i siti web trovati**

## **Strumenti Automatici di Ricognizione Completa**

Ci sono diversi strumenti là fuori che eseguiranno parte delle azioni proposte contro un determinato perimetro.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' datato e non aggiornato

## **Riferimenti**

* Tutti i corsi gratuiti di [**@Jhaddix**](https://twitter.com/Jhaddix) come [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato a una **carriera nell'hacking** e ad hackerare l'inattaccabile - **stiamo assumendo!** (_richiesta competenza polacca scritta e parlata_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
