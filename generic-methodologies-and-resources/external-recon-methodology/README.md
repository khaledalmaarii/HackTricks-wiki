# Méthodologie de reconnaissance externe

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) **et** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **dépôts GitHub.**

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si vous êtes intéressé par une **carrière en piratage** et pirater l'impiratable - **nous recrutons !** (_maîtrise du polonais écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Découvertes d'actifs

> On vous a dit que tout ce qui appartient à une entreprise est dans le périmètre, et vous voulez découvrir ce que possède réellement cette entreprise.

Le but de cette phase est d'obtenir toutes les **entreprises appartenant à l'entreprise principale** puis tous les **actifs** de ces entreprises. Pour ce faire, nous allons :

1. Trouver les acquisitions de l'entreprise principale, cela nous donnera les entreprises dans le périmètre.
2. Trouver l'ASN (le cas échéant) de chaque entreprise, cela nous donnera les plages d'IP possédées par chaque entreprise.
3. Utiliser des recherches whois inversées pour rechercher d'autres entrées (noms d'organisation, domaines...) liées au premier (cela peut être fait de manière récursive).
4. Utiliser d'autres techniques comme les filtres shodan `org` et `ssl` pour rechercher d'autres actifs (le truc `ssl` peut être fait de manière récursive).

### **Acquisitions**

Tout d'abord, nous devons savoir quelles **autres entreprises sont détenues par l'entreprise principale**.\
Une option est de visiter [https://www.crunchbase.com/](https://www.crunchbase.com), **rechercher** l'**entreprise principale**, et **cliquer** sur "**acquisitions**". Vous verrez d'autres entreprises acquises par la principale.\
Une autre option est de visiter la page **Wikipedia** de l'entreprise principale et rechercher les **acquisitions**.

> À ce stade, vous devriez connaître toutes les entreprises dans le périmètre. Voyons comment trouver leurs actifs.

### **ASNs**

Un numéro de système autonome (**ASN**) est un **numéro unique** attribué à un **système autonome** (AS) par l'**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** se compose de **blocs** d'**adresses IP** qui ont une politique d'accès aux réseaux externes clairement définie et sont administrés par une seule organisation mais peuvent être composés de plusieurs opérateurs.

Il est intéressant de savoir si l'**entreprise a attribué un ASN** pour trouver ses **plages d'IP**. Il sera intéressant d'effectuer un **test de vulnérabilité** contre tous les **hôtes** dans le **périmètre** et de rechercher des domaines à l'intérieur de ces IPs.\
Vous pouvez **rechercher** par **nom d'entreprise**, par **IP** ou par **domaine** sur [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Selon la région de l'entreprise, ces liens pourraient être utiles pour recueillir plus de données :** [**AFRINIC**](https://www.afrinic.net) **(Afrique),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amérique du Nord),** [**APNIC**](https://www.apnic.net) **(Asie),** [**LACNIC**](https://www.lacnic.net) **(Amérique latine),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Quoi qu'il en soit, probablement toutes les** informations utiles **(plages d'IP et Whois)** apparaissent déjà dans le premier lien.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
De plus, l'**[outil BBOT](https://github.com/blacklanternsecurity/bbot)** effectue automatiquement l'énumération des sous-domaines et agrège les résumés des ASN à la fin de l'analyse.
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
Vous pouvez trouver les plages d'adresses IP d'une organisation en utilisant également [http://asnlookup.com/](http://asnlookup.com) (il dispose d'une API gratuite).\
Vous pouvez trouver l'IP et l'ASN d'un domaine en utilisant [http://ipv4info.com/](http://ipv4info.com).

### **Recherche de vulnérabilités**

À ce stade, nous connaissons **tous les actifs dans le périmètre**, donc si vous en avez l'autorisation, vous pourriez lancer un **scanner de vulnérabilités** (Nessus, OpenVAS) sur tous les hôtes.\
De plus, vous pourriez lancer des [**scans de ports**](../pentesting-network/#discovering-hosts-from-the-outside) **ou utiliser des services comme** shodan **pour trouver** les ports ouverts **et en fonction de ce que vous trouvez, vous devriez** consulter ce livre pour savoir comment tester de possibles services en cours d'exécution.\
**Il pourrait également être utile de mentionner que vous pouvez également préparer des** listes de noms d'utilisateur **et de** mots de passe **par défaut et essayer de** forcer l'accès aux services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises dans le périmètre et leurs actifs, il est temps de trouver les domaines dans le périmètre.

_Veuillez noter que dans les techniques proposées suivantes, vous pouvez également trouver des sous-domaines et ces informations ne doivent pas être sous-estimées._

Tout d'abord, vous devriez rechercher le(s) **domaine(s) principal(aux)** de chaque entreprise. Par exemple, pour _Tesla Inc._ ce sera _tesla.com_.

### **DNS inversé**

Une fois que vous avez trouvé toutes les plages d'adresses IP des domaines, vous pourriez essayer d'effectuer des **recherches DNS inversées** sur ces **IP pour trouver d'autres domaines dans le périmètre**. Essayez d'utiliser un serveur DNS de la victime ou un serveur DNS bien connu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Pour que cela fonctionne, l'administrateur doit activer manuellement le PTR.\
Vous pouvez également utiliser un outil en ligne pour ces informations : [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (boucle)**

À l'intérieur d'un **whois**, vous pouvez trouver beaucoup d'**informations** intéressantes telles que le **nom de l'organisation**, l'**adresse**, les **emails**, les numéros de téléphone... Mais ce qui est encore plus intéressant, c'est que vous pouvez trouver **d'autres actifs liés à l'entreprise** si vous effectuez des **recherches de reverse whois par l'un de ces champs** (par exemple, d'autres registres whois où le même email apparaît).\
Vous pouvez utiliser des outils en ligne comme :

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuit**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuit**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuit**
* [https://www.whoxy.com/](https://www.whoxy.com) - Web **Gratuit**, API non gratuite.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Non gratuit
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Non gratuit (seulement **100 recherches gratuites**)
* [https://www.domainiq.com/](https://www.domainiq.com) - Non gratuit

Vous pouvez automatiser cette tâche en utilisant [**DomLink** ](https://github.com/vysecurity/DomLink)(nécessite une clé API whoxy).\
Vous pouvez également effectuer une découverte automatique de reverse whois avec [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir plus de noms de domaine à chaque fois que vous trouvez un nouveau domaine.**

### **Trackers**

Si vous trouvez le **même ID du même tracker** sur 2 pages différentes, vous pouvez supposer que **les deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **ID Google Analytics** ou le même **ID Adsense** sur plusieurs pages.

Il existe des pages et des outils qui vous permettent de rechercher ces trackers et plus encore :

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Saviez-vous que nous pouvons trouver des domaines et sous-domaines liés à notre cible en recherchant le même hash d'icône favicon ? C'est exactement ce que l'outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) créé par [@m4ll0k2](https://twitter.com/m4ll0k2) fait. Voici comment l'utiliser :
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - découvrir les domaines avec le même hachage d'icône favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En termes simples, favihash nous permettra de découvrir les domaines qui ont le même hachage d'icône favicon que notre cible.

De plus, vous pouvez également rechercher des technologies en utilisant le hachage d'icône favicon comme expliqué dans [**cet article de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Cela signifie que si vous connaissez le **hachage de l'icône favicon d'une version vulnérable d'une technologie web**, vous pouvez rechercher si dans shodan et **trouver plus d'endroits vulnérables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Voici comment vous pouvez **calculer le hash du favicon** d'un site web :
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
### **Droit d'auteur / Chaîne unique**

Recherchez à l'intérieur des pages web des **chaînes qui pourraient être partagées sur différents sites web de la même organisation**. La **chaîne de droit d'auteur** pourrait être un bon exemple. Ensuite, recherchez cette chaîne sur **Google**, dans d'autres **navigateurs** ou même dans **Shodan**: `shodan search http.html:"Chaîne de droit d'auteur"`

### **Temps CRT**

Il est courant d'avoir une tâche cron telle que
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### **Prise de contrôle passive**

Apparemment, il est courant que des personnes attribuent des sous-domaines à des adresses IP appartenant à des fournisseurs de cloud et à un moment donné **perdent cette adresse IP mais oublient de supprimer l'enregistrement DNS**. Par conséquent, simplement **lancer une VM** dans un cloud (comme Digital Ocean) vous permettra en fait de **prendre le contrôle de certains sous-domaines**.

[**Ce post**](https://kmsec.uk/blog/passive-takeover/) explique une histoire à ce sujet et propose un script qui **démarre une VM dans DigitalOcean**, **obtient** l'**IPv4** de la nouvelle machine, et **cherche dans Virustotal les enregistrements de sous-domaines** pointant vers elle.

### **Autres méthodes**

**Notez que vous pouvez utiliser cette technique pour découvrir plus de noms de domaine à chaque fois que vous trouvez un nouveau domaine.**

**Shodan**

Comme vous connaissez déjà le nom de l'organisation possédant l'espace IP. Vous pouvez rechercher ces données dans shodan en utilisant : `org:"Tesla, Inc."` Vérifiez les hôtes trouvés pour de nouveaux domaines inattendus dans le certificat TLS.

Vous pourriez accéder au **certificat TLS** de la page web principale, obtenir le **nom de l'organisation** et ensuite rechercher ce nom dans les **certificats TLS** de toutes les pages web connues par **shodan** avec le filtre : `ssl:"Tesla Motors"` ou utiliser un outil comme [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) est un outil qui recherche des **domaines associés** à un domaine principal et leurs **sous-domaines**, assez incroyable.

### **Recherche de vulnérabilités**

Vérifiez s'il y a une [prise de contrôle de domaine](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Peut-être qu'une entreprise **utilise un domaine** mais qu'elle **a perdu la propriété**. Enregistrez-le simplement (si c'est assez bon marché) et informez l'entreprise.

Si vous trouvez un **domaine avec une IP différente** de ceux que vous avez déjà trouvés dans la découverte des actifs, vous devriez effectuer une **analyse de vulnérabilité de base** (en utilisant Nessus ou OpenVAS) et un [**scan de ports**](../pentesting-network/#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services en cours d'exécution, vous pouvez trouver dans **ce livre quelques astuces pour les "attaquer"**.\
_Notez que parfois le domaine est hébergé dans une IP qui n'est pas contrôlée par le client, donc il n'est pas inclus dans le périmètre, soyez prudent._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Astuce de prime de bug** : **inscrivez-vous** sur **Intigriti**, une plateforme de prime de bug premium créée par des hackers, pour des hackers ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des primes allant jusqu'à **100 000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Sous-domaines

> Nous connaissons toutes les entreprises dans le périmètre, tous les actifs de chaque entreprise et tous les domaines liés aux entreprises.

Il est temps de trouver tous les sous-domaines possibles de chaque domaine trouvé.

### **DNS**

Essayons d'obtenir les **sous-domaines** à partir des enregistrements **DNS**. Nous devrions également essayer le **Transfert de Zone** (Si vulnérable, vous devriez le signaler).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Le moyen le plus rapide d'obtenir de nombreux sous-domaines est de rechercher dans des sources externes. Les **outils** les plus utilisés sont les suivants (pour de meilleurs résultats, configurez les clés API) :

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
Il existe **d'autres outils/API intéressants** qui, même s'ils ne sont pas directement spécialisés dans la recherche de sous-domaines, pourraient être utiles pour trouver des sous-domaines, tels que :

* [**Crobat**](https://github.com/cgboal/sonarsearch)** :** Utilise l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) pour obtenir des sous-domaines
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**API gratuit JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API gratuit
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
* [**gau**](https://github.com/lc/gau)**:** récupère les URL connues de l'Open Threat Exchange d'AlienVault, de la Machine à remonter le temps et de Common Crawl pour un domaine donné.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Ils parcourent le web à la recherche de fichiers JS et extraient les sous-domaines à partir de là.
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
* [**securitytrails.com**](https://securitytrails.com/) propose une API gratuite pour rechercher des sous-domaines et l'historique des adresses IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ce projet offre gratuitement tous les sous-domaines liés aux programmes de bug bounty. Vous pouvez accéder à ces données également en utilisant [chaospy](https://github.com/dr-0x0x/chaospy) ou même accéder au périmètre utilisé par ce projet [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous pouvez trouver une comparaison de nombreux de ces outils ici: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux sous-domaines en forçant les serveurs DNS en utilisant des noms de sous-domaine possibles.

Pour cette action, vous aurez besoin de certaines listes de mots de sous-domaines courants comme:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Et aussi des adresses IP de bons résolveurs DNS. Pour générer une liste de résolveurs DNS de confiance, vous pouvez télécharger les résolveurs depuis [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Ou vous pourriez utiliser: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour le brute force DNS sont:

* [**massdns**](https://github.com/blechschmidt/massdns): C'était le premier outil qui a effectué un brute force DNS efficace. Il est très rapide mais il est sujet aux faux positifs.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Celui-ci, je pense, utilise simplement 1 résolveur
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est une enveloppe autour de `massdns`, écrite en go, qui vous permet d'énumérer des sous-domaines valides en utilisant la force brute active, ainsi que de résoudre des sous-domaines avec une gestion des jokers et un support d'entrée-sortie facile.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Il utilise également `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour forcer de manière asynchrone les noms de domaine.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Deuxième tour de force brute DNS

Après avoir trouvé des sous-domaines en utilisant des sources ouvertes et la force brute, vous pourriez générer des altérations des sous-domaines trouvés pour essayer d'en trouver encore plus. Plusieurs outils sont utiles à cette fin :

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)** :** À partir des domaines et sous-domaines donnés, générer des permutations.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Étant donné les domaines et sous-domaines, générer des permutations.
* Vous pouvez obtenir la liste de permutations de **wordlist** de goaltdns [**ici**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Étant donné les domaines et sous-domaines, générer des permutations. Si aucun fichier de permutations n'est indiqué, gotator utilisera le sien.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): En plus de générer des permutations de sous-domaines, il peut également essayer de les résoudre (mais il est préférable d'utiliser les outils précédemment commentés).
* Vous pouvez obtenir la **liste de mots** de permutations altdns [**ici**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Un autre outil pour effectuer des permutations, des mutations et des altérations de sous-domaines. Cet outil effectuera une attaque en force sur le résultat (il ne prend pas en charge les wildcards DNS).
* Vous pouvez obtenir la liste de mots de permutations de dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basé sur un domaine, il **génère de nouveaux noms de sous-domaines potentiels** en fonction des modèles indiqués pour essayer de découvrir plus de sous-domaines.

#### Génération intelligente de permutations

* [**regulator**](https://github.com/cramppet/regulator): Pour plus d'informations, consultez ce [**post**](https://cramppet.github.io/regulator/index.html) mais il va essentiellement obtenir les **parties principales** des **sous-domaines découverts** et les mélanger pour trouver plus de sous-domaines.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ est un fuzzer de force brute de sous-domaine couplé à un algorithme immensément simple mais efficace guidé par les réponses DNS. Il utilise un ensemble de données d'entrée fourni, comme une liste de mots personnalisée ou des enregistrements DNS/TLS historiques, pour synthétiser avec précision plus de noms de domaine correspondants et les étendre encore plus dans une boucle basée sur les informations recueillies lors du scan DNS.
```
echo www | subzuf facebook.com
```
### **Workflow de découverte de sous-domaines**

Consultez ce billet de blog que j'ai écrit sur la façon d'**automatiser la découverte de sous-domaines** à partir d'un domaine en utilisant des **flux de travail Trickest** afin de ne pas avoir à lancer manuellement une multitude d'outils sur mon ordinateur :

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Hôtes virtuels**

Si vous trouvez une adresse IP contenant **une ou plusieurs pages web** appartenant à des sous-domaines, vous pouvez essayer de **trouver d'autres sous-domaines avec des sites web sur cette IP** en recherchant dans des sources **OSINT** des domaines dans une IP ou en **forcant les noms de domaine VHost dans cette IP**.

#### OSINT

Vous pouvez trouver certains **VHosts dans des IPs en utilisant** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou d'autres APIs**.

**Brute Force**

Si vous soupçonnez qu'un sous-domaine peut être caché dans un serveur web, vous pouvez essayer de le forcer :
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
Avec cette technique, vous pourriez même être en mesure d'accéder à des endpoints internes/cachés.
{% endhint %}

### **CORS Brute Force**

Parfois, vous trouverez des pages qui ne renvoient que l'en-tête _**Access-Control-Allow-Origin**_ lorsque qu'un domaine/sous-domaine valide est défini dans l'en-tête _**Origin**_. Dans ces scénarios, vous pouvez abuser de ce comportement pour **découvrir** de nouveaux **sous-domaines**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Forçage de seaux**

En cherchant des **sous-domaines**, gardez un œil pour voir s'ils pointent vers un **seau** de quelque type que ce soit, et dans ce cas, [**vérifiez les autorisations**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
De plus, à ce stade, vous connaîtrez tous les domaines dans le périmètre, essayez de [**forcer les noms de seau possibles et vérifiez les autorisations**](../../network-services-pentesting/pentesting-web/buckets/).

### **Surveillance**

Vous pouvez **surveiller** si de **nouveaux sous-domaines** d'un domaine sont créés en surveillant les **logs de transparence des certificats** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Recherche de vulnérabilités**

Vérifiez les possibles [**prises de contrôle de sous-domaine**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **sous-domaine** pointe vers un **seau S3**, [**vérifiez les autorisations**](../../network-services-pentesting/pentesting-web/buckets/).

Si vous trouvez un **sous-domaine avec une IP différente** de celles que vous avez déjà trouvées lors de la découverte des actifs, vous devriez effectuer une **analyse de vulnérabilité de base** (en utilisant Nessus ou OpenVAS) et un [**scan de ports**](../pentesting-network/#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. En fonction des services en cours d'exécution, vous pouvez trouver dans **ce livre quelques astuces pour les "attaquer"**.\
_Notez que parfois le sous-domaine est hébergé à l'intérieur d'une IP qui n'est pas contrôlée par le client, donc ce n'est pas dans le périmètre, soyez prudent._

## IPs

Dans les premières étapes, vous pourriez avoir **trouvé des plages d'IP, des domaines et des sous-domaines**.\
Il est temps de **recueillir toutes les IPs de ces plages** et pour les **domaines/sous-domaines (requêtes DNS).**

En utilisant les services des **APIs gratuites** suivantes, vous pouvez également trouver les **IPs précédentes utilisées par les domaines et sous-domaines**. Ces IPs pourraient toujours être la propriété du client (et pourraient vous permettre de trouver des [**contournements de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Vous pouvez également vérifier les domaines pointant vers une adresse IP spécifique en utilisant l'outil [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Recherche de vulnérabilités**

**Analysez tous les IPs qui n'appartiennent pas à des CDN** (car vous ne trouverez probablement rien d'intéressant là-dedans). Dans les services en cours d'exécution découverts, vous pourriez être **capable de trouver des vulnérabilités**.

**Trouvez un** [**guide**](../pentesting-network/) **sur la façon de scanner les hôtes.**

## Chasse aux serveurs Web

> Nous avons trouvé toutes les entreprises et leurs actifs et nous connaissons les plages d'IP, les domaines et les sous-domaines dans le périmètre. Il est temps de rechercher des serveurs Web.

Dans les étapes précédentes, vous avez probablement déjà effectué une **reconnaissance des IPs et des domaines découverts**, donc vous avez peut-être **déjà trouvé tous les serveurs Web possibles**. Cependant, si ce n'est pas le cas, nous allons maintenant voir quelques **astuces rapides pour rechercher des serveurs Web** dans le périmètre.

Veuillez noter que cela sera **orienté vers la découverte d'applications Web**, donc vous devriez également **effectuer la recherche de vulnérabilités** et **le scan de ports** également (**si autorisé** par le périmètre).

Une **méthode rapide** pour découvrir les **ports ouverts** liés aux **serveurs web** en utilisant [**masscan peut être trouvée ici**](../pentesting-network/#http-port-discovery).\
Un autre outil convivial pour rechercher des serveurs Web est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Vous passez simplement une liste de domaines et il essaiera de se connecter aux ports 80 (http) et 443 (https). De plus, vous pouvez indiquer d'essayer d'autres ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Captures d'écran**

Maintenant que vous avez découvert **tous les serveurs web** présents dans le périmètre (parmi les **IP** de l'entreprise et tous les **domaines** et **sous-domaines**), vous ne savez probablement **pas par où commencer**. Alors, simplifions les choses et commençons par prendre des captures d'écran de chacun d'eux. Juste en **jetant un coup d'œil** à la **page principale**, vous pouvez trouver des **points de terminaison étranges** qui sont plus **susceptibles** d'être **vulnérables**.

Pour mettre en œuvre l'idée proposée, vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

De plus, vous pourriez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) pour analyser toutes les **captures d'écran** et vous indiquer ce qui est susceptible de contenir des vulnérabilités, et ce qui ne l'est pas.

## Actifs Cloud Publics

Pour trouver des actifs cloud potentiels appartenant à une entreprise, vous devriez **commencer par une liste de mots-clés identifiant cette entreprise**. Par exemple, pour une entreprise de crypto, vous pourriez utiliser des mots tels que : `"crypto", "wallet", "dao", "<nom_de_domaine>", <"noms_de_sous-domaines">`.

Vous aurez également besoin de listes de mots **couramment utilisés dans les buckets** :

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, avec ces mots, vous devriez générer des **permutations** (consultez la [**Deuxième phase de Brute-Force DNS**](./#second-dns-bruteforce-round) pour plus d'informations).

Avec les listes de mots résultantes, vous pourriez utiliser des outils tels que [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

N'oubliez pas que lors de la recherche d'actifs Cloud, vous devriez **chercher plus que des buckets dans AWS**.

### **Recherche de vulnérabilités**

Si vous trouvez des éléments tels que des **buckets ou des fonctions cloud ouverts exposés**, vous devriez **y accéder** et essayer de voir ce qu'ils vous offrent et si vous pouvez les exploiter.

## E-mails

Avec les **domaines** et **sous-domaines** dans le périmètre, vous avez essentiellement tout ce dont vous **avez besoin pour commencer à rechercher des e-mails**. Voici les **API** et **outils** qui ont le mieux fonctionné pour moi pour trouver des e-mails d'une entreprise :

* [**theHarvester**](https://github.com/laramies/theHarvester) - avec des APIs
* API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
* API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
* API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Recherche de vulnérabilités**

Les e-mails seront utiles plus tard pour **brute-forcer les connexions web et les services d'authentification** (comme SSH). De plus, ils sont nécessaires pour les **phishings**. De plus, ces APIs vous donneront encore plus d'**informations sur la personne** derrière l'e-mail, ce qui est utile pour la campagne de phishing.

## Fuites d'identifiants

Avec les **domaines**, **sous-domaines** et **e-mails**, vous pouvez commencer à rechercher des identifiants qui ont été divulgués dans le passé appartenant à ces e-mails :

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Recherche de vulnérabilités**

Si vous trouvez des identifiants **divulgués valides**, c'est une victoire très facile.

## Fuites de secrets

Les fuites d'identifiants sont liées aux piratages d'entreprises où des **informations sensibles ont été divulguées et vendues**. Cependant, les entreprises pourraient être affectées par **d'autres fuites** dont les informations ne figurent pas dans ces bases de données :

### Fuites Github

Des identifiants et des APIs peuvent être divulgués dans les **dépôts publics** de l'**entreprise** ou des **utilisateurs** travaillant pour cette entreprise github.\
Vous pouvez utiliser l'**outil** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **dépôts publics** d'une **organisation** et de ses **développeurs** et exécuter [**gitleaks**](https://github.com/zricethezav/gitleaks) dessus automatiquement.

**Leakos** peut également être utilisé pour exécuter **gitleaks** sur tous les **textes** fournis par les **URLs passées** à celui-ci car parfois les **pages web contiennent également des secrets**.

#### Dorks Github

Consultez également cette **page** pour des **dorks github potentiels** que vous pourriez également rechercher dans l'organisation que vous attaquez :

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Fuites de Pastes

Parfois, les attaquants ou simplement les employés **publieront du contenu d'entreprise sur un site de coller**. Cela peut ou non contenir des **informations sensibles**, mais il est très intéressant de le rechercher.\
Vous pouvez utiliser l'outil [**Pastos**](https://github.com/carlospolop/Pastos) pour rechercher dans plus de 80 sites de coller en même temps.

### Dorks Google

Les anciens mais bons dorks google sont toujours utiles pour trouver des **informations exposées qui ne devraient pas s'y trouver**. Le seul problème est que la [**base de données de piratage Google**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas exécuter manuellement. Ainsi, vous pouvez choisir vos 10 préférées ou vous pourriez utiliser un **outil tel que** [**Gorks**](https://github.com/carlospolop/Gorks) **pour les exécuter toutes**.

_Notez que les outils qui s'attendent à exécuter toute la base de données en utilisant le navigateur Google régulier ne se termineront jamais car Google vous bloquera très rapidement._

### **Recherche de vulnérabilités**

Si vous trouvez des **identifiants ou jetons API divulgués valides**, c'est une victoire très facile.

## Vulnérabilités de Code Public

Si vous découvrez que l'entreprise a du **code open-source**, vous pouvez **l'analyser** et rechercher des **vulnérabilités**.

**Selon le langage**, il existe différents **outils** que vous pouvez utiliser :

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Il existe également des services gratuits qui vous permettent de **scanner les dépôts publics**, tels que :

* [**Snyk**](https://app.snyk.io/)
## [**Méthodologie de test d'application Web**](../../network-services-pentesting/pentesting-web/)

La **majorité des vulnérabilités** trouvées par les chasseurs de bugs se trouvent à l'intérieur des **applications web**, c'est pourquoi j'aimerais parler d'une **méthodologie de test d'application web**, que vous pouvez [**trouver ici**](../../network-services-pentesting/pentesting-web/).

Je tiens également à mentionner la section [**Outils open source de scanners automatiques Web**](../../network-services-pentesting/pentesting-web/#automatic-scanners), car, même s'ils ne sont pas censés trouver des vulnérabilités très sensibles, ils sont utiles pour implémenter des **flux de travail pour obtenir des informations web initiales.**

## Récapitulatif

> Félicitations ! À ce stade, vous avez déjà effectué **toute l'énumération de base**. Oui, c'est basique car beaucoup plus d'énumération peut être faite (nous verrons plus de techniques plus tard).

Donc, vous avez déjà :

1. Trouvé toutes les **entreprises** dans le périmètre
2. Trouvé tous les **actifs** appartenant aux entreprises (et effectué une analyse de vulnérabilité si dans le périmètre)
3. Trouvé tous les **domaines** appartenant aux entreprises
4. Trouvé tous les **sous-domaines** des domaines (une prise de contrôle de sous-domaine ?)
5. Trouvé tous les **IP** (à partir de et **pas à partir de CDN**) dans le périmètre.
6. Trouvé tous les **serveurs web** et pris une **capture d'écran** d'eux (quelque chose d'étrange qui mérite un examen plus approfondi ?)
7. Trouvé tous les **actifs publics potentiels dans le cloud** appartenant à l'entreprise.
8. **Emails**, **fuites d'identifiants**, et **fuites de secrets** qui pourraient vous donner une **grosse victoire très facilement**.
9. **Testé en pentestant tous les sites web que vous avez trouvés**

## **Outils automatiques de reconnaissance complets**

Il existe plusieurs outils qui effectueront une partie des actions proposées contre un périmètre donné.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et non mis à jour

## **Références**

* Tous les cours gratuits de [**@Jhaddix**](https://twitter.com/Jhaddix) comme [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si vous êtes intéressé par une **carrière en hacking** et pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le groupe Discord](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
