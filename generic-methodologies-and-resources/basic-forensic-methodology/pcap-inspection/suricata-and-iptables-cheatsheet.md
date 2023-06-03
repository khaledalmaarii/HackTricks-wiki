# Feuille de triche Suricata & Iptables

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Chaînes

Les chaînes Iptables ne sont que des listes de règles, traitées dans l'ordre. Vous trouverez toujours les 3 suivantes, mais d'autres comme NAT peuvent également être prises en charge.

* **Input** - Cette chaîne est utilisée pour contrôler le comportement des connexions entrantes.
* **Forward** - Cette chaîne est utilisée pour les connexions entrantes qui ne sont pas livrées localement. Pensez à un routeur - les données lui sont toujours envoyées mais rarement destinées au routeur lui-même ; les données sont simplement transférées vers leur destination. À moins que vous ne fassiez une sorte de routage, de NAT ou autre chose sur votre système qui nécessite une redirection, vous n'utiliserez même pas cette chaîne.
* **Output** - Cette chaîne est utilisée pour les connexions sortantes.
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Installation et configuration
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
    /etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start 
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
  - rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
    alerts: yes
    flows: all 

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
### Définitions de règles

Une règle/signature se compose des éléments suivants :

* L'**action**, détermine ce qui se passe lorsque la signature correspond.
* L'**en-tête**, définit le protocole, les adresses IP, les ports et la direction de la règle.
* Les **options de règle**, définissent les spécificités de la règle.

![](<../../../.gitbook/assets/image (642) (3).png>)

#### **Les actions valides sont**

* alerte - génère une alerte
* pass - arrête l'inspection ultérieure du paquet
* **drop** - supprime le paquet et génère une alerte
* **reject** - envoie une erreur RST/ICMP inaccessible à l'expéditeur du paquet correspondant.
* rejectsrc - identique à _reject_
* rejectdst - envoie un paquet d'erreur RST/ICMP au destinataire du paquet correspondant.
* rejectboth - envoie des paquets d'erreur RST/ICMP aux deux côtés de la conversation.

#### **Protocoles**

* tcp (pour le trafic tcp)
* udp
* icmp
* ip (ip signifie "tous" ou "n'importe quel")
* _protocoles de couche 7_ : http, ftp, tls, smb, dns, ssh... (plus dans la [**documentation**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Adresses source et de destination

Il prend en charge les plages d'adresses IP, les négations et une liste d'adresses :

| Exemple                        | Signification                            |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Toutes les adresses IP sauf 1.1.1.1       |
| !\[1.1.1.1, 1.1.1.2]           | Toutes les adresses IP sauf 1.1.1.1 et 1.1.1.2 |
| $HOME\_NET                     | Votre paramètre HOME\_NET dans yaml       |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET et pas HOME\_NET           |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 sauf 10.0.0.5                |

#### Ports source et de destination

Il prend en charge les plages de ports, les négations et les listes de ports

| Exemple         | Signification                            |
| --------------- | ---------------------------------------- |
| any             | n'importe quelle adresse                 |
| \[80, 81, 82]   | port 80, 81 et 82                        |
| \[80: 82]       | Plage de 80 à 82                         |
| \[1024: ]       | De 1024 jusqu'au numéro de port le plus élevé |
| !80             | Tous les ports sauf 80                   |
| \[80:100,!99]   | Plage de 80 à 100 mais 99 exclu          |
| \[1:80,!\[2,4]] | Plage de 1 à 80, sauf les ports 2 et 4   |

#### Direction

Il est possible d'indiquer la direction de la règle de communication appliquée :
```
source -> destination
source <> destination  (both directions)
```
#### Mots-clés

Il existe **des centaines d'options** disponibles dans Suricata pour rechercher le **paquet spécifique** que vous recherchez, ici il sera mentionné si quelque chose d'intéressant est trouvé. Consultez la [**documentation**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) pour en savoir plus !
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
