# Suricata & Iptables Spickzettel

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

## Iptables

### Chains

In iptables werden Listen von Regeln, die als Chains bezeichnet werden, sequenziell verarbeitet. Unter diesen sind drei primäre Chains universell vorhanden, wobei zusätzliche wie NAT je nach Fähigkeiten des Systems unterstützt werden können.

- **Input Chain**: Wird zur Verwaltung des Verhaltens eingehender Verbindungen verwendet.
- **Forward Chain**: Wird zur Behandlung eingehender Verbindungen verwendet, die nicht für das lokale System bestimmt sind. Dies ist typisch für Geräte, die als Router fungieren, bei denen die empfangenen Daten an ein anderes Ziel weitergeleitet werden sollen. Diese Chain ist hauptsächlich relevant, wenn das System an Routing, NATing oder ähnlichen Aktivitäten beteiligt ist.
- **Output Chain**: Widmet sich der Regulierung ausgehender Verbindungen.

Diese Chains gewährleisten die geordnete Verarbeitung des Netzwerkverkehrs und ermöglichen die Festlegung detaillierter Regeln für den Datenfluss in ein System, durch ein System und aus einem System heraus.
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

### Installation & Konfiguration

```bash
# Installation
sudo apt-get install suricata

# Konfigurationsdatei
sudo nano /etc/suricata/suricata.yaml

# Aktivieren der IPS-Modus
sudo sed -i 's/#default-mode: default/default-mode: ids/g' /etc/suricata/suricata.yaml

# Aktivieren der Regelaktualisierung
sudo sed -i 's/#rule-update: none/rule-update: enabled/g' /etc/suricata/suricata.yaml

# Starten des Suricata-Dienstes
sudo systemctl start suricata

# Überprüfen des Suricata-Status
sudo systemctl status suricata
```

### Regelverwaltung

```bash
# Regelverzeichnis
cd /etc/suricata/rules

# Regelaktualisierung
sudo suricata-update

# Regelset anzeigen
sudo suricata-update list-enabled-rulesets

# Regelset aktivieren
sudo suricata-update enable-rule-set <rule-set-name>

# Regelset deaktivieren
sudo suricata-update disable-rule-set <rule-set-name>

# Regelset aktualisieren
sudo suricata-update update

# Regelset entfernen
sudo suricata-update remove <rule-set-name>
```

### Log-Dateien

```bash
# Suricata-Log-Verzeichnis
cd /var/log/suricata

# Suricata-Log anzeigen
sudo tail -f /var/log/suricata/fast.log
```

## iptables

### Regeln hinzufügen

```bash
# Neue Regel hinzufügen
sudo iptables -A <chain> -p <protocol> --dport <port> -j <action>

# Beispiel: Erlaube eingehenden HTTP-Verkehr
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### Regeln anzeigen

```bash
# Alle Regeln anzeigen
sudo iptables -L

# Nur Regeln einer bestimmten Kette anzeigen
sudo iptables -L <chain>
```

### Regeln entfernen

```bash
# Regel entfernen
sudo iptables -D <chain> <rule-number>

# Beispiel: Entferne Regel 2 aus der INPUT-Kette
sudo iptables -D INPUT 2
```
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
### Regeldefinitionen

[Aus der Dokumentation:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Eine Regel/Signatur besteht aus folgenden Teilen:

* Die **Aktion** bestimmt, was passiert, wenn die Signatur übereinstimmt.
* Der **Header** definiert das Protokoll, die IP-Adressen, Ports und die Richtung der Regel.
* Die **Regeloptionen** legen die Details der Regel fest.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Gültige Aktionen sind**

* alert - generiere einen Alarm
* pass - stoppe weitere Inspektion des Pakets
* **drop** - verwerfe das Paket und generiere einen Alarm
* **reject** - sende RST/ICMP unerreichbar Fehler an den Absender des passenden Pakets.
* rejectsrc - dasselbe wie _reject_
* rejectdst - sende RST/ICMP Fehlerpaket an den Empfänger des passenden Pakets.
* rejectboth - sende RST/ICMP Fehlerpakete an beide Seiten des Gesprächs.

#### **Protokolle**

* tcp (für TCP-Verkehr)
* udp
* icmp
* ip (ip steht für 'alle' oder 'beliebig')
* _Layer-7-Protokolle_: http, ftp, tls, smb, dns, ssh... (mehr in der [**Dokumentation**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Quell- und Zieladressen

Es unterstützt IP-Bereiche, Negationen und eine Liste von Adressen:

| Beispiel                        | Bedeutung                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Jede IP-Adresse außer 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Jede IP-Adresse außer 1.1.1.1 und 1.1.1.2 |
| $HOME\_NET                     | Ihre Einstellung von HOME\_NET in der YAML-Datei        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET und nicht HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 außer 10.0.0.5          |

#### Quell- und Zielports

Es unterstützt Portbereiche, Negationen und Listen von Ports

| Beispiel         | Bedeutung                                |
| --------------- | -------------------------------------- |
| any             | jede Adresse                            |
| \[80, 81, 82]   | Port 80, 81 und 82                     |
| \[80: 82]       | Bereich von 80 bis 82                  |
| \[1024: ]       | Von 1024 bis zur höchsten Portnummer |
| !80             | Jeder Port außer 80                      |
| \[80:100,!99]   | Bereich von 80 bis 100, aber 99 ausgeschlossen |
| \[1:80,!\[2,4]] | Bereich von 1-80, außer Ports 2 und 4  |

#### Richtung

Es ist möglich, die Richtung der angewendeten Kommunikationsregel anzugeben:
```
source -> destination
source <> destination  (both directions)
```
#### Schlüsselwörter

Es gibt **hunderte von Optionen** in Suricata, um nach dem **spezifischen Paket** zu suchen, nach dem Sie suchen. Hier wird erwähnt, wenn etwas Interessantes gefunden wird. Überprüfen Sie die [**Dokumentation**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) für mehr Informationen!
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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
