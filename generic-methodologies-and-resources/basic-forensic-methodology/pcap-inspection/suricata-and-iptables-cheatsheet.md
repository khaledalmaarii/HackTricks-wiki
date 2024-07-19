# Suricata & Iptables cheatsheet

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Iptables

### Chains

Στο iptables, οι λίστες κανόνων που είναι γνωστές ως αλυσίδες επεξεργάζονται διαδοχικά. Μεταξύ αυτών, τρεις κύριες αλυσίδες είναι παρούσες καθολικά, με επιπλέον όπως το NAT να υποστηρίζονται δυνητικά ανάλογα με τις δυνατότητες του συστήματος.

- **Input Chain**: Χρησιμοποιείται για τη διαχείριση της συμπεριφοράς των εισερχόμενων συνδέσεων.
- **Forward Chain**: Χρησιμοποιείται για την επεξεργασία εισερχόμενων συνδέσεων που δεν προορίζονται για το τοπικό σύστημα. Αυτό είναι τυπικό για συσκευές που λειτουργούν ως δρομολογητές, όπου τα δεδομένα που λαμβάνονται προορίζονται να προωθηθούν σε άλλο προορισμό. Αυτή η αλυσίδα είναι σχετική κυρίως όταν το σύστημα εμπλέκεται σε δρομολόγηση, NATing ή παρόμοιες δραστηριότητες.
- **Output Chain**: Αφιερωμένη στη ρύθμιση των εξερχόμενων συνδέσεων.

Αυτές οι αλυσίδες διασφαλίζουν την τακτική επεξεργασία της δικτυακής κίνησης, επιτρέποντας τον καθορισμό λεπτομερών κανόνων που διέπουν τη ροή των δεδομένων μέσα, μέσω και έξω από ένα σύστημα.
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

### Εγκατάσταση & Ρύθμιση
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
### Κανόνες Ορισμοί

[Από τα έγγραφα:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Ένας κανόνας/υπογραφή αποτελείται από τα εξής:

* Η **ενέργεια**, καθορίζει τι συμβαίνει όταν η υπογραφή ταιριάζει.
* Η **κεφαλίδα**, ορίζει το πρωτόκολλο, τις διευθύνσεις IP, τις θύρες και την κατεύθυνση του κανόνα.
* Οι **επιλογές κανόνα**, καθορίζουν τις λεπτομέρειες του κανόνα.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Έγκυρες ενέργειες είναι**

* alert - δημιουργία ειδοποίησης
* pass - σταματήστε την περαιτέρω επιθεώρηση του πακέτου
* **drop** - απόρριψη πακέτου και δημιουργία ειδοποίησης
* **reject** - αποστολή σφάλματος RST/ICMP μη προσβάσιμο στον αποστολέα του αντίστοιχου πακέτου.
* rejectsrc - το ίδιο με το _reject_
* rejectdst - αποστολή σφάλματος RST/ICMP στον παραλήπτη του αντίστοιχου πακέτου.
* rejectboth - αποστολή σφαλμάτων RST/ICMP και στις δύο πλευρές της συνομιλίας.

#### **Πρωτόκολλα**

* tcp (για tcp-traffic)
* udp
* icmp
* ip (ip σημαίνει ‘όλα’ ή ‘οποιοδήποτε’)
* _layer7 πρωτόκολλα_: http, ftp, tls, smb, dns, ssh... (περισσότερα στα [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Διευθύνσεις Πηγής και Προορισμού

Υποστηρίζει εύρος IP, αρνήσεις και μια λίστα διευθύνσεων:

| Παράδειγμα                     | Σημασία                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Κάθε διεύθυνση IP εκτός από 1.1.1.1     |
| !\[1.1.1.1, 1.1.1.2]           | Κάθε διεύθυνση IP εκτός από 1.1.1.1 και 1.1.1.2 |
| $HOME\_NET                     | Η ρύθμισή σας για το HOME\_NET στο yaml  |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET και όχι HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 εκτός από 10.0.0.5          |

#### Θύρες Πηγής και Προορισμού

Υποστηρίζει εύρος θυρών, αρνήσεις και λίστες θυρών

| Παράδειγμα         | Σημασία                                |
| --------------- | -------------------------------------- |
| any             | οποιαδήποτε διεύθυνση                |
| \[80, 81, 82]   | θύρα 80, 81 και 82                     |
| \[80: 82]       | Εύρος από 80 έως 82                   |
| \[1024: ]       | Από 1024 έως τον υψηλότερο αριθμό θύρας |
| !80             | Κάθε θύρα εκτός από 80                |
| \[80:100,!99]   | Εύρος από 80 έως 100 αλλά 99 εξαιρούμενο |
| \[1:80,!\[2,4]] | Εύρος από 1-80, εκτός από τις θύρες 2 και 4  |

#### Κατεύθυνση

Είναι δυνατόν να υποδείξετε την κατεύθυνση του κανόνα επικοινωνίας που εφαρμόζεται:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Υπάρχουν **εκατοντάδες επιλογές** διαθέσιμες στο Suricata για να αναζητήσετε το **συγκεκριμένο πακέτο** που ψάχνετε, εδώ θα αναφερθεί αν βρεθεί κάτι ενδιαφέρον. Ελέγξτε την [**τεκμηρίωση**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) για περισσότερα!
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
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
