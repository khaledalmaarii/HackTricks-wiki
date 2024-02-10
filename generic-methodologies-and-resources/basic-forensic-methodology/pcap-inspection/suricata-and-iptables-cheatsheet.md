# Οδηγός αναφοράς για Suricata & Iptables

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Αλυσίδες

Στο iptables, λίστες κανόνων γνωστές ως αλυσίδες επεξεργάζονται σειριακά. Ανάμεσα σε αυτές, τρεις κύριες αλυσίδες είναι παντού παρόντες, με επιπλέον αλυσίδες όπως η NAT να υποστηρίζονται ανάλογα με τις δυνατότητες του συστήματος.

- **Αλυσίδα Εισόδου (Input Chain)**: Χρησιμοποιείται για τη διαχείριση της συμπεριφοράς των εισερχόμενων συνδέσεων.
- **Αλυσίδα Διαμετακόμισης (Forward Chain)**: Χρησιμοποιείται για την χειρισμό των εισερχόμενων συνδέσεων που δεν προορίζονται για το τοπικό σύστημα. Αυτό είναι τυπικό για συσκευές που λειτουργούν ως δρομολογητές, όπου τα δεδομένα που λαμβάνονται προορίζονται να προωθηθούν σε άλλο προορισμό. Αυτή η αλυσίδα είναι σημαντική κυρίως όταν το σύστημα εμπλέκεται σε δρομολόγηση, NATing ή παρόμοιες δραστηριότητες.
- **Αλυσίδα Εξόδου (Output Chain)**: Αφιερώνεται στον έλεγχο των εξερχόμενων συνδέσεων.

Αυτές οι αλυσίδες εξασφαλίζουν την τακτοποιημένη επεξεργασία της δικτυακής κίνησης, επιτρέποντας τον καθορισμό λεπτομερών κανόνων που διέπουν τη ροή δεδομένων εισόδου, διέλευσης και εξόδου από ένα σύστημα.
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
# Εγκατάσταση Suricata
sudo apt-get install suricata

# Ρύθμιση αρχείου ρυθμίσεων
sudo nano /etc/suricata/suricata.yaml

# Ρύθμιση κανόνων
sudo nano /etc/suricata/rules/suricata.rules

# Εκκίνηση Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Επιθέσεις & Αποκλεισμός IP

```bash
# Προσθήκη κανόνα στο Suricata
sudo suricatactl rule-update add "alert tcp any any -> any any (msg:\"Possible attack\"; sid:1000001; rev:1;)"

# Επαναφόρτωση κανόνων
sudo suricatactl rule-update

# Επιθέσεις από IP
sudo iptables -A INPUT -s <IP_ADDRESS> -j DROP

# Αποκλεισμός IP
sudo iptables -A INPUT -s <IP_ADDRESS> -j ACCEPT
```

### Επιθέσεις & Αποκλεισμός Πόρων

```bash
# Προσθήκη κανόνα στο Suricata
sudo suricatactl rule-update add "alert tcp any any -> any any (msg:\"Possible attack\"; sid:1000001; rev:1;)"

# Επαναφόρτωση κανόνων
sudo suricatactl rule-update

# Αποκλεισμός πόρων
sudo iptables -A INPUT -p tcp --dport <PORT_NUMBER> -j DROP

# Αποκλεισμός πόρων με εξαίρεση IP
sudo iptables -A INPUT -p tcp --dport <PORT_NUMBER> -s <IP_ADDRESS> -j ACCEPT
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
### Ορισμοί Κανόνων

[Από τα έγγραφα:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Ένας κανόνας/υπογραφή αποτελείται από τα εξής:

* Η **ενέργεια**, καθορίζει τι συμβαίνει όταν ο κανόνας ταιριάζει.
* Η **κεφαλίδα**, καθορίζει το πρωτόκολλο, τις διευθύνσεις IP, τις θύρες και την κατεύθυνση του κανόνα.
* Οι **επιλογές του κανόνα**, καθορίζουν τις λεπτομέρειες του κανόνα.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Οι έγκυρες ενέργειες είναι**

* alert - δημιουργία ειδοποίησης
* pass - διακοπή περαιτέρω επιθεώρησης του πακέτου
* **drop** - απόρριψη του πακέτου και δημιουργία ειδοποίησης
* **reject** - αποστολή RST/ICMP ανεπιτυχούς απάντησης στον αποστολέα του αντίστοιχου πακέτου.
* rejectsrc - ίδιο με το _reject_
* rejectdst - αποστολή RST/ICMP πακέτου σφάλματος στον παραλήπτη του αντίστοιχου πακέτου.
* rejectboth - αποστολή RST/ICMP πακέτων σφάλματος σε και τις δύο πλευρές της συνομιλίας.

#### **Πρωτόκολλα**

* tcp (για tcp-κίνηση)
* udp
* icmp
* ip (το ip σημαίνει 'όλα' ή 'οποιοδήποτε')
* _πρωτόκολλα επιπέδου 7_: http, ftp, tls, smb, dns, ssh... (περισσότερα στα [**έγγραφα**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Διευθύνσεις προέλευσης και προορισμού

Υποστηρίζει εύρος διευθύνσεων IP, αρνήσεις και λίστες διευθύνσεων:

| Παράδειγμα                        | Σημασία                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Κάθε διεύθυνση IP εκτός από την 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Κάθε διεύθυνση IP εκτός από την 1.1.1.1 και 1.1.1.2 |
| $HOME\_NET                     | Η ρύθμισή σας για το HOME\_NET στο αρχείο yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET και όχι HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 εκτός από το 10.0.0.5          |

#### Θύρες προέλευσης και προορισμού

Υποστηρίζει εύρος θυρών, αρνήσεις και λίστες θυρών

| Παράδειγμα         | Σημασία                                |
| --------------- | -------------------------------------- |
| any             | οποιαδήποτε διεύθυνση                            |
| \[80, 81, 82]   | θύρα 80, 81 και 82                     |
| \[80: 82]       | Εύρος από 80 έως 82                  |
| \[1024: ]       | Από 1024 έως τον υψηλότερο αριθμό θύρας |
| !80             | Κάθε θύρα εκτός από την 80                      |
| \[80:100,!99]   | Εύρος από 80 έως 100 αλλά εξαιρούνται οι 99 |
| \[1:80,!\[2,4]] | Εύρος από 1-80, εκτός θυρών 2 και 4  |

#### Κατεύθυνση

Είναι δυνατόν να υποδείξετε την κατεύθυνση του κανόνα επικοινωνίας που εφαρμόζεται:
```
source -> destination
source <> destination  (both directions)
```
#### Λέξεις-κλειδιά

Υπάρχουν **εκατοντάδες επιλογές** διαθέσιμες στο Suricata για να αναζητήσετε το **συγκεκριμένο πακέτο** που ψάχνετε, εδώ θα αναφερθεί αν βρεθεί κάτι ενδιαφέρον. Ελέγξτε την [**τεκμηρίωση**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) για περισσότερες πληροφορίες!
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

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
