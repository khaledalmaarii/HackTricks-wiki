# Μεθοδολογία Εξωτερικής Ανακάλυψης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Συμβουλή για bug bounty**: **εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα bug bounty που δημιουργήθηκε από χάκερς, για χάκερς**! Γίνετε μέλος μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Ανακαλύψεις Περιουσιακών Στοιχείων

> Σας είπαν ότι όλα όσα ανήκουν σε μια εταιρεία εμπίπτουν στο πεδίο εφαρμογής και θέλετε να διαπιστώσετε τι ακριβώς ανήκει σε αυτήν την εταιρεία.

Ο στόχος αυτής της φάσης είναι να αποκτήσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **περιουσιακά στοιχεία** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα πρέπει να:

1. Βρούμε τις εξαγορές της κύριας εταιρείας, αυτό θα μας δώσει τις εταιρείες που εμπίπτουν στο πεδίο εφαρμογής.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας, αυτό θα μας δώσει τις IP εύρους που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε αναστροφή whois για να αναζητήσουμε άλλες καταχωρήσεις (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήσουμε άλλες τεχνικές όπως τα φίλτρα shodan `org` και `ssl` για να αναζητήσουμε άλλα περιουσιακά στοιχεία (το κόλπο του `ssl` μπορεί να γίνει αναδρομικά).

### **Εξαγορές**

Καταρχάς, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε το [https://www.crunchbase.com/](https://www.crunchbase.com), **αναζητήστε** την **κύρια εταιρεία** και **κάντε κλικ** στο "**εξαγορές**". Εκεί θα δείτε άλλες εταιρείες που έχουν εξαγοραστεί από την κύρια.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα **Wikipedia** της κύριας εταιρείας και να αναζητήσετε **εξαγορές**.

> Εντάξει, σε αυτό το σημείο πρέπει να γνωρίζετε όλες τις εταιρείες που εμπίπτουν στο πεδίο εφαρμογής. Ας δούμε πώς θα βρούμε τα περιουσιακά τους στοιχεία.

### **ASNs**

Ένα αυτόνομο αριθμό συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που ανατίθεται σε ένα **αυτόνομο σύστημα** (AS) από την **Αρχή Ανάθεσης Αριθμών Διαδικτύου (IANA)**.\
Ένα **AS** αποτελείται από **εύρη IP** που έχουν ορισμένη πολιτική για την πρόσβαση σε εξωτερικά δίκτυα και διοικούνται από μια μόνο οργάνωση, αλλά μπορεί να αποτελείται από πολλούς φορείς.

Είναι ενδιαφέρον να βρούμε αν η **εταιρεία έχει ανατεθεί κάποιο ASN** για να βρούμε τα **εύρη IP** της. Θα ήταν ενδιαφέρον να πραγματοποιήσουμε ένα **τεστ ευπάθειας** εναντίον όλων των **hosts** που εμπίπτουν στο πεδίο εφαρμογής και να αναζητήσουμε **domains** μέσα σε αυτά τα IP.\
Μπορείτε να **αναζητήσετε** με το όνομα της εταιρείας, με το **IP** ή με το **domain** στο [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για να συγκεντρώ
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, η υπο-απαρίθμηση του [**BBOT**](https://github.com/blacklanternsecurity/bbot) συγκεντρώνει αυτόματα και περιλαμβάνει συνοπτικές πληροφορίες για τα ASNs στο τέλος της σάρωσης.
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
Μπορείτε να βρείτε τις εύρεσης IP ενός οργανισμού χρησιμοποιώντας επίσης το [http://asnlookup.com/](http://asnlookup.com) (διαθέτει δωρεάν API).\
Μπορείτε να βρείτε το IP και το ASN ενός τομέα χρησιμοποιώντας το [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα περιουσιακά στοιχεία εντός του πεδίου εφαρμογής**, οπότε αν σας επιτρέπεται μπορείτε να εκτελέσετε κάποιο **σαρωτή ευπαθειών** (Nessus, OpenVAS) σε όλους τους υπολογιστές.\
Επίσης, μπορείτε να εκτελέσετε κάποια [**σάρωση θυρών**](../pentesting-network/#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** shodan **για να βρείτε** ανοιχτές θύρες **και ανάλογα με αυτό που βρείτε θα πρέπει** να ρίξετε μια ματιά σε αυτό το βιβλίο για το πώς να δοκιμάσετε τις πιθανές υπηρεσίες που εκτελούνται.\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε επίσης να προετοιμάσετε μερικές** προεπιλεγμένες ονομασίες χρήστη **και** κωδικούς πρόσβασης **και να δοκιμάσετε να** βρείτε την κωδικοποίηση των υπηρεσιών με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Τομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του πεδίου εφαρμογής και τα περιουσιακά τους στοιχεία, είναι ώρα να βρούμε τους τομείς εντός του πεδίου εφαρμογής.

_Παρακαλώ, σημειώστε ότι στις παρακάτω τεχνικές που προτείνονται μπορείτε επίσης να βρείτε υποτομείς και αυτές οι πληροφορίες δεν πρέπει να υποτιμηθούν._

Καταρχάς, θα πρέπει να αναζητήσετε τον **κύριο τομέα**(ς) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι _tesla.com_.

### **Αντίστροφο DNS**

Αφού έχετε βρει όλους τους εύρεσης IP των τομέων, μπορείτε να προσπαθήσετε να εκτελέσετε **αντίστροφες αναζητήσεις DNS** σε αυτά τα **IP για να βρείτε περισσότερους τομείς εντός του πεδίου εφαρμογής**. Προσπαθήστε να χρησιμοποιήσετε κάποιον διακομιστή DNS του θύματος ή κάποιον γνωστό διακομιστή DNS (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com)

### **Αντίστροφος Whois (βρόχος)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες** όπως το **όνομα του οργανισμού**, **διεύθυνση**, **ηλεκτρονικά ταχυδρομεία**, αριθμούς τηλεφώνου... Αλλά αυτό που είναι ακόμα πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα περιουσιακά στοιχεία που σχετίζονται με την εταιρεία** αν εκτελέσετε **αντίστροφες αναζητήσεις whois με βάση αυτά τα πεδία** (για παράδειγμα άλλα καταλόγους whois όπου εμφανίζεται το ίδιο ηλεκτρονικό ταχυδρομείο).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** web, όχι δωρεάν API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι Δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
* [https://www.domainiq.com/](https://www.domainiq.com) - Όχι Δωρεάν

Μπορείτε να αυτοματοποιήσετε αυτήν τη διαδικασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτεί ένα κλειδί API του whoxy).\
Μπορείτε επίσης να εκτελέσετε ορισμένες αυτόματες ανακαλύψεις αντίστροφου whois με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα τομέων κάθε φορά που βρίσκετε έναν νέο τομέα.**

### **Trackers**

Εάν βρείτε το **ίδιο αναγνωριστικό του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** διαχειρίζονται από την **ίδια ομάδα**.\
Για παράδειγμα, εάν βλέπετε το **ίδιο αναγνωριστικό Google Analytics** ή το ίδιο **αναγνωριστικό Adsense** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να αναζητήσετε με βάση αυτούς τους trackers και περισσότερα:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Ξέρατε ότι μπορούμε να βρούμε σχετικούς τομείς και υποτομείς για τον στόχο μας αναζητώντας το ίδιο hash εικονίδιου favicon; Αυτό είναι ακριβώς αυτό που κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) που δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Ακολουθούν οι οδηγίες για τη χρήση του:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ανακαλύψτε τομείς με τον ίδιο κατακόρυφο κωδικό hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Απλά, το favihash θα μας επιτρέψει να ανακαλύψουμε τομείς που έχουν τον ίδιο κατακόρυφο κωδικό hash με τον στόχο μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε τεχνολογίες χρησιμοποιώντας τον κατακόρυφο κωδικό hash όπως εξηγείται στο [**αυτό το blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι αν γνωρίζετε τον **κωδικό hash του κατακόρυφου κωδικού του favicon μιας ευπαθούς έκδοσης μιας ιστοσελίδας**, μπορείτε να αναζητήσετε αν υπάρχει στο shodan και να **βρείτε περισσότερα ευπαθή σημεία**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Έτσι μπορείτε να **υπολογίσετε το hash του favicon** ενός ιστότοπου:
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
### **Πνευματικά δικαιώματα / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που μπορεί να κοινοποιούνται σε διάφορες ιστοσελίδες της ίδιας οργάνωσης**. Η **συμβολοσειρά πνευματικών δικαιωμάτων** μπορεί να είναι ένα καλό παράδειγμα. Στη συνέχεια, αναζητήστε αυτήν τη συμβολοσειρά στο **Google**, σε άλλους **περιηγητές** ή ακόμα και στο **Shodan**: `shodan search http.html:"Συμβολοσειρά πνευματικών δικαιωμάτων"`

### **CRT Time**

Συνηθίζεται να υπάρχει ένα προγραμματισμένο έργο όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Για να ανανεώσετε όλα τα πιστοποιητικά τομέων στον διακομιστή. Αυτό σημαίνει ότι ακόμα κι αν ο ΑΚ που χρησιμοποιείται για αυτό δεν ορίζει το χρόνο που δημιουργήθηκε στον χρόνο ισχύος, είναι δυνατόν να **βρεθούν τομείς που ανήκουν στην ίδια εταιρεία στα αρχεία καταγραφής διαφάνειας πιστοποιητικών**.\
Δείτε αυτό το [**άρθρο για περισσότερες πληροφορίες**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Παθητική Κατάληψη**

Φαίνεται ότι είναι συνηθισμένο για τους ανθρώπους να αναθέτουν υποτομείς σε διευθύνσεις IP που ανήκουν σε παρόχους cloud και σε κάποιο σημείο **χάνουν αυτήν τη διεύθυνση IP αλλά ξεχνούν να αφαιρέσουν την εγγραφή DNS**. Επομένως, απλά **δημιουργώντας ένα VM** σε ένα cloud (όπως το Digital Ocean) θα **καταλάβετε πραγματικά ορισμένους υποτομείς**.

[**Αυτή η ανάρτηση**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία για αυτό και προτείνει ένα σενάριο που **δημιουργεί ένα VM στο DigitalOcean**, **παίρνει** τη **διεύθυνση IPv4** της νέας μηχανής και **ψάχνει στο Virustotal για εγγραφές υποτομέων** που δείχνουν προς αυτήν.

### **Άλλοι τρόποι**

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα τομέων κάθε φορά που βρίσκετε ένα νέο τομέα.**

**Shodan**

Καθώς γνωρίζετε ήδη το όνομα του οργανισμού που κατέχει τον χώρο IP. Μπορείτε να αναζητήσετε αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους βρεθέντες κόμβους για νέους αναπάντεχους τομείς στο πιστοποιητικό TLS.

Μπορείτε να αποκτήσετε πρόσβαση στο **πιστοποιητικό TLS** της κύριας ιστοσελίδας, να λάβετε το **όνομα του οργανισμού** και στη συνέχεια να αναζητήσετε αυτό το όνομα μέσα στα **πιστοποιητικά TLS** όλων των ιστοσελίδων που γνωρίζει το **shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder**](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που αναζητά **συναφείς τομείς** με έναν κύριο τομέα και **υποτομείς** τους, πολύ εντυπωσιακό.

### **Αναζήτηση ευπαθειών**

Ελέγξτε για κάποια [κατάληψη τομέα](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί έναν τομέα** αλλά έχει **χάσει την ιδιοκτησία**. Απλά καταχωρίστε τον (αν είναι αρκετά φθηνός) και ενημερώστε την εταιρεία.

Εάν βρείτε οποιονδήποτε **τομέα με διαφορετική διεύθυνση IP** από αυτές που έχετε ήδη βρει στην ανακάλυψη πόρων, θα πρέπει να πραγματοποιήσετε μια **βασική ανίχνευση ευπαθειών** (χρησιμοποιώντας Nessus ή OpenVAS) και μια [**σάρωση θυρών**](../pentesting-network/#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για να "επιτεθείτε" σε αυτές**.\
_Σημειώστε ότι μερικές φορές ο τομέας φιλοξενείται μέσα σε μια διεύθυνση IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι στο πεδίο εφαρμογής, προσέξτε._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Συμβουλή για bug bounty**: **εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα bug bounty που δημιουργήθηκε από χάκερς, για χάκερς**! Γίνετε μέλος σήμερα στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Υποτομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του πεδίου εφαρμογής, όλους τους πόρους κάθε εταιρείας και όλους τους σχετικούς τομείς με τις εταιρείες.

Είναι ώρα να βρούμε όλους τους πιθανούς υποτομείς κάθε βρεθέντα τομέα.

### **DNS**

Ας προσπαθήσουμε να πάρουμε τους **υποτομείς** από τις εγγραφές **DNS**. Θα πρέπει επίσης να δοκιμάσουμε την **Zone Transfer** (Εάν είναι ευπαθής, θα πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο γρηγορότερος τρόπος για να αποκτήσετε πολλά υποτομείς είναι να αναζητήσετε σε εξωτερικές πηγές. Τα πιο χρησιμοποιούμενα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα ρυθμίστε τα κλειδιά των API):

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/el-gr)
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
Υπάρχουν **άλλα ενδιαφέροντα εργαλεία/APIs** που, αν και δεν είναι απευθείας εξειδικευμένα στην εύρεση υποτομέων, μπορούν να είναι χρήσιμα για την εύρεση υποτομέων, όπως:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για να αποκτήσει υποτομείς
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**Δωρεάν API JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) δωρεάν API
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
* [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστούς συνδέσμους από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε δοθέντα τομέα.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Αυτά τα εργαλεία αναζητούν στον ιστό για αρχεία JS και εξάγουν υποτομείς από εκεί.
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
* [**Εργαλείο εύρεσης υποτομέων Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) έχει μια δωρεάν API για αναζήτηση υποτομέων και ιστορικό IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το project προσφέρει **δωρεάν όλους τους υποτομείς που σχετίζονται με προγράμματα bug-bounty**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα χρησιμοποιώντας επίσης το [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμα και να έχετε πρόσβαση στο πεδίο εφαρμογής που χρησιμοποιεί αυτό το project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Βίαιη επίθεση DNS**

Ας προσπαθήσουμε να βρούμε νέους **υποτομείς** με βίαιη επίθεση σε DNS διακομιστές χρησιμοποιώντας πιθανά ονόματα υποτομέων.

Για αυτήν την ενέργεια θα χρειαστείτε μερικές **κοινές λίστες λέξεων για υποτομείς όπως**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Και επίσης τις διευθύνσεις IP καλών DNS αναλυτών. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS αναλυτών, μπορείτε να κατεβάσετε τους αναλυτές από [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Ή μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο συνιστώμενα εργαλεία για βίαιη επίθεση DNS είναι:

* [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που πραγματοποίησε μια αποτελεσματική βίαιη επίθεση DNS. Είναι πολύ γρήγορο, αλλά είναι επιρρεπές σε λανθασμένα θετικά.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω χρησιμοποιεί μόνο 1 αναλυτή
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα περιτύλιγμα γύρω από το `massdns`, γραμμένο σε go, που σας επιτρέπει να απαριθμήσετε έγκυρους υποτομείς χρησιμοποιώντας ενεργή βίαιη επίθεση, καθώς και να επιλύσετε υποτομείς με χειρισμό μπαλαντέρ και εύκολη υποστήριξη εισόδου-εξόδου.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για να εκτελέσει ασύγχρονα επιθέσεις brute force σε ονόματα domain.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Δεύτερος γύρος DNS Brute-Force

Αφού έχετε βρει υποτομείς χρησιμοποιώντας ανοιχτές πηγές και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των βρεθέντων υποτομέων για να προσπαθήσετε να βρείτε ακόμα περισσότερους. Πολλά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δεδομένων των τομέων και των υποτομέων, δημιουργεί περιπτώσεις.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Δεδομένων των τομέων και των υποτομέων, δημιουργήστε περιπτώσεις.
* Μπορείτε να αποκτήσετε τις περιπτώσεις του goaltdns **wordlist** [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Δεδομένων των τομέων και των υποτομέων, δημιουργήστε περιπτώσεις. Εάν δεν υπάρχει αρχείο με περιπτώσεις που έχει καθοριστεί, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία περιπτώσεων υποτομέων, μπορεί επίσης να προσπαθήσει να τις επιλύσει (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγούμενα εργαλεία που σχολιάστηκαν).
* Μπορείτε να αποκτήσετε τις περιπτώσεις υποτομέων του altdns **wordlist** [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Ένα άλλο εργαλείο για να πραγματοποιήσετε περιστροφές, μεταλλάξεις και αλλοιώσεις των υποτομέων. Αυτό το εργαλείο θα δοκιμάσει όλες τις πιθανές περιπτώσεις (δεν υποστηρίζει καρτέλα dns).
* Μπορείτε να αποκτήσετε τη λίστα λέξεων με τις περιστροφές του dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Βασισμένο σε έναν τομέα, **δημιουργεί νέα πιθανά ονόματα υποτομέων** βασισμένα σε καθορισμένα μοτίβα για να ανακαλύψει περισσότερους υποτομείς.

#### Έξυπνη δημιουργία περιπτώσεων

* [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες διαβάστε αυτήν την [**ανάρτηση**](https://cramppet.github.io/regulator/index.html) αλλά ουσιαστικά θα πάρει τα **κύρια μέρη** από τους **ανακαλυφθέντες υποτομείς** και θα τα ανακατέψει για να βρει περισσότερους υποτομείς.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένα εργαλείο brute-force fuzzer για υποτομείς τομές που συνδυάζεται με έναν απλό αλλά αποτελεσματικό αλγόριθμο καθοδήγησης απόκρισης DNS. Χρησιμοποιεί ένα σύνολο παρεχόμενων δεδομένων εισόδου, όπως μια προσαρμοσμένη λίστα λέξεων ή ιστορικά αρχεία DNS/TLS, για να συνθέσει ακριβέστερα αντίστοιχα ονόματα τομέων και να τα επεκτείνει ακόμα περισσότερο σε έναν βρόχο βασισμένο στις πληροφορίες που συλλέγονται κατά τη διάρκεια της σάρωσης DNS.
```
echo www | subzuf facebook.com
```
### **Μεθοδολογία Ανακάλυψης Υποτομέων**

Ελέγξτε αυτήν την ανάρτηση στο blog που έγραψα για το πώς να **αυτοματοποιήσετε την ανακάλυψη υποτομέων** από έναν τομέα χρησιμοποιώντας τις **πιο δοκιμασμένες μεθοδολογίες** έτσι ώστε να μην χρειάζεται να εκτελέσετε χειροκίνητα πολλά εργαλεία στον υπολογιστή σας:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Εικονικοί Κόμβοι**

Εάν βρήκατε μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** που ανήκουν σε υποτομείς, μπορείτε να προσπαθήσετε να **βρείτε άλλους υποτομείς με ιστοσελίδες σε αυτήν την IP** ψάχνοντας σε πηγές **OSINT** για τομές σε μια IP ή με **βίαιη δοκιμή ονομάτων τομέων VHost** σε αυτήν την IP.

#### OSINT

Μπορείτε να βρείτε μερικούς **VHosts σε IPs χρησιμοποιώντας** το [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Βίαιη Δοκιμή**

Εάν υποψιάζεστε ότι κάποιος υποτομέας μπορεί να είναι κρυμμένος σε έναν διακομιστή ιστοσελίδων, μπορείτε να προσπαθήσετε να τον ανακαλύψετε με βίαιη δοκιμή:
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
Με αυτήν την τεχνική μπορείτε ακόμα και να έχετε πρόσβαση σε εσωτερικά/κρυφά endpoints.
{% endhint %}

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν μόνο τον κεφαλίδα _**Access-Control-Allow-Origin**_ όταν ένα έγκυρο domain/subdomain έχει οριστεί στον κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να καταχραστείτε αυτήν τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Βίαιη Δύναμη Κάδων**

Κατά την αναζήτηση για **υποτομείς**, πρέπει να παρακολουθείτε για να δείτε αν αναφέρεται σε οποιοδήποτε είδος **κάδου**, και σε αυτήν την περίπτωση [**ελέγξτε τα δικαιώματα**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Επίσης, σε αυτό το σημείο που θα γνωρίζετε όλους τους τομείς εντός του πεδίου εφαρμογής, προσπαθήστε να [**βίαια δοκιμάσετε πιθανά ονόματα κάδων και ελέγξτε τα δικαιώματα**](../../network-services-pentesting/pentesting-web/buckets/).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν δημιουργούνται **νέοι υποτομείς** ενός τομέα παρακολουθώντας τα **Αρχεία Καταγραφής Πιστοποιητικού Διαφάνειας** που κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανές [**καταλήψεις υποτομέων**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν ο **υποτομέας** αναφέρεται σε κάποιον **κάδο S3**, [**ελέγξτε τα δικαιώματα**](../../network-services-pentesting/pentesting-web/buckets/).

Αν βρείτε οποιονδήποτε **υποτομέα με διαφορετική διεύθυνση IP** από αυτές που έχετε ήδη βρει στην ανακάλυψη των περιουσιακών στοιχείων, πρέπει να πραγματοποιήσετε μια **βασική ανίχνευση ευπαθειών** (χρησιμοποιώντας το Nessus ή το OpenVAS) και μερικές [**σάρωση θυρών**](../pentesting-network/#discovering-hosts-from-the-outside) με το **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για να τις "επιτεθείτε"**.\
_Σημειώστε ότι μερικές φορές ο υποτομέας φιλοξενείται μέσα σε μια διεύθυνση IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι στο πεδίο εφαρμογής, προσέξτε._

## Διευθύνσεις IP

Στα αρχικά βήματα μπορεί να έχετε **βρει ορισμένους εύρους διευθύνσεων IP, τομείς και υποτομείς**.\
Είναι ώρα να **συλλέξετε όλες τις διευθύνσεις IP από αυτούς τους εύρους** και για τους **τομείς/υποτομείς (ερωτήματα DNS).**

Χρησιμοποιώντας υπηρεσίες από τα ακόλουθα **δωρεάν APIs** μπορείτε επίσης να βρείτε **προηγούμενες διευθύνσεις IP που χρησιμοποιήθηκαν από τομείς και υποτομείς**. Αυτές οι διευθύνσεις IP ενδέχεται να εξακολουθούν να ανήκουν στον πελάτη (και ενδέχεται να σας επιτρέψουν να βρείτε [**παρακάμψεις του CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε για τομείς που αναφέρονται σε μια συγκεκριμένη διεύθυνση IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

**Σαρώστε τις θύρες όλων των διευθύνσεων IP που δεν ανήκουν σε CDNs** (καθώς πιθανότατα δεν θα βρείτε κάτι ενδιαφέρον εκεί). Στις ανακαλυφθείσες εκτελούμενες υπηρεσίες ενδέχεται να **βρείτε ευπαθείες**.

**Βρείτε ένα** [**οδηγό**](../pentesting-network/) **σχετικά με το πώς να σαρώσετε τους οικοδεσπότες.**

## Κυνήγι διακομιστών ιστού

> Έχουμε βρει όλες τις εταιρείες και τα περιουσιακά τους στοιχεία και γνωρίζουμε τους εύρους διευθύνσεων IP, τους τομείς και τους υποτομείς εντός του πεδίου εφαρμογής. Είναι ώρα να αναζητήσουμε διακομιστές ιστού.

Στα προηγούμενα βήματα πιθανόν έχετε ήδη πραγματοποιήσει κάποια **αναγνώριση των ανακαλυφθέντων διευθύνσεων IP και τομέων**, οπότε μπορεί να έχετε ήδη βρει όλους τους πιθανούς διακομιστές ιστού. Ωστόσο, αν δεν το έχετε κάνει, θα δούμε τώρα μερικά **γρήγορα κόλπα για να αναζητήσετε διακομιστές ιστού** εντός του πεδίου εφαρμογής.

Παρακαλώ, σημειώστε ότι αυτό θα είναι **εστιασμένο στην ανακάλυψη εφαρμογών ιστού**, οπότε θα πρέπει επίσης να **πραγματοποιήσετε την ευπαθειακή** και **σάρωση θυρών** επίσης (**εάν επιτρέπεται** από το πεδίο εφαρμογής).

Ένας **γρήγορος τρόπος** για να ανακαλύψετε **ανοιχτές θύρες** που σχετίζονται με **διακομιστές ιστού** χρησιμοποιώντας το [**masscan μπορεί να βρεθεί εδώ**](../pentesting-network/#http-port-discovery).\
Ένα άλλο φιλικό εργαλείο για την αναζήτηση διακομιστών ιστού είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλά περνάτε μια λίστα με τους τομείς κ
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Στιγμιότυπα οθόνης**

Τώρα που έχετε ανακαλύψει **όλους τους διακομιστές ιστού** που υπάρχουν στο πεδίο εφαρμογής (μεταξύ των **IP** της εταιρείας και όλων των **τομέων** και **υποτομέων**), πιθανώς **να μην ξέρετε από πού να ξεκινήσετε**. Έτσι, ας το κάνουμε απλό και ας ξεκινήσουμε απλά παίρνοντας στιγμιότυπα οθόνης από όλους αυτούς. Απλά με το **να ρίξετε μια ματιά** στη **κύρια σελίδα** μπορείτε να βρείτε **περίεργα** σημεία που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να εκτελέσετε την προτεινόμενη ιδέα, μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να εκτελέσετε τα **στιγμιότυπα οθόνης** και να σας πει **τι πιθανότατα περιέχει ευπάθειες** και τι όχι.

## Δημόσια Περιουσιακά Στοιχεία Στο Cloud

Για να βρείτε δυνητικά περιουσιακά στοιχεία στο cloud που ανήκουν σε μια εταιρεία, θα πρέπει να **ξεκινήσετε με μια λίστα λέξεων-κλειδιών που αναγνωρίζουν αυτήν την εταιρεία**. Για παράδειγμα, για μια εταιρεία κρυπτονομισμάτων μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης λίστες λέξεων με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσετε **περιπτώσεις** (ελέγξτε την [**Δεύτερη Φάση Βίαιης Δύναμης DNS**](./#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις προκύπτουσες λίστες λέξεων μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Θυμηθείτε ότι όταν αναζητάτε Περιουσιακά Στοιχεία στο Cloud, θα πρέπει να **αναζητήσετε περισσότερα από απλά buckets στο AWS**.

### **Αναζήτηση ευπαθειών**

Εάν βρείτε πράγματα όπως **ανοιχτά buckets ή αποκαλυπτήρια cloud functions**, θα πρέπει να **έχετε πρόσβαση** σε αυτά και να δοκιμάσετε να δείτε τι προσφέρουν και αν μπορείτε να τα καταχραστείτε.

## Emails

Με τους **τομείς** και τους **υποτομείς** που βρίσκονται στο πεδίο εφαρμογής, έχετε βασικά ό,τι χρειάζεστε για να αρχίσετε να αναζητάτε emails. Αυτές είναι οι **APIs** και τα **εργαλεία** που έχουν λειτουργήσει καλύτερα για μένα για να βρω emails μιας εταιρείας:

* [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
* API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
* API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
* API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση ευπαθειών**

Τα emails θα σας φανούν χρήσιμα αργότερα για να **βρείτε τον κωδικό πρόσβασης του ιστοτόπου και τις υπηρεσίες πιστοποίησης** (όπως το SSH). Επίσης, χρειάζονται για **phishing**. Επιπλέον, αυτές οι APIs θα σας δώσουν ακόμη περισσότερες πληροφορίες για το άτομο πίσω από το email, που είναι χρήσιμο για την επίθεση phishing.
## [**Μεθοδολογία Πεντεστινγκ Ιστού**](../../network-services-pentesting/pentesting-web/)

Η **πλειοψηφία των ευπαθειών** που ανακαλύπτουν οι κυνηγοί ευπαθειών βρίσκονται μέσα σε **ιστοσελίδες**, οπότε σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία δοκιμών ιστοσελίδων**, και μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/).

Θέλω επίσης να κάνω μια ειδική αναφορά στην ενότητα [**Εργαλεία αυτόματης σάρωσης ιστοσελίδων ανοιχτού κώδικα**](../../network-services-pentesting/pentesting-web/#automatic-scanners), καθώς, αν και δεν πρέπει να αναμένετε να βρουν ευαίσθητες ευπαθείες, είναι χρήσιμα για να τα ενσωματώσετε σε **ροές εργασίας για να έχετε αρχικές πληροφορίες για τον ιστό**.

## Ανασκόπηση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη πραγματοποιήσει **όλη τη βασική απαρίθμηση**. Ναι, είναι βασική επειδή μπορεί να γίνει πολλή περισσότερη απαρίθμηση (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε ήδη:

1. Βρει όλες τις **εταιρείες** που εμπίπτουν στο πεδίο εφαρμογής
2. Βρει όλα τα **περιουσιακά στοιχεία** που ανήκουν στις εταιρείες (και πραγματοποιήσει μερικές ευπάθειες σάρωσης αν είναι στο πεδίο εφαρμογής)
3. Βρει όλους τους **τομείς** που ανήκουν στις εταιρείες
4. Βρει όλους τους **υποτομείς** των τομέων (υπάρχει κάποια κατάληψη υποτομέων;)
5. Βρει όλες τις **διευθύνσεις IP** (από και **όχι από CDNs**) που εμπίπτουν στο πεδίο εφαρμογής.
6. Βρει όλους τους **διακομιστές ιστού** και έκανε μια **στιγμιότυπη εικόνα** τους (υπάρχει κάτι περίεργο που αξίζει μια πιο λεπτομερή ματιά;)
7. Βρει όλα τα **πιθανά δημόσια περιουσιακά στοιχεία στο cloud** που ανήκουν στην εταιρεία.
8. **Ηλεκτρονικά ταχυδρομεία**, **διαρροές διαπιστευτηρίων** και **διαρροές μυστικών** που μπορούν να σας δώσουν μια **μεγάλη νίκη πολύ εύκολα**.
9. **Πεντεστινγκ όλων των ιστοσελίδων που βρήκατε**

## **Εργαλεία Αυτόματης Πλήρους Αναγνώρισης**

Υπάρχουν πολλά εργαλεία εκεί έξω που θα εκτελέσουν μέρος των προτεινόμενων ενεργειών για ένα συγκεκριμένο πεδίο.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και μη ενημερωμένο

## **Αναφορές**

* Όλα τα δωρεάν μαθήματα του [**@Jhaddix**](https://twitter.com/Jhaddix) όπως το [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Συμβουλή για bug bounty**: **εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα bug bounty που δημιουργήθηκε από χάκερς, για χάκερς**! Γίνετε μέλος μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
