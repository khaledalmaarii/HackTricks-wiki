# Μεθοδολογία Εξωτερικής Αναγνώρισης

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Αν σας ενδιαφέρει η **καριέρα στο χάκινγκ** και να χακεύετε το αχακέυτο - **σας προσλαμβάνουμε!** (_απαιτείται άριστη γνώση γραπτού και προφορικού Πολωνικού_).

{% embed url="https://www.stmcyber.com/careers" %}

## Ανακαλύψεις Περιουσιακών Στοιχείων

> Σας είπαν ότι όλα όσα ανήκουν σε μια εταιρεία εμπίπτουν στο πεδίο εφαρμογής και θέλετε να διαπιστώσετε πραγματικά τι ανήκει σε αυτήν την εταιρεία.

Ο στόχος αυτής της φάσης είναι να αποκτήσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **περιουσιακά στοιχεία** αυτών των εταιρειών. Για να το επιτύχουμε, θα προχωρήσουμε στα εξής:

1. Βρείτε τις εξαγορές της κύριας εταιρείας, αυτό θα μας δώσει τις εταιρείες εντός του πεδίου εφαρμογής.
2. Βρείτε το ASN (εάν υπάρχει) κάθε εταιρείας, αυτό θα μας δώσει τις IP εύρους που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήστε αναστρεφόμενες αναζητήσεις whois για να αναζητήσετε άλλες καταχωρήσεις (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήστε άλλες τεχνικές όπως τα φίλτρα shodan `org` και `ssl` για να αναζητήσετε άλλα περιουσιακά στοιχεία (η τεχνική με το `ssl` μπορεί να γίνει αναδρομικά).

### **Εξαγορές**

Καταρχάς, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε το [https://www.crunchbase.com/](https://www.crunchbase.com), **αναζητήστε** την **κύρια εταιρεία** και **κάντε κλικ** στο "**εξαγορές**". Εκεί θα δείτε άλλες εταιρείες που έχουν εξαγοραστεί από την κύρια.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα **Wikipedia** της κύριας εταιρείας και να αναζητήσετε **εξαγορές**.

> Εντάξει, σε αυτό το σημείο πρέπει να γνωρίζετε όλες τις εταιρείες εντός του πεδίου εφαρμογής. Ας δούμε πώς μπορούμε να βρούμε τα περιουσιακά τους στοιχεία.

### **ASNs**

Ένα αυτόνομο αριθμό συστήματος (**ASN**) είναι ένα **μοναδικό νούμερο** που ανατίθεται σε ένα **αυτόνομο σύστημα** (AS) από την **Αρχή Ανατεθειμένων Αριθμών Διαδικτύου (IANA)**.\
Ένα **AS** αποτελείται από **μπλοκ** διευθύνσεων **IP** που έχουν ορισμένη πολιτική για την πρόσβαση σε εξωτερικά δίκτυα και διοικείται από μία μόνο οργάνωση αλλά μπορεί να αποτελείται από πολλούς φορείς.

Είναι ενδιαφέρον να βρούμε αν η **εταιρεία έχει ανατεθεί κάποιο ASN** για να βρούμε τα **εύρη IP** της. Θα ήταν ενδιαφέρον να πραγματοποιήσουμε ένα **τεστ ευπαθειών** εναντίον όλων των **οικοδεσποζόμενων** μέσα στο **πεδίο εφαρμογής** και να αναζητήσουμε **domains** μέσα σε αυτές τις IP.\
Μπορείτε να **αναζητήσετε** με το όνομα της εταιρείας, με την **IP** ή με το **domain** στο [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Ανάλογα με την περιοχή της εταιρείας αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για να συγκεντρώσετε περισσότερα δεδομένα:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Πάντως, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(εύρη IP και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επιπλέον, η αναγνώριση υποτομέων του [**BBOT**](https://github.com/blacklanternsecurity/bbot) συγκεντρώνει αυτόματα και περιλαμβάνει συνοπτικά τους ASNs στο τέλος της σάρωσης.
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
Μπορείτε να βρείτε την IP και το ASN ενός domain χρησιμοποιώντας το [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα περιουσιακά στοιχεία εντός του εύρους**, οπότε αν σας επιτρέπεται μπορείτε να εκτελέσετε κάποιο **σαρωτή ευπαθειών** (Nessus, OpenVAS) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε κάποια [**σάρωση θυρών**](../pentesting-network/#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** shodan **για να βρείτε** ανοιχτές θύρες **και ανάλογα με αυτό που βρείτε θα πρέπει** να ϭρείτε σε αυτό το βιβλίο πώς να δοκιμάσετε τις υπηρεσίες που εκτελούνται.\
**Επίσης, μπορεί να αξίζει να αναφέρουμε ότι μπορείτε επίσης να ετοιμάσετε κάποιες** λίστες προεπιλεγμένων ονομάτων χρήστη **και** κωδικών πρόσβασης **και να δοκιμάσετε να** κάνετε brute force σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός του εύρους και τα περιουσιακά τους στοιχεία, είναι ώρα να βρούμε τα domains εντός του εύρους.

_Παρακαλώ, σημειώστε ότι στις παρακάτω προτεινόμενες τεχνικές μπορείτε επίσης να βρείτε υποτομές και αυτές οι πληροφορίες δεν πρέπει να υποτιμηθούν._

Καταρχάς, θα πρέπει να αναζητήσετε τον **κύριο domain**(s) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι το _tesla.com_.

### **Αντίστροφη αναζήτηση DNS**

Αφού έχετε βρει όλες τις εύρεσης IP των domains μπορείτε να προσπαθήσετε να εκτελέσετε **αντίστροφες αναζητήσεις DNS** σε αυτά τα **IPs για να βρείτε περισσότερα domains εντός του εύρους**. Δοκιμάστε να χρησιμοποιήσετε κάποιον dns server του θύματος ή κάποιον γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
### **Αντίστροφη Αναζήτηση Whois (loop)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες** όπως το **όνομα της οργάνωσης**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Αλλά ακόμα πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα περιουσιακά στοιχεία που σχετίζονται με την εταιρεία** αν εκτελέσετε **αντίστροφες αναζητήσεις whois με βάση αυτά τα πεδία** (για παράδειγμα άλλες καταχωρήσεις whois όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** web, όχι δωρεάν API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι Δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
* [https://www.domainiq.com/](https://www.domainiq.com) - Όχι Δωρεάν

Μπορείτε να αυτοματοποιήσετε αυτήν την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτεί ένα κλειδί API του whoxy).\
Μπορείτε επίσης να εκτελέσετε ορισμένες αυτόματες ανακαλύψεις αντίστροφης αναζήτησης whois με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα domain κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε τον **ίδιο αριθμό ταυτοποίησης του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** διαχειρίζονται από την **ίδια ομάδα**.\
Για παράδειγμα, αν δείτε τον **ίδιο αριθμό ταυτοποίησης Google Analytics** ή τον **ίδιο αριθμό ταυτοποίησης Adsense** σε αρκετές σελίδες.

Υπάρχουν μερικές σελίδες και εργαλεία που σας επιτρέπουν να αναζητήσετε με βάση αυτούς τους trackers και περισσότερα:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Ξέρατε ότι μπορούμε να βρούμε σχετικά domains και sub domains με τον στόχο μας αναζητώντας τον ίδιο κωδικό hash του εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Εδώ είναι πώς να το χρησιμοποιήσετε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ανακαλύψτε domains με τον ίδιο κατάλογο εικονιδίου favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Απλά ειπών, το favihash θα μας επιτρέψει να ανακαλύψουμε domains που έχουν τον ίδιο κατάλογο εικονιδίου favicon με τον στόχο μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε τεχνολογίες χρησιμοποιώντας το hash του favicon όπως εξηγείται στο [**αυτό το blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι αν γνωρίζετε το **hash του favicon μιας ευάλωτης έκδοσης μιας τεχνολογίας ιστού** μπορείτε να αναζητήσετε αν υπάρχει στο shodan και να **βρείτε περισσότερα ευάλωτα σημεία**:
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
### **Πνευματική Ιδιοκτησία / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που θα μπορούσαν να κοινοποιούνται σε διαφορετικές ιστοσελίδες στον ίδιο οργανισμό**. Η **συμβολοσειρά πνευματικής ιδιοκτησίας** θα μπορούσε να είναι ένα καλό παράδειγμα. Στη συνέχεια αναζητήστε αυτή τη συμβολοσειρά στο **Google**, σε άλλους **περιηγητές** ή ακόμη και στο **Shodan**: `shodan search http.html:"Συμβολοσειρά πνευματικής ιδιοκτησίας"`

### **Χρόνος CRT**

Είναι συνηθισμένο να υπάρχει ένας προγραμματισμένος χρόνος όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### Μεθοδολογία εξωτερικής αναγνώρισης

Για να ανανεώσετε όλα τα πιστοποιητικά τομέων στον διακομιστή. Αυτό σημαίνει ότι ακόμα και αν η Αρχή Πιστοποίησης που χρησιμοποιείται γι' αυτό δεν ορίζει τον χρόνο που δημιουργήθηκε στον Χρόνο Ισχύος, είναι δυνατόν να **βρείτε τους τομείς που ανήκουν στην ίδια εταιρεία στα αρχεία διαφάνειας πιστοποιητικών**.\
Δείτε αυτό το [**άρθρο για περισσότερες πληροφορίες**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Πληροφορίες DMARC για τα Email

Μπορείτε να χρησιμοποιήσετε μια ιστοσελίδα όπως η [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **τομείς και υποτομείς που μοιράζονται τις ίδιες πληροφορίες dmarc**.

### **Παθητική Κατάληψη**

Φαίνεται ότι είναι συνηθισμένο για άτομα να αναθέτουν υποτομείς σε διευθύνσεις IP που ανήκουν σε παρόχους νέφους και σε κάποιο σημείο **χάνουν αυτήν τη διεύθυνση IP αλλά ξεχνούν να αφαιρέσουν τον εγγραφή DNS**. Επομένως, απλά **εκκινώντας ένα VM** σε ένα νέφος (όπως το Digital Ocean) θα **καταλάβετε πραγματικά κάποιους υποτομείς**.

Αυτή η [**ανάρτηση**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία γι' αυτό και προτείνει ένα σενάριο που **εκκινεί ένα VM στο DigitalOcean**, **λαμβάνει** τη **διεύθυνση IPv4** της νέας μηχανής, και **ψάχνει στο Virustotal για εγγραφές υποτομέων** που το δείχνουν.

### **Άλλοι τρόποι**

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα τομέων κάθε φορά που βρίσκετε ένα νέο τομέα.**

**Shodan**

Καθώς γνωρίζετε ήδη το όνομα του οργανισμού που κατέχει τον χώρο IP. Μπορείτε να αναζητήσετε αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους εντοπισμένους οικοδεσπότες για νέους αναπάντητους τομείς στο πιστοποιητικό TLS.

Θα μπορούσατε να έχετε πρόσβαση στο **πιστοποιητικό TLS** της κύριας ιστοσελίδας, να λάβετε το **όνομα του οργανισμού** και στη συνέχεια να αναζητήσετε αυτό το όνομα μέσα στα **πιστοποιητικά TLS** όλων των ιστοσελίδων που γνωρίζει το **shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder**](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που αναζητά **σχετικούς τομείς** με έναν κύριο τομέα και **υποτομείς** τους, πολύ εντυπωσιακό.

### **Αναζήτηση ευπαθειών**

Ελέγξτε για κάποια [κατάληψη τομέα](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **να χρησιμοποιεί έναν τομέα** αλλά **να έχει χάσει την ιδιοκτησία**. Απλά καταχωρίστε τον (αν είναι αρκετά φθηνός) και ενημερώστε την εταιρεία.

Αν βρείτε κάποιον **τομέα με διαφορετική διεύθυνση IP** από αυτές που έχετε ήδη βρει στην ανακάλυψη περιουσιακών στοιχείων, θα πρέπει να πραγματοποιήσετε μια **βασική ανίχνευση ευπαθειών** (χρησιμοποιώντας το Nessus ή το OpenVAS) και μια [**σάρωση θυρών**](../pentesting-network/#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που λειτουργούν, μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για "επίθεση" σε αυτές**.\
_Σημειώστε ότι μερικές φορές ο τομέας φιλοξενείται μέσα σε μια διεύθυνση IP που δεν ελέγχεται από τον πελάτη, οπότε δεν εμπίπτει στο πεδίο εφαρμογής, προσέξτε._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Συμβουλή για bug bounty**: **Εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα ανταμοιβής ευπαθειών δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε ανταμοιβές μέχρι **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Υποτομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του πεδίου εφαρμογής, όλα τα περιουσιακά στοιχεία κάθε εταιρείας και όλους τους τομείς που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλους τους πιθανούς υποτομείς κάθε εντοπισμένου τομέα.

{% hint style="success" %}
Σημειώστε ότι μερικά από τα εργαλεία και τεχνικές για την εύρεση τομέων μπορούν επίσης να βοηθήσουν στην εύρεση υποτομέων!
{% endhint %}

### **DNS**

Ας προσπαθήσουμε να πάρουμε **υποτομείς** από τα **αρχεία DNS**. Θα πρέπει επίσης να δοκιμάσουμε τη **μεταφορά ζώνης** (Αν είναι ευάλωτη, θα πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο ταχύτερος τρόπος για να αποκτήσετε πολλά subdomains είναι να αναζητήσετε σε εξωτερικές πηγές. Τα πιο χρησιμοποιημένα **εργαλεία** είναι τα παρακάτω (για καλύτερα αποτελέσματα ρυθμίστε τα κλειδιά API):

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
Υπάρχουν **άλλα ενδιαφέροντα εργαλεία/APIs** που αν και δεν είναι άμεσα εξειδικευμένα στον εντοπισμό υποτομέων μπορεί να είναι χρήσιμα για τον εντοπισμό υποτομέων, όπως:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για την ανάκτηση υποτομέων
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**Δωρεάν API του JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
* [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστές διευθύνσεις URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε καθορισμένο τομέα.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Αναζητούν πληροφορίες στο web για αρχεία JS και εξάγουν υποτομείς από εκεί.
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
* [**Εργαλείο εύρεσης υποτομέων του Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) έχει ένα δωρεάν API για αναζήτηση subdomains και ιστορικό IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το έργο προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα ανταμοιβής ευρημάτων σφαλμάτων**. Μπορείτε να έχετε πρόσβαση σε αυτά τα δεδομένα χρησιμοποιώντας επίσης το [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμη να έχετε πρόσβαση στο εύρος που χρησιμοποιείται από αυτό το έργο [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Δύναμη DNS Brute**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** με brute-force DNS servers χρησιμοποιώντας πιθανά ονόματα subdomain.

Για αυτή την ενέργεια θα χρειαστείτε μερικές **κοινές λίστες λέξεων subdomains όπως**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Και επίσης IPs καλών DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers μπορείτε να κατεβάσετε τους resolvers από [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Ή μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο συνιστώμενα εργαλεία για τη δύναμη DNS brute-force είναι:

* [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που πραγματοποίησε μια αποτελεσματική δύναμη DNS brute-force. Είναι πολύ γρήγορο, αλλά είναι επιρρεπές σε Ϩενερικά λάθη.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω χρησιμοποιεί απλά 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα περιτύλιγμα γύρω από το `massdns`, γραμμένο σε go, που σας επιτρέπει να καταλογογραφήσετε έγκυρους υποτομείς χρησιμοποιώντας ενεργή βίαιη δύναμη, καθώς και να επιλύσετε υποτομείς με χειρισμό μπαλαντέρ και εύκολη υποστήριξη εισόδου-εξόδου.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για να εκτελέσει βίαια επίθεση στα ονόματα των τομέων ασύγχρονα.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Δεύτερος Γύρος Βίαιης Δύναμης DNS

Αφού βρείτε υποτομές χρησιμοποιώντας ανοιχτές πηγές και βίαιη δύναμη, μπορείτε να δημιουργήσετε τροποποιήσεις των υποτομών που βρέθηκαν για να προσπαθήσετε να βρείτε ακόμη περισσότερες. Πολλά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δεδομένων των τομέων και των υποτομών παράγει μεταθέσεις.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Δεδομένων των domains και subdomains δημιουργεί αναστροφές.
* Μπορείτε να λάβετε τις αναστροφές του goaltdns **wordlist** [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Δεδομένων των domains και subdomains δημιουργεί παραλλαγές. Αν δεν υποδεικνύεται αρχείο παραλλαγών, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία παραλλαγών υποτομέων, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγούμενα σχολιασμένα εργαλεία).
* Μπορείτε να λάβετε τον κατάλογο λέξεων **wordlist** των παραλλαγών του altdns **εδώ**.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Ένα άλλο εργαλείο για να εκτελέσετε περιστροφές, μεταλλάξεις και αλλαγές υποτομέων. Αυτό το εργαλείο θα εκτελέσει βίαια το αποτέλεσμα (δεν υποστηρίζει wild card dns).
* Μπορείτε να λάβετε τη λίστα λέξεων περιστροφών του dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Βασισμένο σε ένα domain, **δημιουργεί νέα πιθανά ονόματα subdomains** βασισμένα σε καθορισμένα πρότυπα για να δοκιμάσει να ανακαλύψει περισσότερα subdomains.

#### Έξυπνη δημιουργία περιπτώσεων

* [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες διαβάστε αυτήν την [**ανάρτηση**](https://cramppet.github.io/regulator/index.html) αλλά βασικά θα πάρει τα **κύρια μέρη** από τα **ανακαλυφθέντα subdomains** και θα τα ανακατέψει για να βρει περισσότερα subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένα εργαλείο ανίχνευσης υποτομέων που συνδυάζεται με έναν απλό αλλά αποτελεσματικό αλγόριθμο καθοδήγησης απόκρισης DNS. Χρησιμοποιεί ένα σύνολο παρεχόμενων δεδομένων εισόδου, όπως μια προσαρμοσμένη λίστα λέξεων ή ιστορικά αρχεία DNS/TLS, για να συνθέσει με ακρίβεια περισσότερα αντίστοιχα ονόματα τομέων και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο βασισμένο στις πληροφορίες που συλλέγονται κατά τη διάρκεια της σάρωσης DNS.
```
echo www | subzuf facebook.com
```
### **Ροή Ανακάλυψης Υποτομέων**

Ελέγξτε αυτή την ανάρτηση στο blog που έγραψα σχετικά με το πώς να **αυτοματοποιήσετε την ανακάλυψη υποτομέων** από ένα τομέα χρησιμοποιώντας τις **ροές εργασίας του Trickest** ώστε να μην χρειάζεται να εκκινήσετε χειροκίνητα πολλά εργαλεία στον υπολογιστή σας:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Εικονικοί Φιλοξενητές**

Αν βρήκατε μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** που ανήκουν σε υποτομείς, μπορείτε να προσπαθήσετε να **βρείτε άλλους υποτομείς με ιστοσελίδες σε αυτήν την IP** ψάχνοντας σε **πηγές OSINT** για τομείς σε μια IP ή με το **brute-forcing ονομάτων VHost σε αυτήν την IP**.

#### OSINT

Μπορείτε να βρείτε μερικούς **VHosts σε IPs χρησιμοποιώντας** το [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιος υποτομέας μπορεί να είναι κρυμμένος σε έναν web διακομιστή, μπορείτε να προσπαθήσετε να τον αναγκάσετε με brute force:
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
Με αυτήν την τεχνική ενδέχεται ακόμα και να έχετε πρόσβαση σε εσωτερικά/κρυφά σημεία πρόσβασης.
{% endhint %}

### **Βία CORS Brute**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν μόνο το κεφαλίδα _**Access-Control-Allow-Origin**_ όταν έχει οριστεί ένα έγκυρο τομέας/υποτομέας στο _**Origin**_ κεφαλίδα. Σε αυτά τα σενάρια, μπορείτε να καταχραστείτε αυτήν τη συμπεριφορά για να **ανακαλύψετε** νέους **υποτομείς**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Βίαιη Δύναμη Κάδων**

Καθώς αναζητάτε **υποτομές**, πρέπει να παρατηρήσετε αν αυτές δείχνουν σε κάποιον τύπο **κάδου**, και σε αυτήν την περίπτωση [**ελέγξτε τις άδειες πρόσβασης**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Επίσης, αφού θα έχετε γνώση όλων των τομέων εντός του πεδίου εφαρμογής, δοκιμάστε να [**εξαναγκάσετε δυναμικά πιθανά ονόματα κάδων και ελέγξτε τις άδειες πρόσβασης**](../../network-services-pentesting/pentesting-web/buckets/).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν **νέες υποτομές** ενός τομέα δημιουργούνται με την παρακολούθηση των **Καταγραφών Διαφάνειας Πιστοποιητικού** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)κάνει.

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανές [**καταλήψεις υποτομών**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν η **υποτομή** δείχνει σε κάποιον **κάδο S3**, [**ελέγξτε τις άδειες πρόσβασης**](../../network-services-pentesting/pentesting-web/buckets/).

Αν βρείτε κάποια **υποτομή με διαφορετική IP** από αυτές που έχετε ήδη βρει στην ανακάλυψη περιουσιακών στοιχείων, πρέπει να εκτελέσετε μια **βασική ανίχνευση ευπαθειών** (χρησιμοποιώντας το Nessus ή το OpenVAS) και μερικές [**σάρωσεις θυρών**](../pentesting-network/#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για "επίθεση" σε αυτές**.\
_Σημειώστε ότι μερικές φορές η υποτομή φιλοξενείται μέσα σε μια IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι στο πεδίο εφαρμογής, προσέξτε._

## IPs

Στα αρχικά στάδια μπορεί να έχετε **βρει ορισμένους εύρος IP, τομείς και υποτομές**.\
Ήρθε η ώρα να **συγκεντρώσετε όλες τις IP από αυτά τα εύρη** και για τους **τομείς/υποτομές (ερωτήσεις DNS).**

Χρησιμοποιώντας υπηρεσίες από τα ακόλουθα **δωρεάν APIs** μπορείτε επίσης να βρείτε **προηγούμενες IP που χρησιμοποιήθηκαν από τομείς και υποτομές**. Αυτές οι IP ενδέχεται ακόμα να ανήκουν στον πελάτη (και ενδέχεται να σας επιτρέψουν να βρείτε [**παρακάμψεις CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε τους τομείς που δείχνουν σε συγκεκριμένη διεύθυνση IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

**Σαρώστε όλες τις IP που δεν ανήκουν σε CDN** (καθώς πιθανότατα δεν θα βρείτε κάτι ενδιαφέρον εκεί). Στις υπηρεσίες που εκτελέστηκαν μπορείτε να **βρείτε ευπαθείες**.

**Βρείτε ένα** [**οδηγό**](../pentesting-network/) **σχετικά με το πώς να σαρώσετε τους οικοδεσπότες.**

## Κυνήγι διακομιστών ιστού

> Έχουμε βρει όλες τις εταιρείες και τα περιουσιακά τους στοιχεία και γνωρίζουμε τα εύρη IP, τομείς και υποτομές εντός του πεδίου εφαρμογής. Ήρθε η ώρα να αναζητήσουμε διακομιστές ιστού.

Στα προηγούμενα βήματα πιθανόν να έχετε ήδη εκτελέσει κάποια **αναγνώριση των IP και των τομέων που ανακαλύφθηκαν**, οπότε μπορεί να έχετε **ήδη βρει όλους τους πιθανούς διακομιστές ιστού**. Ωστόσο, αν δεν το έχετε κάνει, τώρα θα δούμε μερικά **γρήγορα κόλπα για την αναζήτηση διακομιστών ιστού** εντός του πεδίου εφαρμογής.

Παρακαλώ, σημειώστε ότι αυτό θα είναι **προσανατολισμένο για την ανακάλυψη εφαρμογών ιστού**, οπότε θα πρέπει να **εκτελέσετε την ανίχνευση ευπαθειών** και **σάρωση θυρών** επίσης (**εάν επιτρέπεται** από το πεδίο εφαρμογής).

Ένας **γρήγορος τρόπος** για την ανακάλυψη **ανοιχτών θυρών** που σχετίζονται με **διακομιστές web** χρησιμοποιώντας το [**masscan μπορεί να βρεθεί εδώ**](../pentesting-network/#http-port-discovery).\
Ένα άλλο φιλικό εργαλείο για την αναζήτηση διακομιστών ιστού είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλά περνάτε μια λίστα τομέων και θα προσπαθήσει να συνδεθεί στη θύρα 80 (http) και 443 (https). Επιπλέον, μπορείτε να υποδείξετε να δοκιμάσει και άλλες θύρες:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Στιγμιότυπα Οθόνης**

Τώρα που έχετε ανακαλύψει **όλους τους διακομιστές ιστού** που υπάρχουν στο εύρος (μεταξύ των **IPs** της εταιρείας και όλων των **domains** και **subdomains**) πιθανόν **να μην ξέρετε από πού να ξεκινήσετε**. Έτσι, ας το κάνουμε απλό και ας ξεκινήσουμε απλά παίρνοντας στιγμιότυπα οθόνης από όλους αυτούς. Απλά με το **να ρίξετε μια ματιά** στη **κύρια σελίδα** μπορείτε να βρείτε **περίεργα** σημεία που είναι πιο **ευάλωτα**.

Για να εκτελέσετε την προτεινόμενη ιδέα μπορείτε να χρησιμοποιήσετε το [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να εκτελέσετε πάνω σε όλα τα **στιγμιότυπα οθόνης** και να σας πει **τι πιθανόν περιέχει ευπάθειες**, και τι όχι.

## Δημόσια Περιουσιακά Στοιχεία στο Cloud

Για να βρείτε πιθανά περιουσιακά στοιχεία στο cloud που ανήκουν σε μια εταιρεία θα πρέπει **να ξεκινήσετε με μια λίστα λέξεων-κλειδιών που ταυτίζουν αυτή την εταιρεία**. Για παράδειγμα, για μια εταιρεία κρυπτονομισμάτων μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης λίστες λέξεων που χρησιμοποιούνται συχνά σε buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσετε **παραλλαγές** (ελέγξτε το [**Second Round DNS Brute-Force**](./#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις παραγόμενες λίστες λέξεων μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Θυμηθείτε ότι κατά την αναζήτηση Δημόσιων Περιουσιακών Στοιχείων θα πρέπει **να ψάξετε για περισσότερα από απλά buckets στο AWS**.

### **Αναζήτηση ευπαθειών**

Αν βρείτε πράγματα όπως **ανοιχτά buckets ή εκθέτες λειτουργίες cloud** θα πρέπει **να τα ανακτήσετε** και να δοκιμάσετε να δείτε τι σας προσφέρουν και αν μπορείτε να τα καταχραστείτε.

## Emails

Με τα **domains** και τα **subdomains** εντός του εύρους έχετε βασικά ό,τι χρειάζεστε για να αρχίσετε την αναζήτηση emails. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν λειτουργήσει καλύτερα για μένα για την εύρεση emails μιας εταιρείας:

* [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
* API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
* API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
* API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση ευπαθειών**

Τα emails θα είναι χρήσιμα αργότερα για **brute-force στις συνδέσεις ιστού και υπηρεσίες auth** (όπως το SSH). Επίσης, απαιτούνται για **phishings**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμη περισσότερες πληροφορίες για το άτομο πίσω από το email, το οποίο είναι χρήσιμο για την καμπάνια phishing.

## Διαρροές Διαπιστεύσεων

Με τα **domains,** **subdomains** και **emails** μπορείτε να αρχίσετε την αναζήτηση διαρροών διαπιστεύσεων που έχουν διαρρεύσει στο παρελθόν και ανήκουν σε αυτά τα emails:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρες διαρροές** διαπιστεύσεων, αυτό είναι ένα πολύ εύκολο κέρδος.

## Διαρροές Μυστικών

Οι διαρροές διαπιστεύσεων σχετίζονται με επιθέσεις σε εταιρείες όπου **διέρρευσαν και πωλήθηκαν ευαίσθητες πληροφορίες**. Ωστόσο, οι εταιρείες ενδέχεται να επηρεαστούν από **άλλες διαρροές** των οποίων οι πληροφορίες δεν βρίσκονται σε αυτές τις βάσεις δεδομένων:

### Διαρροές στο Github

Διαρροές διαπιστεύσεων και APIs μπορεί να διαρρεύσουν στα **δημόσια αποθετήρια** της **εταιρείας** ή των **χρηστών** που εργάζονται για αυτή την εταιρεία στο github.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **δημόσια αποθετήρια** μιας **οργάνωσης** και των **προγραμματιστών της** και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να εκτελέσετε το **gitleaks** ξανά σε όλα τα **κείμενα** που παρέχονται με τα **URLs που περνάτε** σε αυτό, καθώς μερικές φορές **οι ιστοσελίδες περιέχουν επίσης μυστικά**.

#### Github Dorks

Ελέγξτε επίσης αυτήν τη **σελίδα** για πιθανές **github dorks** που μπορείτε επίσης να αναζητήσετε στον οργανισμό που επιτίθεστε:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Διαρροές σε Σελίδες Επικόλλησης

Μερικές φορές οι επιτιθέμενοι ή απλά οι εργαζόμενοι θα **δημοσιεύσουν περιεχόμενο της εταιρείας σε ιστοσελίδα επικόλλησης**. Αυτό ενδέχεται να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά είναι πολύ ενδιαφέρον να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να αναζητήσετε σε περισσότερες από 80 ιστοσελίδες επικόλλησης ταυτόχρονα.

### Google Dorks

Οι παλιοί αλλά χρυσοί google dorks είναι πάντα χρήσιμοι για να βρείτε **εκτεθειμένες πληροφορίες που δεν θα έπρεπε να υπάρχουν εκεί**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανές ερωτήσεις που δεν μπορείτε να εκτελέσετε χειροκίνητα. Έτσι, μπορείτε να επιλέξετε τις 10 αγαπημένες σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως το** [**Gorks**](
## [**Μεθοδολογία Δοκιμής Διείσδυσης Ιστού**](../../network-services-pentesting/pentesting-web/)

Η **πλειοψηφία των ευπαθειών** που εντοπίζουν οι κυνηγοί ευρετήριων βρίσκεται μέσα σε **ιστοσελίδες**, οπότε σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία δοκιμής εφαρμογών ιστού**, και μπορείτε [**να βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/).

Θέλω επίσης να κάνω μια ειδική αναφορά στην ενότητα [**Εργαλεία Αυτόματης Σάρωσης Ιστού με Ανοιχτό Κώδικα**](../../network-services-pentesting/pentesting-web/#automatic-scanners), καθώς, αν και δεν πρέπει να αναμένετε να βρουν ευαίσθητες ευπαθείες, είναι χρήσιμα για να εφαρμόσετε τα σενάρια σαρώσεων για να έχετε κάποιες αρχικές πληροφορίες ιστού.

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη εκτελέσει **όλη τη βασική απαρίθμηση**. Ναι, είναι βασική επειδή μπορεί να γίνει πολύ περισσότερη απαρίθμηση (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε ήδη:

1. Βρείτε όλες τις **εταιρείες** εντός του πεδίου εφαρμογής
2. Βρείτε όλα τα **περιουσιακά στοιχεία** που ανήκουν στις εταιρείες (και εκτελέστε μια σάρωση ευπαθειών αν είναι στο πεδίο εφαρμογής)
3. Βρείτε όλους τους **τομείς** που ανήκουν στις εταιρείες
4. Βρείτε όλα τα **υποτομείς** των τομέων (κάποια ανάληψη υποτομέων;)
5. Βρείτε όλες τις **IP** (από και **όχι από CDN**) εντός του πεδίου εφαρμογής.
6. Βρείτε όλους τους **διακομιστές ιστού** και πάρτε μια **στιγμιότυπη εικόνα** τους (κάτι περίεργο που αξίζει μια πιο βαθιά ματιά;)
7. Βρείτε όλα τα **πιθανά δημόσια περιουσιακά στοιχεία στο cloud** που ανήκουν στην εταιρεία.
8. **Emails**, **διαρροές διαπιστεύσεων**, και **διαρροές μυστικών** που θα μπορούσαν να σας δώσουν μια **μεγάλη νίκη πολύ εύκολα**.
9. **Δοκιμάστε όλες τις ιστοσελίδες που βρήκατε**

## **Εργαλεία Αυτόματης Πλήρους Αναγνώρισης**

Υπάρχουν πολλά εργαλεία εκεί έξω που θα εκτελέσουν μέρος των προτεινόμενων ενεργειών εναντίον ενός συγκεκριμένου πεδίου.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και μην ενημερώνεται

## **Αναφορές**

* Όλα τα δωρεάν μαθήματα του [**@Jhaddix**](https://twitter.com/Jhaddix) όπως το [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Αν ενδιαφέρεστε για μια **καριέρα στο χάκινγκ** και να χακάρετε το αχάκαρτο - **σας προσλαμβάνουμε!** (_απαιτείται άριστη γραπτή και προφορική γνώση της πολωνικής_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>
