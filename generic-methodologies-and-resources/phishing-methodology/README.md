# Μεθοδολογία Phishing

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Μεθοδολογία

1. Αναγνωρίστε το θύμα
1. Επιλέξτε το **domain του θύματος**.
2. Εκτελέστε κάποια βασική απαρίθμηση ιστοσελίδων **ψάχνοντας για πύλες σύνδεσης** που χρησιμοποιεί το θύμα και **αποφασίστε** ποια θα **παριστάνετε**.
3. Χρησιμοποιήστε κάποιο **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing
2. **Διαμορφώστε τις εγγραφές** σχετικά με την υπηρεσία email (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με το **gophish**
3. Προετοιμάστε την εκστρατεία
1. Προετοιμάστε το **πρότυπο email**
2. Προετοιμάστε τη **σελίδα web** για την κλοπή διαπιστεύσεων
4. Ξεκινήστε την εκστρατεία!

## Δημιουργία παρόμοιων ονομάτων domain ή αγορά ενός αξιόπιστου domain

### Τεχνικές Παραλλαγής Ονομάτων Domain

* **Λέξη-Κλειδί**: Το domain περιέχει ένα σημαντικό **λέξη-κλειδί** του αρχικού domain (π.χ., zelster.com-management.com).
* **Υπο-Διακεκομμένο**: Αλλάξτε το **τελεία με παύλα** ενός υπο-τομέα (π.χ., www-zelster.com).
* **Νέο TLD**: Ίδιο domain χρησιμοποιώντας ένα **νέο TLD** (π.χ., zelster.org)
* **Ομογλυφικό**: Αντικαθιστά μια γράμματος στο όνομα domain με γράμματα που μοιάζουν παρόμοια (π.χ., zelfser.com).
* **Αντιστροφή**: Ανταλλάσσει δύο γράμματα μέσα στο όνομα domain (π.χ., zelsetr.com).
* **Ενικός/Πληθυντικός**: Προσθέτει ή αφαιρεί το "s" στο τέλος του ονόματος domain (π.χ., zeltsers.com).
* **Παράλειψη**: Αφαιρεί ένα από τα γράμματα από το όνομα domain (π.χ., zelser.com).
* **Επανάληψη**: Επαναλαμβάνει ένα από τα γράμματα στο όνομα domain (π.χ., zeltsser.com).
* **Αντικατάσταση**: Όπως το ομογλυφικό αλλά λιγότερο αόρατο. Αντικαθιστά ένα από τα γράμματα στο όνομα domain, ίσως με ένα γράμμα κοντά στο αρχικό γράμμα στο πληκτρολόγιο (π.χ., zektser.com).
* **Υπο-Διακεκομμένο**: Εισάγει μια **τελεία** μέσα στο όνομα domain (π.χ., ze.lster.com).
* **Εισαγωγή**: Εισάγει ένα γράμμα στο όνομα domain (π.χ., zerltser.com).
* **Λείπουσα τελεία**: Προσθέτει το TLD στο όνομα domain. (π.χ., zelstercom.com)

**Αυτόματα Εργαλεία**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Ιστοσελίδες**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει η **πιθανότητα** ένα από μερικά bits που αποθηκεύονται ή μεταδίδονται να αναστραφεί αυτόματα λόγω διάφορων παραγόντων όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτό το **συγκεκριμένο έννοια εφαρμόζεται σε αιτήσεις DNS**, είναι δυνατόν το **domain που λαμβάνεται από τον DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια μετατροπή ενός μόνο bit στο domain "windows.com" μπορεί να το μετατρέψει σε "windnws.com."

Οι επιτιθέμενοι μπορεί **να εκμεταλλευτούν αυτό καταχωρώντας πολλά domains με αναστροφή bit** που είναι παρόμοια με το domain του θύματος. Η πρόθεσή τους είναι να ανακατευθύνουν τους νόμιμους χρήστες στη δική τους υποδομή.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Αγορά ενός αξιόπιστου domain

Μπορείτε να αναζητήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα ληγμένο domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το ληγμένο domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO** μπορείτε να ελέγξετε πώς κατηγοριοποιείται στα:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ανακάλυψη Emails

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% δωρεάν)
* [https://phonebook.cz/](https://phonebook.cz) (100% δωρεάν)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Για να **ανακαλύψετε περισσότερες** έγκυρες διευθύνσεις email ή να **επιβεβαιώσετε αυτές** που έχετε ήδη ανακαλύψει μπορείτε να ελέγξετε αν μπορείτε να τις επιτεθείτε με brute-force στους smtp servers του θύματος. [Μάθετε πώς να επιβεβαιώσετε/ανακαλύψετε διεύθυνση email εδώ](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **κάποια web πύλη για να έχουν πρόσβαση στα emails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτη σε **brute force του ονόματος χρήστη**, και να εκμεταλλευτείτε την ευπάθεια αν είναι δυνατόν.

## Διαμόρφωση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός πρόσβασης για τον διαχειριστή στη θύρα 3333 στην έξοδο. Συνεπώς, μεταβείτε σε αυτήν τη θύρα και χρησιμοποιήστε αυτές τις διαπιστεύσεις γι
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα πρέπει **ήδη να έχετε αγοράσει το domain** που θα χρησιμοποιήσετε και πρέπει να **δείχνει** προς τη **IP του VPS** όπου διαμορφώνετε το **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Διαμόρφωση email**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια προσθέστε το domain στα ακόλουθα αρχεία:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Αλλάξτε επίσης τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** με το όνομα του domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε ένα **DNS A record** του `mail.<domain>` που να δείχνει στη **διεύθυνση ip** του VPS και ένα **DNS MX** record που να δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Διαμόρφωση του Gophish**

Σταματήστε την εκτέλεση του gophish και ας το διαμορφώσουμε.\
Τροποποιήστε το `/opt/gophish/config.json` στο ακόλουθο (σημειώστε τη χρήση του https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Διαμόρφωση υπηρεσίας gophish**

Για να δημιουργήσετε την υπηρεσία gophish έτσι ώστε να μπορεί να ξεκινά αυτόματα και να διαχειρίζεται ως υπηρεσία, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με το παρακάτω περιεχόμενο:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Ολοκληρώστε τη ρύθμιση της υπηρεσίας και ελέγξτε την εκτελώντας:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Ρύθμιση διακομιστή αλληλογραφίας και domain

### Αναμονή & να είστε νόμιμοι

Όσο πιο παλιό είναι ένα domain, τόσο λιγότερο πιθανό είναι να πιαστεί ως ανεπιθύμητη αλληλογραφία. Συνεπώς, θα πρέπει να περιμένετε όσο το δυνατόν περισσότερο χρόνο (τουλάχιστον 1 εβδομάδα) πριν από την αξιολόγηση phishing. Επιπλέον, αν δημιουργήσετε μια σελίδα σχετική με έναν τομέα με καλή φήμη, η φήμη που θα αποκτήσετε θα είναι καλύτερη.

Σημειώστε ότι ακόμα κι αν πρέπει να περιμένετε μια εβδομάδα, μπορείτε να ολοκληρώσετε τη ρύθμιση όλων των στοιχείων τώρα.

### Ρύθμιση αντίστροφης εγγραφής DNS (rDNS)

Ορίστε μια αντίστροφη εγγραφή DNS (PTR) που αντιστοιχεί τη διεύθυνση IP του VPS στο όνομα domain.

### Εγγραφή πλαισίου πολιτικής αποστολέα (SPF)

Πρέπει **να ρυθμίσετε μια εγγραφή SPF για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή SPF, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF σας (χρησιμοποιήστε τη διεύθυνση IP της μηχανής VPS)

![](<../../.gitbook/assets/image (388).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT μέσα στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Εγγραφή Ελέγχου, Αναφοράς και Συμμόρφωσης Μηνυμάτων Βασισμένη στο Domain (DMARC)

Πρέπει **να διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που να δείχνει στο όνομα κεντρικού υπολογιστή `_dmarc.<domain>` με τον παρακάτω περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει **να διαμορφώσετε ένα DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/#dkim).

Αυτό το εγχειρίδιο βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Δοκιμάστε το σκορ ρύθμισης του email σας

Μπορείτε να το κάνετε χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλά επισκεφθείτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης **να ελέγξετε τη διαμόρφωση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα πρέπει **να ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
Βεβαιωθείτε ότι περνάτε όλα τα τεστ:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Μπορείτε επίσης να στείλετε **μήνυμα σε ένα Gmail υπό τον έλεγχό σας**, και να ελέγξετε τα **headers του email** στο inbox του Gmail σας, το `dkim=pass` πρέπει να υπάρχει στο πεδίο header `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Αφαίρεση από τη Μαύρη Λίστα του Spamhouse

Η σελίδα [www.mail-tester.com](www.mail-tester.com) μπορεί να σας ενημερώσει εάν το domain σας έχει μπει στη μαύρη λίστα του spamhouse. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Μαύρη Λίστα της Microsoft

Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Εκστρατείας GoPhish

### Προφίλ Αποστολής

* Ορίστε ένα **όνομα για αναγνώριση** του προφίλ αποστολής
* Αποφασίστε από ποιο λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
* Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Αγνόηση Σφαλμάτων Πιστοποιητικού

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Αποστολή Δοκιμαστικού Email**" για να δοκιμάσετε ότι όλα λειτουργούν.\
Θα σας πρότεινα να **στείλετε τα δοκιμαστικά emails σε διευθύνσεις email 10 λεπτών** προκειμένου να αποφύγετε τη μαύρη λίστα κατά τις δοκιμές.
{% endhint %}

### Πρότυπο Email

* Ορίστε ένα **όνομα για αναγνώριση** του προτύπου
* Στη συνέχεια γράψτε ένα **θέμα** (κάτι συνηθισμένο, απλά κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
* Βεβαιωθείτε ότι έχετε επιλέξει το "**Προσθήκη Εικόνας Παρακολούθησης**"
* Γράψτε το **πρότυπο email** (μπορείτε να χρησιμοποιήσετε μεταβλητές όπως στο παρακάτω παράδειγμα):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Σημείωση ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από ένα email του πελάτη. Προτάσεις:

* Στείλτε ένα email σε μια **μη υπάρχουσα διεύθυνση** και ελέγξτε αν η απάντηση έχει κάποια υπογραφή.
* Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε για απάντηση.
* Δοκιμάστε να επικοινωνήσετε με **κάποιο έγκυρο ανακαλυφθέν** email και περιμένετε για απάντηση

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Το Πρότυπο Email επιτρέπει επίσης την **επισύναψη αρχείων για αποστολή**. Αν θέλετε επίσης να κλέψετε προκλήσεις NTLM χρησιμοποιώντας κάποια ειδικά δημιουργημένα αρχεία/έγγραφα [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Σελίδα Προσγείωσης

* Γράψτε ένα **όνομα**
* **Γράψτε τον κώδικα HTML** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισάγετε** ιστοσελίδες.
* Σημειώστε **Καταγραφή Υποβληθέντων Δεδομένων** και **Καταγραφή Κωδικών**
* Ορίστε μια **ανακατεύθυνση**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Συνήθως θα χρειαστεί να τροποποιήσετε τον κώδικα HTML της σελίδας και να κάνετε κάποιες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον διακομιστή Apache) **μέχρι να σας αρέσουν τα αποτελέσματα**. Στη συνέχεια, γράψτε αυτόν τον κώδικα HTML στο πλαίσιο.\
Σημειώστε ότι αν χρειάζεστε να **χρησιμοποιήσετε κάποιους στατικούς πόρους** για το HTML (ίσως κάποιες σελίδες CSS και JS) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να τα προσπελάσετε από το _**/static/\<όνομα αρχείου>**_
{% endhint %}

{% hint style="info" %}
Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην πραγματική κύρια ιστοσελίδα** του θύματος, ή να τους ανακατευθύνετε σε _/static/migration.html_ για παράδειγμα, να βάλετε κάποιο **περιστρεφόμενο τροχό** ([**https://loading.io/**](https://loading.io)) για 5 δευτερόλεπτα και στη συνέχεια να υποδείξετε ότι η διαδικασία ήταν επιτυχής**.
{% endhint %}

### Χρήστες & Ομάδες

* Ορίστε ένα όνομα
* **Εισαγάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το πρότυπο για το παράδειγμα χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)

![](<../../.gitbook/assets/image (395).png>)

### Εκστρατεία

Τέλος, δημιουργήστε μια εκστρατεία επιλέγοντας ένα όνομα, το πρότυπο email, τη σελίδα προσγείωσης, το URL, το προφίλ αποστολής και την ομάδα. Σημειώστε ότι το URL θα είναι το σύνδεσμος που στέλνετε στα θύματα

Σημείωστε ότι το **Προφίλ Αποστολής επιτρέπει να στείλετε ένα δοκιμαστικό email για να δείτε πώς θα φαίνεται το τελικό email phishing**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Θα συνιστούσα να **στείλετε τα δοκιμαστικά emails σε διευθύνσεις email 10 λεπτών** για να αποφύγετε τη μαύρη λίστα κατά τη διάρκεια των δοκιμών.
{% endhint %}

Μόλις είναι έτοιμα όλα, απλά εκκινήστε την εκστρατεία!

## Κλωνοποίηση Ιστότοπου

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε τον ιστότοπο, ελέγξτε την ακόλουθη σελίδα:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Επισφαλή Έγγραφα & Αρχεία

Σε μερικές αξιολογήσεις phishing (κυρίως για Κόκκινες Ομάδες) θα θέλετε επίσης **να στείλετε αρχεία που περιέχουν κάποιο είδος παρασκηνίου** (ίσως ένα C2 ή ίσως απλά κάτι που θα ενεργοποιήσει μια πιστοποίηση).\
Ελέγξτε την ακόλουθη σελίδα για μερικά παραδείγματα:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Μέσω Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς προσποιείστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που έχει ορίσει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν έχει βάλει τον σωστό κωδικό ή αν η εφαρμογή που προσποιείστε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να προσωποποιήσετε τον απατημένο χρήστη**.

Εδώ είναι όπου εργαλεία όπως το [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena) είναι χρήσιμα. Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, οι επιθέσεις λειτουργούν με τον ακόλουθο τρόπο:

1. Εσείς **προσποιείστε τη φόρμα σύνδεσης** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **διαπιστευτήριά του** στην ψεύτικη σας σελίδα και το εργαλείο τα στέλνει στην πραγματική ιστοσελίδα, **ελέγχοντας αν τα διαπιστευτήρια λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η σελίδα MitM θα ζητήσει αυτό και μόλις ο χρήστης το **εισάγει**, το εργαλείο θα το στείλει στην πραγματική ιστοσελίδα.
4. Μόλις ο χρήστης ελεγχθεί, εσείς (ως επιτιθέμενος) θα έχετε **καταγράψει τα διαπιστευτήρια, το 2FA, το cookie και οποιαδήποτε πληροφορία** από κάθε αλληλεπίδραση σας ενώ το εργαλείο εκτελεί μια επίθεση MitM.

### Μέσω VNC

Τι θα γινόταν αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση με την πραγματική, τον στείλετε σε μια **συνεδρία VNC με έναν περιηγητή συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιείται, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Ανίχνευση της ανίχνευσης

Φυσικά, ένας από τους καλύτερους τρόπους για να μάθετε αν έχετε αποκαλυφθεί εί
