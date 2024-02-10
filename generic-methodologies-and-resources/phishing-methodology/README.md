# Μεθοδολογία Phishing

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Μεθοδολογία

1. Εξερεύνηση του θύματος
1. Επιλέξτε το **τομέα του θύματος**.
2. Εκτελέστε μερικές βασικές εντοπίσεις στον ιστό **αναζητώντας για πύλες σύνδεσης** που χρησιμοποιεί το θύμα και **αποφασίστε** ποια θα **παραπλανήσετε**.
3. Χρησιμοποιήστε κάποιο **OSINT** για να **βρείτε email**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε τον τομέα** που θα χρησιμοποιήσετε για την αξιολόγηση phishing
2. **Διαμορφώστε την υπηρεσία email** σχετικά με τις εγγραφές (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με το **gophish**
3. Προετοιμάστε την εκστρατεία
1. Προετοιμάστε το **πρότυπο email**
2. Προετοιμάστε την **ιστοσελίδα** για να κλέψετε τα διαπιστευτήρια
4. Ξεκινήστε την εκστρατεία!

## Δημιουργία παρόμοιων ονομάτων τομέων ή αγορά ενός αξιόπιστου τομέα

### Τεχνικές Παραλλαγής Ονομάτων Τομέων

* **Λέξη-κλειδί**: Το όνομα του τομέα **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού τομέα (π.χ., zelster.com-management.com).
* **Υποτομέας με παύλα**: Αλλάξτε το **τελεία με παύλα** ενός υποτομέα (π.χ., www-zelster.com).
* **Νέο TLD**: Ίδιος τομέας χρησιμοποιώντας ένα **νέο TLD** (π.χ., zelster.org)
* **Homoglyph**: Αντικαθιστά μια γράμματος στο όνομα του τομέα με γράμματα που μοιάζουν παρόμοια (π.χ., zelfser.com).
* **Αντιστροφή**: Ανταλλάσσει δύο γράμματα μέσα στο όνομα του τομέα (π.χ., zelster.com).
* **Ενικότητα/Πληθυντικότητα**: Προσθέτει ή αφαιρεί το "s" στο τέλος του ονόματος του τομέα (π.χ., zeltsers.com).
* **Παράλειψη**: Αφαιρεί ένα από τα γράμματα από το όνομα του τομέα (π.χ., zelser.com).
* **Επανάληψη**: Επαναλαμβάνει ένα από τα γράμματα στο όνομα του τομέα (π.χ., zeltsser.com).
* **Αντικατάσταση**: Όπως το homoglyph αλλά λιγότερο αόρατο. Αντικαθιστά ένα από τα γράμματα στο όνομα του τομέα, ίσως με ένα γράμμα κοντά στο αρχικό γράμμα στο πληκτρολόγιο (π.χ., zektser.com).
* **Υποτομέας**: Εισάγει μια **τελεία** μέσα στο όνομα του τομέα (π.χ., ze.lster.com).
* **Εισαγωγή**: Εισάγει ένα γράμμα στο όνομα του τομέα (π.χ., zerltser.com).
* **Λείπουσα τελεία**: Προσθέστε το TLD στο όνομα του τομέα. (π.χ., zelstercom.com)

**Αυτόματα Εργαλεία**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanad
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Ρύθμιση

**Ρύθμιση πιστοποιητικού TLS**

Πριν από αυτό το βήμα, θα πρέπει να έχετε **ήδη αγοράσει τον τομέα** που πρόκειται να χρησιμοποιήσετε και πρέπει να **δείχνει** προς την **IP του VPS** όπου ρυθμίζετε το **gophish**.
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
**Ρύθμιση ηλεκτρονικού ταχυδρομείου**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια, προσθέστε τον τομέα στα ακόλουθα αρχεία:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο αρχείο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** με το όνομα του τομέα σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε ένα **DNS A record** για το `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και ένα **DNS MX** record που να δείχνει στο `mail.<domain>`

Ας δοκιμάσουμε τώρα να στείλουμε ένα ηλεκτρονικό μήνυμα:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Ρύθμιση του Gophish**

Σταματήστε την εκτέλεση του Gophish και ας το ρυθμίσουμε.\
Τροποποιήστε το `/opt/gophish/config.json` ως εξής (σημειώστε τη χρήση του https):
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
**Ρύθμιση της υπηρεσίας gophish**

Για να δημιουργήσετε την υπηρεσία gophish έτσι ώστε να μπορεί να ξεκινά αυτόματα και να διαχειρίζεται μια υπηρεσία, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με τον παρακάτω περιεχόμενο:
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
Ολοκληρώστε τη διαμόρφωση της υπηρεσίας και ελέγξτε την εκτελώντας:
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
## Ρύθμιση διακομιστή αλληλογραφίας και τομέα

### Περιμένετε και είστε νόμιμοι

Όσο πιο παλιός είναι ένας τομέας, τόσο λιγότερο πιθανό είναι να πιαστεί ως ανεπιθύμητο μήνυμα. Συνεπώς, θα πρέπει να περιμένετε όσο το δυνατόν περισσότερο χρόνο (τουλάχιστον 1 εβδομάδα) πριν αξιολογήσετε το phishing. Επιπλέον, αν δημιουργήσετε μια σελίδα για έναν τομέα με καλή φήμη, η φήμη που θα αποκτηθεί θα είναι καλύτερη.

Σημειώστε ότι ακόμα κι αν πρέπει να περιμένετε μια εβδομάδα, μπορείτε να ολοκληρώσετε τη ρύθμιση όλων τώρα.

### Ρύθμιση αντίστροφης επίλυσης (rDNS) εγγραφής

Ορίστε μια αντίστροφη επίλυση (PTR) εγγραφή που επιλύει τη διεύθυνση IP του VPS στο όνομα τομέα.

### Εγγραφή πλαισίου πολιτικής αποστολέα (SPF)

Πρέπει **να ρυθμίσετε μια εγγραφή SPF για τον νέο τομέα**. Αν δεν γνωρίζετε τι είναι μια εγγραφή SPF [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF σας (χρησιμοποιήστε τη διεύθυνση IP του VPS μηχανής)

![](<../../.gitbook/assets/image (388).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT εντός του τομέα:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Εγγραφή Domain-based Message Authentication, Reporting & Conformance (DMARC)

Πρέπει να **διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που να δείχνει στο hostname `_dmarc.<domain>` με τον παρακάτω περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **διαμορφώσετε ένα DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/#dkim).

Αυτός ο οδηγός βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το DKIM key:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Δοκιμάστε το σκορ ρύθμισης του email σας

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας το [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλά επισκεφθείτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του ηλεκτρονικού σας ταχυδρομείου** αποστέλλοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απόκριση** (για αυτό θα πρέπει να **ανοίξετε** τη θύρα **25** και να δείτε την απόκριση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Μπορείτε επίσης να στείλετε ένα **μήνυμα σε ένα Gmail υπό τον έλεγχό σας**, και να ελέγξετε τους **κεφαλίδες του email** στο εισερχόμενο του Gmail, το `dkim=pass` θα πρέπει να είναι παρόν στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Αφαίρεση από τη Μαύρη Λίστα του Spamhouse

Η σελίδα [www.mail-tester.com](www.mail-tester.com) μπορεί να σας ενημερώσει αν το domain σας έχει μπλοκαριστεί από το spamhouse. Μπορείτε να ζητήσετε το domain/IP σας να αφαιρεθεί από εκεί: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Μαύρη Λίστα της Microsoft

Μπορείτε να ζητήσετε το domain/IP σας να αφαιρεθεί από εκεί: [https://sender.office.com/](https://sender.office.com).

## Δημιουργία και Εκτέλεση Επίθεσης GoPhish

### Προφίλ Αποστολέα

* Ορίστε ένα **όνομα για αναγνώριση** του προφίλ αποστολέα
* Αποφασίστε από ποιο λογαριασμό θα στείλετε τα ψεύτικα email. Προτάσεις: _noreply, support, servicedesk, salesforce..._
* Μπορείτε να αφήσετε κενά το όνομα χρήστη και ο κωδικός πρόσβασης, αλλά βεβαιωθείτε ότι έχετε επιλέξει την επιλογή Αγνόηση Σφαλμάτων Πιστοποιητικού

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Αποστολή Δοκιμαστικού Email**" για να ελέγξετε ότι όλα λειτουργούν σωστά.\
Θα συνιστούσα να **στείλετε τα δοκιμαστικά email σε διευθύνσεις 10min mail** για να αποφύγετε να μπείτε στη μαύρη λίστα κατά τη διάρκεια των δοκιμών.
{% endhint %}

### Πρότυπο Email

* Ορίστε ένα **όνομα για αναγνώριση** του προτύπου
* Στη συνέχεια, γράψτε ένα **θέμα** (κάτι κανονικό που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
* Βεβαιωθείτε ότι έχετε επιλέξει την επιλογή "**Προσθήκη Εικόνας Παρακολούθησης**"
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
Σημείωση ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε μια υπογραφή από ένα email του πελάτη. Προτάσεις:

* Στείλτε ένα email σε μια **μη υπάρχουσα διεύθυνση** και ελέγξτε αν η απάντηση έχει κάποια υπογραφή.
* Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε για την απάντηση.
* Προσπαθήστε να επικοινωνήσετε με **κάποιο έγκυρο ανακαλυφθέν** email και περιμένετε για την απάντηση.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Το Πρότυπο Email επίσης επιτρέπει να **συνημμένα αρχεία για αποστολή**. Αν θέλετε επίσης να κλέψετε προκλήσεις NTLM χρησιμοποιώντας κάποια ειδικά δημιουργημένα αρχεία/έγγραφα [διαβάστε αυτήν τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Σελίδα Προσγείωσης

* Γράψτε ένα **όνομα**
* **Γράψτε τον κώδικα HTML** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισάγετε** ιστοσελίδες.
* Σημειώστε **Καταγραφή Υποβληθέντων Δεδομένων** και **Καταγραφή Κωδικών Πρόσβασης**
* Ορίστε μια **ανακατεύθυνση**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Συνήθως θα χρειαστεί να τροποποιήσετε τον κώδικα HTML της σελίδας και να κάνετε μερικές δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον διακομιστή Apache) **μέχρι να σας αρέσουν τα αποτελέσματα**. Στη συνέχεια, γράψτε αυτόν τον κώδικα HTML στο πλαίσιο.\
Σημειώστε ότι αν χρειάζεστε να **χρησιμοποιήσετε κάποιους στατικούς πόρους** για το HTML (ίσως κάποιες σελίδες CSS και JS) μπορείτε να τις αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να τις προσπελάσετε από _**/static/\<όνομα αρχείου>**_
{% endhint %}

{% hint style="info" %}
Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην πραγματική κύρια ιστοσελίδα** του θύματος, ή να τους ανακατευθύνετε σε _/static/migration.html_ για παράδειγμα, να βάλετε κάποιο **περιστρεφόμενο τροχό** ([**https://loading.io/**](https://loading.io)) για 5 δευτερόλεπτα και στη συνέχεια να υποδείξετε ότι η διαδικασία ήταν επιτυχής.
{% endhint %}

### Χρήστες & Ομάδες

* Ορίστε ένα όνομα
* **Εισαγάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το πρότυπο για το παράδειγμα χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)

![](<../../.gitbook/assets/image (395).png>)

### Εκστρατεία

Τέλος, δημιουργήστε μια εκστρατεία επιλέγοντας ένα όνομα, το πρότυπο email, τη σελίδα προσγείωσης, το URL, το προφίλ αποστολής και την ομάδα. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα

Σημείωση ότι το **Προφίλ Αποστολής επιτρέπει να στείλετε ένα δοκιμαστικό email για να δείτε πώς
