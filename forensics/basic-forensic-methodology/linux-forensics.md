# Linux forenzika

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Početno prikupljanje informacija

### Osnovne informacije

Prvo, preporučuje se da imate neki **USB** sa **poznatim binarnim fajlovima i bibliotekama** (možete jednostavno preuzeti Ubuntu i kopirati foldere _/bin_, _/sbin_, _/lib_ i _/lib64_), zatim montirajte USB i izmenite okruženjske promenljive da biste koristili te binarne fajlove:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Jednom kada ste konfigurisali sistem da koristi dobre i poznate binarne datoteke, možete početi **izvlačiti osnovne informacije**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Sumnjive informacije

Prilikom dobijanja osnovnih informacija trebali biste proveriti čudne stvari kao što su:

* **Root procesi** obično se izvršavaju sa niskim PID-om, pa ako pronađete root proces sa velikim PID-om, možete posumnjati
* Proverite **registrovane prijave** korisnika bez ljuske unutar `/etc/passwd`
* Proverite da li postoje **hešovi lozinki** unutar `/etc/shadow` za korisnike bez ljuske

### Damp memorije

Da biste dobili memoriju pokrenutog sistema, preporučuje se korišćenje [**LiME**](https://github.com/504ensicsLabs/LiME).\
Da biste ga **kompajlirali**, morate koristiti **istu kernel verziju** koju koristi žrtvena mašina.

{% hint style="info" %}
Zapamtite da **ne možete instalirati LiME ili bilo šta drugo** na žrtvenoj mašini jer će to izazvati nekoliko promena na njoj.
{% endhint %}

Dakle, ako imate identičnu verziju Ubuntu-a, možete koristiti `apt-get install lime-forensics-dkms`\
U drugim slučajevima, morate preuzeti [**LiME**](https://github.com/504ensicsLabs/LiME) sa github-a i kompajlirati ga sa odgovarajućim kernel zaglavljima. Da biste **dobili tačna kernel zaglavlja** žrtvene mašine, jednostavno **kopirajte direktorijum** `/lib/modules/<kernel verzija>` na vašu mašinu, a zatim **kompajlirajte** LiME koristeći ih:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME podržava 3 **formata**:

* Sirovi (svaki segment je konkateniran zajedno)
* Padded (isti kao sirovi, ali sa nulama na desnoj strani)
* Lime (preporučeni format sa metapodacima)

LiME se takođe može koristiti za **slanje dumpa preko mreže** umesto da se čuva na sistemu koristeći nešto poput: `path=tcp:4444`

### Snimanje diska

#### Gašenje

Prvo, moraćete **ugasiti sistem**. To nije uvek opcija jer će neki sistemi biti serverski sistemi koje kompanija ne može da priušti da isključi.\
Postoje **2 načina** za gašenje sistema, **normalno gašenje** i **isključivanje iz struje**. Prvi način će omogućiti **procesima da se završe kao i obično** i da se **fajl sistem sinhronizuje**, ali će takođe omogućiti mogućem **malveru da uništi dokaze**. Pristup "isključivanje iz struje" može dovesti do **gubitka nekih informacija** (neće biti izgubljeno mnogo informacija jer smo već napravili sliku memorije) i **malver neće imati priliku** da bilo šta uradi u vezi toga. Dakle, ako **sumnjate** da postoji **malver**, samo izvršite **`sync`** **komandu** na sistemu i isključite ga iz struje.

#### Snimanje slike diska

Važno je napomenuti da **pre nego što povežete svoj računar sa bilo čim što je povezano sa slučajem**, morate biti sigurni da će biti **montiran samo za čitanje** kako biste izbegli menjanje bilo kakvih informacija.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Preanaliza slike diska

Kreiranje slike diska bez dodatnih podataka.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Pretraga poznatih malvera

### Modifikovane sistemsko datoteke

Linux nudi alate za osiguravanje integriteta sistemskih komponenti, što je ključno za otkrivanje potencijalno problematičnih datoteka.

- **Sistemi zasnovani na RedHat-u**: Koristite `rpm -Va` za sveobuhvatnu proveru.
- **Sistemi zasnovani na Debian-u**: `dpkg --verify` za početnu verifikaciju, a zatim `debsums | grep -v "OK$"` (nakon instaliranja `debsums` sa `apt-get install debsums`) da biste identifikovali bilo kakve probleme.

### Detektori malvera/rootkita

Pročitajte sledeću stranicu da biste saznali o alatima koji mogu biti korisni za pronalaženje malvera:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Pretraga instaliranih programa

Da biste efikasno pretraživali instalirane programe na Debian i RedHat sistemima, razmotrite korišćenje sistemskih logova i baza podataka zajedno sa ručnim proverama u uobičajenim direktorijumima.

- Za Debian, pregledajte **_`/var/lib/dpkg/status`_** i **_`/var/log/dpkg.log`_** da biste dobili detalje o instalacijama paketa, koristeći `grep` za filtriranje određenih informacija.

- Korisnici RedHat-a mogu upitati RPM bazu podataka sa `rpm -qa --root=/mntpath/var/lib/rpm` da bi dobili listu instaliranih paketa.

Da biste otkrili softver koji je instaliran ručno ili izvan ovih upravljača paketa, istražite direktorijume poput **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_** i **_`/sbin`_**. Kombinujte listu direktorijuma sa sistemskim komandama kako biste identifikovali izvršne datoteke koje nisu povezane sa poznatim paketima, poboljšavajući tako pretragu svih instaliranih programa.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** koji se pokreću najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vraćanje obrisanih pokrenutih binarnih fajlova

Zamislite proces koji je pokrenut iz /tmp/exec i obrisan. Moguće je izvući ga
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Pregledajte lokacije automatskog pokretanja

### Zakazani zadaci
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Servisi

Putanje gde se malver može instalirati kao servis:

- **/etc/inittab**: Poziva skripte za inicijalizaciju kao što je rc.sysinit, usmeravajući dalje ka skriptama za pokretanje.
- **/etc/rc.d/** i **/etc/rc.boot/**: Sadrže skripte za pokretanje servisa, pri čemu se ova druga nalazi u starijim verzijama Linuxa.
- **/etc/init.d/**: Koristi se u određenim verzijama Linuxa kao što je Debian za skladištenje skripti za pokretanje.
- Servisi se takođe mogu aktivirati putem **/etc/inetd.conf** ili **/etc/xinetd/**, zavisno o varijanti Linuxa.
- **/etc/systemd/system**: Direktorijum za sistemske i upravljačke skripte servisa.
- **/etc/systemd/system/multi-user.target.wants/**: Sadrži linkove ka servisima koji treba da se pokrenu u više korisničkom nivou.
- **/usr/local/etc/rc.d/**: Za prilagođene ili servise trećih strana.
- **~/.config/autostart/**: Za aplikacije koje se automatski pokreću specifične za korisnika, što može biti skriveno mesto za malver usmeren na korisnika.
- **/lib/systemd/system/**: Univerzalni fajlovi jedinica za ceo sistem koje obezbeđuju instalirani paketi.


### Kernel moduli

Kernel moduli Linuxa, često korišćeni od strane malvera kao komponente rootkita, se učitavaju prilikom pokretanja sistema. Direktorijumi i fajlovi koji su ključni za ove module uključuju:

- **/lib/modules/$(uname -r)**: Sadrži module za trenutnu verziju kernela.
- **/etc/modprobe.d**: Sadrži konfiguracione fajlove za kontrolu učitavanja modula.
- **/etc/modprobe** i **/etc/modprobe.conf**: Fajlovi za globalna podešavanja modula.

### Ostale lokacije za automatsko pokretanje

Linux koristi različite fajlove za automatsko izvršavanje programa prilikom prijave korisnika, potencijalno skrivajući malver:

- **/etc/profile.d/***, **/etc/profile** i **/etc/bash.bashrc**: Izvršavaju se prilikom prijave bilo kog korisnika.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** i **~/.config/autostart**: Fajlovi specifični za korisnika koji se pokreću prilikom njihove prijave.
- **/etc/rc.local**: Pokreće se nakon što su svi sistemski servisi pokrenuti, označavajući kraj prelaska na više korisničko okruženje.

## Pregledajte logove

Linux sistemi prate aktivnosti korisnika i događaje na sistemu putem različitih log fajlova. Ovi logovi su ključni za identifikaciju neovlašćenog pristupa, infekcija malverom i drugih sigurnosnih incidenata. Ključni log fajlovi uključuju:

- **/var/log/syslog** (Debian) ili **/var/log/messages** (RedHat): Snimaju poruke i aktivnosti na nivou sistema.
- **/var/log/auth.log** (Debian) ili **/var/log/secure** (RedHat): Beleže pokušaje autentifikacije, uspešne i neuspešne prijave.
- Koristite `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` da biste filtrirali relevantne događaje autentifikacije.
- **/var/log/boot.log**: Sadrži poruke o pokretanju sistema.
- **/var/log/maillog** ili **/var/log/mail.log**: Beleže aktivnosti email servera, korisne za praćenje email-related servisa.
- **/var/log/kern.log**: Čuva kernel poruke, uključujući greške i upozorenja.
- **/var/log/dmesg**: Sadrži poruke upravljača uređaja.
- **/var/log/faillog**: Beleži neuspele pokušaje prijave, pomažući u istrazi sigurnosnih incidenata.
- **/var/log/cron**: Beleži izvršavanje cron poslova.
- **/var/log/daemon.log**: Prati aktivnosti pozadinskih servisa.
- **/var/log/btmp**: Dokumentuje neuspele pokušaje prijave.
- **/var/log/httpd/**: Sadrži Apache HTTPD logove o greškama i pristupu.
- **/var/log/mysqld.log** ili **/var/log/mysql.log**: Beleže aktivnosti MySQL baze podataka.
- **/var/log/xferlog**: Beleži FTP prenose fajlova.
- **/var/log/**: Uvek proverite da li postoje neočekivani logovi ovde.

{% hint style="info" %}
Logovi sistema Linuxa i podsistemi za nadzor mogu biti onemogućeni ili obrisani tokom napada ili incidenata sa malverom. Pošto logovi na Linux sistemima obično sadrže neke od najkorisnijih informacija o zlonamernim aktivnostima, napadači ih redovno brišu. Stoga, prilikom pregleda dostupnih log fajlova, važno je tražiti praznine ili ulazne zapise koji su van reda, što može ukazivati na brisanje ili manipulaciju.
{% endhint %}

**Linux čuva istoriju komandi za svakog korisnika**, smeštenu u:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Osim toga, komanda `last -Faiwx` pruža listu prijava korisnika. Proverite je za nepoznate ili neočekivane prijave.

Proverite fajlove koji mogu dodeliti dodatne privilegije:

- Pregledajte `/etc/sudoers` za neočekivane korisničke privilegije koje su možda dodeljene.
- Pregledajte `/etc/sudoers.d/` za neočekivane korisničke privilegije koje su možda dodeljene.
- Ispitajte `/etc/groups` da biste identifikovali neobična članstva u grupama ili dozvole.
- Ispitajte `/etc/passwd` da biste identifikovali neobična članstva u grupama ili dozvole.

Neke aplikacije takođe generišu sopstvene logove:

- **SSH**: Pregledajte _~/.ssh/authorized_keys_ i _~/.ssh/known_hosts_ za neovlaštene udaljene konekcije.
- **Gnome Desktop**: Pogledajte _~/.recently-used.xbel_ za nedavno pristupane fajlove putem Gnome aplikacija.
- **Firefox/Chrome**: Proverite istoriju pretraživača i preuzimanja u _~/.mozilla/firefox_ ili _~/.config/google-chrome_ za sumnjive aktivnosti.
- **VIM**: Pregledajte _~/.viminfo_ za detalje o korišćenju, kao što su putanje do pristupanih fajlova i istorija pretrage.
- **Open Office**: Proverite nedavni pristup dokumentima koji mogu ukazivati na kompromitovane fajlove.
- **FTP/SFTP**: Pregledajte logove u _~/.ftp_history_ ili _~/.sftp_history_ za prenose fajlova koji mogu biti neovlašćeni.
- **MySQL**: Istražite _~/.mysql_history_ za izvršene MySQL upite, što može otkriti neovlaštene aktivnosti na bazi podataka.
- **Less**: Analizirajte _~/.lesshst_ za istoriju korišćenja, uključujući pregledane fajlove i izvršene komande.
- **Git**: Pregledajte _~/.gitconfig_ i _.git/logs_ projekta za promene u repozitorijumima.

### USB logovi

[**usbrip**](https://github.com/snovvcrash/usbrip) je mali softver napisan u čistom Pythonu 3 koji analizira Linux log fajlove (`/var/log/syslog*` ili `/var/log/messages*` zavisno od distribucije) kako bi konstruisao tabele istorije događaja sa USB uređajima.

Interesantno je **znati sve USB uređaje koji su korišćeni**, a biće korisno ako imate autorizovanu listu USB uređaja kako biste pronašli "događaje kršenja" (korišćenje USB uređaja koji nisu na toj listi).

### Instalacija
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Primeri
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Više primera i informacija možete pronaći na Github-u: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i automatizovali radne tokove uz pomoć najnaprednijih alata zajednice.\
Danas dobijte pristup:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Pregled korisničkih naloga i aktivnosti prijavljivanja

Pregledajte datoteke _**/etc/passwd**_, _**/etc/shadow**_ i **bezbednosne zapise** u potrazi za neobičnim imenima ili nalozima koji su kreirani ili korišćeni u blizini poznatih neovlašćenih događaja. Takođe, proverite moguće brute-force napade na sudo.\
Takođe, proverite datoteke poput _**/etc/sudoers**_ i _**/etc/groups**_ u potrazi za neočekivanim privilegijama dodeljenim korisnicima.\
Na kraju, potražite naloge bez lozinki ili sa lako pogodivim lozinkama.

## Pregledajte sistem datoteka

### Analiza struktura sistema datoteka u istrazi malvera

Prilikom istraživanja incidenata sa malverom, struktura sistema datoteka je ključni izvor informacija koji otkriva kako su se događaji odvijali i sadržaj malvera. Međutim, autori malvera razvijaju tehnike koje ometaju ovu analizu, kao što su izmena vremena datoteka ili izbegavanje sistema datoteka za skladištenje podataka.

Da biste se suprotstavili ovim anti-forenzičkim metodama, važno je:

- **Sprovoditi temeljnu analizu vremenske linije** koristeći alate poput **Autopsy** za vizualizaciju vremenske linije događaja ili **Sleuth Kit's** `mactime` za detaljne podatke o vremenskoj liniji.
- **Istražiti neočekivane skripte** u $PATH sistemu, koje mogu sadržati skripte ljuske ili PHP skripte koje koriste napadači.
- **Pregledati `/dev` za netipične datoteke**, jer tradicionalno sadrži posebne datoteke, ali može sadržati datoteke povezane sa malverom.
- **Tražiti skrivene datoteke ili direktorijume** sa imenima poput ".. " (tačka tačka razmak) ili "..^G" (tačka tačka kontrola-G), koje mogu sakriti zlonamerni sadržaj.
- **Identifikovati datoteke sa postavljenim setuid privilegijama** korišćenjem komande:
```find / -user root -perm -04000 -print```
Ovo pronalazi datoteke sa povišenim privilegijama koje napadači mogu zloupotrebiti.
- **Pregledati vremenske oznake brisanja** u tabelama inoda kako biste otkrili masovno brisanje datoteka, što može ukazivati na prisustvo rootkitova ili trojanaca.
- **Pregledati uzastopne inode** za bliske zlonamerne datoteke nakon što se jedna identifikuje, jer mogu biti smeštene zajedno.
- **Proveriti uobičajene binarne direktorijume** (_/bin_, _/sbin_) za nedavno izmenjene datoteke, jer ih malver može izmeniti.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Imajte na umu da **napadač** može **izmeniti** **vreme** da bi **fajlovi izgledali** **legitimno**, ali ne može izmeniti **inode**. Ako primetite da **fajl** pokazuje da je kreiran i izmenjen u **istom trenutku** kao i ostali fajlovi u istom folderu, ali je **inode** **neočekivano veći**, onda su **vremenske oznake tog fajla izmenjene**.
{% endhint %}

## Uporedite fajlove različitih verzija fajl sistema

### Rezime uporedjivanja verzija fajl sistema

Da biste uporedili verzije fajl sistema i identifikovali promene, koristite pojednostavljene `git diff` komande:

- **Da biste pronašli nove fajlove**, uporedite dva direktorijuma:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Za izmenjen sadržaj**, navedite promene ignorišući određene linije:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Da biste otkrili izbrisane datoteke**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcije filtera** (`--diff-filter`) pomažu u sužavanju na specifične promene kao što su dodate (`A`), obrisane (`D`) ili izmenjene (`M`) datoteke.
- `A`: Dodate datoteke
- `C`: Kopirane datoteke
- `D`: Obrisane datoteke
- `M`: Izmenjene datoteke
- `R`: Preimenovane datoteke
- `T`: Promene tipa (npr. datoteka u simbolički link)
- `U`: Nespajane datoteke
- `X`: Nepoznate datoteke
- `B`: Oštećene datoteke

## Reference

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Knjiga: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Da li radite u **cybersecurity kompaniji**? Želite li videti **vašu kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
