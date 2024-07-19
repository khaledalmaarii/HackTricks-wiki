# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** pokretane od strane **najnaprednijih** alata zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Početno prikupljanje informacija

### Osnovne informacije

Prvo, preporučuje se da imate neki **USB** sa **dobro poznatim binarnim datotekama i bibliotekama** (možete jednostavno uzeti ubuntu i kopirati foldere _/bin_, _/sbin_, _/lib,_ i _/lib64_), zatim montirajte USB i modifikujte env varijable da koristite te binarne datoteke:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Kada konfigurišete sistem da koristi dobre i poznate binarne datoteke, možete početi sa **ekstrakcijom nekih osnovnih informacija**:
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

Dok prikupljate osnovne informacije, trebali biste proveriti čudne stvari kao što su:

* **Root procesi** obično se pokreću sa niskim PID-ovima, pa ako pronađete root proces sa velikim PID-om, možete posumnjati
* Proverite **registrovane prijave** korisnika bez shel-a unutar `/etc/passwd`
* Proverite **hash-eve lozinke** unutar `/etc/shadow` za korisnike bez shel-a

### Dump memorije

Da biste dobili memoriju pokrenutog sistema, preporučuje se korišćenje [**LiME**](https://github.com/504ensicsLabs/LiME).\
Da biste ga **kompajlirali**, morate koristiti **isti kernel** koji koristi žrtvinska mašina.

{% hint style="info" %}
Zapamtite da **ne možete instalirati LiME ili bilo šta drugo** na žrtvinskoj mašini jer će to napraviti nekoliko promena na njoj
{% endhint %}

Dakle, ako imate identičnu verziju Ubuntua, možete koristiti `apt-get install lime-forensics-dkms`\
U drugim slučajevima, potrebno je preuzeti [**LiME**](https://github.com/504ensicsLabs/LiME) sa github-a i kompajlirati ga sa ispravnim kernel header-ima. Da biste **dobili tačne kernel header-e** žrtvinske mašine, možete jednostavno **kopirati direktorijum** `/lib/modules/<kernel version>` na vašu mašinu, a zatim **kompajlirati** LiME koristeći ih:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME podržava 3 **formata**:

* Raw (svaki segment spojeni zajedno)
* Padded (isto kao raw, ali sa nulama u desnim bitovima)
* Lime (preporučeni format sa metapodacima)

LiME se takođe može koristiti za **slanje dump-a putem mreže** umesto da se čuva na sistemu koristeći nešto poput: `path=tcp:4444`

### Disk Imaging

#### Isključivanje

Prvo, potrebno je **isključiti sistem**. Ovo nije uvek opcija jer neki sistemi mogu biti produkcijski serveri koje kompanija ne može priuštiti da isključi.\
Postoje **2 načina** za isključivanje sistema, **normalno isključivanje** i **"isključi kabl" isključivanje**. Prvi će omogućiti da se **procesi završe kao obično** i da se **fajl sistem** **sinhronizuje**, ali će takođe omogućiti mogućem **malware-u** da **uništi dokaze**. Pristup "isključi kabl" može doneti **neki gubitak informacija** (neće se mnogo informacija izgubiti jer smo već uzeli sliku memorije) i **malware neće imati priliku** da uradi bilo šta povodom toga. Stoga, ako **sumnjate** da može biti **malware**, jednostavno izvršite **`sync`** **komandu** na sistemu i isključite kabl.

#### Uzimanje slike diska

Važno je napomenuti da **pre nego što povežete svoj računar sa bilo čim vezanim za slučaj**, morate biti sigurni da će biti **montiran kao samo za čitanje** kako biste izbegli modifikaciju bilo kojih informacija.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image pre-analysis

Imaging a disk image with no more data.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Pretraživanje poznatog Malware-a

### Izmenjene sistemske datoteke

Linux nudi alate za osiguranje integriteta sistemskih komponenti, što je ključno za uočavanje potencijalno problematičnih datoteka.

* **Sistemi zasnovani na RedHat-u**: Koristite `rpm -Va` za sveobuhvatnu proveru.
* **Sistemi zasnovani na Debian-u**: `dpkg --verify` za inicijalnu verifikaciju, a zatim `debsums | grep -v "OK$"` (nakon instalacije `debsums` sa `apt-get install debsums`) za identifikaciju bilo kakvih problema.

### Detektori Malware-a/Rootkit-a

Pročitajte sledeću stranicu da biste saznali o alatima koji mogu biti korisni za pronalaženje malware-a:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Pretraživanje instaliranih programa

Da biste efikasno pretražili instalirane programe na sistemima Debian i RedHat, razmotrite korišćenje sistemskih logova i baza podataka zajedno sa ručnim proverama u uobičajenim direktorijumima.

* Za Debian, proverite _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_ da biste dobili detalje o instalacijama paketa, koristeći `grep` za filtriranje specifičnih informacija.
* Korisnici RedHat-a mogu upititi RPM bazu podataka sa `rpm -qa --root=/mntpath/var/lib/rpm` da bi prikazali instalirane pakete.

Da biste otkrili softver instaliran ručno ili van ovih menadžera paketa, istražite direktorijume kao što su _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, i _**`/sbin`**_. Kombinujte liste direktorijuma sa sistemskim komandama specifičnim za identifikaciju izvršnih datoteka koje nisu povezane sa poznatim paketima, poboljšavajući vašu pretragu za svim instaliranim programima.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Oporavak obrisanih pokretnih binarnih datoteka

Zamislite proces koji je izvršen iz /tmp/exec i zatim obrisan. Moguće je izvući ga
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspekcija lokacija za automatsko pokretanje

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
### Usluge

Putanje gde se zlonamerni softver može instalirati kao usluga:

* **/etc/inittab**: Poziva skripte inicijalizacije kao što su rc.sysinit, usmeravajući dalje na skripte za pokretanje.
* **/etc/rc.d/** i **/etc/rc.boot/**: Sadrže skripte za pokretanje usluga, pri čemu se potonja nalazi u starijim verzijama Linux-a.
* **/etc/init.d/**: Koristi se u određenim verzijama Linux-a kao što je Debian za čuvanje skripti za pokretanje.
* Usluge se takođe mogu aktivirati putem **/etc/inetd.conf** ili **/etc/xinetd/**, u zavisnosti od Linux varijante.
* **/etc/systemd/system**: Direktorijum za skripte menadžera sistema i usluga.
* **/etc/systemd/system/multi-user.target.wants/**: Sadrži linkove ka uslugama koje treba pokrenuti u višekorisničkom režimu.
* **/usr/local/etc/rc.d/**: Za prilagođene ili usluge trećih strana.
* **\~/.config/autostart/**: Za automatske aplikacije specifične za korisnika, koje mogu biti skriveno mesto za zlonamerni softver usmeren na korisnike.
* **/lib/systemd/system/**: Podrazumevane jedinice sistema koje obezbeđuju instalirani paketi.

### Kernel Moduli

Linux kernel moduli, često korišćeni od strane zlonamernog softvera kao komponenti rootkita, učitavaju se prilikom pokretanja sistema. Direktorijumi i datoteke kritične za ove module uključuju:

* **/lib/modules/$(uname -r)**: Sadrži module za verziju kernel-a koja se trenutno koristi.
* **/etc/modprobe.d**: Sadrži konfiguracione datoteke za kontrolu učitavanja modula.
* **/etc/modprobe** i **/etc/modprobe.conf**: Datoteke za globalne postavke modula.

### Druge Lokacije za Automatsko Pokretanje

Linux koristi razne datoteke za automatsko izvršavanje programa prilikom prijavljivanja korisnika, potencijalno skrivajući zlonamerni softver:

* **/etc/profile.d/**\*, **/etc/profile**, i **/etc/bash.bashrc**: Izvršavaju se za bilo koju prijavu korisnika.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, i **\~/.config/autostart**: Datoteke specifične za korisnika koje se pokreću prilikom njihove prijave.
* **/etc/rc.local**: Izvršava se nakon što su sve sistemske usluge pokrenute, označavajući kraj prelaska na višekorisničko okruženje.

## Istraži Logove

Linux sistemi prate aktivnosti korisnika i događaje sistema kroz razne log datoteke. Ovi logovi su ključni za identifikaciju neovlašćenog pristupa, infekcija zlonamernim softverom i drugih bezbednosnih incidenata. Ključne log datoteke uključuju:

* **/var/log/syslog** (Debian) ili **/var/log/messages** (RedHat): Zabeležavaju poruke i aktivnosti širom sistema.
* **/var/log/auth.log** (Debian) ili **/var/log/secure** (RedHat): Beleže pokušaje autentifikacije, uspešne i neuspešne prijave.
* Koristite `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` za filtriranje relevantnih događaja autentifikacije.
* **/var/log/boot.log**: Sadrži poruke o pokretanju sistema.
* **/var/log/maillog** ili **/var/log/mail.log**: Beleže aktivnosti email servera, korisne za praćenje usluga povezanih sa email-om.
* **/var/log/kern.log**: Čuva poruke kernela, uključujući greške i upozorenja.
* **/var/log/dmesg**: Sadrži poruke drajvera uređaja.
* **/var/log/faillog**: Beleži neuspele pokušaje prijave, pomažući u istragama bezbednosnih proboja.
* **/var/log/cron**: Beleži izvršenja cron poslova.
* **/var/log/daemon.log**: Prati aktivnosti pozadinskih usluga.
* **/var/log/btmp**: Dokumentuje neuspele pokušaje prijave.
* **/var/log/httpd/**: Sadrži Apache HTTPD greške i pristupne logove.
* **/var/log/mysqld.log** ili **/var/log/mysql.log**: Beleže aktivnosti MySQL baze podataka.
* **/var/log/xferlog**: Beleži FTP transfer fajlova.
* **/var/log/**: Uvek proverite neočekivane logove ovde.

{% hint style="info" %}
Linux sistemski logovi i audit pod-sistemi mogu biti onemogućeni ili obrisani tokom upada ili incidenta sa zlonamernim softverom. Pošto logovi na Linux sistemima obično sadrže neke od najkorisnijih informacija o zlonamernim aktivnostima, napadači ih rutinski brišu. Stoga, prilikom ispitivanja dostupnih log datoteka, važno je tražiti praznine ili neuredne unose koji bi mogli biti indikacija brisanja ili manipulacije.
{% endhint %}

**Linux održava istoriju komandi za svakog korisnika**, smeštenu u:

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

Pored toga, komanda `last -Faiwx` pruža listu prijava korisnika. Proverite je za nepoznate ili neočekivane prijave.

Proverite datoteke koje mogu dodeliti dodatne privilegije:

* Pregledajte `/etc/sudoers` za neočekivane privilegije korisnika koje su možda dodeljene.
* Pregledajte `/etc/sudoers.d/` za neočekivane privilegije korisnika koje su možda dodeljene.
* Istražite `/etc/groups` da identifikujete bilo kakva neobična članstva u grupama ili dozvole.
* Istražite `/etc/passwd` da identifikujete bilo kakva neobična članstva u grupama ili dozvole.

Neke aplikacije takođe generišu svoje logove:

* **SSH**: Istražite _\~/.ssh/authorized\_keys_ i _\~/.ssh/known\_hosts_ za neovlašćene udaljene konekcije.
* **Gnome Desktop**: Pogledajte _\~/.recently-used.xbel_ za nedavno pristupane datoteke putem Gnome aplikacija.
* **Firefox/Chrome**: Proverite istoriju pretraživača i preuzimanja u _\~/.mozilla/firefox_ ili _\~/.config/google-chrome_ za sumnjive aktivnosti.
* **VIM**: Pregledajte _\~/.viminfo_ za detalje o korišćenju, kao što su putanje pristupnih datoteka i istorija pretrage.
* **Open Office**: Proverite za nedavni pristup dokumentima koji mogu ukazivati na kompromitovane datoteke.
* **FTP/SFTP**: Pregledajte logove u _\~/.ftp\_history_ ili _\~/.sftp\_history_ za transfer fajlova koji bi mogli biti neovlašćeni.
* **MySQL**: Istražite _\~/.mysql\_history_ za izvršene MySQL upite, potencijalno otkrivajući neovlašćene aktivnosti u bazi podataka.
* **Less**: Analizirajte _\~/.lesshst_ za istoriju korišćenja, uključujući pregledane datoteke i izvršene komande.
* **Git**: Istražite _\~/.gitconfig_ i projekat _.git/logs_ za promene u repozitorijumima.

### USB Logovi

[**usbrip**](https://github.com/snovvcrash/usbrip) je mali komad softvera napisan u čistom Python 3 koji analizira Linux log datoteke (`/var/log/syslog*` ili `/var/log/messages*` u zavisnosti od distribucije) za konstruisanje tabela istorije USB događaja.

Zanimljivo je **znati sve USB uređaje koji su korišćeni** i biće korisnije ako imate ovlašćenu listu USB uređaja da pronađete "događaje kršenja" (korišćenje USB uređaja koji nisu na toj listi).

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
Više primera i informacija unutar github-a: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim **alatima** zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Pregled korisničkih naloga i aktivnosti prijavljivanja

Istražite _**/etc/passwd**_, _**/etc/shadow**_ i **bezbednosne logove** za neobične nazive ili naloge koji su kreirani i ili korišćeni u bliskoj blizini poznatih neovlašćenih događaja. Takođe, proverite moguće sudo brute-force napade.\
Pored toga, proverite datoteke kao što su _**/etc/sudoers**_ i _**/etc/groups**_ za neočekivane privilegije dodeljene korisnicima.\
Na kraju, potražite naloge sa **bez lozinki** ili **lako pogađanim** lozinkama.

## Istraživanje datotečnog sistema

### Analiza struktura datotečnog sistema u istrazi malvera

Kada istražujete incidente malvera, struktura datotečnog sistema je ključni izvor informacija, otkrivajući kako redosled događaja, tako i sadržaj malvera. Međutim, autori malvera razvijaju tehnike za ometanje ove analize, kao što su modifikovanje vremenskih oznaka datoteka ili izbegavanje datotečnog sistema za skladištenje podataka.

Da biste se suprotstavili ovim anti-forenzičkim metodama, važno je:

* **Sprovesti temeljnu analizu vremenskih linija** koristeći alate kao što su **Autopsy** za vizualizaciju vremenskih linija događaja ili **Sleuth Kit's** `mactime` za detaljne podatke o vremenskim linijama.
* **Istražiti neočekivane skripte** u sistemskom $PATH, koje mogu uključivati shell ili PHP skripte koje koriste napadači.
* **Istražiti `/dev` za atipične datoteke**, jer tradicionalno sadrži specijalne datoteke, ali može sadržati i datoteke povezane sa malverom.
* **Pretražiti skrivene datoteke ili direktorijume** sa nazivima kao što su ".. " (tačka tačka razmak) ili "..^G" (tačka tačka kontrola-G), koje bi mogle skrivati zlonamerni sadržaj.
* **Identifikovati setuid root datoteke** koristeći komandu: `find / -user root -perm -04000 -print` Ovo pronalazi datoteke sa povišenim dozvolama, koje bi napadači mogli zloupotrebiti.
* **Pregledati vremenske oznake brisanja** u inode tabelama kako bi se uočila masovna brisanja datoteka, što može ukazivati na prisustvo rootkit-ova ili trojanaca.
* **Istražiti uzastopne inode** za obližnje zlonamerne datoteke nakon identifikacije jedne, jer su možda postavljene zajedno.
* **Proveriti uobičajene binarne direktorijume** (_/bin_, _/sbin_) za nedavno modifikovane datoteke, jer bi ove mogle biti izmenjene od strane malvera.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Napomena da **napadač** može **modifikovati** **vreme** kako bi **datoteke izgledale** **legitimno**, ali ne može **modifikovati** **inode**. Ako otkrijete da **datoteka** pokazuje da je kreirana i modifikovana u **isto vreme** kao i ostale datoteke u istoj fascikli, ali je **inode** **neočekivano veći**, tada su **vremenske oznake te datoteke modifikovane**.
{% endhint %}

## Upoređivanje datoteka različitih verzija datotečnog sistema

### Sažetak upoređivanja verzija datotečnog sistema

Da bismo uporedili verzije datotečnog sistema i precizirali promene, koristimo pojednostavljene `git diff` komande:

* **Da bismo pronašli nove datoteke**, uporedite dve fascikle:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Za izmenjeni sadržaj**, navedite promene ignorišući specifične linije:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Da otkrijete obrisane fajlove**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Opcije filtriranja** (`--diff-filter`) pomažu da se suzite na specifične promene kao što su dodati (`A`), obrisani (`D`) ili izmenjeni (`M`) fajlovi.
* `A`: Dodati fajlovi
* `C`: Kopirani fajlovi
* `D`: Obrisani fajlovi
* `M`: Izmenjeni fajlovi
* `R`: Preimenovani fajlovi
* `T`: Promene tipa (npr., fajl u symlink)
* `U`: Neusaglašeni fajlovi
* `X`: Nepoznati fajlovi
* `B`: Pokvareni fajlovi

## Reference

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Knjiga: Vodič za forenziku malvera za Linux sisteme: Vodiči za digitalnu forenziku**

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** pokretane od strane **najnaprednijih** alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
