# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werksvloei** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Aanvanklike Inligting Versameling

### Basiese Inligting

Eerstens word dit aanbeveel om 'n **USB** met **bekende goeie binêre lêers en biblioteke daarop** te hê (jy kan net Ubuntu kry en die _/bin_, _/sbin_, _/lib,_ en _/lib64_ lêers kopieer), monteer dan die USB, en wysig die omgewingsveranderlikes om daardie binêre lêers te gebruik:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sodra jy die stelsel ingestel het om goeie en bekende binêre lêers te gebruik, kan jy begin **om 'n paar basiese inligting te onttrek**:
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
#### Verdagte inligting

Terwyl jy die basiese inligting bekom, moet jy vir vreemde dinge soos die volgende kyk:

- **Root prosesse** hardloop gewoonlik met lae PIDS, so as jy 'n root proses met 'n groot PID vind, kan jy dit verdenk
- Kyk na **geregistreerde aanmeldings** van gebruikers sonder 'n skaal binne `/etc/passwd`
- Kyk vir **wagwoordhasings** binne `/etc/shadow` vir gebruikers sonder 'n skaal

### Geheue Dump

Om die geheue van die lopende stelsel te bekom, word dit aanbeveel om [**LiME**](https://github.com/504ensicsLabs/LiME) te gebruik.\
Om dit te **kompileer**, moet jy dieselfde kernel gebruik as die slagoffer se masjien.

{% hint style="info" %}
Onthou dat jy **LiME of enige ander ding nie kan installeer** op die slagoffer se masjien nie, aangesien dit verskeie veranderinge daaraan sal maak
{% endhint %}

Dus, as jy 'n identiese weergawe van Ubuntu het, kan jy `apt-get install lime-forensics-dkms` gebruik\
In ander gevalle moet jy [**LiME**](https://github.com/504ensicsLabs/LiME) van github aflaai en dit met die korrekte kernelkoppe kompileer. Om die **presiese kernelkoppe** van die slagoffer se masjien te bekom, kan jy net die gids `/lib/modules/<kernel weergawe>` na jou masjien kopieer, en dan LiME **kompileer** met behulp daarvan:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME ondersteun 3 **formate**:

* Rou (elke segment aanmekaar gekonkatenasieer)
* Gepas (soortgelyk aan rou, maar met nulle in die regter bietjies)
* Lime (aanbevole formaat met metadata)

LiME kan ook gebruik word om die storting via die netwerk te **stuur** in plaas van dit op die stelsel te stoor deur iets soos: `path=tcp:4444`

### Skyfbeelding

#### Afskakel

Eerstens, sal jy die stelsel moet **afskakel**. Dit is nie altyd 'n opsie nie aangesien die stelsel soms 'n produksieserver sal wees wat die maatskappy nie kan bekostig om af te skakel nie.\
Daar is **2 maniere** om die stelsel af te skakel, 'n **normale afskakeling** en 'n **"trek die prop uit" afskakeling**. Die eerste een sal die **prosesse toelaat om soos gewoonlik te beëindig** en die **lêersisteem** om **gesinkroniseer** te word, maar dit sal ook die moontlike **malware** toelaat om **bewyse te vernietig**. Die "trek die prop uit" benadering mag 'n bietjie **inligtingverlies** meebring (nie baie van die inligting gaan verlore gaan aangesien ons reeds 'n beeld van die geheue geneem het nie) en die **malware sal geen geleentheid hê** om iets daaraan te doen nie. Daarom, as jy **vermoed** dat daar 'n **malware** mag wees, voer net die **`sync`** **bevel** op die stelsel uit en trek die prop uit.

#### 'n Beeld van die skyf neem

Dit is belangrik om te let dat **voordat jy jou rekenaar aan iets wat met die saak verband hou, koppel**, moet jy seker maak dat dit as **alleen lees** gemonteer gaan word om te verhoed dat enige inligting gewysig word.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Skijfafbeelding voor-ontleding

Beeldvorming van 'n skijfafbeelding met geen verdere data nie.
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
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiseer werkstrome** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Soek na bekende Malware

### Gewysigde Stelsel lêers

Linux bied gereedskap om die integriteit van stelselkomponente te verseker, wat noodsaaklik is om potensieel problematiese lêers op te spoor.

* **RedHat-gebaseerde stelsels**: Gebruik `rpm -Va` vir 'n omvattende ondersoek.
* **Debian-gebaseerde stelsels**: `dpkg --verify` vir aanvanklike verifikasie, gevolg deur `debsums | grep -v "OK$"` (nadat `debsums` met `apt-get install debsums` geïnstalleer is) om enige probleme te identifiseer.

### Malware/Rootkit Detectors

Lees die volgende bladsy om meer te leer oor gereedskap wat nuttig kan wees om malware te vind:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Soek geïnstalleerde programme

Om doeltreffend te soek na geïnstalleerde programme op beide Debian- en RedHat-stelsels, oorweeg om stelsellogs en databasisse te benut saam met handmatige kontroles in algemene gidsies.

* Vir Debian, ondersoek _**`/var/lib/dpkg/status`**_ en _**`/var/log/dpkg.log`**_ om besonderhede oor pakketaanvullings te kry, gebruik `grep` om te filter vir spesifieke inligting.
* RedHat-gebruikers kan die RPM-databasis ondervra met `rpm -qa --root=/mntpath/var/lib/rpm` om geïnstalleerde pakkette te lys.

Om sagteware wat handmatig geïnstalleer is of buite hierdie pakketsbestuurders geïnstalleer is, te ontdek, verken gidsies soos _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, en _**`/sbin`**_. Kombineer gidslysings met stelselspesifieke opdragte om uitvoerbare lêers te identifiseer wat nie verband hou met bekende pakkette nie, wat jou soektog na alle geïnstalleerde programme verbeter.
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
Gebruik [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) om maklik **werkstrome te bou** en outomatiseer met die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Herstel Verwyderde Lopende Binêre Lêers

Stel jou voor 'n proses wat uitgevoer is vanaf /tmp/exec en verwyder is. Dit is moontlik om dit terug te haal
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspekteer Autostart-plekke

### Beplande Take
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
### Dienste

Paaie waar 'n kwaadwillige program geïnstalleer kan word as 'n diens:

- **/etc/inittab**: Roep inisialiseringsskripte soos rc.sysinit aan, wat verder na aanloopskripte verwys.
- **/etc/rc.d/** en **/etc/rc.boot/**: Bevat skripte vir diensaanloop, waarvan die laaste in ouer Linux-weergawes gevind word.
- **/etc/init.d/**: Word in sekere Linux-weergawes soos Debian gebruik vir die stoor van aanloopskripte.
- Dienste kan ook geaktiveer word via **/etc/inetd.conf** of **/etc/xinetd/**, afhangende van die Linux-variant.
- **/etc/systemd/system**: 'n Gids vir stelsel- en diensbestuurskripte.
- **/etc/systemd/system/multi-user.target.wants/**: Bevat skakels na dienste wat in 'n multi-gebruiker vlak gestart moet word.
- **/usr/local/etc/rc.d/**: Vir aangepaste of derdeparty-dienste.
- **\~/.config/autostart/**: Vir gebruikerspesifieke outomatiese aanlooptoepassings, wat 'n skuilplek vir gebruikersgerigte kwaadwillige sagteware kan wees.
- **/lib/systemd/system/**: Stelselwye verstek eenheidslêers wat deur geïnstalleerde pakkette voorsien word.

### Kernelmodules

Linux-kernelmodules, dikwels deur kwaadwillige sagteware as rootkit-komponente gebruik, word by stelselbegin gelaai. Die kritieke gids en lêers vir hierdie modules sluit in:

- **/lib/modules/$(uname -r)**: Hou modules vir die lopende kernelweergawe.
- **/etc/modprobe.d**: Bevat konfigurasie lêers om modulelaaiing te beheer.
- **/etc/modprobe** en **/etc/modprobe.conf**: Lêers vir globale module-instellings.

### Ander Autostart-plekke

Linux gebruik verskeie lêers om programme outomaties uit te voer by gebruiker aanmelding, wat moontlik kwaadwillige sagteware kan bevat:

- **/etc/profile.d/**\*, **/etc/profile**, en **/etc/bash.bashrc**: Uitgevoer vir enige gebruiker aanmelding.
- **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, en **\~/.config/autostart**: Gebruikerspesifieke lêers wat by hul aanmelding loop.
- **/etc/rc.local**: Loop nadat alle stelseldienste begin het, wat die einde van die oorgang na 'n multi-gebruiker omgewing aandui.

## Ondersoek Logboeke

Linux-stelsels hou gebruikersaktiwiteite en stelselgebeure dop deur verskeie log lêers. Hierdie logboeke is noodsaaklik vir die identifisering van ongemagtigde toegang, kwaadwillige infeksies, en ander veiligheidsvoorvalle. Sleutel log lêers sluit in:

- **/var/log/syslog** (Debian) of **/var/log/messages** (RedHat): Vang stelselwye boodskappe en aktiwiteite op.
- **/var/log/auth.log** (Debian) of **/var/log/secure** (RedHat): Neem outentiseringspogings, suksesvolle en mislukte aanmeldings op.
- Gebruik `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` om relevante outentiseringsgebeure te filter.
- **/var/log/boot.log**: Bevat stelselbeginboodskappe.
- **/var/log/maillog** of **/var/log/mail.log**: Neem e-posbedieneraktiwiteite op, nuttig vir die opsporing van e-posverwante dienste.
- **/var/log/kern.log**: Berg kernelboodskappe op, insluitend foute en waarskuwings.
- **/var/log/dmesg**: Hou toestelbestuurderboodskappe vas.
- **/var/log/faillog**: Neem mislukte aanmeldingspogings op, wat help met veiligheidskrenkingondersoeke.
- **/var/log/cron**: Neem cron-werkuitvoerings op.
- **/var/log/daemon.log**: Volg agtergronddiensaktiwiteite.
- **/var/log/btmp**: Dokumenteer mislukte aanmeldingspogings.
- **/var/log/httpd/**: Bevat Apache HTTPD-fout- en toegangslogboeke.
- **/var/log/mysqld.log** of **/var/log/mysql.log**: Neem MySQL-databasisaktiwiteite op.
- **/var/log/xferlog**: Neem FTP-lêeroordragte op.
- **/var/log/**: Kontroleer altyd vir onverwagte logboeke hier.

{% hint style="info" %}
Linux-stelsellogboeke en ouditsubstelsels kan gedeaktiveer of uitgevee word in 'n indringing of kwaadwillige voorval. Omdat logboeke op Linux-stelsels gewoonlik van die nuttigste inligting oor skadelike aktiwiteite bevat, verwyder indringers dit gereeld. Daarom is dit belangrik om by die ondersoek van beskikbare log lêers te kyk vir gaping of uit plek ininskrywings wat 'n aanduiding van uitveeg of manipulasie kan wees.
{% endhint %}

**Linux hou 'n opdraggeskiedenis vir elke gebruiker by**, gestoor in:

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

Verder bied die `last -Faiwx` opdrag 'n lys van gebruikersaanmeldings. Kontroleer dit vir onbekende of onverwagte aanmeldings.

Kontroleer lêers wat ekstra regte kan verleen:

- Ondersoek `/etc/sudoers` vir onverwagte gebruikersregte wat moontlik toegeken is.
- Ondersoek `/etc/sudoers.d/` vir onverwagte gebruikersregte wat moontlik toegeken is.
- Ondersoek `/etc/groups` om enige ongewone groepslidmaatskappe of -regte te identifiseer.
- Ondersoek `/etc/passwd` om enige ongewone groepslidmaatskappe of -regte te identifiseer.

Sommige programme genereer ook hul eie logboeke:

- **SSH**: Ondersoek _\~/.ssh/authorized\_keys_ en _\~/.ssh/known\_hosts_ vir ongemagtigde afgeleë verbindinge.
- **Gnome Desktop**: Kyk na _\~/.recently-used.xbel_ vir onlangs benaderde lêers via Gnome-toepassings.
- **Firefox/Chrome**: Kontroleer blaaiergeskiedenis en aflaaie in _\~/.mozilla/firefox_ of _\~/.config/google-chrome_ vir verdagte aktiwiteite.
- **VIM**: Ondersoek _\~/.viminfo_ vir gebruiksdetails, soos benaderde lêerpaadjies en soekgeskiedenis.
- **Open Office**: Kontroleer vir onlangse dokumenttoegang wat dui op gekompromitteerde lêers.
- **FTP/SFTP**: Ondersoek logboeke in _\~/.ftp\_history_ of _\~/.sftp\_history_ vir lêeroordragte wat moontlik ongemagtig is.
- **MySQL**: Ondersoek _\~/.mysql\_history_ vir uitgevoerde MySQL-navrae, wat moontlik ongemagtigde databasisaktiwiteite kan onthul.
- **Less**: Analiseer _\~/.lesshst_ vir gebruiksgeskiedenis, insluitend besigtigde lêers en uitgevoerde opdragte.
- **Git**: Ondersoek _\~/.gitconfig_ en projek _.git/logs_ vir veranderinge aan bewaarplekke.

### USB Logboeke

[**usbrip**](https://github.com/snovvcrash/usbrip) is 'n klein stukkie sagteware geskryf in suiwer Python 3 wat Linux-log lêers (`/var/log/syslog*` of `/var/log/messages*` afhangende van die distribusie) ontled om USB-gebeurtenisgeskiedenis tabele saam te stel.

Dit is interessant om **alle USB's wat gebruik is te ken** en dit sal meer nuttig wees as jy 'n gemagtigde lys van USB's het om "oortredinggebeure" te vind (die gebruik van USB's wat nie binne daardie lys is nie). 

### Installasie
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Voorbeelde
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Meer voorbeelde en inligting binne die github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomaties** aangedryf deur die wêreld se **mees gevorderde** gemeenskaplike gereedskap.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Oorsig van Gebruikersrekeninge en Aanmeldaktiwiteite

Ondersoek die _**/etc/passwd**_, _**/etc/shadow**_ en **sekuriteitslêers** vir ongewone name of rekeninge wat geskep is en/of gebruik is in nabyheid van bekende ongemagtigde gebeure. Kyk ook vir moontlike sudo-bruteforce-aanvalle.\
Verder, kyk na lêers soos _**/etc/sudoers**_ en _**/etc/groups**_ vir onverwagte voorregte wat aan gebruikers gegee is.\
Laastens, soek na rekeninge met **geen wagwoorde** of **maklik gerade** wagwoorde.

## Ondersoek Lêersisteem

### Analise van Lêersisteemstrukture in Malware-ondersoek

Wanneer malware-voorvalle ondersoek word, is die struktuur van die lêersisteem 'n belangrike bron van inligting, wat beide die volgorde van gebeure en die inhoud van die malware onthul. Tog ontwikkel malware-skrywers tegnieke om hierdie analise te bemoeilik, soos die wysiging van lêer-timestamps of die vermyding van die lêersisteem vir data-opberging.

Om hierdie teen-forensiese metodes te teenwerk, is dit noodsaaklik om:

* **Voer 'n deeglike tydlyn-analise uit** met behulp van gereedskap soos **Autopsy** om gebeurtenis-tydlyne te visualiseer of **Sleuth Kit's** `mactime` vir gedetailleerde tydlyn-data.
* **Ondersoek onverwagte skripte** in die stelsel se $PATH, wat dalk skul of PHP-skripte wat deur aanvallers gebruik word, kan insluit.
* **Ondersoek `/dev` vir atipiese lêers**, aangesien dit tradisioneel spesiale lêers bevat, maar moontlik malware-verwante lêers kan bevat.
* **Soek na verskuilde lêers of gidsname** met name soos ".. " (dot dot spatie) of "..^G" (dot dot control-G), wat kwaadwillige inhoud kan verberg.
* **Identifiseer setuid-root-lêers** met die opdrag: `find / -user root -perm -04000 -print` Dit vind lêers met verhoogde regte wat deur aanvallers misbruik kan word.
* **Ondersoek verwyderingstydmerke** in inode-tabelle om massiewe lêerverwyderings op te spoor, wat moontlik die teenwoordigheid van rootkits of trojane kan aandui.
* **Inspekteer aaneenlopende inodes** vir nabygeleë kwaadwillige lêers nadat een geïdentifiseer is, aangesien hulle saam geplaas kon wees.
* **Kontroleer algemene binêre gids** (_/bin_, _/sbin_) vir onlangs gewysigde lêers, aangesien hierdie deur malware verander kan word.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Let wel dat 'n **aanvaller** die **tyd** kan **verander** om **lêers te laat voorkom** asof hulle **wettig** is, maar hy kan nie die **inode** verander nie. As jy vind dat 'n **lêer** aandui dat dit geskep en verander is op dieselfde tyd as die res van die lêers in dieselfde vouer, maar die **inode** is **onverwags groter**, dan is die **tydstempels van daardie lêer verander**.
{% endhint %}

## Vergelyk lêers van verskillende lêersisteemweergawes

### Opsomming van Vergelyking van Lêersisteemweergawes

Om lêersisteemweergawes te vergelyk en veranderinge te identifiseer, gebruik ons vereenvoudigde `git diff` opdragte:

* **Om nuwe lêers te vind**, vergelyk twee gide:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Vir gewysigde inhoud**, lys veranderinge terwyl spesifieke lyne geïgnoreer word:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Om uitgewisde lêers op te spoor**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Filter opsies** (`--diff-filter`) help om te spesifiseer soos bygevoeg (`A`), verwyder (`D`), of gewysig (`M`) lêers.
* `A`: Bygevoegde lêers
* `C`: Gekopieerde lêers
* `D`: Verwyderde lêers
* `M`: Gewysigde lêers
* `R`: Hernoemde lêers
* `T`: Tipe veranderinge (bv., lêer na simbooliese skakel)
* `U`: Ongesmerge lêers
* `X`: Onbekende lêers
* `B`: Gebreekte lêers

## Verwysings

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Boek: Malware Forensics Field Guide vir Linux-stelsels: Digitale Forensics Field Guides**

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Werk jy in 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!

* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome te bou en outomatiseer** met die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
