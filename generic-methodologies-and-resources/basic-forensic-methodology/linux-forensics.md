# Linux Forensics

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) om maklik **werkvloei** te bou en te **automate** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapstools.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Aanvanklike Inligting Versameling

### Basiese Inligting

Eerstens, dit word aanbeveel om 'n **USB** te hê met **goeie bekende binaire en biblioteke daarop** (jy kan net ubuntu kry en die mappen _/bin_, _/sbin_, _/lib,_ en _/lib64_ kopieer), dan monteer die USB, en wysig die omgewing veranderlikes om daardie binaire te gebruik:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sodra jy die stelsel gekonfigureer het om goeie en bekende binaire lêers te gebruik, kan jy begin **inligting te onttrek**:
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

Terwyl jy die basiese inligting verkry, moet jy vir vreemde dinge kyk soos:

* **Root prosesse** loop gewoonlik met lae PID's, so as jy 'n root proses met 'n groot PID vind, kan jy vermoed
* Kontroleer **geregistreerde aanmeldings** van gebruikers sonder 'n shell binne `/etc/passwd`
* Kontroleer vir **wagwoord-hashes** binne `/etc/shadow` vir gebruikers sonder 'n shell

### Geheue Dump

Om die geheue van die lopende stelsel te verkry, word dit aanbeveel om [**LiME**](https://github.com/504ensicsLabs/LiME) te gebruik.\
Om dit te **compileer**, moet jy die **dieselfde kern** gebruik wat die slagoffer masjien gebruik.

{% hint style="info" %}
Onthou dat jy **nie LiME of enige ander ding** op die slagoffer masjien kan installeer nie, aangesien dit verskeie veranderinge daaraan sal maak
{% endhint %}

So, as jy 'n identiese weergawe van Ubuntu het, kan jy `apt-get install lime-forensics-dkms` gebruik\
In ander gevalle moet jy [**LiME**](https://github.com/504ensicsLabs/LiME) van github aflaai en dit compileer met die korrekte kernkoppe. Om die **presiese kernkoppe** van die slagoffer masjien te verkry, kan jy net die **gids** `/lib/modules/<kernel version>` na jou masjien kopieer, en dan **compileer** LiME met hulle:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME ondersteun 3 **formate**:

* Rau (elke segment saamgevoeg)
* Gepad (dieselfde as rau, maar met nul in regter bits)
* Lime (aanbevole formaat met metadata)

LiME kan ook gebruik word om die **dump via netwerk te stuur** in plaas van dit op die stelsel te stoor met iets soos: `path=tcp:4444`

### Skyf Beeldvorming

#### Afsluiting

Eerstens, jy sal die **stelsel moet afsluit**. Dit is nie altyd 'n opsie nie, aangesien sommige stelsels 'n produksiebediener kan wees wat die maatskappy nie kan bekostig om af te sluit.\
Daar is **2 maniere** om die stelsel af te sluit, 'n **normale afsluiting** en 'n **"trek die stekker" afsluiting**. Die eerste een sal die **prosesse toelaat om soos gewoonlik te beëindig** en die **lêerstelsel** te **sinkroniseer**, maar dit sal ook die moontlike **malware** toelaat om **bewyse te vernietig**. Die "trek die stekker" benadering kan **sekere inligtingverlies** meebring (nie veel van die inligting gaan verlore gaan nie aangesien ons reeds 'n beeld van die geheue geneem het) en die **malware sal nie enige geleentheid hê** om iets daaroor te doen nie. Daarom, as jy **vermoed** dat daar 'n **malware** mag wees, voer net die **`sync`** **opdrag** op die stelsel uit en trek die stekker.

#### Neem 'n beeld van die skyf

Dit is belangrik om te noem dat **voor jy jou rekenaar aan enigiets wat met die saak verband hou, koppel**, jy moet seker wees dat dit **as slegs lees gemonteer gaan word** om te verhoed dat enige inligting gewysig word.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image pre-analysis

Beeld 'n skyfbeeld met geen verdere data nie.
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) om maklik **werkvloei** te bou en te **automate** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapstools.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Soek na bekende Malware

### Gewysigde Stelselfeiles

Linux bied gereedskap om die integriteit van stelselkome te verseker, wat noodsaaklik is om potensieel problematiese lêers op te spoor.

* **RedHat-gebaseerde stelsels**: Gebruik `rpm -Va` vir 'n omvattende kontrole.
* **Debian-gebaseerde stelsels**: `dpkg --verify` vir aanvanklike verifikasie, gevolg deur `debsums | grep -v "OK$"` (na die installering van `debsums` met `apt-get install debsums`) om enige probleme te identifiseer.

### Malware/Rootkit Detektors

Lees die volgende bladsy om meer te leer oor gereedskap wat nuttig kan wees om malware te vind:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Soek geïnstalleerde programme

Om effektief te soek na geïnstalleerde programme op beide Debian en RedHat stelsels, oorweeg om stelsellogs en databasisse saam met handmatige kontroles in algemene gidse te benut.

* Vir Debian, ondersoek _**`/var/lib/dpkg/status`**_ en _**`/var/log/dpkg.log`**_ om besonderhede oor pakketinstallasies te verkry, met `grep` om vir spesifieke inligting te filter.
* RedHat gebruikers kan die RPM-databasis raadpleeg met `rpm -qa --root=/mntpath/var/lib/rpm` om geïnstalleerde pakkette te lys.

Om sagteware wat handmatig of buite hierdie pakketbestuurders geïnstalleer is, te ontdek, verken gidse soos _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, en _**`/sbin`**_. Kombineer gidse met stelselspesifieke opdragte om uitvoerbare lêers te identifiseer wat nie geassosieer word met bekende pakkette nie, wat jou soektog na alle geïnstalleerde programme verbeter.
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) om maklik **werkvloei** te bou en te **automate** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapstools.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Herstel Verwyderde Loopende Binaries

Stel jou 'n proses voor wat vanaf /tmp/exec uitgevoer is en toe verwyder is. Dit is moontlik om dit te onttrek
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspekteer Autostart plekke

### Geplande Take
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

Paaie waar 'n malware as 'n diens geïnstalleer kan word:

* **/etc/inittab**: Roep inisialisering skripte aan soos rc.sysinit, wat verder na opstart skripte lei.
* **/etc/rc.d/** en **/etc/rc.boot/**: Bevat skripte vir diens opstart, laasgenoemde word in ouer Linux weergawes gevind.
* **/etc/init.d/**: Gebruik in sekere Linux weergawes soos Debian vir die stoor van opstart skripte.
* Dienste kan ook geaktiveer word via **/etc/inetd.conf** of **/etc/xinetd/**, afhangende van die Linux variasie.
* **/etc/systemd/system**: 'n Gids vir stelsels en diensbestuurder skripte.
* **/etc/systemd/system/multi-user.target.wants/**: Bevat skakels na dienste wat in 'n multi-gebruiker runlevel begin moet word.
* **/usr/local/etc/rc.d/**: Vir pasgemaakte of derdeparty dienste.
* **\~/.config/autostart/**: Vir gebruiker-spesifieke outomatiese opstart toepassings, wat 'n wegkruipplek vir gebruiker-gemikte malware kan wees.
* **/lib/systemd/system/**: Stelselswye standaard eenheid lêers verskaf deur geïnstalleerde pakkette.

### Kernel Modules

Linux kernel modules, dikwels deur malware as rootkit komponente gebruik, word by stelselaanvang gelaai. Die gidse en lêers wat krities vir hierdie modules is, sluit in:

* **/lib/modules/$(uname -r)**: Hou modules vir die lopende kernel weergawe.
* **/etc/modprobe.d**: Bevat konfigurasielêers om module laai te beheer.
* **/etc/modprobe** en **/etc/modprobe.conf**: Lêers vir globale module instellings.

### Ander Outomatiese Opstart Plekke

Linux gebruik verskeie lêers om programme outomaties uit te voer by gebruiker aanmelding, wat moontlik malware kan huisves:

* **/etc/profile.d/**\*, **/etc/profile**, en **/etc/bash.bashrc**: Word uitgevoer vir enige gebruiker aanmelding.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, en **\~/.config/autostart**: Gebruiker-spesifieke lêers wat by hul aanmelding loop.
* **/etc/rc.local**: Loop nadat alle stelseldienste begin het, wat die einde van die oorgang na 'n multi-gebruiker omgewing aandui.

## Ondersoek Logs

Linux stelsels volg gebruiker aktiwiteite en stelsel gebeurtenisse deur verskeie log lêers. Hierdie logs is noodsaaklik om ongeoorloofde toegang, malware infeksies, en ander sekuriteitsvoorvalle te identifiseer. Sleutel log lêers sluit in:

* **/var/log/syslog** (Debian) of **/var/log/messages** (RedHat): Vang stelselswye boodskappe en aktiwiteite.
* **/var/log/auth.log** (Debian) of **/var/log/secure** (RedHat): Registreer autentikasie pogings, suksesvolle en mislukte aanmeldings.
* Gebruik `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` om relevante autentikasie gebeurtenisse te filter.
* **/var/log/boot.log**: Bevat stelsel opstart boodskappe.
* **/var/log/maillog** of **/var/log/mail.log**: Log e-pos bediener aktiwiteite, nuttig vir die opsporing van e-pos verwante dienste.
* **/var/log/kern.log**: Stoor kernel boodskappe, insluitend foute en waarskuwings.
* **/var/log/dmesg**: Hou toestel bestuurder boodskappe.
* **/var/log/faillog**: Registreer mislukte aanmeldingspogings, wat help in sekuriteitsbreuk ondersoeke.
* **/var/log/cron**: Log cron taak uitvoerings.
* **/var/log/daemon.log**: Volg agtergrond diens aktiwiteite.
* **/var/log/btmp**: Dokumenteer mislukte aanmeldingspogings.
* **/var/log/httpd/**: Bevat Apache HTTPD fout en toegang logs.
* **/var/log/mysqld.log** of **/var/log/mysql.log**: Log MySQL databasis aktiwiteite.
* **/var/log/xferlog**: Registreer FTP lêer oordragte.
* **/var/log/**: Kontroleer altyd vir onverwagte logs hier.

{% hint style="info" %}
Linux stelsel logs en oudit subsisteme mag gedeaktiveer of verwyder word in 'n indringing of malware voorval. Omdat logs op Linux stelsels oor die algemeen sommige van die nuttigste inligting oor kwaadwillige aktiwiteite bevat, verwyder indringers gereeld hulle. Daarom, wanneer jy beskikbare log lêers ondersoek, is dit belangrik om te soek na gapings of uit die orde inskrywings wat 'n aanduiding van verwydering of manipulasie mag wees.
{% endhint %}

**Linux hou 'n opdrag geskiedenis vir elke gebruiker**, gestoor in:

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

Boonop bied die `last -Faiwx` opdrag 'n lys van gebruiker aanmeldings. Kontroleer dit vir onbekende of onverwagte aanmeldings.

Kontroleer lêers wat ekstra regte kan toeken:

* Hersien `/etc/sudoers` vir onverwagte gebruiker regte wat moontlik toegeken is.
* Hersien `/etc/sudoers.d/` vir onverwagte gebruiker regte wat moontlik toegeken is.
* Ondersoek `/etc/groups` om enige ongewone groep lidmaatskappe of toestemmings te identifiseer.
* Ondersoek `/etc/passwd` om enige ongewone groep lidmaatskappe of toestemmings te identifiseer.

Sommige toepassings genereer ook hul eie logs:

* **SSH**: Ondersoek _\~/.ssh/authorized\_keys_ en _\~/.ssh/known\_hosts_ vir ongeoorloofde afstandverbindinge.
* **Gnome Desktop**: Kyk in _\~/.recently-used.xbel_ vir onlangs toeganklike lêers via Gnome toepassings.
* **Firefox/Chrome**: Kontroleer blaargeskiedenis en aflaaie in _\~/.mozilla/firefox_ of _\~/.config/google-chrome_ vir verdagte aktiwiteite.
* **VIM**: Hersien _\~/.viminfo_ vir gebruik besonderhede, soos toeganklike lêer paaie en soek geskiedenis.
* **Open Office**: Kontroleer vir onlangse dokument toegang wat moontlik gecompromitteerde lêers aandui.
* **FTP/SFTP**: Hersien logs in _\~/.ftp\_history_ of _\~/.sftp\_history_ vir lêer oordragte wat moontlik ongeoorloofde is.
* **MySQL**: Ondersoek _\~/.mysql\_history_ vir uitgevoerde MySQL vrae, wat moontlik ongeoorloofde databasis aktiwiteite onthul.
* **Less**: Analiseer _\~/.lesshst_ vir gebruik geskiedenis, insluitend gesiene lêers en uitgevoerde opdragte.
* **Git**: Ondersoek _\~/.gitconfig_ en projek _.git/logs_ vir veranderinge aan repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is 'n klein stuk sagteware geskryf in suiwer Python 3 wat Linux log lêers (`/var/log/syslog*` of `/var/log/messages*` afhangende van die distro) ontleed om USB gebeurtenis geskiedenis tabelles te bou.

Dit is interessant om **alle USB's wat gebruik is** te weet en dit sal meer nuttig wees as jy 'n gemagtigde lys van USB's het om "oortreding gebeurtenisse" (die gebruik van USB's wat nie binne daardie lys is nie) te vind.

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) om maklik **werkvloei** te bou en te **automate** wat deur die wêreld se **mees gevorderde** gemeenskapstools aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Hersien Gebruikersrekeninge en Aanmeldaktiwiteite

Ondersoek die _**/etc/passwd**_, _**/etc/shadow**_ en **veiligheidslogboek** vir ongewone name of rekeninge wat geskep of gebruik is in nabyheid van bekende ongeoorloofde gebeurtenisse. Kontroleer ook moontlike sudo brute-force aanvalle.\
Boonop, kyk na lêers soos _**/etc/sudoers**_ en _**/etc/groups**_ vir onverwagte voorregte wat aan gebruikers gegee is.\
Laastens, soek na rekeninge met **geen wagwoorde** of **maklik geraadpleegde** wagwoorde.

## Ondersoek Lêerstelsel

### Ontleding van Lêerstelselstrukture in Malware Ondersoek

Wanneer malware-voorvalle ondersoek word, is die struktuur van die lêerstelsel 'n cruciale bron van inligting, wat beide die volgorde van gebeurtenisse en die inhoud van die malware onthul. Malware-skeppers ontwikkel egter tegnieke om hierdie analise te hindernis, soos om lêer tydstempels te verander of die lêerstelsel te vermy vir datastoor.

Om hierdie anti-forensiese metodes teë te werk, is dit noodsaaklik om:

* **'n deeglike tydlynanalise uit te voer** met behulp van gereedskap soos **Autopsy** vir die visualisering van gebeurtenistydlyne of **Sleuth Kit's** `mactime` vir gedetailleerde tydlyn data.
* **Ondersoek ongewone skripte** in die stelsel se $PATH, wat dalk skulp of PHP-skripte insluit wat deur aanvallers gebruik word.
* **Ondersoek `/dev` vir ongewone lêers**, aangesien dit tradisioneel spesiale lêers bevat, maar dalk malware-verwante lêers kan huisves.
* **Soek na versteekte lêers of gidse** met name soos ".. " (dot dot space) of "..^G" (dot dot control-G), wat kwaadwillige inhoud kan verberg.
* **Identifiseer setuid root lêers** met die opdrag: `find / -user root -perm -04000 -print` Dit vind lêers met verhoogde voorregte, wat deur aanvallers misbruik kan word.
* **Hersien verwydering tydstempels** in inode-tabelle om massalêer verwyderings op te spoor, wat moontlik die teenwoordigheid van rootkits of trojans aandui.
* **Inspekteer opeenvolgende inodes** vir nabye kwaadwillige lêers nadat een geïdentifiseer is, aangesien hulle saam geplaas mag wees.
* **Kontroleer algemene binêre gidse** (_/bin_, _/sbin_) vir onlangs gewysigde lêers, aangesien hierdie deur malware verander kan wees.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Let daarop dat 'n **aanvaller** die **tyd** kan **wysig** om **lêers** **legitiem** te laat lyk, maar hy kan nie die **inode** **wysig** nie. As jy vind dat 'n **lêer** aandui dat dit op die **selfde tyd** as die res van die lêers in dieselfde gids geskep en gewysig is, maar die **inode** **onverwagte groter** is, dan is die **tydstempels van daardie lêer gewysig**.
{% endhint %}

## Vergelyk lêers van verskillende lêerstelsels

### Lêerstelsel Weergawe Vergelyking Opsomming

Om lêerstelsels te vergelyk en veranderinge te identifiseer, gebruik ons vereenvoudigde `git diff` opdragte:

* **Om nuwe lêers te vind**, vergelyk twee gidse:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Vir gewysigde inhoud**, lys veranderinge terwyl spesifieke lyne geïgnoreer word:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Om verwyderde lêers te ontdek**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Filter opsies** (`--diff-filter`) help om te fokus op spesifieke veranderinge soos bygevoeg (`A`), verwyder (`D`), of gewysig (`M`) lêers.
* `A`: Bygevoegde lêers
* `C`: Gekopieerde lêers
* `D`: Verwyderde lêers
* `M`: Gewysigde lêers
* `R`: Hernoemde lêers
* `T`: Tipe veranderinge (bv. lêer na symlink)
* `U`: Onvervlegte lêers
* `X`: Onbekende lêers
* `B`: Gebroke lêers

## Verwysings

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Boek: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) om maklik te bou en **werkvloei te outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapstoestelle.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}
