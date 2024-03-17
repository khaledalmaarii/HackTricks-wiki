# Uchunguzi wa Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii ya **juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kukusanya Taarifa za Awali

### Taarifa za Msingi

Kwanza kabisa, ni vyema kuwa na **USB** na **binari na maktaba bora zinazojulikana** (unaweza tu kupata ubuntu na kunakili folda _/bin_, _/sbin_, _/lib,_ na _/lib64_), kisha funga USB, na badilisha mazingira ya env kutumia hizo binari:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Baada ya kuiweka mfumo kutumia programu za msingi na zilizojulikana unaweza kuanza **kuchambua taarifa za msingi**:
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
#### Taarifa za Mashaka

Wakati unapopata taarifa za msingi unapaswa kuangalia mambo ya ajabu kama vile:

- **Mchakato wa Root** kawaida hufanya kazi na PIDS ndogo, hivyo ikiwa utapata mchakato wa Root na PID kubwa unaweza kuwa na shaka
- Angalia **kuingia kwa usajili** wa watumiaji bila ganda ndani ya `/etc/passwd`
- Angalia **hashi za nywila** ndani ya `/etc/shadow` kwa watumiaji bila ganda

### Kudumpisha Kumbukumbu

Ili kupata kumbukumbu ya mfumo unaoendesha, ni vyema kutumia [**LiME**](https://github.com/504ensicsLabs/LiME).\
Kwa **kuichambua**, unahitaji kutumia **kernel sawa** na ule wa mashine ya mwathiriwa.

{% hint style="info" %}
Kumbuka kwamba huwezi **kufunga LiME au kitu kingine chochote** kwenye mashine ya mwathiriwa kwani itafanya mabadiliko kadhaa
{% endhint %}

Hivyo, ikiwa una toleo linalofanana na Ubuntu unaweza kutumia `apt-get install lime-forensics-dkms`\
Katika hali nyingine, unahitaji kupakua [**LiME**](https://github.com/504ensicsLabs/LiME) kutoka github na kuichambua na vichwa sahihi vya kernel. Ili **kupata vichwa sahihi vya kernel** vya mashine ya mwathiriwa, unaweza tu **kuchapisha saraka** `/lib/modules/<toleo la kernel>` kwenye mashine yako, kisha **kuichambua** LiME ukitumia vichwa hivyo:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME inasaidia **muundo** 3:

* Raw (kila sehemu imeunganishwa pamoja)
* Padded (sawa na raw, lakini na sifuri kwenye bits za kulia)
* Lime (muundo unaopendekezwa na metadata)

LiME pia inaweza kutumika kutuma **dump kupitia mtandao** badala ya kuihifadhi kwenye mfumo kwa kutumia kitu kama: `path=tcp:4444`

### Uchoraji wa Diski

#### Kuzima

Kwanza kabisa, utahitaji **kuzima mfumo**. Hii sio chaguo kila wakati kwani mara nyingine mfumo utakuwa server ya uzalishaji ambayo kampuni haiwezi kumudu kuzima.\
Kuna **njia 2** za kuzima mfumo, **kuzima kawaida** na **kuzima kwa kutekeleza**. Ya kwanza itaruhusu **mchakato kumalizika kama kawaida** na **mfumo wa faili** kusawazishwa, lakini pia itaruhusu **programu hasidi** kuharibu **usahihi**. Njia ya "kutekeleza" inaweza kusababisha **upotevu wa taarifa fulani** (sio sana ya taarifa itapotea kwani tayari tumepiga picha ya kumbukumbu) na **programu hasidi haitakuwa na fursa** ya kufanya chochote kuhusu hilo. Kwa hivyo, ikiwa **una shaka** kwamba kunaweza kuwa na **programu hasidi**, tekeleza tu **amri ya `sync`** kwenye mfumo na kutekeleza.

#### Kupiga picha ya diski

Ni muhimu kuzingatia kwamba **kabla ya kuunganisha kompyuta yako kwenye kitu chochote kinachohusiana na kesi**, lazima uhakikishe kuwa itakuwa **imeunganishwa kama soma tu** ili kuepuka kuhariri taarifa yoyote.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Uchambuzi wa Awali wa Picha ya Diski

Kuiga picha ya diski bila data zaidi.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia** mchakato wa kiotomatiki ulioendeshwa na zana za jamii **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Tafuta Malware Inayojulikana

### Faili za Mfumo Zilizobadilishwa

Linux inatoa zana za kuhakikisha uadilifu wa sehemu za mfumo, muhimu kwa kutambua faili zenye matatizo.

* **Mifumo ya RedHat**: Tumia `rpm -Va` kwa uchunguzi kamili.
* **Mifumo ya Debian**: `dpkg --verify` kwa uhakiki wa awali, kisha `debsums | grep -v "OK$"` (baada ya kusakinisha `debsums` kwa kutumia `apt-get install debsums`) kutambua masuala yoyote.

### Zana za Kugundua Malware/Rootkit

Soma ukurasa ufuatao kujifunza kuhusu zana zinazoweza kuwa na manufaa katika kutambua malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Tafuta Programu Zilizosakinishwa

Kutafuta kwa ufanisi programu zilizosakinishwa kwenye mifumo ya Debian na RedHat, fikiria kutumia nyaraka za mfumo na mabadiliko pamoja na uchunguzi wa mwongozo kwenye saraka za kawaida.

* Kwa Debian, angalia _**`/var/lib/dpkg/status`**_ na _**`/var/log/dpkg.log`**_ kupata maelezo kuhusu usakinishaji wa pakiti, kutumia `grep` kufanya uchujaji wa habari maalum.
* Watumiaji wa RedHat wanaweza kuuliza hifadhidata ya RPM kwa kutumia `rpm -qa --root=/mntpath/var/lib/rpm` kuorodhesha pakiti zilizosakinishwa.

Kugundua programu zilizosakinishwa kwa mkono au nje ya mameneja haya ya pakiti, chunguza saraka kama _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, na _**`/sbin`**_. Changanya orodha za saraka na amri za kipekee za mfumo kutambua programu za kutekelezwa ambazo hazihusiani na pakiti zinazojulikana, kuimarisha utafutaji wako wa programu zote zilizosakinishwa.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zaidi yaliyotengenezwa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Kurejesha Programu za Kutekelezwa Zilizofutwa

Fikiria mchakato uliotekelezwa kutoka /tmp/exec na kufutwa. Inawezekana kuutoa
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Angalia Maeneo ya Kuanza moja kwa moja

### Kazi Zilizopangwa
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
### Huduma

Njia ambapo programu hasidi inaweza kuwekwa kama huduma:

- **/etc/inittab**: Huita skripti za uanzishaji kama rc.sysinit, ikiongoza kwa skripti za kuanza.
- **/etc/rc.d/** na **/etc/rc.boot/**: Zina skripti za kuanzisha huduma, ya mwisho ikipatikana kwenye toleo za zamani za Linux.
- **/etc/init.d/**: Hutumiwa katika toleo fulani za Linux kama Debian kwa kuhifadhi skripti za kuanza.
- Huduma pia inaweza kuwezeshwa kupitia **/etc/inetd.conf** au **/etc/xinetd/**, kulingana na toleo la Linux.
- **/etc/systemd/system**: Daktari kwa skripti za mfumo na msimamizi wa huduma.
- **/etc/systemd/system/multi-user.target.wants/**: Ina viungo kwa huduma ambazo zinapaswa kuanza katika kiwango cha mbio cha watumiaji wengi.
- **/usr/local/etc/rc.d/**: Kwa huduma za desturi au za mtu wa tatu.
- **\~/.config/autostart/**: Kwa programu za kuanza moja kwa moja za mtumiaji, ambayo inaweza kuwa mahali pa kujificha kwa programu hasidi inayolenga mtumiaji.
- **/lib/systemd/system/**: Faili za kawaida za kifurushi zinazotolewa na programu zilizowekwa.

### Moduli za Kerneli

Moduli za kerneli za Linux, mara nyingi hutumiwa na programu hasidi kama sehemu za rootkit, hupakiwa wakati wa kuanza kwa mfumo. Miongozo na faili muhimu kwa moduli hizi ni pamoja na:

- **/lib/modules/$(uname -r)**: Inashikilia moduli kwa toleo la sasa la kerneli linalotumika.
- **/etc/modprobe.d**: Ina faili za usanidi kudhibiti upakiaji wa moduli.
- **/etc/modprobe** na **/etc/modprobe.conf**: Faili za mipangilio ya kawaida ya moduli.

### Maeneo Mengine ya Kuanza Moja kwa Moja

Linux hutumia faili mbalimbali kutekeleza programu moja kwa moja wakati wa kuingia kwa mtumiaji, ikificha programu hasidi:

- **/etc/profile.d/**\*, **/etc/profile**, na **/etc/bash.bashrc**: Hutekelezwa kwa kuingia kwa mtumiaji yeyote.
- **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, na **\~/.config/autostart**: Faili za mtumiaji maalum ambazo hutekelezwa wakati wa kuingia kwao.
- **/etc/rc.local**: Hutekelezwa baada ya huduma zote za mfumo kuanza, ikimaanisha mwisho wa mpito kwa mazingira ya watumiaji wengi.

## Chunguza Kumbukumbu

Mifumo ya Linux hufuatilia shughuli za mtumiaji na matukio ya mfumo kupitia faili mbalimbali za kumbukumbu. Kumbukumbu hizi ni muhimu kwa kutambua ufikiaji usiohalali, maambukizi ya programu hasidi, na matukio mengine ya usalama. Faili muhimu za kumbukumbu ni pamoja na:

- **/var/log/syslog** (Debian) au **/var/log/messages** (RedHat): Hukamata ujumbe na shughuli za mfumo kwa ujumla.
- **/var/log/auth.log** (Debian) au **/var/log/secure** (RedHat): Hurekodi majaribio ya uwakilishi, kuingia kwa mafanikio na kushindwa.
- Tumia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kuchuja matukio muhimu ya uwakilishi.
- **/var/log/boot.log**: Ina ujumbe wa kuanza mfumo.
- **/var/log/maillog** au **/var/log/mail.log**: Hurekodi shughuli za seva ya barua pepe, muhimu kwa kufuatilia huduma zinazohusiana na barua pepe.
- **/var/log/kern.log**: Huhifadhi ujumbe wa kerneli, ikiwa ni pamoja na makosa na onyo.
- **/var/log/dmesg**: Inashikilia ujumbe wa dereva wa kifaa.
- **/var/log/faillog**: Hurekodi majaribio yaliyoshindwa ya kuingia, ikisaidia katika uchunguzi wa uvunjaji wa usalama.
- **/var/log/cron**: Hurekodi utekelezaji wa kazi za cron.
- **/var/log/daemon.log**: Hufuatilia shughuli za huduma za nyuma.
- **/var/log/btmp**: Hati majaribio yaliyoshindwa ya kuingia.
- **/var/log/httpd/**: Ina makosa ya Apache HTTPD na kumbukumbu za ufikiaji.
- **/var/log/mysqld.log** au **/var/log/mysql.log**: Hurekodi shughuli za MySQL database.
- **/var/log/xferlog**: Hurekodi uhamisho wa faili za FTP.
- **/var/log/**: Daima angalia kumbukumbu zisizotarajiwa hapa.

{% hint style="info" %}
Kumbukumbu za mfumo wa Linux na mifumo ya ukaguzi inaweza kulemazwa au kufutwa katika uvamizi au tukio la programu hasidi. Kwa sababu kumbukumbu kwenye mifumo ya Linux kwa ujumla zina habari muhimu zaidi kuhusu shughuli za uovu, wavamizi mara kwa mara huifuta. Kwa hivyo, wakati wa kuchunguza faili za kumbukumbu zilizopo, ni muhimu kutafuta mapengo au kuingizwa kwa kuingia ambayo inaweza kuwa ishara ya kufutwa au kuharibiwa.
{% endhint %}

**Linux inahifadhi historia ya amri kwa kila mtumiaji**, iliyohifadhiwa katika:

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

Zaidi ya hayo, amri `last -Faiwx` hutoa orodha ya kuingia kwa mtumiaji. Ichunguze kwa kuingia kwa kuingia kwa kuingia au isiyotarajiwa.

Angalia faili ambazo zinaweza kutoa rprivileges zaidi:

- Pitia `/etc/sudoers` kwa rprivileges zisizotarajiwa ambazo zinaweza kuwa zimetolewa.
- Pitia `/etc/sudoers.d/` kwa rprivileges zisizotarajiwa ambazo zinaweza kuwa zimetolewa.
- Chunguza `/etc/groups` kutambua uanachama wa kikundi au ruhusa zisizotarajiwa.
- Chunguza `/etc/passwd` kutambua uanachama wa kikundi au ruhusa zisizotarajiwa.

Baadhi ya programu pia huzalisha kumbukumbu zake:

- **SSH**: Angalia _\~/.ssh/authorized\_keys_ na _\~/.ssh/known\_hosts_ kwa uhusiano wa mbali usiohalali.
- **Gnome Desktop**: Tazama _\~/.recently-used.xbel_ kwa faili zilizo hivi karibuni kupitia programu za Gnome.
- **Firefox/Chrome**: Angalia historia ya kivinjari na vipakuliwa katika _\~/.mozilla/firefox_ au _\~/.config/google-chrome_ kwa shughuli za shaka.
- **VIM**: Pitia _\~/.viminfo_ kwa maelezo ya matumizi, kama njia za faili zilizotembelewa na historia ya utafutaji.
- **Open Office**: Angalia ufikiaji wa hivi karibuni wa hati ambazo zinaweza kuashiria faili zilizodhuriwa.
- **FTP/SFTP**: Pitia kumbukumbu katika _\~/.ftp\_history_ au _\~/.sftp\_history_ kwa uhamisho wa faili ambao unaweza kuwa usiohalali.
- **MySQL**: Chunguza _\~/.mysql\_history_ kwa kutekelezwa kwa maswali ya MySQL, ikifichua shughuli za usiohalali za database.
- **Less**: Analiza _\~/.lesshst_ kwa historia ya matumizi, ikiwa ni pamoja na faili zilizotazamwa na amri zilizotekelezwa.
- **Git**: Angalia _\~/.gitconfig_ na mradi _.git/logs_ kwa mabadiliko kwenye hazina.

### Kumbukumbu za USB

[**usbrip**](https://github.com/snovvcrash/usbrip) ni programu ndogo iliyoandikwa kwa Python 3 safi ambayo huchambua faili za kumbukumbu za Linux (`/var/log/syslog*` au `/var/log/messages*` kulingana na usambazaji) kwa kujenga meza za historia ya matukio ya USB.

Ni muhimu **kujua USB zote zilizotumiwa** na itakuwa na manufaa zaidi ikiwa una orodha iliyoruhusiwa ya USB za kupata "matukio ya uvunjaji" (matumizi ya USB ambazo hazimo ndani ya orodha hiyo). 

### Usakinishaji
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Mifano
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Zaidi ya mifano na habari ndani ya github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii ya **juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Pitia Akaunti za Mtumiaji na Shughuli za Kuingia

Chunguza _**/etc/passwd**_, _**/etc/shadow**_ na **logs za usalama** kwa majina yasiyo ya kawaida au akaunti zilizoundwa au kutumika karibu na matukio yasiyoruhusiwa yanayojulikana. Pia, angalia mashambulizi ya sudo ya nguvu.\
Zaidi ya hayo, angalia faili kama _**/etc/sudoers**_ na _**/etc/groups**_ kwa mamlaka zisizotarajiwa zilizopewa watumiaji.\
Hatimaye, tafuta akaunti zenye **bila nywila** au nywila **rahisi kudhani**.

## Chunguza Mfumo wa Faili

### Uchambuzi wa Miundo ya Mfumo wa Faili katika Uchunguzi wa Programu Hasidi

Wakati wa kuchunguza matukio ya programu hasidi, muundo wa mfumo wa faili ni chanzo muhimu cha habari, kufunua mfululizo wa matukio na maudhui ya programu hasidi. Hata hivyo, waandishi wa programu hasidi wanatumia mbinu za kuzuia uchambuzi huu, kama vile kubadilisha alama za muda wa faili au kuepuka mfumo wa faili kwa uhifadhi wa data.

Ili kupinga mbinu hizi za kuzuia uchunguzi wa kisasa, ni muhimu:

* **Fanya uchambuzi kamili wa muda** kutumia zana kama **Autopsy** kwa kuonyesha muda wa matukio au **Sleuth Kit's** `mactime` kwa data ya muda ya kina.
* **Chunguza hati za kutarajia** katika $PATH ya mfumo, ambayo inaweza kuwa na hati za shell au PHP zinazotumiwa na wachomaji.
* **Tafuta `/dev` kwa faili za kawaida**, kwani kawaida ina faili maalum, lakini inaweza kuwa na faili zinazohusiana na programu hasidi.
* **Tafuta faili au saraka zilizofichwa** zenye majina kama ".. " (dot dot space) au "..^G" (dot dot control-G), ambayo inaweza kuficha maudhui mabaya.
* **Tambua faili za setuid root** kwa kutumia amri: `find / -user root -perm -04000 -print` Hii inapata faili zenye ruhusa zilizoinuliwa, ambazo zinaweza kutumiwa vibaya na wachomaji.
* **Pitia alama za kufutwa** katika meza za inode ili kutambua kufutwa kwa faili nyingi, ikionyesha uwepo wa rootkits au trojans.
* **Angalia inode za mfululizo** kwa faili za kawaida za kudhuru baada ya kutambua moja, kwani zinaweza kuwekwa pamoja.
* **Chunguza saraka za binary za kawaida** (_/bin_, _/sbin_) kwa faili zilizobadilishwa hivi karibuni, kwani hizi zinaweza kubadilishwa na programu hasidi.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Tafadhali kumbuka kwamba **mshambuliaji** anaweza **kubadilisha** **muda** ili kufanya **faili zionekane** **halali**, lakini hawezi kubadilisha **inode**. Ikiwa utagundua kwamba **faili** inaonyesha kwamba iliumbwa na kubadilishwa kwa **wakati sawa** na faili zingine kwenye folda hiyo hiyo, lakini **inode** ni **kubwa kwa kushangaza**, basi **alama za wakati za faili hiyo zilibadilishwa**.
{% endhint %}

## Linganisha faili za toleo tofauti za mfumo wa faili

### Muhtasari wa Linganisho la Matoleo ya Mfumo wa Faili

Ili kulinganisha matoleo ya mfumo wa faili na kugundua mabadiliko, tunatumia amri za `git diff` zilizorahisishwa:

* **Kutafuta faili mpya**, linganisha saraka mbili:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Kwa maudhui yaliyobadilishwa**, orodhesha mabadiliko ukizingatia mistari maalum:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Kugundua faili zilizofutwa**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Chaguo za Kichuja** (`--diff-filter`) husaidia kupunguza mabadiliko maalum kama vile faili zilizoongezwa (`A`), zilizofutwa (`D`), au zilizobadilishwa (`M`).
* `A`: Faili zilizoongezwa
* `C`: Faili zilizokopiwa
* `D`: Faili zilizofutwa
* `M`: Faili zilizobadilishwa
* `R`: Faili zilizobadilishwa jina
* `T`: Mabadiliko ya aina (k.m., faili kuwa ishara ya alamisho)
* `U`: Faili zisizounganishwa
* `X`: Faili zisizojulikana
* `B`: Faili zilizovunjika

## Marejeo

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Kitabu: Malware Forensics Field Guide for Linux Systems: Mwongozo wa Uchunguzi wa Kidijitali**

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!

* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha **telegram** au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mchakato wa kazi ulioendeshwa na zana za jamii za **juu zaidi** duniani.\
Pata Upatikanaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
