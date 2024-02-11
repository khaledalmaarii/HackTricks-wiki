# Uchunguzi wa Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi zinazotumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kukusanya Taarifa za Awali

### Taarifa Msingi

Kwanza kabisa, ni vyema kuwa na **USB** na **faili za binary na maktaba zinazojulikana vizuri** (unaweza tu kupata ubuntu na kunakili folda _/bin_, _/sbin_, _/lib,_ na _/lib64_), kisha funga USB hiyo, na badilisha mazingira ya mazingira ili kutumia faili hizo za binary:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Baada ya kuweka mfumo kwa kutumia programu tumizi nzuri na zinazojulikana, unaweza kuanza **kuchanganua taarifa za msingi**:
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

Wakati unapata taarifa za msingi, unapaswa kuangalia mambo ya ajabu kama:

* **Mchakato wa Root** kawaida hufanya kazi na PIDS ndogo, kwa hivyo ikiwa utapata mchakato wa Root na PID kubwa, unaweza kuwa na shaka
* Angalia **usajili wa kuingia** kwa watumiaji bila kifaa cha kupokea ndani ya `/etc/passwd`
* Angalia **hashi za nywila** ndani ya `/etc/shadow` kwa watumiaji bila kifaa cha kupokea

### Kumbukumbu ya Kuvuja

Ili kupata kumbukumbu ya mfumo unaoendelea, inashauriwa kutumia [**LiME**](https://github.com/504ensicsLabs/LiME).\
Ili **kuikusanya**, unahitaji kutumia **kernel sawa** ambayo kifaa cha mwathirika kinatumia.

{% hint style="info" %}
Kumbuka kuwa huwezi **kufunga LiME au kitu kingine chochote** kwenye kifaa cha mwathirika kwani itafanya mabadiliko kadhaa kwake.
{% endhint %}

Kwa hivyo, ikiwa una toleo sawa la Ubuntu, unaweza kutumia `apt-get install lime-forensics-dkms`\
Katika hali nyingine, unahitaji kupakua [**LiME**](https://github.com/504ensicsLabs/LiME) kutoka github na kuikusanya na vichwa sahihi vya kernel. Ili **kupata vichwa sahihi vya kernel** vya kifaa cha mwathirika, unaweza tu **nakili saraka** `/lib/modules/<toleo la kernel>` kwenye kifaa chako, na kisha **kuiunda** LiME kwa kutumia vichwa hivyo:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME inasaidia **muundo** 3:

* Raw (kila sehemu imeunganishwa pamoja)
* Padded (sawa na raw, lakini na sifuri kwenye bits za kulia)
* Lime (muundo unaopendekezwa na metadata)

LiME pia inaweza kutumika ku **tuma kumbukumbu kupitia mtandao** badala ya kuihifadhi kwenye mfumo kwa kutumia kitu kama: `path=tcp:4444`

### Picha ya Diski

#### Kuzima

Kwanza kabisa, utahitaji **kuzima mfumo**. Hii sio chaguo zote kwani mara nyingine mfumo utakuwa seva ya uzalishaji ambayo kampuni haiwezi kumudu kuzima.\
Kuna **njia 2** za kuzima mfumo, **kuzima kawaida** na **kuzima kwa kuvuta waya**. Ya kwanza itaruhusu **mchakato kumalizika kama kawaida** na **mfumo wa faili** kuwa **synchronized**, lakini pia itaruhusu **programu hasidi** kuharibu ushahidi. Njia ya "kuvuta waya" inaweza kusababisha **upotevu wa baadhi ya habari** (habari nyingi hazitapotea kwani tayari tumepiga picha ya kumbukumbu) na **programu hasidi haitakuwa na nafasi** ya kufanya chochote kuhusu hilo. Kwa hiyo, ikiwa **una shaka** kuwa kuna **programu hasidi**, tuendeshe **amri ya `sync`** kwenye mfumo na kuvuta waya.

#### Kupiga picha ya diski

Ni muhimu kuzingatia kwamba **kabla ya kuunganisha kompyuta yako kwenye kitu chochote kinachohusiana na kesi**, lazima uhakikishe kuwa itakuwa **imeunganishwa kama soma tu** ili kuepuka kubadilisha habari yoyote.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Uchambuzi wa Awali wa Picha ya Diski

Kuunda nakala ya picha ya diski bila kupoteza data zaidi.
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
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi kwa kutumia zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Tafuta Malware Inayojulikana

### Faili za Mfumo Zilizobadilishwa

Linux inatoa zana za kuhakikisha uadilifu wa sehemu za mfumo, muhimu kwa kutambua faili zenye matatizo.

- **Mifumo ya RedHat**: Tumia `rpm -Va` kwa ukaguzi kamili.
- **Mifumo ya Debian**: `dpkg --verify` kwa uhakiki wa awali, kisha `debsums | grep -v "OK$"` (baada ya kusakinisha `debsums` kwa kutumia `apt-get install debsums`) ili kutambua masuala yoyote.

### Wachunguzi wa Malware/Rootkit

Soma ukurasa ufuatao ili kujifunza kuhusu zana ambazo zinaweza kuwa na manufaa katika kutafuta malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Tafuta programu zilizosakinishwa

Ili kutafuta kwa ufanisi programu zilizosakinishwa kwenye mifumo ya Debian na RedHat, fikiria kutumia magogo na hifadhidata za mfumo pamoja na ukaguzi wa mwongozo kwenye saraka za kawaida.

- Kwa Debian, angalia **_`/var/lib/dpkg/status`_** na **_`/var/log/dpkg.log`_** ili kupata maelezo kuhusu usakinishaji wa pakiti, kutumia `grep` kuchuja habari maalum.

- Watumiaji wa RedHat wanaweza kuuliza hifadhidata ya RPM kwa kutumia `rpm -qa --root=/mntpath/var/lib/rpm` ili kuorodhesha pakiti zilizosakinishwa.

Ili kugundua programu zilizosakinishwa kwa mkono au nje ya mameneja haya ya pakiti, chunguza saraka kama vile **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, na **_`/sbin`_**. Changanya orodha za saraka na amri maalum za mfumo ili kutambua programu zisizohusishwa na pakiti zinazojulikana, kuimarisha utafutaji wako wa programu zote zilizosakinishwa.
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
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** kwa kutumia zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Rudisha Programu Zilizofutwa za Kutekelezwa

Wazia mchakato uliotekelezwa kutoka /tmp/exec na kufutwa. Inawezekana kuzitoa
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Angalia Maeneo ya Kuanza moja kwa moja

### Kazi Zilizopangwa

```html
Scheduled tasks are a common way for programs to run automatically at specific times or intervals. In Linux, scheduled tasks are managed by the cron daemon. To inspect scheduled tasks, you can check the contents of the crontab file for each user.

To view the crontab file for the current user, use the following command:

```bash
crontab -l
```

To view the crontab file for a specific user, use the following command:

```bash
crontab -u <username> -l
```

This will display the scheduled tasks for the specified user. Look for any suspicious or unfamiliar entries that may indicate malicious activity.

Additionally, you can check the system-wide cron configuration files located in the `/etc/cron.d/` and `/etc/cron.daily/` directories. These files contain scheduled tasks that apply to all users on the system.

Inspect the contents of these files using a text editor or the `cat` command:

```bash
cat /etc/cron.d/*
cat /etc/cron.daily/*
```

Again, look for any suspicious or unfamiliar entries.

By inspecting the scheduled tasks, you can identify any potentially malicious programs or scripts that are set to run automatically on the system.
```
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

Njia ambazo programu hasidi inaweza kusakinishwa kama huduma:

- **/etc/inittab**: Inaita skripti za kuanzisha kama vile rc.sysinit, ikielekeza zaidi kwa skripti za kuanzisha.
- **/etc/rc.d/** na **/etc/rc.boot/**: Zina skripti za kuanzisha huduma, ya mwisho ikiwa katika toleo za zamani za Linux.
- **/etc/init.d/**: Inatumika katika toleo fulani za Linux kama Debian kwa kuhifadhi skripti za kuanzisha.
- Huduma pia zinaweza kuwezeshwa kupitia **/etc/inetd.conf** au **/etc/xinetd/**, kulingana na toleo la Linux.
- **/etc/systemd/system**: Daktari kwa skripti za mfumo na meneja wa huduma.
- **/etc/systemd/system/multi-user.target.wants/**: Ina viungo kwa huduma ambazo zinapaswa kuanza katika kiwango cha multi-user.
- **/usr/local/etc/rc.d/**: Kwa huduma za desturi au za tatu.
- **~/.config/autostart/**: Kwa programu za kuanzisha moja kwa moja za mtumiaji, ambayo inaweza kuwa mahali pa kujificha kwa programu hasidi inayolenga mtumiaji.
- **/lib/systemd/system/**: Faili za chaguo-msingi za mfumo kwa pakiti zilizosakinishwa.


### Moduli za Kerneli

Moduli za kerneli za Linux, mara nyingi hutumiwa na programu hasidi kama sehemu za rootkit, zinasakinishwa wakati wa kuanza kwa mfumo. Miongozo na faili muhimu kwa moduli hizi ni pamoja na:

- **/lib/modules/$(uname -r)**: Inashikilia moduli kwa toleo la sasa la kerneli.
- **/etc/modprobe.d**: Ina faili za usanidi za kudhibiti upakiaji wa moduli.
- **/etc/modprobe** na **/etc/modprobe.conf**: Faili za mipangilio ya kawaida ya moduli ya kimataifa.

### Maeneo Mengine ya Kuanzisha Moja kwa Moja

Linux hutumia faili mbalimbali kwa kutekeleza programu kiotomatiki wakati wa kuingia kwa mtumiaji, ambayo inaweza kuwa na programu hasidi:

- **/etc/profile.d/***, **/etc/profile**, na **/etc/bash.bashrc**: Inatekelezwa kwa kuingia kwa mtumiaji yeyote.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile**, na **~/.config/autostart**: Faili za mtumiaji maalum ambazo zinaendesha wakati wa kuingia kwao.
- **/etc/rc.local**: Inatekelezwa baada ya huduma zote za mfumo kuanza, ikionyesha mwisho wa mpito kwenda mazingira ya multiuser.

## Angalia Kumbukumbu

Mifumo ya Linux inafuatilia shughuli za mtumiaji na matukio ya mfumo kupitia faili mbalimbali za kumbukumbu. Kumbukumbu hizi ni muhimu kwa kutambua ufikiaji usiohalali, maambukizo ya programu hasidi, na matukio mengine ya usalama. Kumbukumbu muhimu za kumbukumbu ni pamoja na:

- **/var/log/syslog** (Debian) au **/var/log/messages** (RedHat): Inakamata ujumbe na shughuli za mfumo kwa kiwango cha mfumo mzima.
- **/var/log/auth.log** (Debian) au **/var/log/secure** (RedHat): Inarekodi jaribio la uwakilishi, kuingia kwa mafanikio na kushindwa.
- Tumia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kuchuja matukio muhimu ya uwakilishi.
- **/var/log/boot.log**: Ina ujumbe wa kuanza kwa mfumo.
- **/var/log/maillog** au **/var/log/mail.log**: Inarekodi shughuli za seva ya barua pepe, muhimu kwa kufuatilia huduma zinazohusiana na barua pepe.
- **/var/log/kern.log**: Inahifadhi ujumbe wa kerneli, ikiwa ni pamoja na makosa na onyo.
- **/var/log/dmesg**: Inashikilia ujumbe wa dereva wa kifaa.
- **/var/log/faillog**: Inarekodi jaribio la kuingia lililoshindwa, ikisaidia uchunguzi wa uvunjaji wa usalama.
- **/var/log/cron**: Inarekodi utekelezaji wa kazi za cron.
- **/var/log/daemon.log**: Inafuatilia shughuli za huduma za nyuma.
- **/var/log/btmp**: Inadokumenti jaribio la kuingia lililoshindwa.
- **/var/log/httpd/**: Ina makosa ya Apache HTTPD na kumbukumbu za ufikiaji.
- **/var/log/mysqld.log** au **/var/log/mysql.log**: Inarekodi shughuli za MySQL database.
- **/var/log/xferlog**: Inarekodi uhamisho wa faili za FTP.
- **/var/log/**: Daima angalia kumbukumbu zisizotarajiwa hapa.

{% hint style="info" %}
Kumbukumbu za mfumo za Linux na mfumo wa ukaguzi zinaweza kuwa zimelemazwa au kufutwa katika uvamizi au tukio la programu hasidi. Kwa kuwa kumbukumbu kwenye mifumo ya Linux kwa ujumla zina habari muhimu zaidi kuhusu shughuli za uovu, wavamizi mara kwa mara huwafuta. Kwa hivyo, wakati wa kuchunguza faili za kumbukumbu zilizopo, ni muhimu kutafuta mapengo au kuingia kwa utaratibu ambao unaweza kuwa ishara ya kufutwa au kuharibiwa.
{% endhint %}

**Linux inahifadhi historia ya amri kwa kila mtumiaji**, iliyohifadhiwa katika:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Zaidi ya hayo, amri `last -Faiwx` inatoa orodha ya kuingia kwa mtumiaji. Angalia kwa kuingia kwa mtumiaji asiyejulikana au usiotarajiwa.

Angalia faili ambazo zinaweza kutoa rprivileges ziada:

- Angalia `/etc/sudoers` kwa mamlaka ya mtumiaji ambayo yanaweza kuwa yamepewa bila kutarajiwa.
- Angalia `/etc/sudoers.d/` kwa mamlaka ya mtumiaji ambayo yanaweza kuwa yamepewa bila kutarajiwa.
- Angalia `/etc/groups` ili kutambua uanachama au ruhusa za kikundi zisizo za kawaida.
- Angalia `/etc/passwd` ili kutambua uanachama au ruhusa za kikundi zisizo za kawaida.

Baadhi ya programu pia huzalisha kumbukumbu zao wenyewe:

- **SSH**: Angalia _~/.ssh/authorized_keys_ na _~/.ssh/known_hosts_ kwa uhusiano wa mbali usiohalali.
- **Gnome Desktop**: Tazama _~/.recently-used.xbel_ kwa faili zilizoingiwa hivi karibuni kupitia programu za Gnome.
- **Firefox/Chrome**: Angalia historia ya kivinjari na kupakua katika _~/.mozilla/firefox_ au _~/.config/google-chrome_ kwa shughuli za mashaka.
- **VIM**: Pitia _~/.viminfo_ kwa maelezo ya matumizi, kama njia za faili zilizoingiwa na historia ya utafutaji.
- **Open Office**: Angalia ufikiaji wa hivi karibuni wa hati ambazo zinaweza kuonyesha faili zilizodhulumiwa.
- **FTP/SFTP**: Pitia kumbukumbu katika _~/.ftp_history_ au _~/.sftp_history_ kwa uhamisho wa faili ambao unaweza kuwa usiohalali.
- **MySQL**: Chunguza _~/.mysql_history_ kwa kutekeleza maswali ya MySQL, ambayo inaweza kufunua shughuli zisizo halali za hifadhidata.
- **Less**: Tathmini _~/.lesshst_ kwa historia ya matumizi, ikiwa ni pamoja na faili zilizoonekana na amri zilizotekelezwa.
- **Git**: Angalia _~/.gitconfig_ na mradi _.git/logs_ kwa mabadiliko kwenye hazina.

### Kumbukumbu za USB

[**usbrip**](https://github.com/snovvcrash/usbrip) ni programu ndogo iliyoandikwa kwa Python 3 safi ambayo inachambua faili za kumbukumbu za Linux (`/var/log/syslog*` au `/var/log/messages*` kulingana na distro) kwa kujenga meza za historia ya matukio ya USB.

Ni muhimu kujua **USB zote zilizotumiwa** na itakuwa na manufaa zaidi ikiwa una orodha iliyoidhinishwa ya USB za kutafuta "matukio ya uvunjaji" (matumizi ya USB ambazo hazipo ndani ya orodha hiyo).

### Usakinishaji
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Mifano

#### Example 1: Collecting System Information

#### Mfano 1: Kukusanya Taarifa za Mfumo

To collect system information, you can use the following commands:

Kukusanya taarifa za mfumo, unaweza kutumia amri zifuatazo:

```bash
$ uname -a
$ cat /etc/issue
$ cat /etc/*-release
$ cat /proc/version
$ cat /proc/cpuinfo
$ cat /proc/meminfo
$ df -h
$ mount
$ ps aux
$ netstat -antup
```

#### Example 2: Analyzing Log Files

#### Mfano 2: Kuchambua Faili za Kumbukumbu (Log Files)

To analyze log files, you can use the following commands:

Kuchambua faili za kumbukumbu, unaweza kutumia amri zifuatazo:

```bash
$ cat /var/log/syslog
$ cat /var/log/auth.log
$ cat /var/log/apache2/access.log
$ cat /var/log/apache2/error.log
$ cat /var/log/nginx/access.log
$ cat /var/log/nginx/error.log
$ cat /var/log/mysql/error.log
$ cat /var/log/secure
$ cat /var/log/messages
```

#### Example 3: Examining Network Connections

#### Mfano 3: Kuchunguza Uunganisho wa Mtandao

To examine network connections, you can use the following commands:

Kuchunguza uunganisho wa mtandao, unaweza kutumia amri zifuatazo:

```bash
$ netstat -antup
$ ss -tulwn
$ lsof -i
$ tcpdump -i eth0
$ tcpdump -i any
$ tshark -i eth0
$ tshark -i any
```

#### Example 4: Checking Running Processes

#### Mfano 4: Kuchunguza Mchakato Unaofanya Kazi

To check running processes, you can use the following commands:

Kuchunguza mchakato unaofanya kazi, unaweza kutumia amri zifuatazo:

```bash
$ ps aux
$ top
$ htop
$ pstree
$ lsof -i
```

#### Example 5: Investigating File Permissions

#### Mfano 5: Uchunguzi wa Ruhusa za Faili

To investigate file permissions, you can use the following commands:

Kufanya uchunguzi wa ruhusa za faili, unaweza kutumia amri zifuatazo:

```bash
$ ls -l
$ ls -al
$ find / -perm -4000 2>/dev/null
$ find / -perm -2000 2>/dev/null
$ find / -perm -6000 2>/dev/null
```

#### Example 6: Searching for Sensitive Information

#### Mfano 6: Kutafuta Taarifa Nyeti

To search for sensitive information, you can use the following commands:

Kutafuta taarifa nyeti, unaweza kutumia amri zifuatazo:

```bash
$ grep -i "password" /etc/*.conf
$ grep -i "apikey" /etc/*.conf
$ grep -i "secret" /etc/*.conf
$ grep -i "token" /etc/*.conf
$ grep -i "access_key" /etc/*.conf
$ grep -i "private_key" /etc/*.conf
```
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Mifano zaidi na habari zaidi zinapatikana kwenye github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi kwa kutumia zana za jamii zilizoendelea zaidi duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Angalia Akaunti za Mtumiaji na Shughuli za Kuingia

Chunguza _**/etc/passwd**_, _**/etc/shadow**_ na **kumbukumbu za usalama** kwa majina yasiyo ya kawaida au akaunti zilizoundwa na kutumiwa karibu na matukio yasiyoruhusiwa yanayojulikana. Pia, angalia mashambulizi ya nguvu ya sudo yanayowezekana.\
Zaidi ya hayo, angalia faili kama _**/etc/sudoers**_ na _**/etc/groups**_ kwa mamlaka zisizotarajiwa zilizotolewa kwa watumiaji.\
Hatimaye, tafuta akaunti zisizo na **nywila** au nywila **rahisi kudhani**.

## Angalia Mfumo wa Faili

### Uchambuzi wa Miundo ya Mfumo wa Faili katika Uchunguzi wa Programu Hasidi

Wakati wa kuchunguza matukio ya programu hasidi, muundo wa mfumo wa faili ni chanzo muhimu cha habari, kinachoonyesha mfululizo wa matukio na maudhui ya programu hasidi. Walakini, waandishi wa programu hasidi wanatumia mbinu za kuzuia uchambuzi huu, kama vile kubadilisha alama za wakati wa faili au kuepuka mfumo wa faili kwa uhifadhi wa data.

Ili kupinga mbinu hizi za kuzuia uchunguzi wa kiforensiki, ni muhimu:

- **Fanya uchambuzi kamili wa muda** kwa kutumia zana kama **Autopsy** kwa kuonyesha muda wa matukio au `mactime` ya **Sleuth Kit** kwa data ya muda wa kina.
- **Chunguza hati zisizotarajiwa** katika $PATH ya mfumo, ambayo inaweza kuwa na hati za shell au PHP zinazotumiwa na wadukuzi.
- **Angalia `/dev` kwa faili zisizo za kawaida**, kwani kawaida ina faili maalum, lakini inaweza kuwa na faili zinazohusiana na programu hasidi.
- **Tafuta faili au saraka zilizofichwa** zenye majina kama ".. " (dot dot space) au "..^G" (dot dot control-G), ambazo zinaweza kuficha maudhui mabaya.
- **Tambua faili za setuid root** kwa kutumia amri:
```find / -user root -perm -04000 -print```
Hii inatafuta faili zenye mamlaka ya juu, ambazo zinaweza kutumiwa vibaya na wadukuzi.
- **Pitia alama za kufutwa** katika jedwali za inode ili kugundua kufutwa kwa faili nyingi, ambayo inaweza kuashiria uwepo wa rootkits au trojans.
- **Chunguza inode zinazofuata** kwa faili mbaya karibu baada ya kugundua moja, kwani huenda zimewekwa pamoja.
- **Angalia saraka za binary za kawaida** (_/bin_, _/sbin_) kwa faili zilizobadilishwa hivi karibuni, kwani zinaweza kubadilishwa na programu hasidi.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Tafadhali kumbuka kuwa **mshambuliaji** anaweza **kubadilisha** **wakati** ili kufanya **faili ionekane** **halali**, lakini hawezi kubadilisha **inode**. Ikiwa utagundua kuwa **faili** inaonyesha kuwa imeundwa na kubadilishwa wakati huo huo kama faili zingine katika folda hiyo hiyo, lakini **inode** ni **kubwa kwa kushangaza**, basi **alama za wakati za faili hiyo zilibadilishwa**.
{% endhint %}

## Linganisha faili za toleo tofauti za mfumo wa faili

### Muhtasari wa Linganisho la Toleo la Mfumo wa Faili

Kwa kulinganisha toleo za mfumo wa faili na kubainisha mabadiliko, tunatumia amri za `git diff` zilizorahisishwa:

- **Kutafuta faili mpya**, linganisha saraka mbili:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Kwa maudhui yaliyobadilishwa**, orodhesha mabadiliko bila kuzingatia mistari maalum:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Kutambua faili zilizofutwa**:

To detect deleted files, you can use various techniques in Linux forensics. One common method is to analyze the file system metadata, such as the inode table, to identify any entries that have been marked as deleted. This can be done using tools like `fls` or `icat` from the Sleuth Kit.

Another approach is to search for remnants of deleted files in unallocated space on the disk. Tools like `scalpel` or `foremost` can be used to carve out and recover deleted files based on their file signatures.

Additionally, examining log files, system backups, and temporary directories may provide clues about recently deleted files. Tools like `grep` or `strings` can be used to search for relevant information in these sources.

Remember that the success of file recovery largely depends on the extent of file system activity since the deletion occurred. The longer the time between deletion and investigation, the higher the chances of overwritten data and reduced recoverability.
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Chaguo la kichujio** (`--diff-filter`) husaidia kupunguza mabadiliko maalum kama vile faili zilizoongezwa (`A`), faili zilizofutwa (`D`), au faili zilizobadilishwa (`M`).
- `A`: Faili zilizoongezwa
- `C`: Faili zilizokopiwa
- `D`: Faili zilizofutwa
- `M`: Faili zilizobadilishwa
- `R`: Faili zilizobadilishwa jina
- `T`: Mabadiliko ya aina (kwa mfano, faili kuwa kiungo ishara)
- `U`: Faili zisizounganishwa
- `X`: Faili zisizojulikana
- `B`: Faili zilizovunjika

## Marejeo

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Kitabu: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!

* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi zinazotumia zana za jamii zilizoendelea zaidi ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
