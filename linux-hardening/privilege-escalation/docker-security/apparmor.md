# AppArmor

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

AppArmor is 'n **kernel-verbetering wat ontwerp is om die hulpbronne wat beskikbaar is vir programme te beperk deur middel van per-program profiele**, wat effektief Verpligte Toegangsbeheer (MAC) implementeer deur toegangsbeheerkenmerke direk aan programme te koppel in plaas van aan gebruikers. Hierdie stelsel werk deur profiele in die kernel te laai, gewoonlik tydens opstart, en hierdie profiele bepaal watter hulpbronne 'n program kan benader, soos netwerkverbindinge, rou sokkeltoegang en lêertoestemmings.

Daar is twee bedryfsmodusse vir AppArmor-profiel:

- **Handhawingsmodus**: Hierdie modus dwing aktief die beleide wat binne die profiel gedefinieer is, deur aksies wat hierdie beleide oortree te blokkeer en enige pogings om dit te oortree deur stelsels soos syslog of auditd te log.
- **Klaagmodus**: In teenstelling met handhawingsmodus blokkeer klaagmodus nie aksies wat teen die beleide van die profiel ingaan nie. Dit log eerder hierdie pogings as beleidoortredings sonder om beperkings af te dwing.

### Komponente van AppArmor

- **Kernelmodule**: Verantwoordelik vir die handhawing van beleide.
- **Beleide**: Spesifiseer die reëls en beperkings vir programgedrag en hulpbronbenadering.
- **Parser**: Laai beleide in die kernel vir handhawing of verslagdoening.
- **Hulpprogramme**: Dit is gebruikersmodusprogramme wat 'n koppelvlak bied vir interaksie met en bestuur van AppArmor.

### Profielepad

AppArmor-profiel word gewoonlik gestoor in _**/etc/apparmor.d/**_\
Met `sudo aa-status` kan jy die bineêre lyste wat deur 'n profiel beperk word, lys. As jy die karakter "/" kan verander na 'n punt van die pad van elke gelysde bineêre lêer, sal jy die naam van die apparmor-profiel binne die genoemde vouer verkry.

Byvoorbeeld, 'n **apparmor**-profiel vir _/usr/bin/man_ sal geleë wees in _/etc/apparmor.d/usr.bin.man_

### Opdragte
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Skep 'n profiel

* Om die betrokke uitvoerbare lêer aan te dui, word **absoluut paaie en wildcards** toegelaat (vir lêer globbing) om lêers te spesifiseer.
* Om die toegang wat die binêre lêer oor **lêers** sal hê aan te dui, kan die volgende **toegangsbeheerstellings** gebruik word:
* **r** (lees)
* **w** (skryf)
* **m** (geheuekaart as uitvoerbare lêer)
* **k** (lêer sluiting)
* **l** (skep harde skakels)
* **ix** (om 'n ander program uit te voer met die nuwe program wat beleid erf)
* **Px** (uitvoer onder 'n ander profiel, na skoonmaak van die omgewing)
* **Cx** (uitvoer onder 'n kinderprofiel, na skoonmaak van die omgewing)
* **Ux** (uitvoer sonder beperking, na skoonmaak van die omgewing)
* **Veranderlikes** kan in die profiele gedefinieer word en kan van buite die profiel gemanipuleer word. Byvoorbeeld: @{PROC} en @{HOME} (voeg #include \<tunables/global> by die profiel-lêer in)
* **Verbiedingsreëls word ondersteun om toelaatreëls te oorskryf**.

### aa-genprof

Om maklik 'n profiel te begin skep, kan apparmor jou help. Dit is moontlik om **apparmor die aksies wat deur 'n binêre lêer uitgevoer word te laat ondersoek en dan te besluit watter aksies jy wil toelaat of verbied**.\
Jy hoef net die volgende uit te voer:
```bash
sudo aa-genprof /path/to/binary
```
Dan, in 'n ander konsole, voer al die aksies uit wat die binêre gewoonlik sal uitvoer:
```bash
/path/to/binary -a dosomething
```
Dan, druk "**s**" in die eerste konsole en dui dan aan of jy wil ignoreer, toelaat, of watookal met die opgeneemde aksies. Druk "**f**" as jy klaar is en die nuwe profiel sal geskep word in _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Met die pyltjiesleutels kan jy kies wat jy wil toelaat/weier/watookal
{% endhint %}

### aa-easyprof

Jy kan ook 'n sjabloon van 'n apparmor-profiel van 'n binêre lêer skep met:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Let daarop dat niks standaard toegelaat word in 'n geskepde profiel nie, so alles word ontken. Jy sal lyne soos `/etc/passwd r,` moet byvoeg om die binêre lees `/etc/passwd` byvoorbeeld toe te laat.
{% endhint %}

Jy kan dan die nuwe profiel **afdwing** met
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Wysiging van 'n profiel vanaf logboeke

Die volgende instrument sal die logboeke lees en die gebruiker vra of hy sommige van die opgespoorde verbode aksies wil toelaat:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Deur die pyltjiesleutels te gebruik, kan jy kies wat jy wil toelaat/weier/enigiets
{% endhint %}

### Bestuur van 'n Profiel
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logboeke

Voorbeeld van **AUDIT** en **DENIED** logboeke van die uitvoerbare lêer **`service_bin`** in _/var/log/audit/audit.log_:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Jy kan ook hierdie inligting bekom deur gebruik te maak van:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

Merk op hoe die profiel **docker-profiel** van Docker standaard gelaai word:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Standaard word die **Apparmor docker-default profiel** gegenereer vanaf [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profiel opsomming**:

* **Toegang** tot alle **netwerkverbindings**
* **Geen bevoegdheid** is gedefinieer (Sommige bevoegdhede sal egter kom van die insluiting van basiese basisreëls, d.w.s. #include \<abstractions/base>)
* **Skryf** na enige **/proc** lêer is **nie toegelaat**
* Ander **subdossiers**/**lêers** van /**proc** en /**sys** word **ontken** lees/skryf/vergrendel/skakel/uitvoer toegang
* **Monteer** is **nie toegelaat**
* **Ptrace** kan slegs uitgevoer word op 'n proses wat beperk word deur dieselfde apparmor profiel

Sodra jy 'n **docker houer uitvoer**, behoort jy die volgende uitset te sien:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Let wel dat **apparmor selfs blokkeer bevoegdhede-voorregte** wat aan die houer verleen word. Byvoorbeeld, dit sal in staat wees om **toestemming om binne /proc te skryf te blokkeer selfs as die SYS\_ADMIN bevoegdheid verleen word**, omdat die standaard docker apparmor-profiel hierdie toegang ontken:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Jy moet **apparmor deaktiveer** om sy beperkings te omseil:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Let daarop dat **AppArmor** standaard ook die houer verbied om van binne af vouers te monteer, selfs met die SYS\_ADMIN-vermoë.

Let daarop dat jy **vermoëns** kan **byvoeg/verwyder** aan die docker-houer (dit sal steeds beperk word deur beskermingsmetodes soos **AppArmor** en **Seccomp**):

* `--cap-add=SYS_ADMIN` gee `SYS_ADMIN`-vermoë
* `--cap-add=ALL` gee alle vermoëns
* `--cap-drop=ALL --cap-add=SYS_PTRACE` verwyder alle vermoëns en gee slegs `SYS_PTRACE`

{% hint style="info" %}
Gewoonlik, as jy **vind** dat jy 'n **bevoorregte vermoë** binne 'n **docker**-houer het, maar 'n deel van die **aanval nie werk nie**, sal dit wees omdat docker **apparmor dit voorkom**.
{% endhint %}

### Voorbeeld

(Voorbeeld vanaf [**hier**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Om die AppArmor-funksionaliteit te illustreer, het ek 'n nuwe Docker-profiel "mydocker" geskep met die volgende lyn bygevoeg:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Om die profiel te aktiveer, moet ons die volgende doen:
```
sudo apparmor_parser -r -W mydocker
```
Om die profiele te lys, kan ons die volgende opdrag gebruik. Die opdrag hieronder lys my nuwe AppArmor-profiel.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Soos hieronder getoon, kry ons 'n fout wanneer ons probeer om "/etc/" te verander, aangesien die AppArmor-profiel skryftoegang tot "/etc" voorkom.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Omspring1

Jy kan vind watter **apparmor-profiel 'n houer laat loop** deur die volgende te gebruik:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Dan kan jy die volgende lyn uitvoer om die presiese profiel wat gebruik word te vind:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In die vreemde geval kan jy die apparmor docker-profiel wysig en dit herlaai. Jy kan die beperkings verwyder en dit "omseil".

### AppArmor Docker Omseiling 2

AppArmor is pad-gebaseer, dit beteken dat selfs al beskerm dit dalk lêers binne 'n gids soos `/proc`, as jy kan konfigureer hoe die houer uitgevoer gaan word, kan jy die proc-gids van die gasheer binne `/host/proc` monteer en dit sal nie meer deur AppArmor beskerm word nie.

### AppArmor Shebang Omseiling

In [hierdie fout](https://bugs.launchpad.net/apparmor/+bug/1911431) kan jy 'n voorbeeld sien van hoe selfs al voorkom jy dat perl uitgevoer word met sekere hulpbronne, as jy net 'n skulpskrip skep wat in die eerste lyn **`#!/usr/bin/perl`** spesifiseer en jy voer die lêer direk uit, sal jy in staat wees om enigiets uit te voer. Byvoorbeeld:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
