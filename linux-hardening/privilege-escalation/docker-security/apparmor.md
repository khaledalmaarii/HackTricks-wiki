# AppArmor

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steelmalware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekening-oorneemings en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteelmalware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

---

## Basiese Inligting

AppArmor is 'n **kernel-verbetering ontwerp om die hulpbronne wat beskikbaar is vir programme deur per-program profiele te beperk**, wat effektief Verpligte Toegangsbeheer (MAC) implementeer deur toegangsbeheer-eienskappe direk aan programme te koppel in plaas van gebruikers. Hierdie stelsel werk deur **profiele in die kernel te laai**, gewoonlik tydens opstart, en hierdie profiele bepaal watter hulpbronne 'n program kan benader, soos netwerkverbindinge, rou sokkeltoegang, en lêertoestemmings.

Daar is twee bedryfsmodusse vir AppArmor-profiels:

- **Afdwingingsmodus**: Hierdie modus dwing aktief die beleide wat binne die profiel gedefinieer is, blokkeer aksies wat hierdie beleide oortree en log enige pogings om dit te breek deur stelsels soos syslog of auditd.
- **Klaagmodus**: Anders as afdwingingsmodus, blokkeer klaagmodus nie aksies wat teen die profiel se beleide ingaan nie. Dit log eerder hierdie pogings as beleidoortredings sonder om beperkings af te dwing.

### Komponente van AppArmor

- **Kernelmodule**: Verantwoordelik vir die afdwinging van beleide.
- **Beleide**: Spesifiseer die reëls en beperkings vir programgedrag en hulpbronbenadering.
- **Parser**: Laai beleide in die kernel vir afdwinging of verslagdoening.
- **Hulpprogramme**: Dit is gebruikersmodusprogramme wat 'n koppelvlak bied vir interaksie met en bestuur van AppArmor.

### Profiele-pad

Apparmor-profiels word gewoonlik gestoor in _**/etc/apparmor.d/**_\
Met `sudo aa-status` sal jy in staat wees om die bineêre lêers te lys wat deur 'n profiel beperk word. As jy die karakter "/" vir 'n punt van die pad van elke gelysde bineêre lêer kan verander, sal jy die naam van die apparmor-profiel binne die genoemde vouer kry.

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

* Om die geaffekteerde uitvoerbare lêer aan te dui, word **absolute paaie en wildcards** toegelaat (vir lêer globbing) vir die spesifisering van lêers.
* Om die toegang aan te dui wat die binêre lêer oor **lêers** sal hê, kan die volgende **toegangsbeheer** gebruik word:
* **r** (lees)
* **w** (skryf)
* **m** (geheuekaart as uitvoerbare lêer)
* **k** (lêer sluiting)
* **l** (skep harde skakels)
* **ix** (om 'n ander program uit te voer met die nuwe program wat beleid erf)
* **Px** (uitvoer onder 'n ander profiel, na skoonmaak van die omgewing)
* **Cx** (uitvoer onder 'n kinderprofiel, na skoonmaak van die omgewing)
* **Ux** (uitvoer onbeperk, na skoonmaak van die omgewing)
* **Veranderlikes** kan in die profiele gedefinieer word en kan van buite die profiel gemanipuleer word. Byvoorbeeld: @{PROC} en @{HOME} (voeg #include \<tunables/global> by die profiel lêer)
* **Weieringsreëls word ondersteun om toelaatreëls te oorskry**.

### aa-genprof

Om maklik te begin met die skep van 'n profiel, kan apparmor jou help. Dit is moontlik om **apparmor die aksies wat deur 'n binêre lêer uitgevoer word, te laat inspekteer en dan te besluit watter aksies jy wil toelaat of weier**.\
Jy hoef net die volgende uit te voer:
```bash
sudo aa-genprof /path/to/binary
```
Dan, in 'n ander konsole, voer al die aksies uit wat die binêre lêer gewoonlik sal uitvoer:
```bash
/path/to/binary -a dosomething
```
Dan, druk in die eerste konsole "**s**" en dui dan in die opgeneemde aksies aan of jy wil ignoreer, toelaat, of watookal. Wanneer jy klaar is, druk "**f**" en die nuwe profiel sal geskep word in _/etc/apparmor.d/path.to.binary_

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
Let daarop dat standaard in 'n geskepte profiel niks toegelaat word nie, dus word alles ontken. Jy sal lyne soos `/etc/passwd r,` moet byvoeg om die binêre lees `/etc/passwd` byvoorbeeld toe te laat.
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

Voorbeeld van **AUDIT** en **DENIED** logboeke vanaf _/var/log/audit/audit.log_ van die uitvoerbare **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Jy kan ook hierdie inligting kry deur:
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

Merk op hoe die profiel **docker-profile** van docker standaard gelaai word:
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
Standaard word die **Apparmor docker-standaardprofiel** gegenereer vanaf [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-standaardprofiel Opsomming**:

* **Toegang** tot alle **netwerke**
* Geen **vermoë** is gedefinieer (Tog sal sommige vermoëns kom vanaf die insluiting van basiese basisreëls, d.w.s. #include \<abstractions/base>)
* **Skryf** na enige **/proc** lêer is **nie toegelaat**
* Ander **subdossiers**/**lêers** van /**proc** en /**sys** word **ontsê** lees/skryf/slot/skakel/uitvoer toegang
* **Monteer** is **nie toegelaat**
* **Ptrace** kan slegs uitgevoer word op 'n proses wat beperk word deur dieselfde **apparmor-profiel**

Sodra jy 'n **docker houer uitvoer**, behoort jy die volgende uitset te sien:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Merk op dat **apparmor selfs bevoegdhede-voorregte sal blokkeer** wat standaard aan die houer toegeken is. Byvoorbeeld, dit sal in staat wees om **toestemming om binne /proc te skryf te blokkeer selfs as die SYS\_ADMIN bevoegdheid toegeken is** omdat die standaard docker apparmor profiel hierdie toegang ontken:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Jy moet **apparmor uitskakel** om sy beperkings te omseil:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Merk op dat standaard **AppArmor** ook **die houer verbied om** van binne af volumes te koppel selfs met SYS\_ADMIN-vermoë.

Merk op dat jy **vermoëns kan byvoeg/verwyder** aan die docker-houer (dit sal steeds beperk word deur beskermingsmetodes soos **AppArmor** en **Seccomp**):

* `--cap-add=SYS_ADMIN` gee `SYS_ADMIN` vermoë
* `--cap-add=ALL` gee alle vermoëns
* `--cap-drop=ALL --cap-add=SYS_PTRACE` laat alle vermoëns val en gee slegs `SYS_PTRACE`

{% hint style="info" %}
Gewoonlik, wanneer jy **vind** dat jy 'n **bevoorregte vermoë** beskikbaar het **binne** 'n **docker**-houer **maar** 'n deel van die **uitbuiting nie werk nie**, sal dit wees omdat docker **apparmor dit voorkom**.
{% endhint %}

### Voorbeeld

(Voorbeeld van [**hier**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Om AppArmor-funksionaliteit te illustreer, het ek 'n nuwe Docker-profiel "mydocker" geskep met die volgende lyn bygevoeg:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Om die profiel te aktiveer, moet ons die volgende doen:
```
sudo apparmor_parser -r -W mydocker
```
Om die profiele te lys, kan ons die volgende bevel gebruik. Die bevel hieronder lys my nuwe AppArmor-profiel.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Soos hieronder getoon, kry ons 'n fout wanneer ons probeer om "/etc/" te verander aangesien die AppArmor-profiel skryftoegang tot "/etc" voorkom.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Omgang1

Jy kan vind watter **apparmor profiel 'n houer** gebruik deur:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Dan kan jy die volgende lyn hardloop om **die presiese profiel wat gebruik word te vind**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Omskip2

**AppArmor is pad-gebaseer**, dit beteken dat selfs al mag dit dalk **lêers binne 'n gids soos** `/proc` **beskerm**, as jy kan **konfigureer hoe die houer uitgevoer gaan word**, kan jy die proc-gids van die gasheer binne **`/host/proc`** **aankoppel** en dit **sal nie meer deur AppArmor beskerm word nie**.

### AppArmor Shebang Omskip

In [**hierdie fout**](https://bugs.launchpad.net/apparmor/+bug/1911431) kan jy 'n voorbeeld sien van hoe **selfs al voorkom jy dat perl met sekere hulpbronne uitgevoer word**, as jy net 'n skalie-skripsie **skep wat** in die eerste lyn **`#!/usr/bin/perl`** **spesifiseer** en jy **voer die lêer direk uit**, sal jy in staat wees om enigiets uit te voer. Byvoorbeeld:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steel-malware** **gekompromiteer** is.

Hul primêre doel van WhiteIntel is om rekening-oorneemings en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteel-malware.

Jy kan hul webwerf besoek en hul enjin vir **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
