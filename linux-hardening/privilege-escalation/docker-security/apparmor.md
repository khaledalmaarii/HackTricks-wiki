# AppArmor

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

AppArmor ni **uboreshaji wa kernel ulioundwa kuzuia rasilimali zinazopatikana kwa programu kupitia maelezo ya kila programu**, kwa ufanisi kutekeleza Udhibiti wa Upatikanaji wa Lazima (MAC) kwa kuunganisha sifa za udhibiti wa upatikanaji moja kwa moja kwa programu badala ya watumiaji. Mfumo huu hufanya kazi kwa **kupakia maelezo ya kila programu kwenye kernel**, kawaida wakati wa kuanza, na maelezo haya yanadhibiti ni rasilimali gani programu inaweza kupata, kama vile uhusiano wa mtandao, upatikanaji wa soketi za moja kwa moja, na ruhusa za faili.

Kuna njia mbili za uendeshaji kwa maelezo ya kila programu ya AppArmor:

- **Njia ya Utekelezaji**: Njia hii inatekeleza kikamilifu sera zilizoelezwa ndani ya maelezo ya kila programu, kwa kuzuia vitendo vinavyokiuka sera hizi na kurekodi jaribio lolote la kukiuka sera hizo kupitia mifumo kama syslog au auditd.
- **Njia ya Malalamiko**: Tofauti na njia ya utekelezaji, njia ya malalamiko haikatazi vitendo vinavyokwenda kinyume na sera za maelezo ya kila programu. Badala yake, inarekodi majaribio haya kama uvunjaji wa sera bila kutekeleza vizuizi.

### Vipengele vya AppArmor

- **Moduli ya Kernel**: Inahusika na utekelezaji wa sera.
- **Sera**: Zinaeleza sheria na vizuizi kwa tabia ya programu na upatikanaji wa rasilimali.
- **Kisomaji**: Inapakia sera kwenye kernel kwa utekelezaji au taarifa.
- **Zana**: Hizi ni programu za mode ya mtumiaji ambazo zinatoa kiolesura cha kuwasiliana na kusimamia AppArmor.

### Njia za Maelezo ya AppArmor

Maelezo ya AppArmor kawaida hufungwa katika _**/etc/apparmor.d/**_\
Kwa kutumia `sudo aa-status` utaweza kuorodhesha programu ambazo zimezuiliwa na maelezo ya kila programu. Ikiwa unaweza kubadilisha herufi "/" na kipindi cha njia ya kila programu iliyoorodheshwa, utapata jina la maelezo ya AppArmor ndani ya folda iliyotajwa.

Kwa mfano, maelezo ya **AppArmor** kwa _/usr/bin/man_ yatakuwa yamehifadhiwa katika _/etc/apparmor.d/usr.bin.man_

### Amri
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Kuunda wasifu

* Ili kuonyesha faili zilizoathiriwa, **njia kamili na alama za wilcard** zinaruhusiwa (kwa ajili ya kuchagua faili).
* Ili kuonyesha upatikanaji wa faili ambao programu itakuwa nayo, **udhibiti wa upatikanaji** ufuatao unaweza kutumika:
* **r** (kusoma)
* **w** (kuandika)
* **m** (kumbukumbu ya ram kama inayoweza kutekelezwa)
* **k** (kufunga faili)
* **l** (kuunda viungo vya ngumu)
* **ix** (kutekeleza programu nyingine na programu mpya inarithi sera)
* **Px** (kutekeleza chini ya wasifu mwingine, baada ya kusafisha mazingira)
* **Cx** (kutekeleza chini ya wasifu wa mtoto, baada ya kusafisha mazingira)
* **Ux** (kutekeleza bila kizuizi, baada ya kusafisha mazingira)
* **Mipangilio** inaweza kuwekwa katika wasifu na inaweza kubadilishwa kutoka nje ya wasifu. Kwa mfano: @{PROC} na @{HOME} (ongeza #include \<tunables/global> kwenye faili ya wasifu)
* **Sheria za kukataa zinasaidiwa ili kubadilisha sheria za kuruhusu**.

### aa-genprof

Ili kuanza kwa urahisi kuunda wasifu, apparmor inaweza kukusaidia. Ni rahisi kufanya **apparmor ichunguze vitendo vilivyofanywa na programu na kisha kukuruhusu kuamua vitendo gani unataka kuruhusu au kukataa**.\
Unahitaji tu kukimbia:
```bash
sudo aa-genprof /path/to/binary
```
Kisha, katika konsoli tofauti fanya vitendo vyote ambavyo kawaida programu itatekeleza:
```bash
/path/to/binary -a dosomething
```
Kisha, katika konsoli ya kwanza bonyeza "**s**" na kisha katika hatua zilizorekodiwa eleza ikiwa unataka kuzipuuza, kuruhusu, au chochote. Ukimaliza bonyeza "**f**" na wasifu mpya utaundwa katika _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Kwa kutumia mishale unaweza kuchagua unachotaka kuruhusu/kukataa/chochote
{% endhint %}

### aa-easyprof

Unaweza pia kuunda kigezo cha wasifu wa apparmor ya programu ya binary na:
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
Tafadhali kumbuka kuwa kwa chaguo-msingi katika wasifu uliozalishwa hakuna kitu kinachoruhusiwa, kwa hivyo kila kitu kimekataliwa. Utahitaji kuongeza mistari kama `/etc/passwd r,` ili kuruhusu kusoma faili ya binary `/etc/passwd` kwa mfano.
{% endhint %}

Kisha unaweza **kutekeleza** wasifu mpya na
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Kubadilisha wasifu kutoka kwenye magogo

Zana ifuatayo itasoma magogo na kuuliza mtumiaji ikiwa anataka kuruhusu baadhi ya vitendo vilivyopigwa marufuku vilivyogunduliwa:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Kwa kutumia mishale ya kibonyezo unaweza kuchagua unachotaka kuruhusu/kukataa/chochote
{% endhint %}

### Kusimamia Profaili
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Kumbukumbu

Mfano wa kumbukumbu za **AUDIT** na **DENIED** kutoka kwa faili _/var/log/audit/audit.log_ ya programu inayoweza kutekelezwa **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Unaweza pia kupata habari hii kwa kutumia:
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
## Apparmor katika Docker

Tazama jinsi wasifu **docker-profile** wa docker unavyopakiwa kwa chaguo-msingi:
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
Kwa chaguo-msingi, **Profaili ya Apparmor ya docker-default** inatengenezwa kutoka [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Muhtasari wa profaili ya docker-default**:

* **Upatikanaji** wa mtandao wote
* **Uwezo wowote** haujatolewa (Hata hivyo, baadhi ya uwezo utatoka kwa kuingiza sheria za msingi za msingi kama vile #include \<abstractions/base>)
* **Kuandika** kwenye faili yoyote ya **/proc** **hairuhusiwi**
* **Subdirectories**/**faili** nyingine za /**proc** na /**sys** zinaruhusiwa kusoma/kuandika/kufunga/kuunganisha/kutekeleza
* **Kufunga** **hairuhusiwi**
* **Ptrace** inaweza kufanywa tu kwenye mchakato ambao umefungwa na **profaili sawa ya apparmor**

Maranyi unapo **kuanzisha chombo cha docker**, unapaswa kuona matokeo yafuatayo:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Tafadhali kumbuka kuwa **apparmor itazuia hata uwezo wa ruhusa** uliopewa kontena kwa chaguo-msingi. Kwa mfano, itaweza **kuzuia ruhusa ya kuandika ndani ya /proc hata kama uwezo wa SYS\_ADMIN umepewa** kwa sababu ya profaili ya apparmor ya docker kukataa ufikiaji huu kwa chaguo-msingi:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Unahitaji **kulemaza apparmor** ili kuepuka vizuizi vyake:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Tafadhali kumbuka kwamba kwa chaguo-msingi **AppArmor** pia itakataza kontena kufunga folda kutoka ndani hata na uwezo wa SYS\_ADMIN.

Tafadhali kumbuka unaweza **kuongeza/kuondoa** uwezo kwa kontena ya docker (hii itakuwa bado imezuiliwa na njia za ulinzi kama **AppArmor** na **Seccomp**):

* `--cap-add=SYS_ADMIN` itaongeza uwezo wa `SYS_ADMIN`
* `--cap-add=ALL` itaongeza uwezo wote
* `--cap-drop=ALL --cap-add=SYS_PTRACE` itaondoa uwezo wote na kuongeza tu `SYS_PTRACE`

{% hint style="info" %}
Kawaida, unapogundua kuwa una uwezo wa **kipekee** uliopo **ndani** ya kontena ya **docker** lakini sehemu fulani ya shambulio haifanyi kazi, hii itakuwa kwa sababu **apparmor ya docker itazuia**.
{% endhint %}

### Mfano

(Mfano kutoka [**hapa**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Ili kuelezea utendaji wa AppArmor, niliumba maelezo mapya ya Docker "mydocker" na mstari ufuatao uliongezwa:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Kuamsha wasifu, tunahitaji kufanya yafuatayo:
```
sudo apparmor_parser -r -W mydocker
```
Kuorodhesha maelezo ya profaili, tunaweza kutumia amri ifuatayo. Amri hapa chini inaorodhesha maelezo ya profaili yangu mpya ya AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Kama inavyoonekana hapa chini, tunapata kosa tunapojaribu kubadilisha "/etc/" kwani maelezo ya AppArmor yanazuia ufikiaji wa kuandika kwenye "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Kupita1

Unaweza kupata **profaili ya apparmor inayotumika kwenye kontena** kwa kutumia:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Kisha, unaweza kukimbia mstari ufuatao ili **kupata maelezo sahihi ya profile inayotumiwa**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Katika kesi ya ajabu unaweza **kubadilisha maelezo ya apparmor ya docker na kuirudisha tena.** Unaweza kuondoa vizuizi na "kuvuka" vizuizi hivyo.

### Kuvuka AppArmor ya Docker 2

**AppArmor inategemea njia**, hii inamaanisha kwamba hata kama inaweza **kulinda** faili ndani ya saraka kama **`/proc`** ikiwa unaweza **kuweka jinsi chombo cha kudhibitiwa kitakavyotekelezwa**, unaweza **kufunga** saraka ya proc ya mwenyeji ndani ya **`/host/proc`** na haitalindwa tena na AppArmor.

### Kuvuka Shebang ya AppArmor

Katika [**mdudu huu**](https://bugs.launchpad.net/apparmor/+bug/1911431) unaweza kuona mfano wa jinsi **hata kama unazuia perl kutumika na rasilimali fulani**, ikiwa tu unatengeneza script ya shell **ukiainisha** kwenye mstari wa kwanza **`#!/usr/bin/perl`** na **kutekeleza faili moja kwa moja**, utaweza kutekeleza chochote unachotaka. Kwa mfano:
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
