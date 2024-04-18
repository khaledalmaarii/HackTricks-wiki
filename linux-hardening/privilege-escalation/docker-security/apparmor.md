# AppArmor

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

---

## Taarifa Msingi

AppArmor ni **uboreshaji wa kernel ulioundwa kuzuia rasilimali zilizopo kwa programu kupitia maelezo ya programu, kutekeleza Udhibiti wa Kufikia wa Lazima (MAC) kwa kuunganisha sifa za kudhibiti upatikanaji moja kwa moja kwa programu badala ya watumiaji.** Mfumo huu hufanya kazi kwa **kupakia maelezo ya programu kwenye kernel**, kawaida wakati wa kuanza, na maelezo haya yanadhibiti ni rasilimali gani programu inaweza kupata, kama vile uhusiano wa mtandao, ufikiaji wa soketi za moja kwa moja, na ruhusa za faili.

Kuna njia mbili za uendeshaji kwa maelezo ya AppArmor:

- **Hali ya Utekelezaji**: Hali hii inatekeleza sera zilizoelezwa ndani ya maelezo, kuzuia vitendo vinavyokiuka sera hizi na kuingiza jaribio lolote la kukiuka kupitia mifumo kama syslog au auditd.
- **Hali ya Malalamiko**: Tofauti na hali ya utekelezaji, hali ya malalamiko haikatazi vitendo vinavyokwenda kinyume na sera za maelezo. Badala yake, inaingiza jaribio hizi kama uvunjaji wa sera bila kutekeleza vizuizi.

### Vipengele vya AppArmor

- **Moduli ya Kernel**: Inayowajibika kwa utekelezaji wa sera.
- **Sera**: Hufafanua sheria na vizuizi kwa tabia ya programu na ufikiaji wa rasilimali.
- **Mchambuzi**: Hupakia sera kwenye kernel kwa utekelezaji au kuripoti.
- **Zana**: Hizi ni programu za mode ya mtumiaji zinazotoa kiolesura cha kuingiliana na kusimamia AppArmor.

### Njia za Maelezo

Maelezo ya Apparmor kawaida hufutwa katika _**/etc/apparmor.d/**_\
Kwa `sudo aa-status` utaweza kuorodhesha programu ambazo zinazuiliwa na maelezo fulani. Ikiwa unaweza kubadilisha herufi "/" kwa mshale wa njia ya kila programu iliyoorodheshwa na utapata jina la maelezo ya apparmor ndani ya folda iliyotajwa.

Kwa mfano, maelezo ya **apparmor** kwa _/usr/bin/man_ yatakuwa yamehifadhiwa katika _/etc/apparmor.d/usr.bin.man_

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

* Ili kuelezea kielelezo kilichoathiriwa, **njia kamili na manyoya** huruhusiwa (kwa ajili ya kufanya mchanganyiko wa faili) kwa kufafanua faili.
* Ili kuelezea ufikiaji ambao programu ya binary itakuwa nayo juu ya **faili** inaweza kutumika **udhibiti wa ufikiaji** zifuatazo:
  * **r** (soma)
  * **w** (andika)
  * **m** (ramani ya kumbukumbu kama inayoweza kutekelezwa)
  * **k** (kufunga faili)
  * **l** (kuunda viungo vya ngumu)
  * **ix** (kutekeleza programu nyingine na programu mpya kurithi sera)
  * **Px** (kutekeleza chini ya wasifu mwingine, baada ya kusafisha mazingira)
  * **Cx** (kutekeleza chini ya wasifu wa mtoto, baada ya kusafisha mazingira)
  * **Ux** (kutekeleza bila kizuizi, baada ya kusafisha mazingira)
* **Viarasa** vinaweza kutajwa katika maelezo na vinaweza kubadilishwa kutoka nje ya wasifu. Kwa mfano: @{PROC} na @{HOME} (ongeza #include \<tunables/global> kwenye faili ya wasifu)
* **Mipangilio ya kukataa inasaidia kubadilisha viarasa vya kuruhusu**.

### aa-genprof

Ili kuanza kwa urahisi kuunda wasifu, apparmor inaweza kukusaidia. Ni rahisi kufanya **apparmor ichunguze vitendo vilivyofanywa na binary na kisha kuruhusu au kukataa vitendo unavyotaka**.\
Unachohitaji kufanya ni kukimbia:
```bash
sudo aa-genprof /path/to/binary
```
Kisha, kwenye konsoli tofauti fanya vitendo vyote ambavyo kawaida binary itafanya:
```bash
/path/to/binary -a dosomething
```
Kisha, kwenye konsoli ya kwanza bonyeza "**s**" na kisha kwenye hatua zilizorekodiwa eleza ikiwa unataka kupuuza, kuruhusu, au chochote. Ukimaliza bonyeza "**f**" na wasifu mpya utaundwa katika _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Kwa kutumia mishale unaweza kuchagua unachotaka kuruhusu/kukataa/chochote
{% endhint %}

### aa-easyprof

Unaweza pia kuunda kiolezo cha wasifu wa apparmor wa binary kwa:
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
Tafadhali elewa kwamba kwa chaguo-msingi katika wasifu ulioundwa hakuna kitu kilichoruhusiwa, kwa hivyo kila kitu kimekataliwa. Utahitaji kuongeza mistari kama `/etc/passwd r,` kuruhusu kusoma faili ya binary `/etc/passwd` kwa mfano.
{% endhint %}

Unaweza kisha **kuimarisha** wasifu mpya na
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Kubadilisha wasifu kutoka kwenye magogo

Zana ifuatayo itasoma magogo na kuuliza mtumiaji ikiwa anataka kuruhusu baadhi ya vitendo vilivyopigwa marufuku vilivyogunduliwa:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Kwa kutumia mishale unaweza kuchagua unachotaka kuruhusu/kukataa/au chochote
{% endhint %}

### Kusimamia Wasifu
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Ripoti

Mfano wa **AUDIT** na **DENIED** ripoti kutoka _/var/log/audit/audit.log_ ya programu inayoweza kutekelezwa **`service_bin`**:
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

Tafadhali angalia jinsi wasifu **docker-profile** wa docker unavyopakiwa kwa chaguo-msingi:
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
Kwa chaguo-msingi **Profaili ya Apparmor ya docker-default** inatengenezwa kutoka [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Muhtasari wa Profaili ya docker-default**:

- **Upatikanaji** wa mtandao wote
- **Uwezo wowote** haujatambuliwa (Hata hivyo, baadhi ya uwezo utatoka kwa kuingiza sheria za msingi kama vile #include \<abstractions/base>)
- **Kuandika** kwenye faili yoyote ya **/proc** **hairuhusiwi**
- **Vidirisha vingine**/**faili** vya /**proc** na /**sys** vinaruhusiwa kusoma/kuandika/kufunga/kuunganisha/kutekeleza
- **Kufunga** **hairuhusiwi**
- **Ptrace** inaweza kufanywa kwenye mchakato ambao umefungwa na **profaili ile ile ya apparmor**

Maranyingi **unapoendesha chombo cha docker** unapaswa kuona matokeo yafuatayo:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Tafadhali elewa kwamba **apparmor itazuia hata uwezo wa ruhusa** uliopewa kontena kwa chaguo-msingi. Kwa mfano, itaweza **kuzuia ruhusa ya kuandika ndani ya /proc hata kama uwezo wa SYS\_ADMIN umepewa** kwa sababu kwa chaguo-msingi, wasifu wa apparmor wa docker unakataa ufikiaji huu:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Unahitaji **kulemaza apparmor** ili kupita vizuizi vyake:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Tafadhali kumbuka kwamba kwa chaguo-msingi **AppArmor** pia **itazuia kontena kufanya uwezo wa kufunga** folda kutoka ndani hata na uwezo wa SYS\_ADMIN.

Tafadhali kumbuka unaweza **kuongeza/kuondoa** **uwezo** kwa kontena ya docker (hii bado itazuiliwa na njia za ulinzi kama **AppArmor** na **Seccomp**):

- `--cap-add=SYS_ADMIN` inatoa uwezo wa `SYS_ADMIN`
- `--cap-add=ALL` inatoa uwezo wote
- `--cap-drop=ALL --cap-add=SYS_PTRACE` inaondoa uwezo wote na kutoa tu `SYS_PTRACE`

{% hint style="info" %}
Kawaida, unapopata kwamba una **uwezo wa kipekee** uliopo **ndani** ya **kontena ya docker** lakini sehemu fulani ya **kudukua haifanyi kazi**, hii ni kwa sababu **apparmor ya docker itakuwa inazuia**.
{% endhint %}

### Mfano

(Mfano kutoka [**hapa**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Ili kufafanua utendaji wa AppArmor, niliunda wasifu mpya wa Docker "mydocker" na mstari ufuatao uliongezwa:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Ili kuamsha wasifu, tunahitaji kufanya yafuatayo:
```
sudo apparmor_parser -r -W mydocker
```
Kutaja maelezo, tunaweza kutumia amri ifuatayo. Amri hapa chini inataja maelezo yangu ya AppArmor mpya.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Kama inavyoonekana hapa chini, tunapata kosa tunapojaribu kubadilisha "/etc/" kwani wasifu wa AppArmor unazuia ufikiaji wa kuandika kwenye "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Kizuizi cha AppArmor cha Docker Bypass1

Unaweza kupata ni **wasifu wa apparmor unaoendesha kontena** kwa kutumia:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Kisha, unaweza kukimbia mstari ufuatao **kupata wasifu sahihi unao tumika**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Katika kesi ya ajabu unaweza **kurekebisha wasifu wa apparmor wa docker na kuuweka upya.** Unaweza kuondoa vizuizi na "kuvuka" yao.

### Kuvuka AppArmor ya Docker2

**AppArmor inategemea njia**, hii inamaanisha hata kama inaweza **kulinda** faili ndani ya saraka kama **`/proc`** ikiwa unaweza **kuweka jinsi kontena itakavyotekelezwa**, unaweza **kufunga** saraka ya proc ya mwenyeji ndani ya **`/mwenyeji/proc`** na **hakitakuwa tena kilinziwa na AppArmor**.

### Kuvuka Shebang ya AppArmor

Katika [**kosa hili**](https://bugs.launchpad.net/apparmor/+bug/1911431) unaweza kuona mfano wa jinsi **hata kama unazuia perl kutumika na rasilimali fulani**, ikiwa tu unajenga script ya shel **ukiainisha** kwenye mstari wa kwanza **`#!/usr/bin/perl`** na **utekelezi faili moja kwa moja**, utaweza kutekeleza chochote unachotaka. K.m.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao kwa **bure** kwa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
