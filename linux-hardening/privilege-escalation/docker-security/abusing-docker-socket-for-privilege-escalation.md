# Kufanya Matumizi Mabaya ya Docker Socket kwa Kupandisha Hadhi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Kuna nyakati ambapo una **upatikanaji wa soketi ya docker** na unataka kuitumia ku **pandisha hadhi**. Baadhi ya vitendo vinaweza kuwa vya kushuku sana na unaweza kutaka kuviepuka, hivyo hapa unaweza kupata bendera tofauti ambazo zinaweza kuwa na manufaa kwa kupandisha hadhi:

### Kupitia kufunga

Unaweza **kufunga** sehemu tofauti za **mfumo wa faili** kwenye kontena linaloendeshwa kama root na **kuzifikia**.\
Pia unaweza **kufanya matumizi mabaya ya kufunga ili kupandisha hadhi** ndani ya kontena.

* **`-v /:/host`** -> Funga mfumo wa faili wa mwenyeji kwenye kontena ili uweze **kusoma mfumo wa faili wa mwenyeji.**
* Ikiwa unataka **kuwa kama wewe uko kwenye mwenyeji** lakini ukiwa kwenye kontena unaweza kulemaza vifaa vingine vya ulinzi kwa kutumia bendera kama:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Hii ni sawa na njia iliyotangulia, lakini hapa tunafanya **kufunga diski ya kifaa**. Kisha, ndani ya kontena endesha `mount /dev/sda1 /mnt` na unaweza **kufikia** mfumo wa faili wa **mwenyeji** kwenye `/mnt`
* Endesha `fdisk -l` kwenye mwenyeji ili kupata kifaa cha `</dev/sda1>` cha kufunga
* **`-v /tmp:/host`** -> Ikiwa kwa sababu fulani unaweza **kufunga tu saraka fulani** kutoka kwenye mwenyeji na una upatikanaji ndani ya mwenyeji. Funga na uunde **`/bin/bash`** na **suid** kwenye saraka iliyofungwa ili uweze **kuitekeleza kutoka kwenye mwenyeji na kupandisha hadhi hadi root**.

{% hint style="info" %}
Tafadhali kumbuka kuwa labda huwezi kufunga saraka `/tmp` lakini unaweza kufunga saraka **nyingine inayoweza kuandikwa**. Unaweza kupata saraka zinazoweza kuandikwa kwa kutumia: `find / -writable -type d 2>/dev/null`

**Tafadhali kumbuka kuwa sio saraka zote kwenye mashine ya Linux zitasaidia biti ya suid!** Ili kuchunguza ni saraka zipi zinasaidia biti ya suid, endesha `mount | grep -v "nosuid"` Kwa mfano kawaida `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` na `/var/lib/lxcfs` hazisaidii biti ya suid.

Pia kumbuka kuwa ikiwa unaweza **kufunga `/etc`** au saraka nyingine yoyote **yenye faili za usanidi**, unaweza kuzibadilisha kutoka kwenye kontena ya docker kama root ili **kuzitumia vibaya kwenye mwenyeji** na kupandisha hadhi (labda kwa kubadilisha `/etc/shadow`)
{% endhint %}

### Kutoroka kutoka kwenye kontena

* **`--privileged`** -> Kwa bendera hii unatoa [kizuizi chote kutoka kwenye kontena](docker-privileged.md#what-affects). Angalia mbinu za [kutoroka kutoka kwenye kontena zenye kizuizi kama root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Ili [pandisha hadhi kwa kufanya matumizi mabaya ya uwezo](../linux-capabilities.md), **tolea uwezo huo kwa kontena** na lemaza njia nyingine za ulinzi ambazo zinaweza kuzuia shambulio kufanya kazi.

### Curl

Katika ukurasa huu tumegusia njia za kupandisha hadhi kwa kutumia bendera za docker, unaweza kupata **njia za kufanya matumizi mabaya ya njia hizi kwa kutumia amri ya curl** kwenye ukurasa:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
