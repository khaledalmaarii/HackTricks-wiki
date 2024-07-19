# Abusing Docker Socket for Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Kuna nyakati fulani ambapo una **ufikiaji wa docker socket** na unataka kuutumia ili **kuinua mamlaka**. Vitendo vingine vinaweza kuwa vya kutatanisha na unaweza kutaka kuvikwepa, hivyo hapa unaweza kupata bendera tofauti ambazo zinaweza kuwa na manufaa katika kuinua mamlaka:

### Via mount

Unaweza **kuweka** sehemu tofauti za **filesystem** katika kontena linaloendesha kama root na **kuzipata**.\
Pia unaweza **kudhulumu mount ili kuinua mamlaka** ndani ya kontena.

* **`-v /:/host`** -> Weka filesystem ya mwenyeji katika kontena ili uweze **kusoma filesystem ya mwenyeji.**
* Ikiwa unataka **kujisikia kama uko kwenye mwenyeji** lakini ukiwa kwenye kontena unaweza kuzima mitambo mingine ya ulinzi kwa kutumia bendera kama:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Hii ni sawa na njia ya awali, lakini hapa tuna **weka diski ya kifaa**. Kisha, ndani ya kontena endesha `mount /dev/sda1 /mnt` na unaweza **kupata** **filesystem ya mwenyeji** katika `/mnt`
* Endesha `fdisk -l` kwenye mwenyeji ili kupata kifaa `</dev/sda1>` cha kuweka
* **`-v /tmp:/host`** -> Ikiwa kwa sababu fulani unaweza **kweka tu directory fulani** kutoka kwa mwenyeji na una ufikiaji ndani ya mwenyeji. Weka na unda **`/bin/bash`** yenye **suid** katika directory iliyowekwa ili uweze **kuitekeleza kutoka kwa mwenyeji na kuinua hadi root**.

{% hint style="info" %}
Kumbuka kwamba huenda usiweze kuweka folda `/tmp` lakini unaweza kuweka **folda nyingine inayoweza kuandikwa**. Unaweza kupata directories zinazoweza kuandikwa kwa kutumia: `find / -writable -type d 2>/dev/null`

**Kumbuka kwamba si directories zote katika mashine ya linux zitasaidia suid bit!** Ili kuangalia ni zipi zinasaidia suid bit endesha `mount | grep -v "nosuid"` Kwa mfano kawaida `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` na `/var/lib/lxcfs` hazisaidii suid bit.

Kumbuka pia kwamba ikiwa unaweza **kweka `/etc`** au folda nyingine yoyote **iliyokuwa na faili za usanidi**, unaweza kuzibadilisha kutoka kwa kontena la docker kama root ili **uzitumie kwenye mwenyeji** na kuinua mamlaka (labda kubadilisha `/etc/shadow`)
{% endhint %}

### Escaping from the container

* **`--privileged`** -> Kwa bendera hii un [ondoa kila ulinzi kutoka kwa kontena](docker-privileged.md#what-affects). Angalia mbinu za [kutoroka kutoka kwa kontena zenye mamlaka kama root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Ili [kuinua kwa kudhulumu uwezo](../linux-capabilities.md), **pata uwezo huo kwa kontena** na uzime njia nyingine za ulinzi ambazo zinaweza kuzuia exploit kufanya kazi.

### Curl

Katika ukurasa huu tumajadili njia za kuinua mamlaka kwa kutumia bendera za docker, unaweza kupata **njia za kudhulumu mbinu hizi kwa kutumia amri ya curl** katika ukurasa:

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
