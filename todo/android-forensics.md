# Android Forensics

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Kifaa kilichofungwa

Ili kuanza kutoa data kutoka kwa kifaa cha Android, lazima kifaa kiwe wazi. Ikiwa kimefungwa unaweza:

* Kuangalia ikiwa kifaa kina ufuatiliaji kupitia USB umewezeshwa.
* Kuangalia kwa shambulio la [smudge](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
* Jaribu na [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Upataji wa Data

Unda [backup ya android kwa kutumia adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) na uitoe kwa kutumia [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Ikiwa kuna ufikiaji wa root au muunganisho wa kimwili kwa interface ya JTAG

* `cat /proc/partitions` (tafuta njia ya kumbukumbu ya flash, kwa ujumla ingizo la kwanza ni _mmcblk0_ na inahusiana na kumbukumbu yote ya flash).
* `df /data` (Gundua ukubwa wa block wa mfumo).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (itekeleze kwa kutumia taarifa zilizokusanywa kutoka kwa ukubwa wa block).

### Kumbukumbu

Tumia Linux Memory Extractor (LiME) kutoa taarifa za RAM. Ni nyongeza ya kernel ambayo inapaswa kupakiwa kupitia adb.

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
