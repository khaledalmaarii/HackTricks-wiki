# macOS Memory Dumping

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


## Memory Artifacts

### Swap Files

Faili za kubadilishana, kama `/private/var/vm/swapfile0`, hutumikia kama **cache wakati kumbukumbu ya kimwili imejaa**. Wakati hakuna nafasi zaidi katika kumbukumbu ya kimwili, data yake inahamishwa kwenye faili ya kubadilishana na kisha inarudishwa kwenye kumbukumbu ya kimwili inapohitajika. Faili nyingi za kubadilishana zinaweza kuwepo, zikiwa na majina kama swapfile0, swapfile1, na kadhalika.

### Hibernate Image

Faili iliyoko kwenye `/private/var/vm/sleepimage` ni muhimu wakati wa **hali ya kulala**. **Data kutoka kwenye kumbukumbu huhifadhiwa katika faili hii wakati OS X inalala**. Wakati kompyuta inapoamka, mfumo unapata data ya kumbukumbu kutoka kwenye faili hii, ikiruhusu mtumiaji kuendelea mahali alipoacha.

Inafaa kutajwa kwamba kwenye mifumo ya kisasa ya MacOS, faili hii kwa kawaida imefungwa kwa sababu za usalama, na kufanya urejeleaji kuwa mgumu.

* Ili kuangalia kama usimbaji umewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutumika. Hii itaonyesha kama faili imefungwa.

### Memory Pressure Logs

Faili nyingine muhimu inayohusiana na kumbukumbu katika mifumo ya MacOS ni **kumbukumbu ya shinikizo la kumbukumbu**. Kumbukumbu hizi ziko katika `/var/log` na zina maelezo ya kina kuhusu matumizi ya kumbukumbu ya mfumo na matukio ya shinikizo. Zinweza kuwa na manufaa hasa kwa kutambua matatizo yanayohusiana na kumbukumbu au kuelewa jinsi mfumo unavyosimamia kumbukumbu kwa muda.

## Dumping memory with osxpmem

Ili kutupa kumbukumbu katika mashine ya MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Maelekezo yafuatayo yatatumika tu kwa Macs zenye usanifu wa Intel. Chombo hiki sasa kimehifadhiwa na toleo la mwisho lilikuwa mwaka 2017. Binary iliyopakuliwa kwa kutumia maelekezo hapa chini inalenga chips za Intel kwani Apple Silicon haikuwapo mwaka 2017. Inaweza kuwa inawezekana kukusanya binary kwa usanifu wa arm64 lakini itabidi ujaribu mwenyewe.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ikiwa unakutana na kosa hili: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kulitatua kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kurekebishwa kwa **kuruhusu upakiaji wa kext** katika "Usalama & Faragha --> Kawaida", tu **ruhusu**.

Unaweza pia kutumia hii **oneliner** kupakua programu, kupakia kext na kutupa kumbukumbu: 

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
