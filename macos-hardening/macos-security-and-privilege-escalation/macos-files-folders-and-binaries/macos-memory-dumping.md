# Kudondosha Kumbukumbu za Kumbukumbu za macOS

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

***

## Vitu vya Kumbukumbu

### Faili za Kubadilishana

Faili za kubadilishana, kama vile `/private/var/vm/swapfile0`, hutumika kama **akiba wakati kumbukumbu ya kimwili imejaa**. Wakati hakuna nafasi zaidi katika kumbukumbu ya kimwili, data yake inahamishwa kwenye faili ya kubadilishana na kisha kurudishwa kwenye kumbukumbu ya kimwili kama inavyohitajika. Faili za kubadilishana nyingi zinaweza kuwepo, zenye majina kama swapfile0, swapfile1, na kadhalika.

### Picha ya Kulala

Faili iliyoko katika `/private/var/vm/sleepimage` ni muhimu wakati wa **hali ya kulala**. **Data kutoka kumbukumbu hifadhiwa katika faili hii wakati OS X inalala**. Kwa kuamsha kompyuta, mfumo unapata data ya kumbukumbu kutoka kwenye faili hii, kuruhusu mtumiaji kuendelea pale walipoishia.

Ni muhimu kutambua kwamba kwenye mifumo ya MacOS ya kisasa, faili hii kawaida imefichwa kwa sababu za usalama, hivyo kufanya kupona kuwa ngumu.

* Ili kuthibitisha ikiwa uchawi umewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutumika. Hii itaonyesha ikiwa faili imefichwa.

### Kumbukumbu ya Shinikizo la Kumbukumbu

Faili nyingine muhimu inayohusiana na kumbukumbu kwenye mifumo ya MacOS ni **kumbukumbu ya shinikizo la kumbukumbu**. Kumbukumbu hizi ziko katika `/var/log` na zina taarifa za kina kuhusu matumizi ya kumbukumbu ya mfumo na matukio ya shinikizo. Zinaweza kuwa muhimu hasa kwa kugundua masuala yanayohusiana na kumbukumbu au kuelewa jinsi mfumo unavyosimamia kumbukumbu kwa muda.

## Kudondosha kumbukumbu na osxpmem

Ili kudondosha kumbukumbu kwenye kifaa cha MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Maelezo**: Maelekezo yafuatayo yatafanya kazi tu kwa Macs zenye muundo wa Intel. Zana hii sasa imehifadhiwa na toleo la mwisho lilikuwa mwaka 2017. Binari iliyopakuliwa kwa kutumia maelekezo yaliyotolewa hapa inalenga chips za Intel kwani Apple Silicon haikuwepo mwaka 2017. Inaweza kuwa inawezekana kuchakata binari kwa muundo wa arm64 lakini utalazimika kujaribu mwenyewe.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Kama unapata kosa hili: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kulirekebisha kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kusuluhishwa kwa **kuruhusu mzigo wa kext** katika "Usalama & Faragha --> Jumla", tu **ruhusu**.

Unaweza pia kutumia hii **mistari moja** kupakua programu, kuruhusu kext na kudondosha kumbukumbu:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malwares za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Jifunze & jifanye AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & jifanye GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
