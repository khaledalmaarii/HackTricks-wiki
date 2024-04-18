# Kudondosha Kumbukumbu za Kumbukumbu za macOS

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za wizi wa habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

---

## Vitu vya Kumbukumbu

### Faili za Kubadilishana

Faili za kubadilishana, kama vile `/private/var/vm/swapfile0`, hutumika kama **cache wakati kumbukumbu ya kimwili imejaa**. Wakati hakuna nafasi tena kwenye kumbukumbu ya kimwili, data yake inahamishwa kwenye faili ya kubadilishana na kisha kurudishwa kwenye kumbukumbu ya kimwili kama inavyohitajika. Inaweza kuwepo faili nyingi za kubadilishana, zenye majina kama swapfile0, swapfile1, na kadhalika.

### Picha ya Kulala

Faili iliyoko kwenye `/private/var/vm/sleepimage` ni muhimu wakati wa **hali ya kulala**. **Data kutoka kumbukumbu inahifadhiwa kwenye faili hii wakati OS X inalala**. Kwa kuamsha kompyuta, mfumo unapata data ya kumbukumbu kutoka kwenye faili hii, kuruhusu mtumiaji kuendelea pale walipoishia.

Ni muhimu kutambua kwamba kwenye mifumo ya MacOS ya kisasa, faili hii kawaida imefichwa kwa sababu za usalama, ikifanya kupona kuwa ngumu.

* Ili kuthibitisha ikiwa uchawi umewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutumika. Hii itaonyesha ikiwa faili imefichwa.

### Kumbukumbu za Shinikizo la Kumbukumbu

Faili nyingine muhimu inayohusiana na kumbukumbu kwenye mifumo ya MacOS ni **kumbukumbu za shinikizo la kumbukumbu**. Kumbukumbu hizi ziko katika `/var/log` na zina habari za kina kuhusu matumizi ya kumbukumbu ya mfumo na matukio ya shinikizo. Zinaweza kuwa muhimu hasa kwa kugundua masuala yanayohusiana na kumbukumbu au kuelewa jinsi mfumo unavyosimamia kumbukumbu kwa muda.

## Kudondosha kumbukumbu na osxpmem

Ili kudondosha kumbukumbu kwenye kompyuta ya MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Maelezo**: Maelekezo yafuatayo yatafanya kazi kwa Macs zenye muundo wa Intel tu. Zana hii sasa imehifadhiwa na toleo la mwisho lilikuwa mwaka 2017. Binari iliyopakuliwa kwa kutumia maelekezo yaliyotolewa hapa inalenga chips za Intel kwani Apple Silicon haikuwepo mwaka 2017. Inaweza kuwa inawezekana kuchakata binari kwa muundo wa arm64 lakini utalazimika kujaribu mwenyewe.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ikiwa unapata kosa hili: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kulitatua kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kusuluhishwa kwa **kuruhusu mzigo wa kext** katika "Usalama & Faragha --> Jumla", tu **ruhusu**.

Unaweza pia kutumia hii **oneliner** kupakua programu, kuruhusu kext na kudondosha kumbukumbu:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malwares za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

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
