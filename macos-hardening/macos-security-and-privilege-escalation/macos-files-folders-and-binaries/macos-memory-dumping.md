# Kupata Kumbukumbu za macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vitu vya Kumbukumbu

### Faili za Kubadilishana

Faili za kubadilishana, kama vile `/private/var/vm/swapfile0`, hutumika kama **hifadhi wakati kumbukumbu ya kimwili imejaa**. Wakati hakuna nafasi zaidi katika kumbukumbu ya kimwili, data yake hutiwa kwenye faili ya kubadilishana na kisha hurudishwa kwenye kumbukumbu ya kimwili kama inavyohitajika. Inaweza kuwepo faili nyingi za kubadilishana, zenye majina kama swapfile0, swapfile1, na kadhalika.

### Picha ya Kuhifadhi

Faili iliyo katika eneo la `/private/var/vm/sleepimage` ni muhimu wakati wa **hali ya kulala**. **Data kutoka kwenye kumbukumbu huhifadhiwa kwenye faili hii wakati OS X inalala**. Wakati kompyuta inapoamka, mfumo unapata data ya kumbukumbu kutoka kwenye faili hii, kuruhusu mtumiaji kuendelea pale walipoishia.

Ni muhimu kufahamu kuwa kwenye mifumo ya MacOS ya kisasa, faili hii kwa kawaida imefichwa kwa sababu za usalama, hivyo kufanya kupona kuwa ngumu.

* Ili kuthibitisha ikiwa ufunuo umewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutumika. Hii itaonyesha ikiwa faili imefichwa.

### Kumbukumbu za Shinikizo la Kumbukumbu

Faili nyingine muhimu inayohusiana na kumbukumbu kwenye mifumo ya MacOS ni **kumbukumbu ya shinikizo la kumbukumbu**. Kumbukumbu hizi ziko katika `/var/log` na zina habari za kina kuhusu matumizi ya kumbukumbu ya mfumo na matukio ya shinikizo la kumbukumbu. Zinaweza kuwa na manufaa hasa katika kutambua matatizo yanayohusiana na kumbukumbu au kuelewa jinsi mfumo unavyosimamia kumbukumbu kwa muda.

## Kupata kumbukumbu kwa kutumia osxpmem

Ili kupata kumbukumbu kwenye kifaa cha MacOS, unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Maelekezo yafuatayo yatafanya kazi tu kwa Macs zenye muundo wa Intel. Zana hii sasa imehifadhiwa na toleo la mwisho lilikuwa mwaka 2017. Programu tumizi iliyopakuliwa kwa kutumia maelekezo yaliyotolewa hapa inalenga vifaa vya Intel kwani Apple Silicon haikuwepo mwaka 2017. Inaweza kuwa inawezekana kuunda programu tumizi kwa muundo wa arm64 lakini utalazimika kujaribu mwenyewe.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ikiwa utapata kosa hili: `osxpmem.app/MacPmem.kext haikufanikiwa kupakia - (libkern/kext) kushindwa kwa uthibitisho (umiliki wa faili/ruhusa); angalia magogo ya mfumo/kernel kwa makosa au jaribu kextutil(8)` Unaweza kulitatua kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kurekebishwa kwa **kuruhusu mzigo wa kext** katika "Usalama na Faragha --> Jumla", tu **ruhusu**.

Unaweza pia kutumia **oneliner** hii kupakua programu, kupakia kext na kudump kumbukumbu:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
