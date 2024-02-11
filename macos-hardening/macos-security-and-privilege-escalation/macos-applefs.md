# macOS AppleFS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Apple Propietary File System (APFS)

**Apple File System (APFS)** ni mfumo wa faili wa kisasa ulioundwa kuchukua nafasi ya Hierarchical File System Plus (HFS+). Maendeleo yake yalichochea hitaji la **utendaji bora, usalama, na ufanisi**.

Baadhi ya sifa muhimu za APFS ni pamoja na:

1. **Kugawana Nafasi**: APFS inaruhusu sehemu nyingi kushiriki **uhifadhi huru sawa** kwenye kifaa kimoja cha kimwili. Hii inawezesha matumizi bora ya nafasi kwani sehemu zinaweza kukua na kupungua kwa urahisi bila hitaji la kubadilisha ukubwa au kugawa upya kwa mikono.
1. Hii inamaanisha, ikilinganishwa na sehemu za jadi kwenye diski za faili, **kwamba kwenye APFS sehemu tofauti (sehemu) zinashiriki nafasi yote ya diski**, wakati sehemu ya kawaida kawaida ilikuwa na ukubwa uliowekwa.
2. **Picha za Haraka**: APFS inasaidia **kuunda picha za haraka**, ambazo ni nakala za mfumo wa faili kwa wakati fulani ambazo ni **soma tu**. Picha za haraka hufanikisha nakala za rudufu zenye ufanisi na kurudisha mfumo kwa urahisi, kwani zinatumia uhifadhi wa ziada kidogo na zinaweza kuundwa au kurudishwa haraka.
3. **Mara mbili**: APFS inaweza **kuunda nakala za faili au saraka ambazo zinashiriki uhifadhi sawa** na asili hadi nakala au faili ya asili inapobadilishwa. Kipengele hiki kinatoa njia yenye ufanisi ya kuunda nakala za faili au saraka bila kuiga nafasi ya uhifadhi.
4. **Ufichaji**: APFS **inasaidia kwa asili uchimbaji kamili wa diski** pamoja na uchimbaji wa faili na saraka kwa kila faili, ikiboresha usalama wa data katika matumizi tofauti.
5. **Ulinzi wa Ajali**: APFS hutumia **mfumo wa meta-data wa nakala-on-kuandika ambao huhakikisha utulivu wa mfumo wa faili** hata katika kesi za kupoteza umeme ghafla au kuzuka kwa mfumo, kupunguza hatari ya uharibifu wa data.

Kwa ujumla, APFS inatoa mfumo wa faili wa kisasa, wenye nguvu, na wenye ufanisi zaidi kwa vifaa vya Apple, ukiwa na lengo la kuboresha utendaji, uaminifu, na usalama.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Kiasi cha `Data` kimeunganishwa katika **`/System/Volumes/Data`** (unaweza kuthibitisha hili kwa kutumia `diskutil apfs list`).

Orodha ya firmlinks inaweza kupatikana katika faili ya **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
Kwenye **kushoto**, kuna njia ya saraka kwenye **kiasi cha Mfumo**, na kwenye **kulia**, njia ya saraka ambapo inaunganisha kwenye **kiasi cha Data**. Kwa hivyo, `/library` --> `/system/Volumes/data/library`
