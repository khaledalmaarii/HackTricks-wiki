# macOS Dirty NIB

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kwa maelezo zaidi kuhusu mbinu hii angalia chapisho la asili kutoka: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Hapa kuna muhtasari:

Faili za NIB, sehemu ya mfumo wa maendeleo wa Apple, zinatumika kwa kufafanua **vipengele vya UI** na mwingiliano wao katika programu. Zinaunda vitu vilivyosanidishwa kama madirisha na vitufe, na hulipwa wakati wa utekelezaji. Ingawa bado zinatumika, Apple sasa inapendekeza matumizi ya Storyboards kwa kuonyesha vizuri mtiririko wa UI.

### Wasiwasi wa Usalama na Faili za NIB
Ni muhimu kuzingatia kuwa **faili za NIB zinaweza kuwa hatari kwa usalama**. Zina uwezo wa **kutekeleza amri za kiholela**, na mabadiliko kwenye faili za NIB ndani ya programu hayazuizi Gatekeeper kutoka kutekeleza programu, hivyo kuwa tishio kubwa.

### Mchakato wa Uingizaji wa Dirty NIB
#### Kuunda na Kuweka Up Faili ya NIB
1. **Usanidi wa Awali**:
- Unda faili mpya ya NIB ukitumia XCode.
- Ongeza kitu kwenye kiolesura, ukiweka darasa lake kuwa `NSAppleScript`.
- Sanidi mali ya awali ya `source` kupitia Atributi za Wakati wa Utekelezaji Zilizofafanuliwa na Mtumiaji.

2. **Kifaa cha Utekelezaji wa Kanuni**:
- Usanidi huu unawezesha kukimbia AppleScript kwa ombi.
- Ingiza kitufe cha kuamsha kitu cha `Apple Script`, kwa kusababisha hasa chaguo la `executeAndReturnError:`.

3. **Jaribio**:
- Apple Script rahisi kwa ajili ya majaribio:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Jaribu kwa kukimbia kwenye kichujio cha XCode na bonyeza kitufe.

#### Kulenga Programu (Mfano: Pages)
1. **Maandalizi**:
- Nakili programu lengwa (k.m., Pages) kwenye saraka tofauti (k.m., `/tmp/`).
- Anzisha programu ili kuepuka matatizo ya Gatekeeper na kuihifadhi kwenye akiba.

2. **Kubadilisha Faili ya NIB**:
- Badilisha faili ya NIB iliyopo (k.m., About Panel NIB) na faili iliyoundwa ya DirtyNIB.

3. **Utekelezaji**:
- Sababisha utekelezaji kwa kuingiliana na programu (k.m., kuchagua kipengee cha menyu ya `About`).

#### Uthibitisho wa Dhana: Kupata Data ya Mtumiaji
- Badilisha AppleScript ili kupata na kuchambua data ya mtumiaji, kama picha, bila idhini ya mtumiaji.

### Mfano wa Kanuni: Faili ya .xib Iliyodhuru
- Pata na ukague [**mfano wa faili ya .xib iliyo dhahiri**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) ambayo inaonyesha utekelezaji wa nambari za kiholela.

### Kukabiliana na Vizuizi vya Kuzindua
- Vizuizi vya Kuzindua vinazuia utekelezaji wa programu kutoka maeneo yasiyotarajiwa (k.m., `/tmp`).
- Inawezekana kutambua programu ambazo hazilindwi na Vizuizi vya Kuzindua na kuzilenga kwa uingizaji wa faili za NIB.

### Kinga za Ziada za macOS
Kuanzia macOS Sonoma na kuendelea, marekebisho ndani ya vifurushi vya Programu yanazuiliwa. Walakini, njia za awali zilijumuisha:
1. Kunakili programu kwenye eneo tofauti (k.m., `/tmp/`).
2. Kubadilisha majina ya saraka ndani ya kifurushi cha programu ili kuepuka kinga za awali.
3. Baada ya kukimbia programu ili kujiandikisha na Gatekeeper, kubadilisha kifurushi cha programu (k.m., kubadilisha MainMenu.nib na Dirty.nib).
4. Kubadilisha majina ya saraka kurudi na kukimbia tena programu ili kutekeleza faili ya NIB iliyoingizwa.

**Kumbuka**: Sasisho za hivi karibuni za macOS zimezuia udanganyifu huu kwa kuzuia marekebisho ya faili ndani ya vifurushi vya programu baada ya akiba ya Gatekeeper, hivyo kufanya udanganyifu huu usifanikiwe.


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
