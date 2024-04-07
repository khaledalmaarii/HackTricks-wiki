# Matumizi Mabaya ya Wasakinishaji wa macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi za Pkg

Makala ya macOS **pakiti ya wasakinishaji** (inayojulikana pia kama faili ya `.pkg`) ni muundo wa faili unaotumiwa na macOS kwa **kugawa programu**. Faili hizi ni kama **sanduku linaloleta kila kitu ambacho programu** inahitaji kusakinisha na kukimbia kwa usahihi.

Faili ya pakiti yenyewe ni nyaraka inayoshikilia **hiraki ya faili na saraka ambazo zitasakinishwa kwenye** kompyuta ya lengo. Inaweza pia kujumuisha **maandishi** kutekeleza kazi kabla na baada ya usakinishaji, kama vile kuweka faili za usanidi au kusafisha toleo za zamani za programu.

### Hiraki

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Usambazaji (xml)**: Kubinafsisha (jina, maandishi ya kukaribisha...) na maandishi/vipimo vya usakinishaji
* **PackageInfo (xml)**: Taarifa, mahitaji ya usakinishaji, mahali pa usakinishaji, njia za maandishi za kukimbia
* **Bili ya vifaa (bom)**: Orodha ya faili za kusakinisha, kuboresha au kuondoa na ruhusa za faili
* **Mzigo (CPIO nyaraka gzip zilizosongwa)**: Faili za kusakinisha kwenye `mahali-pakinishi` kutoka PackageInfo
* **Maandishi (CPIO nyaraka gzip zilizosongwa)**: Maandishi kabla na baada ya usakinishaji na rasilimali zaidi zilizochimbuliwa kwenye saraka ya muda kwa utekelezaji.
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Ili kuona maudhui ya programu ya usakinishaji bila kuidondoa kwa mkono unaweza kutumia zana ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Taarifa Msingi za DMG

Faili za DMG, au Picha za Diski za Apple, ni muundo wa faili unaotumiwa na macOS ya Apple kwa picha za diski. Faili ya DMG ni **picha ya diski inayoweza kufungwa** (ina mifumo yake ya faili) ambayo ina data ya block ya ghafi mara nyingi imepakwa na wakati mwingine imefichwa. Unapofungua faili ya DMG, macOS **inaifunga kama vile ingekuwa diski halisi**, kuruhusu kupata maudhui yake.

### Hierarchy

<figure><img src="../../../.gitbook/assets/image (222).png" alt=""><figcaption></figcaption></figure>

Utaratibu wa faili ya DMG unaweza kutofautiana kulingana na maudhui. Hata hivyo, kwa DMGs za programu, kawaida inafuata muundo huu:

* Kiwango cha Juu: Hii ni mzizi wa picha ya diski. Mara nyingi ina programu na labda kiungo kwa folda ya Maombi.
* Maombi (.app): Hii ni programu halisi. Katika macOS, programu ni kawaida pakiti inayojumuisha faili na folda nyingi zinazounda programu.
* Kiungo cha Maombi: Hii ni mkato kwa folda ya Maombi katika macOS. Lengo la hili ni kukufanya iwe rahisi kusakinisha programu. Unaweza kuburuta faili ya .app kwenye mkato huu kusakinisha programu.

## Privesc kupitia unyanyasaji wa pkg

### Utekelezaji kutoka kwenye folda za umma

Ikiwa script ya usakinishaji kabla au baada ya usakinishaji inatekelezwa kwa mfano kutoka **`/var/tmp/Installerutil`**, na mshambuliaji anaweza kudhibiti script hiyo ili apande vyeo kila wakati inatekelezwa. Au mfano mwingine sawa:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [kazi ya umma](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo wasakinishaji na wakusasisha kadhaa watatumia kutekeleza kitu kama mizizi. Kazi hii inakubali **njia** ya **faili** ya **kutekeleza** kama parameter, hata hivyo, ikiwa mshambuliaji anaweza **kurekebisha** faili hii, ataweza **kunyanyasa** utekelezaji wake na mizizi ili **kupandisha vyeo**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Utekelezaji kwa kufunga

Ikiwa mtengenezaji anaandika kwa `/tmp/fixedname/bla/bla`, inawezekana **kuunda mlima** juu ya `/tmp/fixedname` bila wamiliki ili uweze **kurekebisha faili yoyote wakati wa usakinishaji** kwa lengo la kutumia mchakato wa usakinishaji.

Mfano wa hii ni **CVE-2021-26089** ambayo ilifanikiwa **kubadilisha skripti ya kipindi** ili kupata utekelezaji kama mtumiaji wa mizizi. Kwa maelezo zaidi angalia mazungumzo: [**OBTS v4.0: "Mlima wa Mende" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kama zisizo

### Mzigo wa Kufuta

Inawezekana tu kuzalisha faili ya **`.pkg`** na **skripti za kabla na baada ya usakinishaji** bila mzigo wowote.

### JS katika Usambazaji wa xml

Inawezekana kuongeza vitambulisho vya **`<script>`** katika faili ya **usambazaji xml** ya pakiti na msimbo huo utatekelezwa na unaweza **kutekeleza amri** kutumia **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1040).png" alt=""><figcaption></figcaption></figure>

## Marejeo

* [**DEF CON 27 - Kufungua Pkgs Tazama Ndani ya Pakiti za Usakinishaji wa Macos na Uvimbe wa Usalama wa Kawaida**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Dunia ya Kufunga ya macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
