# Uvunjaji wa Matumizi ya Wafungaji wa macOS

<details>

<summary><strong>Jifunze kuhusu uvunjaji wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuvunja kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Habari Msingi za Pkg

Kifurushi cha **ufungaji wa macOS** (pia hujulikana kama faili ya `.pkg`) ni muundo wa faili unaotumiwa na macOS kusambaza programu. Faili hizi ni kama **sanduku linaloambatanisha kila kitu ambacho kipande cha programu** inahitaji ili kusakinisha na kukimbia kwa usahihi.

Faili ya kifurushi yenyewe ni kiunzi kinachoshikilia **muundo wa faili na saraka ambazo zitasakinishwa kwenye kompyuta ya lengo**. Inaweza pia kuwa na **hati** za kutekeleza kazi kabla na baada ya usakinishaji, kama vile kuweka faili za usanidi au kusafisha toleo la zamani la programu.

### Muundo

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Usambazaji (xml)**: Kubinafsisha (kichwa, maandishi ya karibu...) na ukaguzi wa hati/usakinishaji
* **PackageInfo (xml)**: Habari, mahitaji ya usakinishaji, mahali pa usakinishaji, njia za hati za kukimbia
* **Bili ya vifaa (bom)**: Orodha ya faili za kusakinisha, kusasisha au kuondoa na ruhusa za faili
* **Payload (CPIO kiunzi kilichopunguzwa kwa gzip)**: Faili za kusakinisha kwenye `mahali-pakua` kutoka kwa PackageInfo
* **Hati (CPIO kiunzi kilichopunguzwa kwa gzip)**: Hati za kabla na baada ya usakinishaji na rasilimali zaidi zilizopatikana kwenye saraka ya muda kwa ajili ya utekelezaji.

### Kupunguza kiunzi
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
## Taarifa Msingi kuhusu DMG

Faili za DMG, au Picha za Diski za Apple, ni muundo wa faili unaotumiwa na macOS ya Apple kwa picha za diski. Faili ya DMG ni kimsingi **picha ya diski inayoweza kufungwa** (ina mfumo wa faili yake) ambayo ina data ya kibodi iliyopakwa kawaida na wakati mwingine imefichwa. Unapofungua faili ya DMG, macOS **inafunga kama vile ni diski halisi**, kuruhusu ufikiaji wa maudhui yake.

### Mfumo wa Hierarchy

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Mfumo wa hierarchy wa faili ya DMG unaweza kuwa tofauti kulingana na maudhui. Walakini, kwa DMG za programu, kawaida inafuata muundo huu:

* Kiwango cha Juu: Hii ni mzizi wa picha ya diski. Mara nyingi ina programu na labda kiunga kwa folda ya Maombi.
* Programu (.app): Hii ni programu halisi. Katika macOS, programu kawaida ni mfuko ambao una faili na folda nyingi ambazo hufanya programu hiyo.
* Kiunga cha Maombi: Hii ni njia ya mkato kwa folda ya Maombi katika macOS. Lengo la hii ni kufanya iwe rahisi kwako kufunga programu. Unaweza kuvuta faili ya .app kwenye njia hii ya mkato ili kufunga programu.

## Privesc kupitia utumiaji mbaya wa pkg

### Utekelezaji kutoka kwenye folda za umma

Ikiwa hati ya ufungaji kabla au baada ya ufungaji inatekelezwa, kwa mfano, kutoka kwenye **`/var/tmp/Installerutil`**, na mshambuliaji anaweza kudhibiti hati hiyo ili apate mamlaka ya juu wakati inatekelezwa. Au mfano mwingine kama huo:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [kazi ya umma](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo wakala na wakurugenzi wengi watatumia kutekeleza kitu kama mizizi. Kazi hii inakubali **njia** ya **faili** ya **utekelezaji** kama parameter, hata hivyo, ikiwa mshambuliaji anaweza **kubadilisha** faili hii, ataweza **kutumia vibaya** utekelezaji wake na mizizi ili kupata mamlaka ya juu.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Kwa habari zaidi angalia mazungumzo haya: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Utekelezaji kwa kufunga

Ikiwa mtunzi wa programu anaandika kwenye `/tmp/fixedname/bla/bla`, ni **inawezekana kuunda kifungu** juu ya `/tmp/fixedname` bila mmiliki ili uweze **kubadilisha faili yoyote wakati wa usakinishaji** ili kutumia mchakato wa usakinishaji.

Mfano wa hii ni **CVE-2021-26089** ambayo ilifanikiwa **kubadilisha skripti ya kawaida** ili kupata utekelezaji kama mtumiaji mkuu. Kwa habari zaidi angalia mazungumzo haya: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kama programu hasidi

### Malipo tupu

Inawezekana tu kuunda faili ya **`.pkg`** na **skripti za kabla na baada ya usakinishaji** bila malipo yoyote.

### JS katika xml ya Usambazaji

Inawezekana kuongeza vitambulisho vya **`<script>`** katika faili ya xml ya **usambazaji** ya kifurushi na namna hiyo itatekelezwa na inaweza **kutekeleza amri** kwa kutumia **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Marejeo

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
