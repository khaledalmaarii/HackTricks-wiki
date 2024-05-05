# Matumizi Mabaya ya Wasakinishaji wa macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi za Pkg

Kifurushi cha wasakinishaji wa macOS (pia inajulikana kama faili ya `.pkg`) ni muundo wa faili unaotumiwa na macOS kusambaza programu. Faili hizi ni kama **sanduku linaloleta kila kitu ambacho programu** inahitaji kusakinisha na kukimbia kwa usahihi.

Faili ya kifurushi yenyewe ni nyaraka inayoshikilia **hiraki ya faili na saraka ambazo zitasakinishwa kwenye** kompyuta ya lengo. Inaweza pia kujumuisha **maandishi** kutekeleza kazi kabla na baada ya usakinishaji, kama vile kuweka faili za usanidi au kusafisha toleo za zamani za programu.

### Hiraki

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Usambazaji (xml)**: Kubinafsisha (jina, maandishi ya kukaribisha...) na maandishi/vipimo vya usakinishaji
* **PackageInfo (xml)**: Taarifa, mahitaji ya usakinishaji, mahali pa usakinishaji, njia za maandishi za kukimbia
* **Bili ya vifaa (bom)**: Orodha ya faili za kusakinisha, kuboresha au kuondoa na ruhusa za faili
* **Mzigo (CPIO archive gzip compresses)**: Faili za kusakinisha kwenye `mahali-pa-usakinishaji` kutoka PackageInfo
* **Maandishi (CPIO archive gzip compressed)**: Maandishi kabla na baada ya usakinishaji na rasilimali zaidi zilizochimbuliwa kwenye saraka ya muda kwa utekelezaji.

### Kuchambua
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
Ili kuona maudhui ya installer bila kudecompress manually unaweza kutumia zana ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Taarifa Msingi za DMG

Faili za DMG, au Picha za Apple Disk, ni muundo wa faili unaotumiwa na macOS ya Apple kwa picha za diski. Faili ya DMG ni **picha ya diski inayoweza kufungwa** (ina filesystem yake) ambayo ina data ya block ya ghafi mara nyingi imepakwa na wakati mwingine imefichwa. Unapofungua faili ya DMG, macOS **inaifunga kama vile ingekuwa diski halisi**, kuruhusu kupata maudhui yake.

{% hint style="danger" %}
Tambua kwamba wasakinishaji wa **`.dmg`** hushikilia **muundo mwingi sana** ambao hapo awali baadhi yao wakiwa na mapungufu walitumika kupata **utekelezaji wa nambari ya msingi**.
{% endhint %}

### Mfumo wa Hierarchy

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Mfumo wa faili ya DMG unaweza kutofautiana kulingana na maudhui. Hata hivyo, kwa DMGs za programu, kawaida inafuata muundo huu:

* Kiwango cha Juu: Hii ni mzizi wa picha ya diski. Mara nyingi ina programu na labda kiungo kwa folda ya Maombi.
* Programu (.app): Hii ni programu halisi. Katika macOS, programu ni kawaida pakiti inayojumuisha faili na folda nyingi binafsi zinazounda programu.
* Kiungo cha Maombi: Hii ni mkato kwenda kwa folda ya Maombi katika macOS. Lengo la hili ni kufanya iwe rahisi kwako kusakinisha programu. Unaweza kuburuta faili ya .app kwenye mkato huu kusakinisha programu.

## Privesc kupitia unyanyasaji wa pkg

### Utekelezaji kutoka kwenye folda za umma

Ikiwa script ya usakinishaji kabla au baada ya kusakinisha inatekelezwa kwa mfano kutoka **`/var/tmp/Installerutil`**, na mshambuliaji anaweza kudhibiti script hiyo ili apande vyeo wakati wowote inapotekelezwa. Au mfano mwingine sawa:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [kazi ya umma](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo wasakinishaji na wakusasisha kadhaa watatumia kutekeleza kitu kama mzizi. Kazi hii inakubali **njia** ya **faili** ya **kutekeleza** kama parameter, hata hivyo, ikiwa mshambuliaji anaweza **kurekebisha** faili hii, ataweza **kunyanyasa** utekelezaji wake na mzizi ili **apande vyeo**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Utekelezaji kwa kufunga

Ikiwa mtunzaji anaandika kwa `/tmp/fixedname/bla/bla`, inawezekana **kuunda mlima** juu ya `/tmp/fixedname` bila wamiliki ili uweze **kurekebisha faili yoyote wakati wa usakinishaji** kwa kudhuru mchakato wa usakinishaji.

Mfano wa hii ni **CVE-2021-26089** ambayo ilifanikiwa **kubadilisha skripti ya kipindi** ili kupata utekelezaji kama mzizi. Kwa maelezo zaidi angalia mazungumzo: [**OBTS v4.0: "Mlima wa Mende" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kama zisizo

### Mzigo wa Kufuta

Inawezekana tu kuzalisha faili ya **`.pkg`** na **skripti za kabla na baada ya usakinishaji** bila mzigo wowote.

### JS katika usambazaji wa xml

Inawezekana kuongeza vitambulisho vya **`<script>`** katika faili ya **usambazaji xml** ya pakiti na hiyo nambari itatekelezwa na inaweza **kutekeleza amri** kutumia **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Marejeo

* [**DEF CON 27 - Kufungua Pkgs Tazama Ndani ya Pakiti za Usakinishaji wa MacOS na Uvimbe wa Kawaida wa Usalama**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Dunia ya Kufunga ya macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Kufungua Pkgs Tazama Ndani ya Pakiti za Usakinishaji wa MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
