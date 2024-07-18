# Matumizi Mabaya ya Wasakinishaji wa macOS

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Taarifa Msingi za Pkg

**Pakiti ya wasakinishaji wa macOS** (inayojulikana pia kama faili ya `.pkg`) ni muundo wa faili unaotumiwa na macOS kwa **kugawa programu**. Faili hizi ni kama **sanduku linaloleta kila kitu ambacho programu** inahitaji kusakinisha na kukimbia kwa usahihi.

Faili ya pakiti yenyewe ni nyaraka inayoshikilia **mfululizo wa faili na saraka ambazo zitasakinishwa kwenye** kompyuta ya lengo. Inaweza pia kujumuisha **maandishi** kutekeleza kazi kabla na baada ya usakinishaji, kama vile kuweka faili za usanidi au kusafisha toleo za zamani za programu.

### Mfululizo

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Usambazaji (xml)**: Kubinafsisha (jina, maandishi ya karibu...) na maandishi/uchunguzi wa usakinishaji
* **PackageInfo (xml)**: Taarifa, mahitaji ya usakinishaji, mahali pa usakinishaji, njia za maandishi za kukimbia
* **Bili ya vifaa (bom)**: Orodha ya faili za kusakinisha, kuboresha au kuondoa na ruhusa za faili
* **Mzigo (CPIO nyaraka gzip compresses)**: Faili za kusakinisha kwenye `mahali-pa-usakinishaji` kutoka PackageInfo
* **Maandishi (CPIO nyaraka gzip compresses)**: Maandishi kabla na baada ya usakinishaji na rasilimali zaidi zilizochimbuliwa kwenye saraka ya muda kwa utekelezaji.
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
## Maelezo Muhimu ya DMG

Faili za DMG, au Picha za Diski za Apple, ni muundo wa faili unaotumiwa na macOS ya Apple kwa picha za diski. Faili ya DMG ni msingi wa **picha ya diski inayoweza kufungwa** (ina filesystem yake) ambayo ina data ya block ya ghafi mara nyingi imepakwa na wakati mwingine imefichwa. Unapofungua faili ya DMG, macOS **inaifunga kama vile ingekuwa diski halisi**, kuruhusu kupata yaliyomo yake.

{% hint style="danger" %}
Tafadhali kumbuka kwamba wasakinishaji wa **`.dmg`** hushikilia **muundo mwingi sana** ambao hapo awali baadhi yao waliokuwa na mapungufu walitumika kupata **utekelezaji wa nambari ya msingi**.
{% endhint %}

### Mfumo wa Hierarchy

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Mfumo wa faili ya DMG unaweza kutofautiana kulingana na yaliyomo. Hata hivyo, kwa DMGs za programu, kawaida inafuata muundo huu:

* Kiwango cha Juu: Hii ni mzizi wa picha ya diski. Mara nyingi ina programu na labda kiungo kwa folda za Maombi.
* Programu (.app): Hii ni programu halisi. Katika macOS, programu ni kawaida pakiti inayojumuisha faili na folda nyingi zinazounda programu.
* Kiungo cha Maombi: Hii ni mkato kwenda kwa folda za Maombi kwenye macOS. Lengo la hili ni kufanya iwe rahisi kwako kusakinisha programu. Unaweza kuburuta faili ya .app kwenye mkato huu kusakinisha programu.

## Privesc kupitia unyanyasaji wa pkg

### Utekelezaji kutoka kwenye folda za umma

Ikiwa scripti ya usakinishaji kabla au baada ya usakinishaji inatekelezwa kwa mfano kutoka **`/var/tmp/Installerutil`**, na mshambuliaji anaweza kudhibiti scripti hiyo ili apande vyeo kila wakati inapotekelezwa. Au mfano mwingine sawa:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [kazi ya umma](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo wasakinishaji na wakusasisha kadhaa watatumia kutekeleza kitu kama mzizi. Kazi hii inakubali **njia** ya **faili** ya **kutekeleza** kama parameter, hata hivyo, ikiwa mshambuliaji anaweza **kurekebisha** faili hii, ataweza **kunyanyasa** utekelezaji wake na mzizi ili **kupandisha vyeo**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Utekelezaji kwa kufunga

Ikiwa mtengenezaji anaandika kwa `/tmp/fixedname/bla/bla`, inawezekana **kuunda mlima** juu ya `/tmp/fixedname` bila wamiliki hivyo unaweza **kurekebisha faili yoyote wakati wa usakinishaji** kwa kudhuru mchakato wa usakinishaji.

Mfano wa hii ni **CVE-2021-26089** ambayo ilifanikiwa **kubadilisha skripti ya kipindi** ili kupata utekelezaji kama mtumiaji wa mizizi. Kwa maelezo zaidi angalia mazungumzo: [**OBTS v4.0: "Mlima wa Mende" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kama zisizo

### Mzigo wa Kufuta

Inawezekana tu kuzalisha faili ya **`.pkg`** na **skripti za kabla na baada ya usakinishaji** bila mzigo wowote.

### JS katika xml ya Usambazaji

Inawezekana kuongeza vitambulisho vya **`<script>`** katika faili ya **xml ya usambazaji** ya pakiti na msimbo huo utatekelezwa na inaweza **kutekeleza amri** kutumia **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Marejeo

* [**DEF CON 27 - Kufungua Pkgs Tazama Ndani ya Pakiti za Usakinishaji wa MacOS na Uvimbe wa Kawaida wa Usalama**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Dunia ya Kufunga ya macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Kufungua Pkgs Tazama Ndani ya Pakiti za Usakinishaji wa MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
