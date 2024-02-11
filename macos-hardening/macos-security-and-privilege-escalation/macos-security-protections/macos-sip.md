# macOS SIP

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## **Taarifa Msingi**

**System Integrity Protection (SIP)** kwenye macOS ni mfumo ulioundwa kuzuia hata watumiaji wenye mamlaka zaidi kufanya mabadiliko yasiyoruhusiwa kwenye folda muhimu za mfumo. Kipengele hiki kina jukumu muhimu katika kudumisha uadilifu wa mfumo kwa kuzuia vitendo kama kuongeza, kubadilisha, au kufuta faili katika maeneo yaliyolindwa. Folders kuu zinazolindwa na SIP ni pamoja na:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Sheria zinazosimamia tabia ya SIP zimefafanuliwa katika faili ya usanidi iliyoko kwenye **`/System/Library/Sandbox/rootless.conf`**. Ndani ya faili hii, njia zilizo na alama ya nyota (*) zinatajwa kama ubaguzi kwa vikwazo vikali vya SIP vinginevyo.

Chukua mfano hapa chini:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Kifungu hiki kinaonyesha kuwa wakati SIP kwa ujumla inalinda saraka ya **`/usr`**, kuna saraka maalum (`/usr/libexec/cups`, `/usr/local`, na `/usr/share/man`) ambapo marekebisho yanaruhusiwa, kama inavyoonyeshwa na nyota (*) kabla ya njia zao.

Ili kuthibitisha ikiwa saraka au faili inalindwa na SIP, unaweza kutumia amri ya **`ls -lOd`** kuangalia uwepo wa bendera ya **`restricted`** au **`sunlnk`**. Kwa mfano:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Katika kesi hii, bendera ya **`sunlnk`** inaashiria kwamba directory ya `/usr/libexec/cups` yenyewe **haiwezi kufutwa**, ingawa faili zilizomo ndani yake zinaweza kuundwa, kuhaririwa, au kufutwa.

Kwa upande mwingine:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hapa, bendera ya **`restricted`** inaonyesha kuwa saraka ya `/usr/libexec` inalindwa na SIP. Katika saraka iliyolindwa na SIP, faili haziwezi kuundwa, kuhaririwa, au kufutwa.

Zaidi ya hayo, ikiwa faili ina sifa ya ziada ya **`com.apple.rootless`**, faili hiyo pia italindwa na SIP.

**SIP pia inazuia vitendo vingine vya root** kama vile:

* Kupakia ugani wa kernel usioaminika
* Kupata bandari za kazi kwa michakato iliyo sainiwa na Apple
* Kubadilisha vipimo vya NVRAM
* Kuruhusu uchunguzi wa kernel

Chaguo zinahifadhiwa katika kivinjari cha nvram kama bitflag (`csr-active-config` kwenye Intel na `lp-sip0` inasomwa kutoka Mti wa Kifaa uliopakia kwa ARM). Unaweza kupata bendera hizo katika msimbo wa chanzo wa XNU katika `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### Hali ya SIP

Unaweza kuangalia ikiwa SIP imeamilishwa kwenye mfumo wako kwa amri ifuatayo:
```bash
csrutil status
```
Ikiwa unahitaji kulemaza SIP, lazima uanzishe upya kompyuta yako kwenye hali ya kurejesha (kwa kubonyeza Amri+R wakati wa kuanza), kisha tekeleza amri ifuatayo:
```bash
csrutil disable
```
Ikiwa unataka kuweka SIP kuwezeshwa lakini kuondoa ulinzi wa kurekebisha hitilafu, unaweza kufanya hivyo kwa:
```bash
csrutil enable --without debug
```
### Vizuizi Vingine

- **Inakataza kupakia nyongeza za kernel zisizo na saini** (kexts), kuhakikisha kuwa nyongeza zilizothibitishwa tu zinafanya kazi na kernel ya mfumo.
- **Inazuia uchunguzi** wa michakato ya mfumo wa macOS, kulinda sehemu kuu za mfumo kutokana na ufikiaji na ubadilishaji usiohalali.
- **Inazuia zana** kama dtrace kutoka kuchunguza michakato ya mfumo, kulinda zaidi uadilifu wa uendeshaji wa mfumo.

**[Jifunze zaidi kuhusu habari za SIP katika mazungumzo haya](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## Mbinu za Kupita Kizuizi cha SIP

Kupita kizuizi cha SIP kunawezesha mshambuliaji kufanya yafuatayo:

- **Kupata Data ya Mtumiaji**: Kusoma data nyeti ya mtumiaji kama barua, ujumbe, na historia ya Safari kutoka kwenye akaunti zote za mtumiaji.
- **Kupita Kizuizi cha TCC**: Kudhibiti moja kwa moja hifadhidata ya TCC (Transparency, Consent, and Control) ili kutoa ufikiaji usiohalali kwa kamera, kipaza sauti, na rasilimali zingine.
- **Kuanzisha Uthabiti**: Kuweka programu hasidi katika maeneo yaliyolindwa na SIP, kufanya iwe ngumu kuiondoa, hata kwa mamlaka ya mizizi. Hii pia ni pamoja na uwezekano wa kuharibu Zana ya Kuondoa Programu Hasidi (MRT).
- **Kupakia Nyongeza za Kernel**: Ingawa kuna ulinzi zaidi, kupita kizuizi cha SIP kunafanya iwe rahisi kupakia nyongeza za kernel zisizo na saini.

### Pakiti za Wasanidi Programu

**Pakiti za wasanidi programu zilizosainiwa na cheti cha Apple** zinaweza kupita kinga zake. Hii inamaanisha kuwa hata pakiti zilizosainiwa na wasanidi programu wa kawaida zitazuiliwa ikiwa zitajaribu kubadilisha saraka zilizolindwa na SIP.

### Faili ya SIP Isiyopo

Njia moja ya kuepuka ni kwamba ikiwa faili imeelekezwa katika **`rootless.conf` lakini haipo kwa sasa**, inaweza kuundwa. Programu hasidi inaweza kutumia hii kuanzisha uthabiti kwenye mfumo. Kwa mfano, programu hasidi inaweza kuunda faili ya .plist katika `/System/Library/LaunchDaemons` ikiwa iko kwenye orodha ya `rootless.conf` lakini haipo.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Ruhusa ya **`com.apple.rootless.install.heritable`** inaruhusu kupita kizuizi cha SIP.
{% endhint %}

#### Shrootless

[**Watafiti kutoka chapisho hili la blogu**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) waligundua udhaifu katika mfumo wa Ulinzi wa Uadilifu wa Mfumo (SIP) wa macOS, ulioitwa udhaifu wa 'Shrootless'. Udhaifu huu unahusiana na kifaa cha **`system_installd`**, ambacho kina ruhusa ya **`com.apple.rootless.install.heritable`**, ambayo inaruhusu michakato yoyote ya mtoto kuepuka vizuizi vya mfumo wa faili vya SIP.

Kifaa cha **`system_installd`** kitainstall pakiti zilizosainiwa na **Apple**.

Watafiti waligundua kuwa wakati wa kusanikisha pakiti iliyosainiwa na Apple (.pkg file), **`system_installd`** **huendesha** hati za **post-install** zilizomo kwenye pakiti hiyo. Hati hizi zinatekelezwa na kabati la msingi, **`zsh`**, ambayo kwa moja kwa moja **huendesha** amri kutoka kwenye faili ya **`/etc/zshenv`**, ikiwepo, hata katika hali isiyo ya mwingiliano. Mshambuliaji anaweza kutumia tabia hii: kwa kuunda faili mbaya ya `/etc/zshenv` na kusubiri **`system_installd` kuita `zsh`**, wanaweza kufanya operesheni za kiholela kwenye kifaa.

Zaidi ya hayo, iligundulika kuwa **`/etc/zshenv inaweza kutumika kama mbinu ya mashambulizi kwa ujumla**, sio tu kwa kupita kizuizi cha SIP. Kila wasifu wa mtumiaji una faili ya `~/.zshenv`, ambayo inafanya kazi kwa njia ile ile kama `/etc/zshenv` lakini haitahitaji ruhusa za mizizi. Faili hii inaweza kutumika kama mbinu ya uthabiti, ikianza kila wakati `zsh` inapoanza, au kama mbinu ya kuongeza haki za mamlaka. Ikiwa mtumiaji wa admin anapata haki za mizizi kwa kutumia `sudo -s` au `sudo <amri>`, faili ya `~/.zshenv` itaanza, ikiongeza haki za mizizi.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Katika [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), iligundulika kuwa mchakato huo huo wa **`system_installd`** bado unaweza kutumiwa vibaya kwa sababu ulikuwa ukiiweka hati ya **post-install ndani ya saraka yenye jina la nasibu iliyolindwa na SIP ndani ya `/tmp`**. Jambo ni kwamba **`/tmp` yenyewe haijamilindwa na SIP**, kwa hivyo ilikuwa inawezekana **kufunga** picha ya **virtual kwenye hiyo**, kisha **msanidi programu** angeiweka ndani yake **hati ya post-install**, **kufunga** tena picha ya virtual, **kuunda upya** saraka zote na **kuongeza** hati ya **post-install** na **payload** ya kutekelezwa.

#### [zana ya fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Udhaifu uligunduliwa ambapo **`fsck_cs`** ulidanganywa kuharibu faili muhimu, kutokana na uwezo wake wa kufuata **viungo vya ishara**. Hasa, wadukuzi walitengeneza kiungo kutoka _`/dev/diskX`_ kwenda faili ya `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Kutekeleza **`fsck_cs`** kwenye _`/dev/diskX`_ kulifanya `Info.plist` kuharibika. Uadilifu wa faili hii ni muhimu kwa Ulinzi wa Uadilifu wa Mfumo wa mfumo wa uendeshaji, ambao unadhibiti kupakia nyongeza za kernel. Mara ilipoharibika, uwezo wa SIP wa kusimamia uzuiaji wa kernel unakuwa hatarini.

Amri za kutumia udhaifu huu ni:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Udhalilishaji wa udhaifu huu una athari kubwa. Faili ya `Info.plist`, kawaida inayohusika na usimamizi wa ruhusa za nyongeza za kernel, inakuwa haifanyi kazi. Hii ni pamoja na kutokuweza kuweka orodha nyeusi ya nyongeza fulani, kama vile `AppleHWAccess.kext`. Kwa hivyo, na mfumo wa udhibiti wa SIP ukiwa umeharibika, nyongeza hii inaweza kupakia, ikiruhusu ufikiaji usiohalali wa kusoma na kuandika kwenye RAM ya mfumo.

#### [Kufunga juu ya folda zilizolindwa na SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Ilikuwa inawezekana kufunga mfumo wa faili mpya juu ya **folda zilizolindwa na SIP ili kuepuka ulinzi**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Kupuuza Upgrader (2016)](https://objective-see.org/blog/blog\_0x14.html)

Mfumo umewekwa ili kuanza kutoka kwenye picha ya diski ya mwendeshaji iliyounganishwa ndani ya `Install macOS Sierra.app` ili kuboresha mfumo wa uendeshaji, kwa kutumia kifaa cha `bless`. Amri inayotumiwa ni kama ifuatavyo:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Usalama wa mchakato huu unaweza kudhoofishwa ikiwa mshambuliaji anabadilisha picha ya kuboresha (`InstallESD.dmg`) kabla ya kuanza. Mkakati huu unahusisha kubadilisha mzigo wa kudumu (dyld) na toleo la hatari (`libBaseIA.dylib`). Mabadiliko haya husababisha utekelezaji wa nambari ya mshambuliaji wakati mchakato wa kufunga unaanzishwa.

Nambari ya mshambuliaji inapata udhibiti wakati wa mchakato wa kuboresha, ikitumia imani ya mfumo katika programu ya kufunga. Shambulio linaendelea kwa kubadilisha picha ya `InstallESD.dmg` kupitia njia ya kubadilishana, haswa ikilenga njia ya `extractBootBits`. Hii inaruhusu uingizaji wa nambari ya hatari kabla ya picha ya diski kutumiwa.

Zaidi ya hayo, ndani ya `InstallESD.dmg`, kuna `BaseSystem.dmg`, ambayo ni mfumo wa faili wa msingi wa nambari ya kuboresha. Kuingiza maktaba ya kudumu ndani yake kunaruhusu nambari ya hatari kufanya kazi ndani ya mchakato ambao unaweza kubadilisha faili za kiwango cha mfumo, ikiongeza sana uwezekano wa kudhoofisha mfumo.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Katika mazungumzo haya kutoka [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), inaonyeshwa jinsi **`systemmigrationd`** (ambayo inaweza kuepuka SIP) inatekeleza script ya **bash** na **perl**, ambayo inaweza kutumiwa vibaya kupitia mazingira ya pembejeo **`BASH_ENV`** na **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Ruhusa ya **`com.apple.rootless.install`** inaruhusu kuepuka SIP
{% endhint %}

Ruhusa ya `com.apple.rootless.install` inajulikana kuepuka System Integrity Protection (SIP) kwenye macOS. Hii ilielezwa hasa kuhusiana na [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Katika kesi hii maalum, huduma ya XPC ya mfumo iliyoko kwenye `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` inamiliki ruhusa hii. Hii inaruhusu mchakato unaohusiana kuepuka vizuizi vya SIP. Zaidi ya hayo, huduma hii hasa ina njia inayoruhusu hoja ya faili bila kutekeleza hatua yoyote ya usalama.

## Picha Zilizofungwa za Mfumo

Picha Zilizofungwa za Mfumo ni kipengele kilicholetwa na Apple katika **macOS Big Sur (macOS 11)** kama sehemu ya mfumo wake wa **System Integrity Protection (SIP)** ili kutoa safu ya ziada ya usalama na utulivu wa mfumo. Kimsingi, ni toleo lisiloweza kuhaririwa la kiasi cha mfumo.

Hapa kuna muhtasari zaidi:

1. **Mfumo Usiobadilika**: Picha Zilizofungwa za Mfumo hufanya kiasi cha mfumo wa macOS kuwa "usiobadilika", maana yake haiwezi kuhaririwa. Hii inazuia mabadiliko yoyote yasiyoruhusiwa au ya bahati mbaya kwenye mfumo ambayo inaweza kudhoofisha usalama au utulivu wa mfumo.
2. **Visasisho vya Programu ya Mfumo**: Unapoweka visasisho au uboreshaji wa macOS, macOS hujenga picha mpya ya mfumo. Kisha kiasi cha kuanza cha macOS kinatumia **APFS (Apple File System)** kubadilisha kwenye picha hii mpya. Mchakato mzima wa kuomba visasisho unakuwa salama na wa kuaminika zaidi kwani mfumo unaweza kurudi kwenye picha ya awali ikiwa kuna shida wakati wa kusasisha.
3. **Ugawaji wa Data**: Kwa kushirikiana na dhana ya kugawanya kiasi cha Data na Mfumo iliyowasilishwa katika macOS Catalina, kipengele cha Picha Zilizofungwa za Mfumo kinahakikisha kuwa data yako yote na mipangilio inahifadhiwa kwenye kiasi tofauti cha "**Data**". Kugawanya huku kunafanya data yako kuwa huru kutoka kwa mfumo, ambayo inasaidia mchakato wa visasisho vya mfumo na kuimarisha usalama wa mfumo.

Kumbuka kuwa picha hizi zinaendeshwa moja kwa moja na macOS na hazichukui nafasi ya ziada kwenye diski yako, shukrani kwa uwezo wa kushiriki nafasi wa APFS. Ni muhimu pia kutambua kuwa picha hizi zinatofautiana na **picha za Time Machine**, ambazo ni nakala rudufu zinazopatikana kwa mtumiaji ya mfumo mzima.

### Angalia Picha Zilizofungwa

Amri **`diskutil apfs list`** inaorodhesha **maelezo ya kina ya kiasi cha APFS** na muundo wake:

<pre><code>+-- Kifaa cha kuhifadhi disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Kumbukumbu ya Chombo cha APFS:     disk3
|   Ukubwa (Uwezo wa Juu):      494384795648 B (494.4 GB)
|   Uwezo Uliotumiwa na Vipimo:   219214536704 B (219.2 GB) (44.3% imeitwa)
|   Uwezo Usiotengwa:       275170258944 B (275.2 GB) (55.7% ya bure)
|   |
|   +-&#x3C; Uhifadhi wa Fizikia disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Uhifadhi wa Fizikia wa APFS:   disk0s2
|   |   Ukubwa:                       494384795648 B (494.4 GB)
|   |
|   +-> Kiasi disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Kiasi cha APFS (Jukumu):   disk3s1 (Mfumo)
</strong>|   |   Jina:                      Macintosh HD (Haijali herufi kubwa)
<strong>|   |   Nafasi ya Kufunga:               /System/Volumes/Update/mnt1
</strong>|   |   Uwezo Uliotumiwa:         12819210240 B (12.8 GB)
|   |   Imefungwa:                    Imevunjika
|   |   FileVault:                 Ndiyo (Imefunguliwa)
|   |   Imefichwa:                 Hapana
|   |   |
|   |   Picha ya Kumbukumbu:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Kumbukumbu ya Picha:             disk3s1s1
<strong>|   |   Nafasi ya Kufunga ya Picha:      /
</strong><strong>|   |   Picha Imefungwa:           Ndiyo
</strong>[...]
+-> Kiasi disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Kiasi cha APFS (Jukumu):   disk3s5 (Data)
|   Jina:                      Macintosh HD - Data (Haijali herufi kubwa)
<strong>    |   Nafasi ya Kufunga:               /System/Volumes/Data
</strong><strong>    |   Uwezo Uliotumiwa:         412071784448 B (412.1 GB)
</strong>    |   Imefungwa:                    Hapana
|   FileVault:                 Ndiyo (Imefunguliwa)
</code></pre>

Katika matokeo hapo juu, ni wazi kuwa maeneo yanayopatikana kwa mtumiaji yamefungwa chini ya `/System/Volumes/Data`.

Zaidi ya hayo, kiasi cha mfumo cha macOS kimefungwa na kimefungwa kwenye `/`, na ni **imefungwa** (imehifadhiwa kwa saini ya kielektroniki na mfumo wa uendeshaji). Kwa hivyo, ikiwa SIP inapuuzwa na kubadilishwa, **mfumo hautaanza tena**.

Pia ni muhimu kuhakikisha kuwa muhuri umewezeshwa kwa kukimbia:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Zaidi ya hayo, diski ya picha pia imefungwa kama **soma-tu**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
