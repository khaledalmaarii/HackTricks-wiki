# macOS SIP

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** kuchunguza ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

---

## **Taarifa Msingi**

**Ulinzi wa Uadilifu wa Mfumo (SIP)** kwenye macOS ni mbinu iliyoundwa kuzuia hata watumiaji wenye mamlaka zaidi kufanya mabadiliko yasiyoruhusiwa kwenye folda muhimu za mfumo. Kipengele hiki kina jukumu muhimu katika kudumisha uadilifu wa mfumo kwa kuzuia vitendo kama kuongeza, kuhariri, au kufuta faili katika maeneo yaliyolindwa. Folda kuu zinazolindwa na SIP ni pamoja na:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Sheria zinazosimamia tabia ya SIP zimefafanuliwa kwenye faili ya usanidi iliyoko kwenye **`/System/Library/Sandbox/rootless.conf`**. Ndani ya faili hii, njia zilizo na alama ya nyota (\*) zinatajwa kama ubaguzi wa vikwazo vikali vya SIP.

Chukua mfano hapa chini:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Hii sehemu inaashiria kwamba ingawa SIP kwa ujumla inalinda saraka ya **`/usr`**, kuna vichwa vya kipekee (`/usr/libexec/cups`, `/usr/local`, na `/usr/share/man`) ambapo marekebisho yanaruhusiwa, kama ilivyodokezwa na asterisk (\*) inayotangulia njia zao.

Ili kuthibitisha ikiwa saraka au faili inalindwa na SIP, unaweza kutumia amri ya **`ls -lOd`** kuangalia uwepo wa bendera ya **`restricted`** au **`sunlnk`**. Kwa mfano:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Katika kesi hii, bendera ya **`sunlnk`** inamaanisha kuwa directory ya `/usr/libexec/cups` yenyewe **haiwezi kufutwa**, ingawa mafaili ndani yake yanaweza kuundwa, kuhaririwa, au kufutwa.

Kwa upande mwingine:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hapa, bendera ya **`iliyozuiwa`** inaonyesha kuwa directory ya `/usr/libexec` inalindwa na SIP. Katika directory iliyo na ulinzi wa SIP, faili haziwezi kuundwa, kuhaririwa, au kufutwa.

Zaidi ya hayo, ikiwa faili ina sifa ya ziada ya **`com.apple.rootless`**, faili hiyo pia itakuwa **lindwa na SIP**.

**SIP pia inazuia vitendo vingine vya root** kama vile:

* Kupakia vifaa vya msingi visivyoaminika
* Kupata task-ports kwa michakato iliyosainiwa na Apple
* Kubadilisha mazingira ya NVRAM
* Kuruhusu uchunguzi wa kernel

Chaguo zinahifadhiwa katika mazingira ya nvram kama bitflag (`csr-active-config` kwenye Intel na `lp-sip0` inasomwa kutoka kwa Mti wa Kifaa kilicho booted kwa ARM). Unaweza kupata bendera hizo katika msimbo wa chanzo wa XNU katika `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

### Hali ya SIP

Unaweza kuangalia ikiwa SIP imewezeshwa kwenye mfumo wako kwa amri ifuatayo:
```bash
csrutil status
```
Ikiwa unahitaji kulemaza SIP, lazima uanzishe upya kompyuta yako kwenye hali ya kupona (kwa kubonyeza Amri+R wakati wa kuanza), kisha tekeleza amri ifuatayo:
```bash
csrutil disable
```
Ikiwa unataka kuweka SIP kuwa imewezeshwa lakini uondoe ulinzi wa uchunguzi, unaweza kufanya hivyo kwa:
```bash
csrutil enable --without debug
```
### Vizuizi vingine

* **Inazuia kupakia nyongeza za kernel zisizosainiwa** (kexts), ikisimamia tu nyongeza zilizothibitishwa kuingiliana na kernel ya mfumo.
* **Inazuia uchunguzi** wa michakato ya mfumo wa macOS, ikilinda sehemu kuu za mfumo kutokana na ufikiaji usioruhusiwa na mabadiliko.
* **Inazuia zana** kama dtrace kutoka kuchunguza michakato ya mfumo, ikilinda zaidi uadilifu wa uendeshaji wa mfumo.

[**Jifunze zaidi kuhusu habari ya SIP katika mazungumzo haya**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## Kupita kizuizi cha SIP

Kupita kizuizi cha SIP kunamwezesha mshambuliaji kufanya yafuatayo:

* **Kufikia Data ya Mtumiaji**: Kusoma data nyeti ya mtumiaji kama barua pepe, ujumbe, na historia ya Safari kutoka kwa akaunti zote za watumiaji.
* **Kupita TCC**: Kudhibiti moja kwa moja hifadhidata ya TCC (Transparency, Consent, and Control) kutoa ufikiaji usioruhusiwa kwa kamera, kipaza sauti, na rasilimali nyingine.
* **Kuanzisha Uimara**: Kuweka zisizo katika maeneo yaliyolindwa na SIP, ikifanya iwe ngumu kuondoa, hata kwa mamlaka ya mizizi. Hii pia ni pamoja na uwezekano wa kuharibu zana ya Kuondoa Zisizo (MRT).
* **Kupakia Nyongeza za Kernel**: Ingawa kuna kinga zaidi, kupita kizuizi cha SIP kunasimplisha mchakato wa kupakia nyongeza za kernel zisizosainiwa.

### Pakiti za Usakinishaji

**Pakiti za usakinishaji zilizosainiwa na cheti cha Apple** zinaweza kupita kinga zake. Hii inamaanisha kwamba hata pakiti zilizosainiwa na watengenezaji wa kawaida zitazuiliwa ikiwa zitajaribu kurekebisha saraka zilizolindwa na SIP.

### Faili ya SIP isiyopo

Mianya moja inawezekana ni kwamba ikiwa faili imeorodheshwa katika **`rootless.conf` lakini haipo kwa sasa**, inaweza kuundwa. Programu hasidi inaweza kutumia hii kwa **kuanzisha uimara** kwenye mfumo. Kwa mfano, programu hasidi inaweza kuunda faili ya .plist katika `/System/Library/LaunchDaemons` ikiwa imeorodheshwa katika `rootless.conf` lakini haipo.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Ruhusa **`com.apple.rootless.install.heritable`** inaruhusu kupita kizuizi cha SIP
{% endhint %}

#### Shrootless

[**Watafiti kutoka chapisho hili la blogi**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) waligundua mianya katika mfumo wa Ulinzi wa Mfumo wa macOS (SIP), iliyopewa jina la 'Shrootless' vulnerability. Mianya hii inazingatia kuzunguka kwa **`system_installd`** daemon, ambayo ina ruhusa, **`com.apple.rootless.install.heritable`**, inayoruhusu mchakato wowote wa watoto wake kupita kinga ya mfumo wa SIP kwenye mfumo wa faili.

**`system_installd`** daemon itasakinisha pakiti zilizosainiwa na **Apple**.

Watafiti waligundua kwamba wakati wa usakinishaji wa pakiti iliyosainiwa na Apple (.pkg file), **`system_installd`** **inaendesha** hati yoyote ya **post-install** iliyomo kwenye pakiti hiyo. Hati hizi zinaendeshwa na kabati la msingi, **`zsh`**, ambayo kwa moja kwa moja **inaendesha** amri kutoka kwa faili ya **`/etc/zshenv`**, ikiwepo, hata katika hali isiyo ya mwingiliano. Tabia hii inaweza kutumiwa na wachomaji: kwa kuunda faili mbaya ya `/etc/zshenv` na kusubiri **`system_installd` kuita `zsh`**, wanaweza kufanya operesheni za aina yoyote kwenye kifaa.

Zaidi ya hayo, iligunduliwa kwamba **`/etc/zshenv` inaweza kutumika kama mbinu ya mashambulizi ya jumla**, si tu kwa kupita kizuizi cha SIP. Kila wasifu wa mtumiaji una faili ya `~/.zshenv`, ambayo ina tabia sawa na `/etc/zshenv` lakini haitaji ruhusa za mizizi. Faili hii inaweza kutumika kama mbinu ya uimara, ikianzisha kila wakati `zsh` inapoanza, au kama mbinu ya kupandisha hadhi. Ikiwa mtumiaji wa admin anapandisha hadhi kuwa mizizi kwa kutumia `sudo -s` au `sudo <amri>`, faili ya `~/.zshenv` itaanzishwa, ikipandisha hadhi kwa mizizi kwa ufanisi.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Katika [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) iligunduliwa kwamba mchakato huo wa **`system_installd`** unaweza bado kutumiwa vibaya kwa sababu ulikuwa ukiiweka **hati ya post-install ndani ya folda yenye jina la kubahatisha iliyolindwa na SIP ndani ya `/tmp`**. Jambo ni kwamba **`/tmp` yenyewe haikulindwa na SIP**, hivyo ilikuwa inawezekana **kufunga** picha ya **virtual** juu yake, kisha **msakinishaji** ungehifadhi hapo **hati ya post-install**, **kufunga** tena picha ya virtual, **kuunda upya** folda zote na **kuongeza** hati ya **usakinishaji wa baadae** na **mzigo** wa kutekelezwa.

#### [zana ya fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Mianya iligunduliwa ambapo **`fsck_cs`** ilidanganywa kuharibu faili muhimu, kutokana na uwezo wake wa kufuata **viungo vya ishara**. Hasa, wachomaji walitengeneza kiungo kutoka _`/dev/diskX`_ kwenda kwa faili `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Kutekeleza **`fsck_cs`** kwenye _`/dev/diskX`_ kulipelekea uharibifu wa `Info.plist`. Uadilifu wa faili hii ni muhimu kwa SIP ya mfumo wa uendeshaji, ambayo inadhibiti kupakia nyongeza za kernel. Mara ilipoharibika, uwezo wa SIP wa kusimamia uzuiaji wa kernel unakuwa hatarini.

Amri za kutumia mianya hii ni:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Udhalilishaji wa udhaifu huu una matokeo makubwa. Faili ya `Info.plist`, kawaida inayohusika na usimamizi wa ruhusa za nyongeza za kernel, inakuwa batili. Hii ni pamoja na uwezekano wa kuzuia nyongeza fulani, kama vile `AppleHWAccess.kext`. Kwa hivyo, na mfumo wa udhibiti wa SIP ukiwa nje ya utaratibu, nyongeza hii inaweza kupakiwa, ikiruhusu ufikiaji usioruhusiwa wa kusoma na kuandika kwenye RAM ya mfumo.

#### [Kufunga juu ya folda zilizolindwa na SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Ilitowezekana kufunga mfumo wa faili mpya juu ya **folda zilizolindwa na SIP ili kudanganya ulinzi**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Kupuuza Upgrader (2016)](https://objective-see.org/blog/blog\_0x14.html)

Mfumo umewekwa kuanza kutoka kwenye picha ya diski ya mjenzi iliyomo ndani ya `Sakinisha macOS Sierra.app` ili kuboresha OS, kwa kutumia kifaa cha `bless`. Amri iliyotumika ni kama ifuatavyo:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Usalama wa mchakato huu unaweza kuhatarishwa ikiwa mshambuliaji anabadilisha picha ya kuboresha (`InstallESD.dmg`) kabla ya kuanza. Mkakati huu unahusisha kubadilisha mzigo wa kudhibiti (dyld) na toleo la uovu (`libBaseIA.dylib`). Kubadilishwa huku kunasababisha utekelezaji wa msimbo wa mshambuliaji wakati mchakato wa usakinishaji unapoanzishwa.

Msimbo wa mshambuliaji unapata udhibiti wakati wa mchakato wa kuboresha, kwa kutumia imani ya mfumo katika msakinishaji. Shambulio linaendelea kwa kubadilisha picha ya `InstallESD.dmg` kupitia njia ya swizzling, hasa ikilenga njia ya `extractBootBits`. Hii inaruhusu kuingiza msimbo wa uovu kabla ya picha ya diski kutumika.

Zaidi ya hayo, ndani ya `InstallESD.dmg`, kuna `BaseSystem.dmg`, ambayo hutumikia kama mfumo wa mizizi wa msimbo wa kuboresha. Kuingiza maktaba ya kudhibiti katika hii inaruhusu msimbo wa uovu kufanya kazi ndani ya mchakato unaoweza kubadilisha faili za kiwango cha OS, ikiongeza sana uwezekano wa kuhatarisha mfumo.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Katika mazungumzo haya kutoka [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), inaonyeshwa jinsi **`systemmigrationd`** (ambayo inaweza kukiuka SIP) inatekeleza script ya **bash** na **perl**, ambayo inaweza kutumiwa vibaya kupitia mazingira ya env variables **`BASH_ENV`** na **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Ruhusa **`com.apple.rootless.install`** inaruhusu kukiuka SIP
{% endhint %}

Ruhusa `com.apple.rootless.install` inajulikana kukiuka Ulinzi wa Uadilifu wa Mfumo (SIP) kwenye macOS. Hii ilionyeshwa hasa kuhusiana na [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Katika kesi hii maalum, huduma ya XPC ya mfumo iliyoko kwenye `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` inamiliki ruhusa hii. Hii inaruhusu mchakato unaohusika kuzunguka vizuizi vya SIP. Zaidi ya hayo, huduma hii ina njia inayoruhusu harakati ya faili bila kutekeleza hatua yoyote ya usalama.

## Picha za Mfumo Zilizofungwa

Picha za Mfumo Zilizofungwa ni kipengele kilicholetwa na Apple katika **macOS Big Sur (macOS 11)** kama sehemu ya mfumo wake wa **Ulinzi wa Uadilifu wa Mfumo (SIP)** kutoa safu ya ziada ya usalama na utulivu wa mfumo. Kimsingi ni toleo lisiloweza kuhaririwa la kiasi cha mfumo.

Hapa kuna muonekano wa kina zaidi:

1. **Mfumo Usiobadilika**: Picha za Mfumo Zilizofungwa hufanya kiasi cha mfumo wa macOS kuwa "usio badilika", maana yake hauwezi kuhaririwa. Hii inazuia mabadiliko yoyote yasiyoruhusiwa au ya bahati mbaya kwenye mfumo ambayo yanaweza kuhatarisha usalama au utulivu wa mfumo.
2. **Sasisho za Programu ya Mfumo**: Unapoweka sasisho au kuboresha macOS, macOS inaunda picha mpya ya mfumo. Kiasi cha kuanza cha macOS kisha kutumia **APFS (Mfumo wa Faili wa Apple)** kubadilisha kwenye picha hii mpya. Mchakato mzima wa kutumia sasisho unakuwa salama zaidi na wa kuaminika zaidi kwani mfumo unaweza kurudi kwenye picha ya awali ikiwa kitu kitakwenda vibaya wakati wa sasisho.
3. **Ufafanuzi wa Data**: Pamoja na dhana ya Ufafanuzi wa Kiasi cha Data na Mfumo iliyotambulishwa katika macOS Catalina, kipengele cha Picha za Mfumo Zilizofungwa kuhakikisha kuwa data yako yote na mipangilio inahifadhiwa kwenye kiasi cha "**Data**" tofauti. Ufafanuzi huu unafanya data yako kuwa huru kutoka kwa mfumo, ambayo inasimplisha mchakato wa sasisho wa mfumo na kuimarisha usalama wa mfumo.

Kumbuka kuwa picha hizi zinasimamiwa moja kwa moja na macOS na hazichukui nafasi ya ziada kwenye diski yako, shukrani kwa uwezo wa kushirikiana nafasi wa APFS. Pia ni muhimu kutambua kuwa picha hizi ni tofauti na **picha za Time Machine**, ambazo ni nakala za kurejesheka za mfumo mzima zinazoweza kufikiwa na mtumiaji.

### Angalia Picha za Mfumo

Amri **`diskutil apfs list`** inaorodhesha **maelezo ya kina ya kiasi cha APFS** na muundo wake:

<pre><code>+-- Kontena diski3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Kiungo cha Kontena cha APFS:     diski3
|   Ukubwa (Uwezo wa dari):         494384795648 B (494.4 GB)
|   Uwezo Uliotumiwa na Vipimo:     219214536704 B (219.2 GB) (44.3% imeitwa)
|   Uwezo Usiowekwa:                275170258944 B (275.2 GB) (55.7% bure)
|   |
|   +-&#x3C; Uhifadhi wa Fizikia diski0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Uhifadhi wa Fizikia wa APFS:   diski0s2
|   |   Ukubwa:                       494384795648 B (494.4 GB)
|   |
|   +-> Kiasi diski3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Kiasi cha APFS Disk (Jukumu):   diski3s1 (Mfumo)
</strong>|   |   Jina:                          Macintosh HD (Bila kuzingatia herufi kubwa)
<strong>|   |   Kiungo cha Kufunga:             /System/Volumes/Update/mnt1
</strong>|   |   Uwezo Uliotumiwa:               12819210240 B (12.8 GB)
|   |   Imefungwa:                      Imevunjika
|   |   FileVault:                     Ndiyo (Imefunguliwa)
|   |   Imefichwa:                     Hapana
|   |   |
|   |   Picha ya Kuchukua:              FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Kiasi cha Picha ya Kuchukua:     diski3s1s1
<strong>|   |   Kiungo cha Kufunga cha Picha ya Kuchukua:      /
</strong><strong>|   |   Picha ya Kuchukua Imefungwa:           Ndiyo
</strong>[...]
+-> Kiasi diski3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Kiasi cha APFS Disk (Jukumu):   diski3s5 (Data)
|   Jina:                          Macintosh HD - Data (Bila kuzingatia herufi kubwa)
<strong>    |   Kiungo cha Kufunga:             /System/Volumes/Data
</strong><strong>    |   Uwezo Uliotumiwa:               412071784448 B (412.1 GB)
</strong>    |   Imefungwa:                      Hapana
|   FileVault:                     Ndiyo (Imefunguliwa)
</code></pre>

Katika matokeo ya awali inawezekana kuona kuwa **maeneo yanayoweza kufikiwa na mtumiaji** yamefungwa chini ya `/System/Volumes/Data`.

Zaidi ya hayo, **picha ya mfumo wa macOS** imefungwa katika `/` na ni **imefungwa** (iliyosainiwa kwa njia ya kielektroniki na OS). Kwa hivyo, ikiwa SIP itapuuzwa na kuhariri, **OS haitaanza tena**.

Pia ni **rahisi kuthibitisha kuwa kufungwa kumewezeshwa** kwa kukimbia:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Zaidi ya hayo, diski ya picha inaunganishwa kama **soma-tu**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
