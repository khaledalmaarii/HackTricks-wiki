# macOS Faili, Vyeo, Binaries & Kumbukumbu

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Mpangilio wa Hiyerarkia ya Faili

* **/Applications**: Programu zilizosakinishwa zinapaswa kuwa hapa. Watumiaji wote wataweza kuzifikia.
* **/bin**: Binaries za mstari wa amri
* **/cores**: Ikiwepo, hutumiwa kuhifadhi dump za msingi
* **/dev**: Kila kitu kinafanywa kama faili hivyo unaweza kuona vifaa vya kuhifadhi vilivyohifadhiwa hapa.
* **/etc**: Faili za mipangilio
* **/Library**: Ving'amuzi vingi na faili zinazohusiana na mapendeleo, cache na logs zinaweza kupatikana hapa. Kuna folda ya Maktaba inayopatikana kwenye mizizi na kwenye folda ya kila mtumiaji.
* **/private**: Isiyoelezwa lakini ving'amuzi vingi vilivyotajwa ni viungo vya alama kwa folda ya faragha.
* **/sbin**: Binaries muhimu za mfumo (zinazohusiana na usimamizi)
* **/System**: Faili za kuendesha OS X. Unapaswa kupata hasa faili za Apple hapa (si za tatu).
* **/tmp**: Faili hufutwa baada ya siku 3 (ni kiungo laini kwenda /private/tmp)
* **/Users**: Folda ya nyumbani kwa watumiaji.
* **/usr**: Mipangilio na binaries za mfumo
* **/var**: Faili za logi
* **/Volumes**: Madereva yaliyomwekwa yataonekana hapa.
* **/.vol**: Ukikimbia `stat a.txt` unapata kitu kama `16777223 7545753 -rw-r--r-- 1 jina_la_mtumiaji gurudumu ...` ambapo nambari ya kwanza ni nambari ya kitambulisho cha kiasi ambapo faili ipo na ya pili ni nambari ya inode. Unaweza kupata maudhui ya faili hii kupitia /.vol/ kwa habari hiyo ukikimbia `cat /.vol/16777223/7545753`

### Vyeo vya Programu

* **Vyeo vya mfumo** vipo chini ya `/System/Applications`
* **Programu zilizosakinishwa** kawaida zinasakinishwa katika `/Applications` au katika `~/Applications`
* **Data ya programu** inaweza kupatikana katika `/Library/Application Support` kwa programu zinazoendeshwa kama mizizi na `~/Library/Application Support` kwa programu zinazoendeshwa kama mtumiaji.
* **Daemons** za programu za tatu zinazohitaji **kuendeshwa kama mizizi** kawaida zinapatikana katika `/Library/PrivilegedHelperTools/`
* Programu **zenye mchanga** zimeorodheshwa katika folda ya `~/Library/Containers`. Kila programu ina folda iliyoitwa kulingana na kitambulisho cha vyeo vya programu (`com.apple.Safari`).
* **Kernel** iko katika `/System/Library/Kernels/kernel`
* **Vyeo vya nyongeza vya kernel vya Apple** viko katika `/System/Library/Extensions`
* **Vyeo vya nyongeza vya kernel vya tatu** hifadhiwa katika `/Library/Extensions`

### Faili zenye Taarifa Nyeti

MacOS inahifadhi taarifa kama nywila katika maeneo kadhaa:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Wajasiriamali Wanaoweza Kudhurika

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Vyeo Maalum vya OS X

* **`.dmg`**: Faili za Picha za Apple Disk ni za kawaida kwa wasakinishaji.
* **`.kext`**: Lazima ifuate muundo maalum na ni toleo la OS X la dereva. (ni kifurushi)
* **`.plist`**: Inajulikana pia kama orodha ya mali inahifadhi taarifa kwa muundo wa XML au binary.
* Inaweza kuwa XML au binary. Zile za binary zinaweza kusomwa na:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Programu za Apple zinazofuata muundo wa folda (ni kifurushi).
* **`.dylib`**: Maktaba za kudumu (kama faili za DLL za Windows)
* **`.pkg`**: Ni sawa na xar (muundo wa Kumbukumbu inayoweza kupanuliwa). Amri ya wasakinishaji inaweza kutumika kusakinisha maudhui ya faili hizi.
* **`.DS_Store`**: Faili hii iko kwenye kila folda, inahifadhi sifa na ubinafsishaji wa folda.
* **`.Spotlight-V100`**: Folda hii inaonekana kwenye mizizi ya kila kiasi kwenye mfumo.
* **`.metadata_never_index`**: Ikiwa faili hii iko kwenye mizizi ya kiasi Spotlight haitaindeksi kiasi hicho.
* **`.noindex`**: Faili na folda zenye kipengee hiki hazitaindeksiwa na Spotlight.
* **`.sdef`**: Faili ndani ya vifurushi vinavyoeleza jinsi inavyowezekana kuingiliana na programu kutoka kwa AppleScript.

### Vifurushi vya macOS

Kifurushi ni **folda** ambayo **inaonekana kama kitu katika Finder** (mfano wa Kifurushi ni faili za `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

Kwenye macOS (na iOS) maktaba zote za mfumo, kama fremu na dylibs, zimeunganishwa katika faili moja, inayoitwa **dyld shared cache**. Hii imeboresha utendaji, kwani nambari inaweza kupakiwa haraka.

Kama dyld shared cache, kernel na nyongeza za kernel pia zimeunganishwa katika cache ya kernel, ambayo inapakiwa wakati wa kuanza.

Ili kutoa maktaba kutoka kwenye faili moja ya dylib shared cache ilikuwa inawezekana kutumia binary [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) ambayo labda haifanyi kazi leo lakini unaweza pia kutumia [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

Katika toleo za zamani unaweza kupata **cache iliyoshirikiwa** katika **`/System/Library/dyld/`**.

Katika iOS unaweza kuzipata katika **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Tambua kwamba hata kama zana ya `dyld_shared_cache_util` haifanyi kazi, unaweza kumpitisha **binary iliyoshirikiwa ya dyld kwa Hopper** na Hopper itaweza kutambua maktaba zote na kukuruhusu **kuchagua ni ipi** unayotaka kuchunguza:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1149).png" alt="" width="563"><figcaption></figcaption></figure>

## Mamlaka Maalum ya Faili

### Mamlaka ya Folda

Katika **folda**, **kusoma** inaruhusu **kuorodhesha**, **kuandika** inaruhusu **kufuta** na **kuandika** faili ndani yake, na **kutekeleza** inaruhusu **kuvuka** saraka. Kwa hivyo, kwa mfano, mtumiaji mwenye **ruhusa ya kusoma kwenye faili** ndani ya saraka ambapo hana ruhusa ya **utekelezaji** **hataweza kusoma** faili hiyo.

### Modifiers ya Bendera

Kuna baadhi ya bendera ambazo zinaweza kuwekwa kwenye faili ambazo zitafanya faili zichukue tabia tofauti. Unaweza **kuangalia bendera** za faili ndani ya saraka na `ls -lO /njia/saraka`

* **`uchg`**: Inayojulikana kama bendera ya **uchange** itazuia kitendo chochote cha kubadilisha au kufuta **faili**. Kuweka ni: `chflags uchg faili.txt`
* Mtumiaji wa mizizi anaweza **kuondoa bendera** na kuhariri faili
* **`restricted`**: Bendera hii inafanya faili ilindwe na SIP (hauwezi kuongeza bendera hii kwa faili).
* **`Bit ya Sticky`**: Ikiwa kuna saraka yenye biti ya sticky, **pekee** mmiliki wa saraka au mizizi wanaweza kubadilisha jina au kufuta **faili**. Kawaida hii huwekwa kwenye saraka ya /tmp kuzuia watumiaji wa kawaida kufuta au kuhamisha faili za watumiaji wengine.

Bendera zote zinaweza kupatikana kwenye faili `sys/stat.h` (ipate kwa kutumia `mdfind stat.h | grep stat.h`) na ni:

* `UF_SETTABLE` 0x0000ffff: Kifuniko cha bendera zinazoweza kubadilishwa na mmiliki.
* `UF_NODUMP` 0x00000001: Usidumishe faili.
* `UF_IMMUTABLE` 0x00000002: Faili haitaweza kubadilishwa.
* `UF_APPEND` 0x00000004: Kuandika kwenye faili kunaweza kuongeza tu.
* `UF_OPAQUE` 0x00000008: Saraka ni isiyoonekana kuhusiana na muungano.
* `UF_COMPRESSED` 0x00000020: Faili imepakatwa (baadhi ya mfumo wa faili).
* `UF_TRACKED` 0x00000040: Hakuna arifa kwa kufuta/kubadilisha majina kwa faili zilizo na hii.
* `UF_DATAVAULT` 0x00000080: Haki inahitajika kwa kusoma na kuandika.
* `UF_HIDDEN` 0x00008000: Kiashiria kwamba kipengee hiki haitakiwi kuonyeshwa kwenye GUI.
* `SF_SUPPORTED` 0x009f0000: Kifuniko cha bendera zinazoungwa mkono na msimamizi wa mizizi.
* `SF_SETTABLE` 0x3fff0000: Kifuniko cha bendera zinazoweza kubadilishwa na msimamizi wa mizizi.
* `SF_SYNTHETIC` 0xc0000000: Kifuniko cha bendera za kusoma tu za mfumo.
* `SF_ARCHIVED` 0x00010000: Faili imehifadhiwa.
* `SF_IMMUTABLE` 0x00020000: Faili haitaweza kubadilishwa.
* `SF_APPEND` 0x00040000: Kuandika kwenye faili kunaweza kuongeza tu.
* `SF_RESTRICTED` 0x00080000: Haki inahitajika kwa kuandika.
* `SF_NOUNLINK` 0x00100000: Kipengee hakiwezi kuondolewa, kubadilishwa jina au kufungwa.
* `SF_FIRMLINK` 0x00800000: Faili ni firmlink.
* `SF_DATALESS` 0x40000000: Faili ni kitu cha bila data.

### **ACL za Faili**

ACL za Faili zina **ACE** (Mingilio ya Kudhibiti Upatikanaji) ambapo **ruhusa za kina** zinaweza kupewa watumiaji tofauti.

Inawezekana kutoa **ruhusa** hizi kwa **directory**: `kuorodhesha`, `tafuta`, `ongeza_faili`, `ongeza_subdirectory`, `futa_mtoto`, `futa_mtoto`.\
Na kwa **faili**: `soma`, `andika`, `ongeza`, `tekeleza`.

Wakati faili ina ACL utaona **"+" wakati wa kuorodhesha ruhusa kama ilivyo**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Unaweza **kusoma ACLs** ya faili kwa:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Unaweza kupata **faili zote zenye ACLs** kwa (hii ni polepole sana):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Vipengele Vilivyozidishwa

Vipengele vilivyozidishwa vina jina na thamani yoyote inayotakiwa, na vinaweza kuonekana kwa kutumia `ls -@` na kuhaririwa kwa kutumia amri ya `xattr`. Baadhi ya vipengele vilivyozidishwa vya kawaida ni:

- `com.apple.resourceFork`: Ulinganifu wa rasilimali. Pia inaonekana kama `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Mfumo wa karantini wa Gatekeeper (III/6)
- `metadata:*`: MacOS: metadata mbalimbali, kama vile `_backup_excludeItem`, au `kMD*`
- `com.apple.lastuseddate` (#PS): Tarehe ya mwisho ya utumiaji wa faili
- `com.apple.FinderInfo`: MacOS: Taarifa za Finder (k.m., lebo za rangi)
- `com.apple.TextEncoding`: Inabainisha uendeshaji wa maandishi ya faili za ASCII
- `com.apple.logd.metadata`: Hutumiwa na logd kwenye faili katika `/var/db/diagnostics`
- `com.apple.genstore.*`: Uhifadhi wa kizazi (`/.DocumentRevisions-V100` katika mizizi ya mfumo wa faili)
- `com.apple.rootless`: MacOS: Hutumiwa na System Integrity Protection kuweka lebo ya faili (III/10)
- `com.apple.uuidb.boot-uuid`: Alama za logd za nyakati za kuanza upya na UUID ya kipekee
- `com.apple.decmpfs`: MacOS: Ufutaji wa faili kwa uwazi (II/7)
- `com.apple.cprotect`: \*OS: Data ya kielektroniki ya kila faili (III/11)
- `com.apple.installd.*`: \*OS: Metadata hutumiwa na installd, k.m., `installType`, `uniqueInstallID`

### Rasilimali Forks | macOS ADS

Hii ni njia ya kupata **Mito za Data Mbadala kwenye Mashine za MacOS**. Unaweza kuokoa maudhui ndani ya kipengele kilichozidishwa kinachoitwa **com.apple.ResourceFork** ndani ya faili kwa kuokoa katika **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Unaweza **kupata faili zote zinazo na sifa hii iliyozidishwa** kwa:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Kipengele cha ziada `com.apple.decmpfs` inaonyesha kuwa faili imehifadhiwa kwa njia ya kusimbwa, `ls -l` itaripoti **ukubwa wa 0** na data iliyosimbwa iko ndani ya kipengele hiki. Kila wakati faili inapofikiwa itadondoshwa kumbukani.

Kipengele hiki kinaweza kuonekana kwa `ls -lO` kikiashiria kama kimezimwa kwa sababu faili zilizosimbwa pia zinatambuliwa na bendera `UF_COMPRESSED`. Ikiwa faili iliyosimbwa inaondolewa bendera hii kwa `chflags nocompressed </path/to/file>`, mfumo hautajua kuwa faili ilikuwa imesimbwa na hivyo hautaweza kuidondosha na kufikia data (itadhani kuwa ni tupu).

Zana ya afscexpand inaweza kutumika kufanya kazi ya kufungua faili iliyosimbwa.

## **Faili za Universal &** Muundo wa Mach-o

Faili za Mac OS kawaida hukusanywa kama **faili za universal**. **Faili ya universal** inaweza **kusaidia miundo mingi ndani ya faili moja**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Kudondosha Kumbukumbu ya macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Aina za Hatari za Faili za Mac OS

Dereva `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ndipo ambapo habari kuhusu **hatari inayohusiana na viendelezi tofauti vya faili** imehifadhiwa. Daktari huyu anachambua faili kwa viwango tofauti vya hatari, ikibadilisha jinsi Safari inavyoshughulikia faili hizi baada ya kupakuliwa. Vikundi ni kama ifuatavyo:

* **LSRiskCategorySafe**: Faili katika kundi hili zinachukuliwa kuwa **salama kabisa**. Safari itafungua faili hizi moja kwa moja baada ya kupakuliwa.
* **LSRiskCategoryNeutral**: Hizi ni faili ambazo hazina onyo lolote na **hazifunguliwi moja kwa moja** na Safari.
* **LSRiskCategoryUnsafeExecutable**: Faili katika kundi hili **huchochea onyo** linaloonyesha kuwa faili ni programu. Hii ni hatua ya usalama ya kumwonya mtumiaji.
* **LSRiskCategoryMayContainUnsafeExecutable**: Kundi hili ni kwa faili, kama vile nyaraka, ambazo zinaweza kuwa na programu inayoweza kutekelezwa. Safari ita **chochea onyo** isipokuwa iweze kuthibitisha kuwa maudhui yote ni salama au yasiyo na hatari.

## Faili za Kumbukumbu

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Ina habari kuhusu faili zilizopakuliwa, kama URL kutoka mahali zilipopakuliwa.
* **`/var/log/system.log`**: Kumbukumbu kuu ya mifumo ya OSX. com.apple.syslogd.plist inahusika na utekelezaji wa syslogging (unaweza kuangalia ikiwa imezimwa kwa kutafuta "com.apple.syslogd" katika `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Hizi ni Kumbukumbu za Mfumo wa Apple ambazo zinaweza kuwa na habari muhimu.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Inahifadhi faili na programu zilizoangaliwa hivi karibuni kupitia "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Inahifadhi vitu vya kuzindua wakati wa kuanza kwa mfumo
* **`$HOME/Library/Logs/DiskUtility.log`**: Faili ya kumbukumbu ya Programu ya DiskUtility (habari kuhusu diski, ikiwa ni pamoja na USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data kuhusu vituo vya upatikanaji wa wireless.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Orodha ya daemons zilizozimwa.

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
