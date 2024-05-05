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
* **/dev**: Kila kitu kinafanywa kama faili hivyo unaweza kuona vifaa vya vifaa vilivyohifadhiwa hapa.
* **/etc**: Faili za mipangilio
* **/Library**: Ving'amuzi vingi na faili zinazohusiana na mapendeleo, cache na logs zinaweza kupatikana hapa. Kuna folda ya Maktaba inayopatikana kwenye mizizi na kwenye saraka ya kila mtumiaji.
* **/private**: Isiyoelezwa lakini ving'amuzi vingi vilivyotajwa ni viungo vya alama kwa saraka ya faragha.
* **/sbin**: Binaries muhimu za mfumo (zinazohusiana na usimamizi)
* **/System**: Faili za kuendesha OS X. Unapaswa kupata hasa faili za Apple hapa (si za tatu).
* **/tmp**: Faili hufutwa baada ya siku 3 (ni kiungo laini kwenda /private/tmp)
* **/Users**: Saraka ya nyumbani kwa watumiaji.
* **/usr**: Mipangilio na binaries za mfumo
* **/var**: Faili za logi
* **/Volumes**: Madereva yaliyomount yataonekana hapa.
* **/.vol**: Ukikimbia `stat a.txt` unapata kitu kama `16777223 7545753 -rw-r--r-- 1 jina la mtumiaji gurudumu ...` ambapo nambari ya kwanza ni nambari ya kitambulisho cha kiasi ambapo faili ipo na ya pili ni nambari ya inode. Unaweza kupata maudhui ya faili hii kupitia /.vol/ kwa habari hiyo ukikimbia `cat /.vol/16777223/7545753`

### Saraka za Programu

* **Programu za Mfumo** zinapatikana chini ya `/System/Applications`
* **Programu zilizosakinishwa** kawaida zinasakinishwa katika `/Applications` au katika `~/Applications`
* **Data ya Programu** inaweza kupatikana katika `/Library/Application Support` kwa programu zinazoendeshwa kama mizizi na `~/Library/Application Support` kwa programu zinazoendeshwa kama mtumiaji.
* **Daemons** za programu za tatu zinazohitaji kuendeshwa kama mizizi kawaida zinapatikana katika `/Library/PrivilegedHelperTools/`
* Programu **zenye mchanga** zimepangwa katika saraka ya `~/Library/Containers`. Kila programu ina saraka iliyoitwa kulingana na kitambulisho cha bundi cha programu (`com.apple.Safari`).
* **Kernel** iko katika `/System/Library/Kernels/kernel`
* **Extensions za kernel za Apple** ziko katika `/System/Library/Extensions`
* **Extensions za kernel za tatu** zinahifadhiwa katika `/Library/Extensions`

### Faili zenye Taarifa Nyeti

MacOS inahifadhi taarifa kama nywila katika maeneo kadhaa:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Wajasiriamali Wadhaifu wa Paket Installers

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Vifaa Maalum vya OS X

* **`.dmg`**: Faili za Picha za Apple Disk ni za kawaida kwa wasakinishaji.
* **`.kext`**: Lazima ifuate muundo maalum na ni toleo la OS X la dereva. (ni bundi)
* **`.plist`**: Inajulikana pia kama orodha ya mali inahifadhi taarifa kwa muundo wa XML au binary.
* Inaweza kuwa XML au binary. Zile za binary zinaweza kusomwa na:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Programu za Apple zinazofuata muundo wa saraka (ni bundi).
* **`.dylib`**: Maktaba za kudumu (kama faili za DLL za Windows)
* **`.pkg`**: Ni sawa na xar (muundo wa Kumbukumbu inayoweza kupanuliwa). Amri ya wasakinishaji inaweza kutumika kusakinisha maudhui ya faili hizi.
* **`.DS_Store`**: Faili hii iko kwenye kila saraka, inahifadhi sifa na ubinafsishaji wa saraka.
* **`.Spotlight-V100`**: Saraka hii inaonekana kwenye saraka ya mizizi ya kila kiasi kwenye mfumo.
* **`.metadata_never_index`**: Ikiwa faili hii iko kwenye mizizi ya kiasi Spotlight haitaindeksi kiasi hicho.
* **`.noindex`**: Faili na saraka zenye kipengee hiki hazitaindeksiwa na Spotlight.
* **`.sdef`**: Faili ndani ya bundi inayoeleza jinsi inavyowezekana kuingiliana na programu kutoka kwa AppleScript.

### Vifurushi vya macOS

Bundi ni **saraka** ambayo **inaonekana kama kitu katika Finder** (mfano wa Bundle ni faili za `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Library Cache (SLC)

Kwenye macOS (na iOS) maktaba zote za mfumo, kama fremu na dylibs, zime **unganishwa katika faili moja**, inayoitwa **dyld shared cache**. Hii imeboresha utendaji, kwani nambari inaweza kupakia haraka.

Hii iko macOS katika `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` na katika toleo za zamani unaweza kupata **shared cache** katika **`/System/Library/dyld/`**.\
Kwenye iOS unaweza kuzipata katika **`/System/Library/Caches/com.apple.dyld/`**.

Kama dyld shared cache, kernel na extensions za kernel pia zimeunganishwa katika cache ya kernel, ambayo inapakiwa wakati wa kuanza.

Ili kutoa maktaba kutoka kwa faili moja ya dylib shared cache ilikuwa inawezekana kutumia binary [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) ambayo inaweza isifanye kazi siku hizi lakini unaweza pia kutumia [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

{% hint style="success" %}
Tafadhali kumbuka hata kama zana ya `dyld_shared_cache_util` haifanyi kazi, unaweza kumtumia **dyld binary iliyoshirikiwa kwa Hopper** na Hopper itaweza kutambua maktaba zote na kukuruhusu **kuchagua ni ipi** unayotaka kuchunguza:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Baadhi ya wachimbaji hawatafanyi kazi kwa sababu dylibs zimeunganishwa mapema na anwani zilizowekwa kwa hivyo wanaweza kuhamia kwenye anwani zisizojulikana

{% hint style="success" %}
Pia ni rahisi kupakua Hifadhi ya Maktaba iliyoshirikiwa ya vifaa vingine vya \*OS kwenye macos kwa kutumia emulator katika Xcode. Zitapakuliwa ndani ya: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, kama:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### Kupanga SLC

**`dyld`** hutumia syscall **`shared_region_check_np`** kujua ikiwa SLC imepangwa (ambayo inarudisha anwani) na **`shared_region_map_and_slide_np`** kupanga SLC.

Kumbuka hata kama SLC imepangwa mara ya kwanza, **mchakato wote** hutumia **nakala ile ile**, ambayo **inaondoa ulinzi wa ASLR** ikiwa mshambuliaji alikuwa na uwezo wa kuendesha michakato kwenye mfumo. Hii ilikuwa ikitumiwa hapo awali na kusuluhishwa na ukurasa wa eneo la pamoja.

Pools za matawi ni dylibs ndogo za Mach-O ambazo huzalisha nafasi ndogo kati ya ramani za picha ambazo hufanya kuwa haiwezekani kuingilia kazi.

### Kuzidi SLCs

Kwa kutumia mazingira ya mazingira:

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Hii itaruhusu kupakia hifadhi mpya ya maktaba iliyoshirikiwa
* **`DYLD_SHARED_CACHE_DIR=avoid`** na kubadilisha maktaba kwa mikato kwa hifadhi iliyoshirikiwa na ile halisi (utahitaji kuzitoa)

## Ruhusa Maalum za Faili

### Ruhusa za Folda

Katika **folda**, **kusoma** kuruhusu **kuorodhesha**, **kuandika** kuruhusu **kufuta** na **kuandika** faili juu yake, na **kutekeleza** kuruhusu **kuvuka** saraka. Kwa hivyo, kwa mfano, mtumiaji mwenye **ruhusa ya kusoma juu ya faili** ndani ya saraka ambapo hana ruhusa ya **utekelezaji** **hataweza kusoma** faili hiyo.

### Modifiers ya Bendera

Kuna baadhi ya bendera ambazo zinaweza kuwekwa kwenye faili ambazo zitafanya faili zichukue tabia tofauti. Unaweza **kuangalia bendera** za faili ndani ya saraka na `ls -lO /path/directory`

* **`uchg`**: Inayojulikana kama bendera ya **uchange** itazuia hatua yoyote ya kubadilisha au kufuta **faili**. Kuweka ni: `chflags uchg file.txt`
* Mtumiaji wa mizizi anaweza **kuondoa bendera** na kuhariri faili
* **`restricted`**: Bendera hii inafanya faili ilindwe na SIP (huwezi kuongeza bendera hii kwa faili).
* **`Sticky bit`**: Ikiwa kuna saraka na biti ya kushikamana, **tu** mmiliki wa **saraka au mizizi wanaweza kubadilisha jina au kufuta** faili. Kawaida hii imewekwa kwenye saraka ya /tmp kuzuia watumiaji wa kawaida kufuta au kuhamisha faili za watumiaji wengine.

Bendera zote zinaweza kupatikana kwenye faili `sys/stat.h` (ipate kwa kutumia `mdfind stat.h | grep stat.h`) na ni:

* `UF_SETTABLE` 0x0000ffff: Kifuniko cha bendera inayoweza kubadilishwa na mmiliki.
* `UF_NODUMP` 0x00000001: Usidumishe faili.
* `UF_IMMUTABLE` 0x00000002: Faili haiwezi kubadilishwa.
* `UF_APPEND` 0x00000004: Kuandika kwenye faili kunaweza kuongeza tu.
* `UF_OPAQUE` 0x00000008: Saraka ni isiyoonekana kuhusiana na muungano.
* `UF_COMPRESSED` 0x00000020: Faili imepakwa (baadhi ya mifumo ya faili).
* `UF_TRACKED` 0x00000040: Hakuna arifa kwa kufuta/kubadilisha majina kwa faili zilizo na hii.
* `UF_DATAVAULT` 0x00000080: Haki inahitajika kwa kusoma na kuandika.
* `UF_HIDDEN` 0x00008000: Kiashiria kwamba kipengee hiki haitaki kuonyeshwa kwenye GUI.
* `SF_SUPPORTED` 0x009f0000: Kifuniko cha bendera zinazoungwa mkono na msimamizi.
* `SF_SETTABLE` 0x3fff0000: Kifuniko cha bendera zinazoweza kubadilishwa na msimamizi.
* `SF_SYNTHETIC` 0xc0000000: Kifuniko cha bendera za kusoma tu za mfumo.
* `SF_ARCHIVED` 0x00010000: Faili imehifadhiwa.
* `SF_IMMUTABLE` 0x00020000: Faili haiwezi kubadilishwa.
* `SF_APPEND` 0x00040000: Kuandika kwenye faili kunaweza kuongeza tu.
* `SF_RESTRICTED` 0x00080000: Haki inahitajika kwa kuandika.
* `SF_NOUNLINK` 0x00100000: Kipengee hakiwezi kuondolewa, kubadilishwa jina au kufungwa.
* `SF_FIRMLINK` 0x00800000: Faili ni firmlink.
* `SF_DATALESS` 0x40000000: Faili ni kitu cha dataless.

### **ACL za Faili**

ACL za Faili zina **ACE** (Viingilio vya Kudhibiti Upatikanaji) ambapo ruhusa za **kina zaidi** zinaweza kupewa watumiaji tofauti.

Inawezekana kutoa **ruhusa** hizi kwa **directory**: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Na kwa **faili**: `read`, `write`, `append`, `execute`.

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

* `com.apple.resourceFork`: Ulinganifu wa rasilimali. Pia inaonekana kama `filename/..namedfork/rsrc`
* `com.apple.quarantine`: MacOS: Mfumo wa karantini wa Gatekeeper (III/6)
* `metadata:*`: MacOS: metadata mbalimbali, kama vile `_backup_excludeItem`, au `kMD*`
* `com.apple.lastuseddate` (#PS): Tarehe ya mwisho ya matumizi ya faili
* `com.apple.FinderInfo`: MacOS: Taarifa za Finder (k.m., lebo za rangi)
* `com.apple.TextEncoding`: Inabainisha uendeshaji wa maandishi ya faili za ASCII
* `com.apple.logd.metadata`: Hutumiwa na logd kwenye faili katika `/var/db/diagnostics`
* `com.apple.genstore.*`: Uhifadhi wa kizazi (`/.DocumentRevisions-V100` katika mizizi ya mfumo wa faili)
* `com.apple.rootless`: MacOS: Hutumiwa na System Integrity Protection kuorodhesha faili (III/10)
* `com.apple.uuidb.boot-uuid`: Alama za logd za vipindi vya kuanza upya na UUID ya kipekee
* `com.apple.decmpfs`: MacOS: Ufutwaji wa faili kwa uwazi (II/7)
* `com.apple.cprotect`: \*OS: Data ya kielektroniki ya faili kwa faili (III/11)
* `com.apple.installd.*`: \*OS: Metadata hutumiwa na installd, k.m., `installType`, `uniqueInstallID`

### Rasilimali Forks | macOS ADS

Hii ni njia ya kupata **Mizizi ya Data Mbadala kwenye mashine za MacOS**. Unaweza kuokoa maudhui ndani ya kipengele kilichozidishwa kinachoitwa **com.apple.ResourceFork** ndani ya faili kwa kuokoa katika **file/..namedfork/rsrc**.
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

Kipengele cha ziada `com.apple.decmpfs` inaonyesha kuwa faili imehifadhiwa kwa kuchapwa, `ls -l` itaripoti **ukubwa wa 0** na data iliyosambazwa iko ndani ya kipengele hiki. Kila wakati faili inapofikiwa itadondoshwa kumbukani.

Kipengele hiki kinaweza kuonekana na `ls -lO` kikiashiria kama kilichapwa kwa sababu faili zilizochapwa pia zinatambuliwa na bendera `UF_COMPRESSED`. Ikiwa faili iliyochapwa inaondolewa bendera hii kwa kutumia `chflags nocompressed </path/to/file>`, mfumo hautajua kuwa faili ilichapwa na kwa hivyo haitaweza kuchapua na kupata data (itadhani kuwa ni tupu).

Zana ya afscexpand inaweza kutumika kulazimisha kuchapua faili.

## **Faili za Universal &** Muundo wa Mach-o

Faili za Mac OS kawaida hukusanywa kama **faili za universal**. **Faili ya universal** inaweza **kusaidia miundo mingi ndani ya faili moja**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Kumbukumbu ya Mchakato wa macOS

## Kudondosha Kumbukumbu ya macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Aina za Hatari za Faili za Mac OS

Dhibiti `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ndipo ambapo habari kuhusu **hatari inayohusiana na viendelezi tofauti vya faili** imehifadhiwa. Dhibiti hii inagawa faili katika viwango tofauti vya hatari, ikibadilisha jinsi Safari inavyoshughulikia faili hizi baada ya kupakuliwa. Vikundi ni kama ifuatavyo:

* **LSRiskCategorySafe**: Faili katika kundi hili zinachukuliwa kuwa **salama kabisa**. Safari itafungua faili hizi moja kwa moja baada ya kupakuliwa.
* **LSRiskCategoryNeutral**: Faili hizi hazina onyo lolote na **hazifunguliwi moja kwa moja** na Safari.
* **LSRiskCategoryUnsafeExecutable**: Faili katika kundi hili **huchochea onyo** linaloonyesha kuwa faili ni programu. Hii ni kama hatua ya usalama kumwonya mtumiaji.
* **LSRiskCategoryMayContainUnsafeExecutable**: Kundi hili ni kwa faili, kama vile nyaraka, ambazo zinaweza kuwa na programu inayoweza kutekelezwa. Safari ita **chochea onyo** isipokuwa iweze kuthibitisha kuwa maudhui yote ni salama au yasiyo na hatari.

## Faili za Kumbukumbu

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Ina habari kuhusu faili zilizopakuliwa, kama URL kutoka mahali zilipopakuliwa.
* **`/var/log/system.log`**: Kumbukumbu kuu ya mifumo ya OSX. com.apple.syslogd.plist inahusika na utekelezaji wa syslogging (unaweza kuangalia ikiwa imelemazwa kwa kutafuta "com.apple.syslogd" katika `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Hizi ni Kumbukumbu za Mifumo ya Apple ambayo inaweza kuwa na habari ya kuvutia.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Inahifadhi faili na programu zilizoangaliwa hivi karibuni kupitia "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Inahifadhi vitu vya kuzindua wakati wa kuanza kwa mfumo
* **`$HOME/Library/Logs/DiskUtility.log`**: Faili ya kumbukumbu kwa Programu ya DiskUtility (habari kuhusu diski, pamoja na USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data kuhusu pointi za kupata mtandao zisizo na waya.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Orodha ya daemons iliyozimwa.
