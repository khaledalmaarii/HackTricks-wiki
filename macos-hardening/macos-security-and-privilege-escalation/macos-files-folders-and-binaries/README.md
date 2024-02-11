# Faili, Folda, na Programu za macOS & Kumbukumbu

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Muundo wa Hiyerakia ya Faili

* **/Applications**: Programu zilizosakinishwa zinapaswa kuwa hapa. Watumiaji wote wataweza kuzifikia.
* **/bin**: Programu za amri za mstari
* **/cores**: Ikiwepo, hutumiwa kuhifadhi kumbukumbu za msingi
* **/dev**: Kila kitu kinachotibiwa kama faili, kwa hivyo unaweza kuona vifaa vya vifaa vilivyohifadhiwa hapa.
* **/etc**: Faili za usanidi
* **/Library**: Sehemu nyingi na faili zinazohusiana na mapendeleo, akiba, na magogo zinaweza kupatikana hapa. Folda ya Maktaba iko kwenye mzizi na kwenye folda ya kila mtumiaji.
* **/private**: Haijathibitishwa lakini folda nyingi zilizotajwa ni viungo vya ishara kwa folda ya kibinafsi.
* **/sbin**: Programu muhimu za mfumo (zinazohusiana na usimamizi)
* **/System**: Faili za kuendesha OS X. Unapaswa kupata hasa faili za Apple hapa (sio za watu wa tatu).
* **/tmp**: Faili zinafutwa baada ya siku 3 (ni kiungo laini kwa /private/tmp)
* **/Users**: Folda ya nyumbani kwa watumiaji.
* **/usr**: Usanidi na programu za mfumo
* **/var**: Faili za kuingiza
* **/Volumes**: Drives zilizounganishwa zitaonekana hapa.
* **/.vol**: Ukikimbia `stat a.txt` utapata kitu kama `16777223 7545753 -rw-r--r-- 1 username wheel ...` ambapo nambari ya kwanza ni nambari ya kitambulisho ya kiasi ambapo faili inapatikana na ya pili ni nambari ya inode. Unaweza kupata yaliyomo ya faili hii kupitia /.vol/ na habari hiyo ukikimbia `cat /.vol/16777223/7545753`

### Folda za Programu

* **Programu za mfumo** ziko chini ya `/System/Applications`
* **Programu zilizosakinishwa** kawaida zinasakinishwa katika `/Applications` au katika `~/Applications`
* **Data ya programu** inaweza kupatikana katika `/Library/Application Support` kwa programu zinazotumika kama mizizi na `~/Library/Application Support` kwa programu zinazotumika kama mtumiaji.
* **Daemons** za programu za watu wa tatu **zinahitaji kukimbia kama mizizi** kawaida ziko katika `/Library/PrivilegedHelperTools/`
* Programu **zilizofungwa kwenye sanduku** zimepangwa katika folda ya `~/Library/Containers`. Kila programu ina folda iliyoitwa kulingana na Kitambulisho cha Pakiti cha programu (`com.apple.Safari`).
* **Kernel** iko katika `/System/Library/Kernels/kernel`
* **Nyongeza za kernel za Apple** ziko katika `/System/Library/Extensions`
* **Nyongeza za kernel za watu wa tatu** zimehifadhiwa katika `/Library/Extensions`

### Faili zenye Taarifa Nyeti

MacOS inahifadhi habari kama nywila katika maeneo kadhaa:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Wadukuzi wa Pkg Wanaoweza Kudhurika

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Nyongeza Maalum za OS X

* **`.dmg`**: Faili za Picha za Diski za Apple ni za kawaida sana kwa wasakinishaji.
* **`.kext`**: Inapaswa kufuata muundo maalum na ni toleo la OS X la dereva. (ni kifurushi)
* **`.plist`**: Inajulikana pia kama orodha ya mali inahifadhi habari katika muundo wa XML au binary.
* Inaweza kuwa XML au binary. Zile za binary zinaweza kusomwa na:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Programu za Apple zinazofuata muundo wa folda (Ni kifurushi).
* **`.dylib`**: Maktaba za kudumu (kama faili za DLL za Windows)
* **`.pkg`**: Ni sawa na xar (muundo wa Kumbukumbu Unaojulikana). Amri ya wasakinishaji inaweza kutumika kusakinisha yaliyomo ya faili hizi.
* **`.DS_Store`**: Faili hii iko kwenye kila saraka, inahifadhi sifa na ubinafsishaji wa saraka.
* **`.Spotlight-V100`**: Folda hii inaonekana kwenye saraka ya mzizi ya kila kiasi kwenye mfumo.
* **`.metadata_never_index`**: Ikiwa faili hii iko kwenye mzizi wa kiasi, Spotlight haitaunda faharisi ya kiasi hicho.
* **`.noindex`**: Faili na saraka zenye kifungu hiki hazitafaharishwa na Spotlight.

### Vifurushi vya macOS

Kifurushi ni **folda** ambayo **inaonekana kama kitu katika Finder** (mfano wa kifurushi ni faili za `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Hifadhi ya Pamoja ya Dyld

Kwenye macOS (na iOS) maktaba za pamoja za mfumo, kama fremu na dylib, zinaunganishwa katika faili moja, inayoitwa **hifadhi ya pamoja ya dyld**. Hii inaboresha utendaji, kwani namna ya namna inaweza kupakia haraka.

Kama hifadhi ya pamoja ya dyld, kernel na nyongeza za kernel pia zimekamilishwa katika hifadhi ya kernel, ambayo inapakia wakati wa kuanza.

Ili kutoa maktaba kutoka kwenye faili moja ya hifadhi ya pamoja ya dylib, ilikuwa inawezekana kutumia binary [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) ambayo labda haifanyi kazi siku hizi lakini unaweza pia kutumia [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

Katika toleo za zamani unaweza kupata **shared cache** katika **`/System/Library/dyld/`**.

Katika iOS unaweza kuzipata katika **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Tambua kwamba hata kama zana ya `dyld_shared_cache_util` haifanyi kazi, unaweza kumfikishia **binary ya dyld iliyoshirikiwa kwa Hopper** na Hopper ataweza kutambua maktaba zote na kukuruhusu **kuchagua ni ipi** unayotaka kuchunguza:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Mamlaka Maalum ya Faili

### Mamlaka ya Folda

Katika **folda**, **kusoma** inaruhusu **kuorodhesha**, **kuandika** inaruhusu **kufuta** na **kuandika** faili ndani yake, na **kutekeleza** inaruhusu **kupitia** saraka. Kwa hivyo, kwa mfano, mtumiaji mwenye **mamlaka ya kusoma juu ya faili** ndani ya saraka ambapo hana **mamlaka ya kutekeleza** **hataweza kusoma** faili hiyo.

### Viongeza vya Bendera

Kuna viongeza kadhaa ambavyo vinaweza kuwekwa kwenye faili ambavyo vitafanya faili ifanye kazi tofauti. Unaweza **kuchunguza viongeza** vya faili ndani ya saraka na `ls -lO /njia/saraka`

* **`uchg`**: Inajulikana kama bendera ya **uchange** itazuia **hatua yoyote** ya kubadilisha au kufuta **faili**. Kuweka bendera hiyo fanya: `chflags uchg file.txt`
* Mtumiaji wa mizizi anaweza **kuondoa bendera** na kubadilisha faili
* **`restricted`**: Bendera hii inafanya faili iwe **imekingwa na SIP** (hauwezi kuongeza bendera hii kwenye faili).
* **`Sticky bit`**: Ikiwa kuna saraka na biti ya kushikamana, **tu** mmiliki wa **saraka au mizizi inaweza kubadilisha jina au kufuta** faili. Kawaida hii imewekwa kwenye saraka ya /tmp ili kuzuia watumiaji wa kawaida kufuta au kuhamisha faili za watumiaji wengine.

### **ACL za Faili**

ACL za faili zina **ACE** (Kuingia Kudhibiti Upatikanaji) ambapo mamlaka zaidi **za kina** zinaweza kupewa watumiaji tofauti.

Inawezekana kutoa **mamlaka haya** kwa **saraka**: `orodhesha`, `tafuta`, `ongeza_faili`, `ongeza_saraka_ndogo`, `futa_mtoto`, `futa_mtoto`.\
Na kwa **faili**: `soma`, `andika`, `ongeza`, `tekeleza`.

Wakati faili ina ACL, utaona **"+" wakati wa kuorodhesha mamlaka kama vile**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Unaweza **kusoma ACLs** ya faili kwa kutumia:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Unaweza kupata **faili zote zenye ACLs** kwa kutumia (hii ni polepole sana):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Vyanzo vya Rasilimali | macOS ADS

Hii ni njia ya kupata **Alternate Data Streams kwenye mashine za MacOS**. Unaweza kuokoa maudhui ndani ya sifa iliyopanuliwa inayoitwa **com.apple.ResourceFork** ndani ya faili kwa kuokoa katika **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Unaweza **kupata faili zote zinazohifadhi sifa hii ya ziada** kwa kutumia:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Universal binaries &** Mach-o Format

Binaries za Mac OS kawaida zinakusanywa kama **universal binaries**. **Universal binary** inaweza **kusaidia miundo tofauti ya usanidi katika faili moja**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Kudumpisha Kumbukumbu ya macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Pembejeo za Hatari za Faili za Mac OS

Folda `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ndio mahali ambapo habari kuhusu **hatari zinazohusiana na viendelezi tofauti vya faili zimehifadhiwa**. Folda hii inagawa faili katika viwango tofauti vya hatari, ikiongoza jinsi Safari inavyoshughulikia faili hizi baada ya kuzipakua. Vikundi hivi ni kama ifuatavyo:

- **LSRiskCategorySafe**: Faili katika kundi hili inachukuliwa kuwa **salama kabisa**. Safari itaifungua faili hii moja kwa moja baada ya kupakuliwa.
- **LSRiskCategoryNeutral**: Faili hizi hazina onyo na **hazifunguliwi moja kwa moja** na Safari.
- **LSRiskCategoryUnsafeExecutable**: Faili zilizo chini ya kundi hili **zinasababisha onyo** linaloonyesha kuwa faili hiyo ni programu. Hii ni hatua ya usalama ya kumjulisha mtumiaji.
- **LSRiskCategoryMayContainUnsafeExecutable**: Kundi hili ni kwa ajili ya faili, kama vile nyaraka, ambazo zinaweza kuwa na programu. Safari itatoa **onyo** isipokuwa iweze kuthibitisha kuwa yaliyomo yote ni salama au yana hatari ya kawaida.

## Faili za Kumbukumbu

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Ina habari kuhusu faili zilizopakuliwa, kama vile URL ambapo zilipakuliwa.
* **`/var/log/system.log`**: Kumbukumbu kuu ya mifumo ya OSX. com.apple.syslogd.plist inahusika na utekelezaji wa syslogging (unaweza kuangalia ikiwa imelemazwa kwa kutafuta "com.apple.syslogd" katika `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Hizi ni Kumbukumbu za Mfumo wa Apple ambazo zinaweza kuwa na habari muhimu.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Inahifadhi faili na programu zilizotembelewa hivi karibuni kupitia "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Inahifadhi vitu vya kuzindua wakati wa kuanza kwa mfumo.
* **`$HOME/Library/Logs/DiskUtility.log`**: Faili ya kumbukumbu ya Programu ya DiskUtility (habari kuhusu diski, pamoja na USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data kuhusu vituo vya kupata mtandao wa wireless.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Orodha ya daemons iliyozimwa.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
