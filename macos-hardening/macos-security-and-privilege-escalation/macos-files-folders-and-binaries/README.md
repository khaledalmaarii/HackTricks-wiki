# macOS Lêers, Vouers, Binêre & Geheue

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Lêerhiërargie-uitleg

* **/Applications**: Die geïnstalleerde programme moet hier wees. Alle gebruikers sal daartoe toegang hê.
* **/bin**: Opdraglyn-binêre
* **/cores**: As dit bestaan, word dit gebruik om kernaflewerings te stoor
* **/dev**: Alles word as 'n lêer hanteer, sodat jy hardewaretoestelle hier kan sien.
* **/etc**: Konfigurasie-lêers
* **/Library**: 'n Groot aantal subgids en lêers wat verband hou met voorkeure, cache en logboeke kan hier gevind word. 'n Library-gids bestaan in die wortel en in elke gebruiker se gids.
* **/private**: Onbeskryf, maar baie van die genoemde vouers is simboliese skakels na die private-gids.
* **/sbin**: Essensiële stelsel-binêre (verwant aan administrasie)
* **/System**: Lêer om OS X te laat loop. Jy moet meestal net Apple-spesifieke lêers hier vind (nie van derde party nie).
* **/tmp**: Lêers word na 3 dae uitgewis (dit is 'n sagte skakel na /private/tmp)
* **/Users**: Tuisgids vir gebruikers.
* **/usr**: Konfigurasie- en stelsel-binêre
* **/var**: Loglêers
* **/Volumes**: Die gemonteerde aandrywings sal hier verskyn.
* **/.vol**: Deur `stat a.txt` uit te voer, verkry jy iets soos `16777223 7545753 -rw-r--r-- 1 gebruikersnaam wiel ...` waar die eerste nommer die id-nommer van die volume is waar die lêer bestaan en die tweede een die inode-nommer is. Jy kan die inhoud van hierdie lêer benader deur /.vol/ met daardie inligting uit te voer `cat /.vol/16777223/7545753`

### Toepassingsvouers

* **Stelseltoepassings** is geleë onder `/System/Applications`
* **Geïnstalleerde** toepassings word gewoonlik geïnstalleer in `/Applications` of in `~/Applications`
* **Toepassingsdata** kan gevind word in `/Library/Application Support` vir toepassings wat as root uitgevoer word en `~/Library/Application Support` vir toepassings wat as die gebruiker uitgevoer word.
* Derdeparty-toepassings **daemons** wat **as root moet loop**, is gewoonlik geleë in `/Library/PrivilegedHelperTools/`
* **Gesandbokseerde** programme word gekarteer na die `~/Library/Containers`-gids. Elke toepassing het 'n gids met die naam van die toepassing se bundel-ID (`com.apple.Safari`).
* Die **kernel** is geleë in `/System/Library/Kernels/kernel`
* **Apple se kernel-uitbreidings** is geleë in `/System/Library/Extensions`
* **Derdeparty-kernel-uitbreidings** word gestoor in `/Library/Extensions`

### Lêers met Sensitiewe Inligting

MacOS stoor inligting soos wagwoorde op verskeie plekke:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Kwesbare pkg-installeerders

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X Spesifieke Uitbreidings

* **`.dmg`**: Apple Disk Image-lêers is baie algemeen vir installeerders.
* **`.kext`**: Dit moet 'n spesifieke struktuur volg en dit is die OS X-weergawe van 'n bestuurder. (Dit is 'n bundel)
* **`.plist`**: Ook bekend as eienskapslys, stoor inligting in XML- of binêre formaat.
* Dit kan XML of binêre wees. Binêre eenhede kan gelees word met:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Apple-toepassings wat die gidsstruktuur volg (Dit is 'n bundel).
* **`.dylib`**: Dinamiese biblioteke (soos Windows DLL-lêers)
* **`.pkg`**: Dit is dieselfde as xar (eXtensible Archive-formaat). Die installer-opdrag kan gebruik word om die inhoud van hierdie lêers te installeer.
* **`.DS_Store`**: Hierdie lêer is in elke gids, dit stoor die eienskappe en aanpassings van die gids.
* **`.Spotlight-V100`**: Hierdie vouer verskyn op die wortelgids van elke volume op die stelsel.
* **`.metadata_never_index`**: As hierdie lêer aan die wortel van 'n volume is, sal Spotlight daardie volume nie indeks nie.
* **`.noindex`**: Lêers en vouers met hierdie uitbreiding sal nie deur Spotlight geïndekseer word nie.

### macOS-bundels

'n Bundel is 'n **gids** wat **lyk soos 'n voorwerp in Finder** ('n voorbeeld van 'n bundel is `*.app`-lêers).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Gedeelde Cache

Op macOS (en iOS) word alle stelsel gedeelde biblioteke, soos raamwerke en dylibs, **gekombineer in 'n enkele lêer**, genaamd die **dyld gedeelde cache**. Dit verbeter die prestasie, aangesien kode vinniger gelaai kan word.

Soortgelyk aan die dyld gedeelde cache, word die kernel en die kernel-uitbreidings ook saamgestel in 'n kernel-cache wat by die opstarttyd gelaai word.

Om die biblioteke uit die enkele lêer dylib gedeelde cache te onttrek, was dit moontlik om die binêre [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) te gebruik wat dalk nie meer werk nie, maar jy kan ook [**dyldextractor**](https://github.com/arandomdev/dyldextractor) gebruik:

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

In ouer weergawes kan jy die **gedeelde cache** in **`/System/Library/dyld/`** vind.

In iOS kan jy hulle vind in **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Let daarop dat selfs as die `dyld_shared_cache_util`-instrument nie werk nie, kan jy die **gedeelde dyld-binêre aan Hopper oorhandig** en Hopper sal in staat wees om al die biblioteke te identifiseer en jou **laat kies watter een** jy wil ondersoek:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Spesiale Lêerregte

### Vouerregte

In 'n **vouer** laat **lees** toe om dit te **lys**, **skryf** laat toe om lêers daarop te **verwyder** en **skryf** en **uitvoer** laat toe om deur die gids te **beweeg**. So, byvoorbeeld, 'n gebruiker met **leestoestemming oor 'n lêer** binne 'n gids waar hy **nie uitvoer** toestemming het **nie sal nie in staat wees om** die lêer te lees nie.

### Vlagwysigers

Daar is sekere vlae wat in die lêers ingestel kan word wat die gedrag van die lêer anders maak. Jy kan die vlae van die lêers binne 'n gids **nagaan met `ls -lO /pad/gids`**

* **`uchg`**: Bekend as die **uchange**-vlag sal enige aksie wat die **lêer verander of verwyder** voorkom. Om dit in te stel, doen: `chflags uchg lêer.txt`
* Die root-gebruiker kan die vlag **verwyder** en die lêer wysig
* **`restricted`**: Hierdie vlag maak die lêer **beskerm deur SIP** (jy kan hierdie vlag nie by 'n lêer voeg nie).
* **`Sticky bit`**: As 'n gids 'n plakkerige bit het, kan **slegs** die **gidseienaar of root lêers hernoem of verwyder**. Tipies word dit op die /tmp-gids ingestel om te voorkom dat gewone gebruikers ander gebruikers se lêers verwyder of skuif.

### **Lêer ACL's**

Lêer **ACL's** bevat **ACE's** (Access Control Entries) waar meer **fynkorrelige regte** aan verskillende gebruikers toegewys kan word.

Dit is moontlik om hierdie regte aan 'n **gids** toe te ken: `lys`, `soek`, `voeg_lêer_by`, `voeg_subgids_by`, `verwyder_kind`, `verwyder_kind`.\
En aan 'n **lêer**: `lees`, `skryf`, `aanheg`, `uitvoer`.

Wanneer die lêer ACL's bevat, sal jy 'n "+" vind wanneer jy die regte lys, soos in:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Jy kan die ACL's van die lêer lees met:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Jy kan **alle lêers met ACL's** vind met (dit is baie stadig):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Bronvurke | macOS ADS

Dit is 'n manier om **Alternatiewe Datastrome in MacOS**-masjiene te verkry. Jy kan inhoud binne 'n uitgebreide eienskap genaamd **com.apple.ResourceFork** in 'n lêer stoor deur dit in **file/..namedfork/rsrc** te stoor.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Jy kan **alle lêers wat hierdie uitgebreide eienskap bevat**, vind met:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Universele binaêre &** Mach-o-formaat

Mac OS-binaêre lêers word gewoonlik saamgestel as **universele binaêre lêers**. 'n **Universele binaêre lêer** kan **ondersteuning bied vir verskeie argitekture in dieselfde lêer**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS-geheue-afvoer

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risikokategorie-lêers Mac OS

Die gids `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` is waar inligting oor die **risiko wat verband hou met verskillende lêeruitbreidings** gestoor word. Hierdie gids kategoriseer lêers in verskillende risikovlakke, wat beïnvloed hoe Safari hierdie lêers hanteer wanneer dit afgelaai word. Die kategorieë is as volg:

- **LSRiskCategorySafe**: Lêers in hierdie kategorie word as **volkome veilig** beskou. Safari sal hierdie lêers outomaties oopmaak nadat hulle afgelaai is.
- **LSRiskCategoryNeutral**: Hierdie lêers kom sonder waarskuwings en word deur Safari **nie outomaties oopgemaak** nie.
- **LSRiskCategoryUnsafeExecutable**: Lêers onder hierdie kategorie **aktiveer 'n waarskuwing** wat aandui dat die lêer 'n toepassing is. Dit dien as 'n sekuriteitsmaatreël om die gebruiker te waarsku.
- **LSRiskCategoryMayContainUnsafeExecutable**: Hierdie kategorie is vir lêers, soos argiewe, wat 'n uitvoerbare lêer kan bevat. Safari sal 'n waarskuwing **aktiveer** tensy dit kan verifieer dat alle inhoud veilig of neutraal is.

## Loglêers

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Bevat inligting oor afgelaai lêers, soos die URL waarvandaan hulle afgelaai is.
* **`/var/log/system.log`**: Hooflog van OSX-stelsels. com.apple.syslogd.plist is verantwoordelik vir die uitvoering van syslogging (jy kan nagaan of dit gedeaktiveer is deur te soek na "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Dit is die Apple-stelsellogboeke wat interessante inligting kan bevat.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stoor onlangs benaderde lêers en toepassings deur "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stoor items om by stelselopstart te begin
* **`$HOME/Library/Logs/DiskUtility.log`**: Loglêer vir die DiskUtility-toepassing (inligting oor aandrywings, insluitend USB's)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data oor draadlose toegangspunte.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lys van gedeaktiveerde daemons.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
