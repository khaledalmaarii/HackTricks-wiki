# macOS Lêers, Vouers, Binêre & Geheue

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **laai HackTricks af in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Lêerhierargie-indeling

* **/Toepassings**: Die geïnstalleerde programme behoort hier te wees. Alle gebruikers sal hulle kan bereik.
* **/bin**: Opdraglyn-binêre
* **/kerne**: Indien dit bestaan, word dit gebruik om kernafleidings te stoor
* **/dev**: Alles word behandel as 'n lêer sodat jy hardewaretoestelle hier gestoor kan sien.
* **/ens**: Opsetlêers
* **/Biblioteek**: 'n Baie subdossiers en lêers wat verband hou met voorkeure, cache en logboeke kan hier gevind word. 'n Biblioteek-vouer bestaan in die wortel en op elke gebruiker se gids.
* **/privaat**: Onbeskryf, maar baie van die genoemde vouers is simboliese skakels na die privaat-gids.
* **/sbin**: Essensiële stelsel-binêre (verwant aan administrasie)
* **/Stelsel**: Lêer om OS X te laat loop. Jy behoort meestal net Apple-spesifieke lêers hier te vind (nie derdeparty nie).
* **/tmp**: Lêers word na 3 dae verwyder (dit is 'n sagte skakel na /privaat/tmp)
* **/Gebruikers**: Tuisgids vir gebruikers.
* **/usr**: Opset- en stelsel-binêre
* **/var**: Loglêers
* **/Volumes**: Die gemoniteerde aandrywings sal hier verskyn.
* **/.vol**: Deur `stat a.txt` te hardloop, verkry jy iets soos `16777223 7545753 -rw-r--r-- 1 gebruikersnaam wiel ...` waar die eerste nommer die id-nommer van die volume waar die lêer bestaan is en die tweede een die inode-nommer is. Jy kan die inhoud van hierdie lêer benader deur /.vol/ met daardie inligting te hardloop `cat /.vol/16777223/7545753`

### Toepassingsvouers

* **Stelseltoepassings** is geleë onder `/Stelsel/Toepassings`
* **Geïnstalleerde** toepassings is gewoonlik geïnstalleer in `/Toepassings` of in `~/Toepassings`
* **Toepassingsdata** kan gevind word in `/Biblioteek/Toepassingondersteuning` vir die toepassings wat as root loop en `~/Biblioteek/Toepassingondersteuning` vir toepassings wat as die gebruiker loop.
* Derdeparty-toepassings **daemons** wat **as root moet loop** is gewoonlik geleë in `/Biblioteek/BevoorregteHulpprogramme/`
* **Gesandboxte** programme word in die `~/Biblioteek/Houers`-vouer afgebeeld. Elke toepassing het 'n vouer wat genoem is volgens die toepassing se bondel-ID (`com.apple.Safari`).
* Die **kern** is geleë in `/Stelsel/Biblioteek/Kerne/kern`
* **Apple se kernuitbreidings** is geleë in `/Stelsel/Biblioteek/Uitbreidings`
* **Derdeparty-kernuitbreidings** word gestoor in `/Biblioteek/Uitbreidings`

### Lêers met Sensitiewe Inligting

MacOS stoor inligting soos wagwoorde op verskeie plekke:

{% content-ref url="macos-sensitiewe-plekke.md" %}
[macos-sensitiewe-plekke.md](macos-sensitiewe-plekke.md)
{% endcontent-ref %}

### Kwesbare pkg-installeerders

{% content-ref url="macos-installeerders-misbruik.md" %}
[macos-installeerders-misbruik.md](macos-installeerders-misbruik.md)
{% endcontent-ref %}

## OS X Spesifieke Uitbreidings

* **`.dmg`**: Apple Skyfafbeeldingslêers is baie algemeen vir installeerders.
* **`.kext`**: Dit moet 'n spesifieke struktuur volg en dit is die OS X-weergawe van 'n bestuurder. (Dit is 'n bondel)
* **`.plist`**: Ook bekend as eienskapslys stoor inligting in XML- of binêre formaat.
* Dit kan XML of binêre wees. Binêre eenhede kan gelees word met:
* `standaarde lees konfig.plist`
* `/usr/libexec/PlistBuddy -c druk konfig.plsit`
* `plutil -p ~/Biblioteek/Voorkeure/com.apple.screensaver.plist`
* `plutil -omskakel xml1 ~/Biblioteek/Voorkeure/com.apple.screensaver.plist -o -`
* `plutil -omskakel json ~/Biblioteek/Voorkeure/com.apple.screensaver.plist -o -`
* **`.app`**: Apple-toepassings wat die gidsstruktuur volg (Dit is 'n bondel).
* **`.dylib`**: Dinamiese biblioteke (soos Windows DLL-lêers)
* **`.pkg`**: Is dieselfde as xar (Uitbreibare Argief-formaat). Die installeerderopdrag kan gebruik word om die inhoud van hierdie lêers te installeer.
* **`.DS_Store`**: Hierdie lêer is in elke gids, dit stoor die eienskappe en aanpassings van die gids.
* **`.Spotlight-V100`**: Hierdie vouer verskyn op die wortelgids van elke volume op die stelsel.
* **`.metadata_never_index`**: As hierdie lêer aan die wortel van 'n volume is, sal Spotlight daardie volume nie indekseer nie.
* **`.noindex`**: Lêers en vouers met hierdie uitbreiding sal nie deur Spotlight geïndekseer word nie.

### macOS Bondels

'n Bondel is 'n **gids** wat **soos 'n voorwerp in Finder lyk** ( 'n Voorbeeld van 'n Bondel is `*.app` lêers).

{% content-ref url="macos-bondels.md" %}
[macos-bondels.md](macos-bondels.md)
{% endcontent-ref %}

## Dyld Gedeelde Keg

Op macOS (en iOS) word alle stelsel gedeelde biblioteke, soos raamwerke en dylibs, **gekombineer in 'n enkele lêer**, genaamd die **dyld gedeelde keg**. Dit verbeter die prestasie, aangesien kode vinniger gelaai kan word.

Soortgelyk aan die dyld gedeelde keg, word die kern en die kernuitbreidings ook saamgestel in 'n kernkeg, wat by opstarttyd gelaai word.

Om die biblioteke uit die enkele lêer dylib gedeelde keg te onttrek, was dit moontlik om die binêre [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) te gebruik wat dalk nie meer werk nie, maar jy kan ook [**dyldextractor**](https://github.com/arandomdev/dyldextractor) gebruik:

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
Merk op dat selfs as die `dyld_shared_cache_util`-werktuig nie werk nie, kan jy die **gedeelde dyld-binêre lêer aan Hopper oorhandig** en sal Hopper in staat wees om al die biblioteke te identifiseer en jou **laat kies watter een** jy wil ondersoek:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1149).png" alt="" width="563"><figcaption></figcaption></figure>

## Spesiale Lêerregte

### Vouerregte

In 'n **vouer** laat **lees** toe om dit te **lys**, **skryf** laat toe om **lêers** daarop te **verwyder** en **skryf** laat toe om die vouer te **deursoek**. Dus, byvoorbeeld, 'n gebruiker met **leestoestemming oor 'n lêer** binne 'n vouer waar hy **nie uitvoeringsregte** het **nie, sal nie in staat wees om** die lêer te lees nie.

### Vlagmodifiseerders

Daar is sekere vlae wat in die lêers ingestel kan word wat die lêer anders laat optree. Jy kan die vlae van die lêers binne 'n vouer nagaan met `ls -lO /pad/vouer`

* **`uchg`**: Bekend as die **uchange**-vlag sal **enige aksie** wat die **lêer** verander of verwyder **voorkom**. Om dit in te stel doen: `chflags uchg lêer.txt`
* Die root-gebruiker kan die vlag **verwyder** en die lêer wysig
* **`beperk`**: Hierdie vlag maak die lêer **beskerm deur SIP** (jy kan nie hierdie vlag by 'n lêer voeg nie).
* **`Sticky bit`**: As 'n vouer 'n plakkerige bit het, kan **slegs** die **vouereienaar of root** lêers hernoem of verwyder. Tipies word dit ingestel op die /tmp-vouer om gewone gebruikers te verhoed om ander gebruikers se lêers te verwyder of te skuif.

Al die vlae kan in die lêer `sys/stat.h` gevind word (vind dit met `mdfind stat.h | grep stat.h`) en is:

* `UF_SETTABLE` 0x0000ffff: Masker van eienaar-veranderbare vlae.
* `UF_NODUMP` 0x00000001: Moet lêer nie dump nie.
* `UF_IMMUTABLE` 0x00000002: Lêer mag nie verander word nie.
* `UF_APPEND` 0x00000004: Skrywes na lêer mag slegs aangeheg word.
* `UF_OPAQUE` 0x00000008: Vouer is ondeursigtig t.o.v. unie.
* `UF_COMPRESSED` 0x00000020: Lêer is saamgedruk (sekere lêersisteme).
* `UF_TRACKED` 0x00000040: Geen kennisgewings vir verwyderings/hernoemings vir lêers met hierdie stel.
* `UF_DATAVAULT` 0x00000080: Toestemming vereis vir lees en skryf.
* `UF_HIDDEN` 0x00008000: Aanduiding dat hierdie item nie in 'n GUI vertoon moet word nie.
* `SF_SUPPORTED` 0x009f0000: Masker van supergebruiker-ondersteunde vlae.
* `SF_SETTABLE` 0x3fff0000: Masker van supergebruiker-veranderbare vlae.
* `SF_SYNTHETIC` 0xc0000000: Masker van stelsel slegs-lees sintetiese vlae.
* `SF_ARCHIVED` 0x00010000: Lêer is ge-argiveer.
* `SF_IMMUTABLE` 0x00020000: Lêer mag nie verander word nie.
* `SF_APPEND` 0x00040000: Skrywes na lêer mag slegs aangeheg word.
* `SF_RESTRICTED` 0x00080000: Toestemming vereis vir skryf.
* `SF_NOUNLINK` 0x00100000: Item mag nie verwyder, hernoem of aangeheg word nie.
* `SF_FIRMLINK` 0x00800000: Lêer is 'n firmlink.
* `SF_DATALESS` 0x40000000: Lêer is 'n datalose voorwerp.

### **Lêer ACL's**

Lêer **ACL's** bevat **ACE** (Toegangsbeheerinskrywings) waar meer **fynkorrelige regte** aan verskillende gebruikers toegewys kan word.

Dit is moontlik om 'n **vouer** hierdie regte te gee: `lys`, `soek`, `voeg_lêer_by`, `voeg_subvouer_by`, `verwyder_kind`, `verwyder_kind`.\
En aan 'n **lêer**: `lees`, `skryf`, `aanheg`, `uitvoer`.

Wanneer die lêer ACL's bevat, sal jy 'n "+" vind wanneer jy die regte lys soos in:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Jy kan die **ACL's lees** van die lêer met:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Jy kan **alle lêers met ACLs vind** met (dit is baaaie stadig):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Uitgebreide Eienskappe

Uitgebreide eienskappe het 'n naam en enige gewenste waarde, en kan gesien word deur `ls -@` te gebruik en gemanipuleer word met behulp van die `xattr` bevel. Sommige algemene uitgebreide eienskappe is:

- `com.apple.resourceFork`: Hulpbronvurkverenigbaarheid. Ook sigbaar as `lêernaam/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Gatekeeper karantynmeganisme (III/6)
- `metadata:*`: MacOS: verskeie metadata, soos `_backup_excludeItem`, of `kMD*`
- `com.apple.lastuseddate` (#PS): Laaste lêer gebruik datum
- `com.apple.FinderInfo`: MacOS: Finder-inligting (bv., kleur Etikette)
- `com.apple.TextEncoding`: Spesifiseer teksenkodering van ASCII-tekslêers
- `com.apple.logd.metadata`: Gebruik deur logd op lêers in `/var/db/diagnostics`
- `com.apple.genstore.*`: Generasie stoor (`/.DocumentRevisions-V100` in die wortel van die lêersisteem)
- `com.apple.rootless`: MacOS: Gebruik deur Stelselintegriteitsbeskerming om lêer te etiketteer (III/10)
- `com.apple.uuidb.boot-uuid`: logd-merkings van opstarts met unieke UUID
- `com.apple.decmpfs`: MacOS: Deursigtige lêerkompressie (II/7)
- `com.apple.cprotect`: \*OS: Per-lêer enkripsiedata (III/11)
- `com.apple.installd.*`: \*OS: Metadata gebruik deur installd, bv., `installType`, `uniqueInstallID`

### Hulpbronvurke | macOS ADS

Dit is 'n manier om **Alternatiewe Datastrome in MacOS**-toestelle te verkry. Jy kan inhoud binne 'n uitgebreide eienskap genaamd **com.apple.ResourceFork** binne 'n lêer stoor deur dit te stoor in **lêernaam/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Jy kan **alle lêers wat hierdie uitgebreide attribuut bevat, vind met:**

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Die uitgebreide attribuut `com.apple.decmpfs` dui aan dat die lêer versleutel is, `ls -l` sal 'n **grootte van 0** rapporteer en die saamgedrukte data is binne hierdie attribuut. Telkens wanneer die lêer benader word, sal dit in die geheue ontsluit word.

Hierdie attribuut kan gesien word met `ls -lO` aangedui as saamgedruk omdat saamgedrukte lêers ook gemerk is met die vlag `UF_COMPRESSED`. As 'n saamgedrukte lêer verwyder word, sal hierdie vlag met `chflags nocompressed </path/to/file>` verwyder word, die stelsel sal dan nie weet dat die lêer saamgedruk was nie en daarom sal dit nie in staat wees om die data te ontsluit en toegang te verkry nie (dit sal dink dat dit eintlik leeg is).

Die instrument afscexpand kan gebruik word om 'n lêer kragtig te ontsluit.

## **Universele lêers &** Mach-o-formaat

Mac OS-lêers is gewoonlik saamgestel as **universele lêers**. 'n **Universele lêer** kan **verskeie argitekture in dieselfde lêer ondersteun**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS-geheue-aflees

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risikokategorie-lêers Mac OS

Die gids `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` is waar inligting oor die **risiko wat met verskillende lêeruitbreidings verband hou, gestoor word**. Hierdie gids kategoriseer lêers in verskeie risikovlakke, wat beïnvloed hoe Safari hierdie lêers hanteer wanneer dit afgelaai word. Die kategorieë is as volg:

* **LSRiskCategorySafe**: Lêers in hierdie kategorie word as **heeltemal veilig** beskou. Safari sal hierdie lêers outomaties oopmaak nadat hulle afgelaai is.
* **LSRiskCategoryNeutral**: Hierdie lêers kom sonder waarskuwings en word **nie outomaties oopgemaak** deur Safari nie.
* **LSRiskCategoryUnsafeExecutable**: Lêers onder hierdie kategorie **lok 'n waarskuwing** uit wat aandui dat die lêer 'n aansoek is. Dit dien as 'n sekuriteitsmaatreël om die gebruiker te waarsku.
* **LSRiskCategoryMayContainUnsafeExecutable**: Hierdie kategorie is vir lêers, soos argiewe, wat 'n uitvoerbare lêer mag bevat. Safari sal 'n waarskuwing **uitlok** tensy dit kan verifieer dat alle inhoud veilig of neutraal is.

## Log lêers

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Bevat inligting oor afgelaai lêers, soos die URL waarvandaan hulle afgelaai is.
* **`/var/log/system.log`**: Hooflog van OSX-stelsels. com.apple.syslogd.plist is verantwoordelik vir die uitvoering van die stelsellog (jy kan nagaan of dit gedeaktiveer is deur te soek na "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Dit is die Apple-stelsellogboeke wat dalk interessante inligting bevat.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Berg onlangs benaderde lêers en aansoeke deur "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Berg items om te begin met die stelselopstart
* **`$HOME/Library/Logs/DiskUtility.log`**: Log lêer vir die DiskUtility-toep (inligting oor aandrywings, insluitend USB's)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data oor draadlose toegangspunte.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lys van gedeaktiveerde daemons.
