# macOS SIP

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## **Basiese Inligting**

**System Integrity Protection (SIP)** in macOS is 'n meganisme wat ontwerp is om selfs die mees bevoorregte gebruikers te verhoed om ongemagtigde veranderinge aan sleutel-sisteemlêers te maak. Hierdie funksie speel 'n kritieke rol in die handhawing van die integriteit van die stelsel deur aksies soos die byvoeging, wysiging of verwydering van lêers in beskermde areas te beperk. Die primêre lêers wat deur SIP beskerm word, sluit in:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Die reëls wat SIP se gedrag bepaal, word gedefinieer in die konfigurasie-lêer wat geleë is by **`/System/Library/Sandbox/rootless.conf`**. Binne hierdie lêer word paaie wat voorafgegaan word deur 'n asterisk (*) aangedui as uitsonderings op die andersins streng SIP-beperkings.

Oorweeg die volgende voorbeeld:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Hierdie stukkie impliseer dat terwyl SIP oor die algemeen die **`/usr`**-gids beveilig, daar spesifieke subgidse (`/usr/libexec/cups`, `/usr/local`, en `/usr/share/man`) is waar wysigings toegelaat word, soos aangedui deur die asterisk (*) voor hul paaie.

Om te verifieer of 'n gids of lêer deur SIP beskerm word, kan jy die **`ls -lOd`**-opdrag gebruik om te kyk vir die teenwoordigheid van die **`restricted`** of **`sunlnk`**-vlag. Byvoorbeeld:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In hierdie geval dui die **`sunlnk`** vlag aan dat die `/usr/libexec/cups` gids self **nie uitgevee kan word nie**, alhoewel lêers binne dit geskep, gewysig of uitgevee kan word.

Aan die ander kant:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hier, die **`beperkte`** vlag dui aan dat die `/usr/libexec` gids beskerm word deur SIP. In 'n SIP-beskermde gids kan lêers nie geskep, gewysig, of uitgevee word nie.

Verder, as 'n lêer die **`com.apple.rootless`** uitgebreide **kenmerk** bevat, sal daardie lêer ook deur SIP **beskerm word**.

**SIP beperk ook ander root-aksies** soos:

* Laai onbetroubare kernel-uitbreidings
* Kry taakpoorte vir Apple-ondertekende prosesse
* Wysig NVRAM-veranderlikes
* Kernel-afstel toelaat

Opsies word in die nvram-veranderlike as 'n bitvlag onderhou (`csr-active-config` op Intel en `lp-sip0` word gelees uit die geboote Device Tree vir ARM). Jy kan die vlae in die XNU-bronkode in `csr.sh` vind:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP Status

Jy kan nagaan of SIP op jou stelsel geaktiveer is met die volgende opdrag:
```bash
csrutil status
```
As jy SIP wil deaktiveer, moet jy jou rekenaar herlaai in herstelmodus (deur Commando+R tydens opstart te druk), en dan die volgende bevel uitvoer:
```bash
csrutil disable
```
As jy wil hê SIP moet aangeskakel bly, maar die ontsluitingsbeskerming wil verwyder, kan jy dit doen met:
```bash
csrutil enable --without debug
```
### Ander Beperkings

- **Verbied die laai van ongetekende kernel-uitbreidings** (kexts), wat verseker dat slegs geverifieerde uitbreidings met die stelselkernel interaksie het.
- **Voorkom die afstel** van macOS-stelselprosesse, wat die kernkomponente van die stelsel teen ongemagtigde toegang en wysiging beskerm.
- **Belemmer hulpmiddels** soos dtrace om stelselprosesse te ondersoek, wat die integriteit van die stelsel se werking verder beskerm.

**[Leer meer oor SIP-inligting in hierdie praatjie](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## SIP-Omseilings

Om SIP te omseil, stel 'n aanvaller in staat om:

- **Toegang tot gebruikersdata**: Lees sensitiewe gebruikersdata soos e-pos, boodskappe en Safari-geskiedenis van alle gebruikersrekeninge.
- **TCC-omseiling**: Direk die TCC (Transparency, Consent, and Control) databasis manipuleer om ongemagtigde toegang tot die webkamera, mikrofoon en ander hulpbronne te verleen.
- **Volharding vestig**: Plaas kwaadwillige sagteware in SIP-beskermde liggings, wat dit bestand maak teen verwydering, selfs deur root-voorregte. Dit sluit ook die potensiaal in om met die Malware Removal Tool (MRT) te knoei.
- **Laai kernel-uitbreidings**: Alhoewel daar addisionele beskermings is, vereenvoudig die omseiling van SIP die proses om ongetekende kernel-uitbreidings te laai.

### Installeerderpakkette

**Installeerderpakkette wat onderteken is met Apple se sertifikaat**, kan sy beskerming omseil. Dit beteken dat selfs pakkette wat deur standaardontwikkelaars onderteken is, geblokkeer sal word as hulle probeer om SIP-beskermde gidslys te wysig.

### Nie-bestaande SIP-lêer

Een potensiële gaping is dat as 'n lêer in **`rootless.conf` gespesifiseer word maar tans nie bestaan nie**, dit geskep kan word. Kwaadwillige sagteware kan hiervan gebruik maak om **volharding te vestig** op die stelsel. Byvoorbeeld, 'n kwaadwillige program kan 'n .plist-lêer skep in `/System/Library/LaunchDaemons` as dit in `rootless.conf` gelys word maar nie teenwoordig is nie.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Die toekenning **`com.apple.rootless.install.heritable`** maak dit moontlik om SIP te omseil.
{% endhint %}

#### Shrootless

[**Navorsers van hierdie blogpos**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) het 'n kwesbaarheid in macOS se System Integrity Protection (SIP) meganisme ontdek, genaamd die 'Shrootless' kwesbaarheid. Hierdie kwesbaarheid draai om die **`system_installd`** daemon, wat 'n toekenning, **`com.apple.rootless.install.heritable`**, het wat enige van sy kinderprosesse toelaat om SIP se lêersisteembeperkings te omseil.

**`system_installd`** daemon sal pakkette installeer wat deur **Apple** onderteken is.

Navorsers het bevind dat tydens die installasie van 'n Apple-ondertekende pakkie (.pkg-lêer), **`system_installd`** enige **post-install** skripte wat in die pakkie ingesluit is, **uitvoer**. Hierdie skripte word deur die verstekskulp, **`zsh`**, uitgevoer wat outomaties opdragte uit die **`/etc/zshenv`**-lêer uitvoer as dit bestaan, selfs in nie-interaktiewe modus. Hierdie gedrag kan deur aanvallers uitgebuit word: deur 'n kwaadwillige `/etc/zshenv`-lêer te skep en te wag vir **`system_installd` om `zsh` aan te roep**, kan hulle arbitrêre handelinge op die toestel uitvoer.

Daarbenewens is daar ontdek dat **`/etc/zshenv as 'n algemene aanvalstegniek gebruik kan word**, nie net vir 'n SIP-omseiling nie. Elke gebruikersprofiel het 'n `~/.zshenv`-lêer, wat dieselfde gedrag as `/etc/zshenv` vertoon, maar nie root-regte vereis nie. Hierdie lêer kan as 'n volhardingsmeganisme gebruik word, wat elke keer as `zsh` begin, geaktiveer word, of as 'n bevoorregtingsverhogingsmeganisme. As 'n administrateurgebruiker na root verhoog met behulp van `sudo -s` of `sudo <opdrag>`, sal die `~/.zshenv`-lêer geaktiveer word, wat effektief na root verhoog.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) is ontdek dat dieselfde **`system_installd`**-proses nog steeds misbruik kan word omdat dit die **post-install-skrip binne 'n willekeurig genoemde gids beskerm deur SIP binne `/tmp`** geplaas het. Die ding is dat **`/tmp` self nie deur SIP beskerm word nie**, dus was dit moontlik om 'n virtuele beeld daarop te **monteer**, dan sou die **installeerder** die **post-install-skrip** daarin plaas, die virtuele beeld **ontmonteer**, al die **gidse herstel** en die **post-installasie-skrip met die payload** om uit te voer, byvoeg.

#### [fsck\_cs-hulpprogram](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Daar is 'n kwesbaarheid geïdentifiseer waar **`fsck_cs`** mislei is om 'n belangrike lêer te beskadig as gevolg van sy vermoë om **simboliese skakels** te volg. Spesifiek het aanvallers 'n skakel vanaf _`/dev/diskX`_ na die lêer `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` geskep. Die uitvoering van **`fsck_cs`** op _`/dev/diskX`_ het gelei tot die beskadiging van `Info.plist`. Die integriteit van hierdie lêer is van kritieke belang vir die stelsel se SIP (System Integrity Protection), wat die laai van kernel-uitbreidings beheer. Sodra dit beskadig is, is SIP se vermoë om kernel-uitsluitings te bestuur, gekompromitteer.

Die opdragte om van hierdie kwesbaarheid misbruik te maak, is:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die uitbuiting van hierdie kwesbaarheid het ernstige implikasies. Die `Info.plist` lêer, normaalweg verantwoordelik vir die bestuur van toestemmings vir kernel-uitbreidings, word ondoeltreffend. Dit sluit die onvermoë in om sekere uitbreidings, soos `AppleHWAccess.kext`, op 'n swartlys te plaas. Gevolglik kan hierdie uitbreiding gelaai word met die SIP se beheer-meganisme buite werking, wat ongemagtigde lees- en skryftoegang tot die stelsel se RAM verleen.


#### [Monteer oor SIP-beskermde lêers](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Dit was moontlik om 'n nuwe lêersisteem oor **SIP-beskermde lêers te monteer om die beskerming te omseil**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader omseil (2016)](https://objective-see.org/blog/blog\_0x14.html)

Die stelsel is ingestel om te begin vanaf 'n ingebedde installeerder-diskbeeld binne die `Install macOS Sierra.app` om die bedryfstelsel op te gradeer, deur gebruik te maak van die `bless` nutsprogram. Die gebruikte bevel is as volg:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die veiligheid van hierdie proses kan in gedrang kom as 'n aanvaller die opgraderingsbeeld (`InstallESD.dmg`) voor die opstart verander. Die strategie behels die vervanging van 'n dinamiese laaier (dyld) met 'n skadelike weergawe (`libBaseIA.dylib`). Hierdie vervanging lei daartoe dat die aanvaller se kode uitgevoer word wanneer die installeerder geïnisieer word.

Die aanvaller se kode verkry beheer gedurende die opgraderingsproses deur die stelsel se vertroue in die installeerder uit te buit. Die aanval vorder deur die `InstallESD.dmg`-beeld te verander deur middel van metode swizzling, wat spesifiek die `extractBootBits`-metode teiken. Dit maak die inspuiting van skadelike kode moontlik voordat die skyfbeeld gebruik word.

Verder is daar binne die `InstallESD.dmg` 'n `BaseSystem.dmg`, wat as die wortel-lêerstelsel van die opgraderingskode dien. Deur 'n dinamiese biblioteek in te spuit, kan die skadelike kode binne 'n proses werk wat in staat is om OS-vlak lêers te verander, wat die potensiaal vir stelselkompromittering aansienlik verhoog.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In hierdie praatjie van [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) word getoon hoe **`systemmigrationd`** (wat SIP kan omseil) 'n **bash** en 'n **perl** skrip uitvoer, wat misbruik kan word deur middel van omgewingsveranderlikes **`BASH_ENV`** en **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Die toekenning **`com.apple.rootless.install`** maak dit moontlik om SIP te omseil
{% endhint %}

Die toekenning `com.apple.rootless.install` is bekend om System Integrity Protection (SIP) op macOS te omseil. Dit is veral genoem in verband met [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In hierdie spesifieke geval besit die stelsel XPC-diens wat geleë is by `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` hierdie toekenning. Dit maak dit vir die betrokke proses moontlik om SIP-beperkings te omseil. Verder bied hierdie diens veral 'n metode wat die verplasing van lêers moontlik maak sonder om enige sekuriteitsmaatreëls af te dwing.


## Verseëlde Stelselsnapshots

Verseëlde Stelselsnapshots is 'n funksie wat deur Apple in **macOS Big Sur (macOS 11)** bekendgestel is as deel van sy **System Integrity Protection (SIP)** meganisme om 'n addisionele laag van veiligheid en stelselstabiliteit te bied. Dit is essensieel lees-slegs weergawes van die stelselvolume.

Hier is 'n meer gedetailleerde oorsig:

1. **Onveranderlike Stelsel**: Verseëlde Stelselsnapshots maak die macOS stelselvolume "onveranderlik", wat beteken dat dit nie gewysig kan word nie. Dit voorkom enige ongemagtigde of toevallige veranderinge aan die stelsel wat veiligheid of stelselstabiliteit kan benadeel.
2. **Stelsel Sagteware-opdaterings**: Wanneer jy macOS-opdaterings of opgraderings installeer, skep macOS 'n nuwe stelselsnapshot. Die macOS opstartvolume gebruik dan **APFS (Apple File System)** om na hierdie nuwe snapshot oor te skakel. Die hele proses van die toepassing van opdaterings word veiliger en betroubaarder, aangesien die stelsel altyd kan terugkeer na die vorige snapshot as iets fout loop tydens die opdatering.
3. **Data Skeiding**: In samewerking met die konsep van Data- en Stelselvolumeskeiding wat in macOS Catalina bekendgestel is, verseker die Verseëlde Stelselsnapshot-funksie dat al jou data en instellings op 'n aparte "**Data**" volume gestoor word. Hierdie skeiding maak jou data onafhanklik van die stelsel, wat die proses van stelselopdaterings vereenvoudig en stelselveiligheid verbeter.

Onthou dat hierdie snapshots outomaties deur macOS bestuur word en geen addisionele spasie op jou skyf inneem nie, dankie aan die spasiedelingsvermoëns van APFS. Dit is ook belangrik om te let dat hierdie snapshots verskil van **Time Machine-snapshots**, wat gebruikerstoeganklike rugsteun van die hele stelsel is.

### Kontroleer Snapshots

Die opdrag **`diskutil apfs list`** lys die **besonderhede van die APFS-volumes** en hul uitleg:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Verwysing:     disk3
|   Grootte (Kapasiteit Plafon):  494384795648 B (494.4 GB)
|   Kapasiteit In Gebruik Deur Volumes:   219214536704 B (219.2 GB) (44.3% gebruik)
|   Kapasiteit Nie Toegeken:       275170258944 B (275.2 GB) (55.7% vry)
|   |
|   +-&#x3C; Fisiese Stoor disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Fisiese Stoor Skyf:   disk0s2
|   |   Grootte:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Skyf (Rol):   disk3s1 (Stelsel)
</strong>|   |   Naam:                      Macintosh HD (Nie-hooflettergevoelig)
<strong>|   |   Koppel Punt:               /System/Volumes/Update/mnt1
</strong>|   |   Kapasiteit Verbruik:         12819210240 B (12.8 GB)
|   |   Verseël:                    Gebreek
|   |   FileVault:                 Ja (Oopgemaak)
|   |   Versleutel:                 Nee
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Skyf:             disk3s1s1
<strong>|   |   Snapshot Koppel Punt:      /
</strong><strong>|   |   Snapshot Verseël:           Ja
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Skyf (Rol):   disk3s5 (Data)
|   Naam:                      Macintosh HD - Data (Nie-hooflettergevoelig)
<strong>    |   Koppel Punt:               /System/Volumes/Data
</strong><strong>    |   Kapasiteit Verbruik:         412071784448 B (412.1 GB)
</strong>    |   Verseël:                    Nee
|   FileVault:                 Ja (Oopgemaak)
</code></pre>

In die vorige uitset is dit moontlik om te sien dat **gebruikerstoeganklike liggings** gekoppel is onder `/System/Volumes/Data`.

Verder is die **macOS Stelselvolumesnapshot** gekoppel in `/` en dit is **verseël** (kriptografies deur die OS onderteken). As SIP omseil word en dit verander, sal die **OS nie meer opstart nie**.

Dit is ook moontlik om te **verifieer dat verseël aktief is** deur die volgende uit te voer:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Daarbenewens word die afskrifskyf ook as **alleen-lees** gemonteer:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
