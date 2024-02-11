# Windows Artefakte

## Windows Artefakte

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Generiese Windows Artefakte

### Windows 10 Kennisgewings

In die pad `\Users\<gebruikersnaam>\AppData\Local\Microsoft\Windows\Notifications` kan jy die databasis `appdb.dat` (voor Windows-verjaarsdag) of `wpndatabase.db` (na Windows-verjaarsdag) vind.

Binne hierdie SQLite-databasis kan jy die `Notification`-tabel vind met al die kennisgewings (in XML-formaat) wat moontlik interessante data kan bevat.

### Tydlyn

Tydlyn is 'n Windows-kenmerk wat 'n **chronologiese geskiedenis** van besoekte webbladsye, bewerkte dokumente en uitgevoerde toepassings bied.

Die databasis bly in die pad `\Users\<gebruikersnaam>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Hierdie databasis kan geopen word met 'n SQLite-hulpmiddel of met die hulpmiddel [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **wat 2 lêers genereer wat geopen kan word met die hulpmiddel** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternatiewe Datastrome)

Gedownloade lêers kan die **ADS Zone.Identifier** bevat wat aandui **hoe** dit van die intranet, internet, ens. afgelaai is. Sommige sagteware (soos webblaaier) plaas gewoonlik selfs **meer** **inligting** soos die **URL** waarvandaan die lêer afgelaai is.

## **Lêerback-ups**

### Herwinbin

In Vista/Win7/Win8/Win10 kan die **Herwinbin** in die **`$Recycle.bin`**-map in die hoof van die aandrywing (`C:\$Recycle.bin`) gevind word.\
Wanneer 'n lêer in hierdie map uitgevee word, word 2 spesifieke lêers geskep:

* `$I{id}`: Lêerinligting (datum van uitvee}
* `$R{id}`: Inhoud van die lêer

![](<../../../.gitbook/assets/image (486).png>)

Met hierdie lêers kan jy die hulpmiddel [**Rifiuti**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike adres van die uitgevee lêers en die datum waarop dit uitgevee is, te kry (gebruik `rifiuti-vista.exe` vir Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy is 'n tegnologie wat ingesluit is in Microsoft Windows wat **back-up kopieë** of afskrifte van rekenaar lêers of volumes kan skep, selfs wanneer hulle in gebruik is.

Hierdie rugsteun kopieë is gewoonlik geleë in die `\System Volume Information` vanaf die wortel van die lêersisteem en die naam bestaan uit **UIDs** soos getoon in die volgende prentjie:

![](<../../../.gitbook/assets/image (520).png>)

Deur die forensiese beeld te monteer met die **ArsenalImageMounter**, kan die instrument [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) gebruik word om 'n skadukopie te ondersoek en selfs die lêers uit die skadukopie-rugsteunkopieë te **onttrek**.

![](<../../../.gitbook/assets/image (521).png>)

Die registerinskrywing `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` bevat die lêers en sleutels **wat nie rugsteunkopieë moet wees nie**:

![](<../../../.gitbook/assets/image (522).png>)

Die register `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` bevat ook konfigurasie-inligting oor die `Volume Shadow Copies`.

### Office AutoSaved-lêers

Jy kan die kantoor outomatiese gestoorde lêers vind in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

'n Skulpunt is 'n item wat inligting bevat oor hoe om toegang tot 'n ander lêer te verkry.

### Onlangse Dokumente (LNK)

Windows skep **outomaties** hierdie **kortpaaie** wanneer die gebruiker 'n lêer **open, gebruik of skep** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wanneer 'n vouer geskep word, word 'n skakel na die vouer, na die ouervouer en die ouergrootouervouer ook geskep.

Hierdie outomaties geskepte skakel lêers **bevat inligting oor die oorsprong** soos of dit 'n **lêer** **of** 'n **vouer** is, **MAC** **tye** van daardie lêer, **volume-inligting** van waar die lêer gestoor word en die **vouer van die teikenvouer**. Hierdie inligting kan nuttig wees om daardie lêers te herstel in die geval dat hulle verwyder is.

Verder is die **skepdatum van die skakel** lêer die eerste **keer** wat die oorspronklike lêer **eerste** **gebruik** is en die **gewysigde datum** van die skakel lêer is die **laaste** **keer** wat die oorspronklike lêer gebruik is.

Om hierdie lêers te ondersoek, kan jy die instrument [**LinkParser**](http://4discovery.com/our-tools/) gebruik.

In hierdie instrument sal jy **2 stelle** tydmerke vind:

* **Eerste Stel:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Tweede Stel:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die eerste stel tydmerke verwys na die **tydmerke van die lêer self**. Die tweede stel verwys na die **tydmerke van die gekoppelde lêer**.

Jy kan dieselfde inligting kry deur die Windows CLI-instrument [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) uit te voer.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In hierdie geval sal die inligting binne 'n CSV-lêer gestoor word.

### Springlyste

Dit is die onlangse lêers wat per toepassing aangedui word. Dit is die lys van onlangse lêers wat deur 'n toepassing gebruik word en waartoe jy toegang kan verkry op elke toepassing. Hulle kan outomaties geskep word of aangepas wees.

Die outomaties geskepte springlyste word gestoor in `C:\Users\{gebruikersnaam}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Die springlyste word genoem volgens die formaat `{id}.autmaticDestinations-ms` waar die aanvanklike ID die ID van die toepassing is.

Die aangepaste springlyste word gestoor in `C:\Users\{gebruikersnaam}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` en hulle word gewoonlik deur die toepassing geskep omdat iets belangrik met die lêer gebeur het (dalk as gunsteling gemerk).

Die **geskepte tyd** van enige springlys dui die **eerste keer aan dat die lêer geopen is** en die **veranderde tyd die laaste keer**.

Jy kan die springlyste ondersoek met behulp van [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Let daarop dat die tye wat deur JumplistExplorer verskaf word, verband hou met die springlys-lêer self_)

### Shellbags

[**Volg hierdie skakel om uit te vind wat die shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows USB's

Dit is moontlik om te identifiseer dat 'n USB-toestel gebruik is as gevolg van die skepping van:

* Windows Onlangse Gids
* Microsoft Office Onlangse Gids
* Springlyste

Let daarop dat sommige LNK-lêers in plaas van na die oorspronklike pad te verwys, na die WPDNSE-gids verwys:

![](<../../../.gitbook/assets/image (476).png>)

Die lêers in die WPDNSE-gids is 'n kopie van die oorspronklike lêers en sal dus nie oorleef na 'n herlaai van die rekenaar nie, en die GUID word geneem uit 'n shellbag.

### Registerinligting

[Kyk na hierdie bladsy om uit te vind](interesting-windows-registry-keys.md#usb-information) watter registerkodes interessante inligting oor USB-aangeslote toestelle bevat.

### setupapi

Kyk na die lêer `C:\Windows\inf\setupapi.dev.log` om die tye te kry wanneer die USB-aansluiting plaasgevind het (soek na `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting te verkry oor die USB-toestelle wat aan 'n beeld gekoppel was.

![](<../../../.gitbook/assets/image (483).png>)

### Inprop en Speel Skoonmaak

Die geskeduleerde taak wat bekend staan as 'Inprop en Speel Skoonmaak' is primêr ontwerp vir die verwydering van verouderde bestuurdersweergawes. In teenstelling met sy gespesifiseerde doelwit om die nuutste bestuurderspakketweergawe te behou, dui aanlynbronne daarop dat dit ook mik op bestuurders wat vir 30 dae onaktief was. Gevolglik kan bestuurders vir verwyderbare toestelle wat nie in die afgelope 30 dae aangesluit is nie, onderhewig wees aan uitwissing.

Die taak is geleë by die volgende pad:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

'n Skermkiekie wat die inhoud van die taak uitbeeld, word voorsien:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kernkomponente en instellings van die taak:**
- **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike skoonmaakproses.
- **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat dui op die gebruik van die generiese taakbeplanning-enjin.
- **MaintenanceSettings**:
- **Period ('P1M')**: Stuur die Taakbeplanner om die skoonmaaktaak maandeliks tydens gereelde outomatiese instandhouding te begin.
- **Deadline ('P2M')**: Instrueer die Taakbeplanner, as die taak vir twee opeenvolgende maande misluk, om die taak tydens noodgevalle outomatiese instandhouding uit te voer.

Hierdie konfigurasie verseker gereelde instandhouding en skoonmaak van bestuurders, met voorsiening vir herpoging van die taak in geval van opeenvolgende mislukkings.

**Vir meer inligting, kyk na:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-posse

E-posse bevat **2 interessante dele: Die koppe en die inhoud** van die e-pos. In die **koppe** kan jy inligting soos vind:

* **Wie** het die e-posse gestuur (e-posadres, IP, posbedieners wat die e-pos omgelei het)
* **Wanneer** is die e-posse gestuur

Binne die `References` en `In-Reply-To` koppe kan jy ook die ID van die boodskappe vind:

![](<../../../.gitbook/assets/image (484).png>)

### Windows-pos-app

Hierdie toepassing stoor e-posse in HTML- of teksformaat. Jy kan die e-posse binne subgidsies binne `\Users\<gebruikersnaam>\AppData\Local\Comms\Unistore\data\3\` vind. Die e-posse word met die `.dat`-uitbreiding gestoor.

Die **metadata** van die e-posse en die **kontakte** kan binne die **EDB-databasis** gevind word: `\Users\<gebruikersnaam>\AppData\Local\Comms\UnistoreDB\store.vol`

**Verander die uitbreiding** van die lêer van `.vol` na `.edb` en jy kan die instrument [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) gebruik om dit oop te maak. Binne die `Message`-tabel kan jy die e-posse sien.

### Microsoft Outlook

Wanneer Exchange-bedieners of Outlook-kliënte gebruik word, sal daar sekere MAPI-koppe wees:

* `Mapi-Client-Submit-Time`: Tyd van die stelsel toe die e-pos gestuur is
* `Mapi-Conversation-Index`: Aantal kinderboodskappe van die draad en tydstempel van elke boodskap van die draad
* `Mapi-Entry-ID`: Boodskapidentifiseerder.
* `Mappi-Message-Flags` en `Pr_last_Verb-Executed`: Inligting oor die MAPI-kliënt (boodskap gelees? nie gelees nie? geantwoord? omgelei? uit die kantoor?)

In die Microsoft Outlook-kliënt word al die gestuur/ontvang boodskappe, kontakte-inligting en kalenderinligting gestoor in 'n PST-lêer in:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registerpad `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` dui die lêer aan wat gebruik word.

Jy kan die PST-lêer oopmaak met die instrument [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST-lêers

'n **OST-lêer** word gegenereer deur Microsoft Outlook wanneer dit gekonfigureer is met 'n **IMAP** of 'n **Exchange**-bediener, wat soortgelyke inligting as 'n PST-lêer stoor. Hierdie lêer word gesinkroniseer met die bediener en behou data vir **die laaste 12 maande** tot 'n **maksimum grootte van 50GB**, en dit is geleë in dieselfde gids as die PST-lêer. Om 'n OST-lêer te sien, kan die [**Kernel OST-kieker**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.

### Terugwinning van Aanhegsels

Verlore aanhegsels kan herwin word vanaf:

- Vir **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Vir **IE11 en hoër**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX-lêers

**Thunderbird** maak gebruik van **MBOX-lêers** om data te stoor, geleë by `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Beeld Duimnaels

- **Windows XP en 8-8.1**: Toegang tot 'n gids met duimnaels skep 'n `thumbs.db`-lêer wat beeldvoorbeelde stoor, selfs na uitvee.
- **Windows 7/10**: `thumbs.db` word geskep wanneer dit oor 'n netwerk via 'n UNC-paad benader word.
- **Windows Vista en nuwer**: Duimnaelvoorbeelde word gekentraliseer in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` met lêers genaamd **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) en [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) is hulpmiddels vir die sien van hierdie lêers.

### Windows Registerinligting

Die Windows-register, wat omvattende stelsel- en gebruikersaktiwiteitsdata stoor, word bevat binne lêers in:

- `%windir%\System32\Config` vir verskeie `HKEY_LOCAL_MACHINE` subleutels.
- `%UserProfile%{User}\NTUSER.DAT` vir `HKEY_CURRENT_USER`.
- Windows Vista en nuwer weergawe maak rugsteun van `HKEY_LOCAL_MACHINE` registerlêers in `%Windir%\System32\Config\RegBack\`.
- Daarbenewens word programuitvoeringsinligting gestoor in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` vanaf Windows Vista en Windows 2008 Server voortgaan.

### Hulpmiddels

Sommige hulpmiddels is nuttig vir die analise van die registerlêers:

* **Registerredakteur**: Dit is geïnstalleer in Windows. Dit is 'n GUI om deur die Windows-register van die huidige sessie te blaai.
* [**Registerverkenner**](https://ericzimmerman.github.io/#!index.md): Dit stel jou in staat om die registerlêer te laai en daardeur te blaai met 'n GUI. Dit bevat ook Bladmerke wat sleutels met interessante inligting uitlig.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Weereens, dit het 'n GUI wat toelaat om deur die gelaai register te blaai en bevat ook plugins wat interessante inligting binne die gelaai register uitlig.
* [**Windows Registerherwinning**](https://www.mitec.cz/wrr.html): 'n Ander GUI-toepassing wat in staat is om die belangrike inligting uit die gelaai register te onttrek.

### Herstel van Verwyderde Element

Wanneer 'n sleutel verwyder word, word dit as sodanig gemerk, maar dit sal nie verwyder word totdat die spasie wat dit beset word benodig nie. Daarom is dit moontlik om hierdie verwyderde sleutels te herstel deur gebruik te maak van hulpmiddels soos **Registerverkenner**.

### Laaste Skryftyd

Elke Sleutel-Waarde bevat 'n **tydstempel** wat aandui wanneer dit laas gewysig is.

### SAM

Die lêer/hive **SAM** bevat die **gebruikers, groepe en gebruikerswagwoorde**-hasings van die stelsel.

In `SAM\Domains\Account\Users` kan jy die gebruikersnaam, die RID, laaste aanmelding, laaste mislukte aanmelding, aanmeldingteller, wagwoordbeleid en wanneer die rekening geskep is, verkry. Om die **hasings** te kry, het jy ook die lêer/hive **SYSTEM** **nodig**.

### Interessante inskrywings in die Windows-register

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Uitgevoerde Programme

### Basiese Windows-prosesse

In [hierdie berig](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) kan jy leer oor die algemene Windows-prosesse om verdagte gedrag te identifiseer.

### Windows Onlangse Programme

Binne die register `NTUSER.DAT` in die pad `Software\Microsoft\Current Version\Search\RecentApps` kan jy subleutels kry met inligting oor die **uitgevoerde toepassing**, **laaste keer** wat dit uitgevoer is, en **aantal kere** wat dit geloods is.

### BAM (Background Activity Moderator)

Jy kan die `SYSTEM`-lêer oopmaak met 'n registerredakteur en binne die pad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` kan jy die inligting oor die **toepassings wat deur elke gebruiker uitgevoer is** vind (merk die `{SID}` in die pad) en **watter tyd** hulle uitgevoer is (die tyd is binne die Data-waarde van die register).

### Windows Prefetch

Prefetching is 'n tegniek wat 'n rekenaar in staat stel om stilweg die nodige hulpbronne op te haal wat nodig is om inhoud te vertoon wat 'n gebruiker **moontlik binnekort sal toegang** sodat hulpbronne vinniger toeganklik kan wees.

Windows prefetch bestaan uit die skep van **kasgeheues van die uitgevoerde programme** om hulle vinniger te kan laai. Hierdie kasgeheues word geskep as `.pf`-lêers binne die pad: `C:\Windows\Prefetch`. Daar is 'n limiet van 128 lêers in XP/VISTA/WIN7 en 1024 lêers in Win8/Win10.

Die lêernaam word geskep as `{program_naam}-{hash}.pf` (die hash is gebaseer op die pad en argumente van die uitvoerbare lêer). In W10 is hierdie lêers saamgedruk. Let daarop dat die blootwesigheid van die lêer aandui dat **die program op 'n stadium uitgevoer is**.

Die lêer `C:\Windows\Prefetch\Layout.ini` bevat die **name van die gids van die lêers wat geprefetch word**. Hierdie lêer bevat **inligting oor die aantal uitvoerings**, **datums** van die uitvoering en **lêers** **wat oop** is deur die program.

Om hierdie lêers te ondersoek, kan jy die hulpmiddel [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** het dieselfde doel as prefetch, **laai programme vinniger** deur te voorspel wat die volgende gelaaide item sal wees. Dit vervang egter nie die prefetch-diens nie.\
Hierdie diens sal databasislêers genereer in `C:\Windows\Prefetch\Ag*.db`.

In hierdie databasisse kan jy die **naam** van die **program**, **aantal** **uitvoerings**, **geopen** **lêers**, **toegang tot** **volume**, **volledige** **pad**, **tydperke** en **tydstempels** vind.

Jy kan hierdie inligting kry deur die hulpmiddel [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) te gebruik.

### SRUM

**System Resource Usage Monitor** (SRUM) **monitor** die **hulpbronne** **verbruik** **deur 'n proses**. Dit het in W8 verskyn en stoor die data in 'n ESE-databasis wat in `C:\Windows\System32\sru\SRUDB.dat` geleë is.

Dit gee die volgende inligting:

* AppID en Pad
* Gebruiker wat die proses uitgevoer het
* Gestuurde bytes
* Ontvangsbytes
* Netwerkinterface
* Verbindingsduur
* Prosesduur

Hierdie inligting word elke 60 minute opgedateer.

Jy kan die datum uit hierdie lêer kry deur die hulpmiddel [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) te gebruik.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, vorm deel van die **Application Compatibility Database** wat deur **Microsoft** ontwikkel is om programverenigbaarheidsprobleme aan te spreek. Hierdie stelselkomponent neem verskeie stukke lêermetadata op, wat insluit:

- Volledige pad van die lêer
- Grootte van die lêer
- Laaste gewysigde tyd onder **$Standard\_Information** (SI)
- Laaste opgedateerde tyd van die ShimCache
- Prosesuitvoeringsvlag

Sodanige data word binne die register gestoor op spesifieke plekke gebaseer op die weergawe van die bedryfstelsel:

- Vir XP word die data gestoor onder `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` met 'n kapasiteit vir 96 inskrywings.
- Vir Server 2003, sowel as vir Windows-weergawes 2008, 2012, 2016, 7, 8 en 10, is die bergpad `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, wat onderskeidelik 512 en 1024 inskrywings akkommodeer.

Om die gestoorde inligting te ontleden, word die [**AppCompatCacheParser**-hulpmiddel](https://github.com/EricZimmerman/AppCompatCacheParser) aanbeveel vir gebruik.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Die **Amcache.hve**-lêer is in wese 'n registerhys wat besonderhede oor toepassings wat op 'n stelsel uitgevoer is, registreer. Dit word tipies gevind by `C:\Windows\AppCompat\Programas\Amcache.hve`.

Hierdie lêer is merkwaardig omdat dit rekords van onlangs uitgevoerde prosesse stoor, insluitend die paaie na die uitvoerbare lêers en hul SHA1-hashes. Hierdie inligting is van onschatbare waarde vir die opspoor van die aktiwiteit van toepassings op 'n stelsel.

Om die data uit **Amcache.hve** te onttrek en te analiseer, kan die [**AmcacheParser**-hulpmiddel](https://github.com/EricZimmerman/AmcacheParser) gebruik word. Die volgende opdrag is 'n voorbeeld van hoe om AmcacheParser te gebruik om die inhoud van die **Amcache.hve**-lêer te ontleden en die resultate in CSV-formaat uit te voer:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Onder die gegenereerde CSV-lêers is die `Amcache_Unassociated file entries` veral merkwaardig vanweë die ryk inligting wat dit verskaf oor nie-geassosieerde lêerinvoere.

Die mees interessante CVS-lêer wat gegenereer word, is die `Amcache_Unassociated file entries`.

### RecentFileCache

Hierdie artefak kan slegs in W7 gevind word in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` en dit bevat inligting oor die onlangse uitvoering van sekere bineêre lêers.

Jy kan die instrument [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te ontled.

### Geskeduleerde take

Jy kan hulle onttrek uit `C:\Windows\Tasks` of `C:\Windows\System32\Tasks` en as XML lees.

### Dienste

Jy kan hulle in die register vind onder `SYSTEM\ControlSet001\Services`. Jy kan sien wat uitgevoer gaan word en wanneer.

### **Windows Store**

Die geïnstalleerde programme kan gevind word in `\ProgramData\Microsoft\Windows\AppRepository\`\
Hierdie bewaarplek het 'n **log** met **elke geïnstalleerde toepassing** in die stelsel binne die databasis **`StateRepository-Machine.srd`**.

Binne die Toepassingstabel van hierdie databasis is dit moontlik om die kolomme te vind: "Toepassings-ID", "Pakketnommer" en "Vertoonnaam". Hierdie kolomme bevat inligting oor vooraf geïnstalleerde en geïnstalleerde toepassings en dit kan gevind word of sommige toepassings gedeïnstalleer is omdat die ID's van geïnstalleerde toepassings opeenvolgend moet wees.

Dit is ook moontlik om **geïnstalleerde toepassing** te vind binne die registerpad: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
En **gedeïnstalleerde** **toepassings** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows-gebeure

Inligting wat binne Windows-gebeure verskyn, is:

* Wat gebeur het
* Tydstempel (UTC + 0)
* Betrokke gebruikers
* Betrokke gasheer (gasheernaam, IP)
* Betrokke bates (lêers, vouer, drukkers, dienste)

Die loglêers is geleë in `C:\Windows\System32\config` voor Windows Vista en in `C:\Windows\System32\winevt\Logs` na Windows Vista. Voor Windows Vista was die gebeurtenisloglêers in binêre formaat en daarna is dit in **XML-formaat** en gebruik die **.evtx**-uitbreiding.

Die ligging van die gebeurtenislêers kan gevind word in die SISTEEM-register in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Dit kan gesien word vanuit die Windows-gebeurtenisleser (**`eventvwr.msc`**) of met ander instrumente soos [**Event Log Explorer**](https://eventlogxp.com) **of** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Begrip van Windows-sekuriteitsgebeure

Toegangsgebeure word aangeteken in die sekuriteitskonfigurasie-lêer wat geleë is by `C:\Windows\System32\winevt\Security.evtx`. Hierdie lêer se grootte is aanpasbaar, en wanneer sy kapasiteit bereik is, word ouer gebeure oorskryf. Aangetekende gebeure sluit gebruikersaanmeldings en -afmeldings, gebruikersaksies en veranderinge aan sekuriteitsinstellings in, sowel as toegang tot lêers, vouers en gedeelde bates.

### Sleutel-gebeurtenis-ID's vir gebruikersverifikasie:

- **Gebeurtenis-ID 4624**: Dui aan dat 'n gebruiker suksesvol geverifieer is.
- **Gebeurtenis-ID 4625**: Dui op 'n mislukte verifikasie.
- **Gebeurtenis-ID's 4634/4647**: Verteenwoordig gebruikersafmeldingsgebeure.
- **Gebeurtenis-ID 4672**: Dui op aanmelding met administratiewe voorregte.

#### Subtipes binne Gebeurtenis-ID 4634/4647:

- **Interaktief (2)**: Direkte gebruikersaanmelding.
- **Netwerk (3)**: Toegang tot gedeelde vouers.
- **Batch (4)**: Uitvoering van lotprosesse.
- **Diens (5)**: Dienslansering.
- **Proxy (6)**: Proxy-verifikasie.
- **Ontsluit (7)**: Skerm ontgrendel met 'n wagwoord.
- **Netwerkduidelike teks (8)**: Duidelike teks wagwoordoordrag, dikwels vanaf IIS.
- **Nuwe legitimasie (9)**: Gebruik van verskillende legitimasie vir toegang.
- **Verwyderde interaktief (10)**: Verwyderde skerm of terminaaldiensaanmelding.
- **Verwyderde interaktiewe opgesluit (11)**: Aanmelding met opgeslote legitimasie sonder kontak met 'n domeinbeheerder.
- **Verwyderde ontgrendeling (12)**: Verwyderde aanmelding met opgeslote legitimasie.
- **Opgeslote ontgrendeling (13)**: Ontsluiting met opgeslote legitimasie.

#### Status- en Substatuskodes vir Gebeurtenis-ID 4625:

- **0xC0000064**: Gebruikersnaam bestaan nie - Kan dui op 'n aanval van gebruikersnaamopname.
- **0xC000006A**: Korrekte gebruikersnaam, maar verkeerde wagwoord - Moontlike wagwoord raai of brute force-poging.
- **0xC0000234**: Gebruikersrekening gesluit - Kan volg op 'n brute force-aanval met verskeie mislukte aanmeldings.
- **0xC0000072**: Rekening gedeaktiveer - Onbevoegde pogings om gedeaktiveerde rekeninge te benader.
- **0xC000006F**: Aanmelding buite toegelate tyd - Dui op pogings om buite die vasgestelde aanmeldingstye toegang te verkry, 'n moontlike teken van onbevoegde toegang.
- **0xC0000070**: Oortreding van werksplekbeperkings - Kan 'n poging wees om vanaf 'n onbevoegde plek aan te meld.
- **0xC0000193**: Rekening verval - Toegangspogings met vervalde gebruikersrekeninge.
- **0xC0000071**: Vervalde wagwoord - Aanmeldingspogings met verouderde wagwoorde.
- **0xC0000133**: Tydsinkronisasieprobleme - Groot tydverskille tussen kliënt en bediener kan dui op meer gesofistikeerde aanvalle soos pass-the-ticket.
- **0xC0000224**: Verpligte wagwoordverandering vereis - Gereelde verpligte veranderinge kan dui op 'n poging om rekeningsekuriteit te destabiliseer.
- **0xC0000225**: Dui op 'n stelselfout eerder as 'n sekuriteitsprobleem.
- **0xC000015b**: Geweierde aanmeldingstipe - Toegangspoging met onbevoegde aanmeldingstipe, soos 'n gebruiker wat probeer om 'n diensaanmelding uit te voer.

#### Gebeurtenis-ID 4616:
- **Tydverandering**: Wysiging van die stelseltyd, kan die tydlyn van gebeure verwar.

#### Gebeurtenis-ID's 6005 en 6006:
- **Stelselbegin en -afsluiting**: Gebeurtenis-ID 6005 dui op die begin van die stelsel, terwyl Gebeurtenis-ID 6006 dit aandui wanneer dit afsluit.

#### Gebeurtenis-ID 1102:
- **Logwissing**: Sekuriteitslêers wat skoongevee word, wat dikwels 'n rooi vlag is vir die bedek van onwettige aktiwiteite.

#### Gebeurtenis-ID's vir USB-toestelopsporing:
- **20001 / 20003 / 10000**: Eerste koppeling van USB-toestel.
- **10100**: USB-bestuursprogramopdatering.
- **Gebeurtenis-ID 112**: Tyd van USB-toestelinvoeging.

Vir praktiese voorbeelde van die simulasie van hierdie aanmeldingstipes en geleenthede vir legitimasie-onttrekking, verwys na [Altered Security se gedetailleerde gids](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Gebeurtenisbesonderhede, insluitend status- en substatuskodes, bied verdere insig in die oorsake van gebeure, ver
#### Stelselkraggebeure

EventID 6005 dui op stelselbegin, terwyl EventID 6006 afsluiting aandui.

#### Logverwydering

Veiligheid EventID 1102 dui op die verwydering van logboeke, 'n kritieke gebeurtenis vir forensiese analise.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
