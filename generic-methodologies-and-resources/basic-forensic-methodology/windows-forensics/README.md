# Windows Artefakte

## Windows Artefakte

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Generiese Windows Artefakte

### Windows 10 Kennisgewings

In die pad `\Users\<gebruikersnaam>\AppData\Local\Microsoft\Windows\Notifications` kan jy die databasis `appdb.dat` (voor Windows-herdenking) of `wpndatabase.db` (na Windows-herdenking) vind.

Binne hierdie SQLite-databasis kan jy die `Kennisgewing`-tabel vind met al die kennisgewings (in XML-formaat) wat interessante data kan bevat.

### Tydlyn

Tydlyn is 'n Windows kenmerk wat 'n **chronologiese geskiedenis** van besoekte webbladsye, bewerkte dokumente, en uitgevoerde toepassings bied.

Die databasis bly in die pad `\Users\<gebruikersnaam>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Hierdie databasis kan geopen word met 'n SQLite-instrument of met die instrument [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **wat 2 lêers genereer wat geopen kan word met die instrument** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternatiewe Datastrome)

Lêers wat afgelaai is, kan die **ADS Zone.Identifier** bevat wat aandui **hoe** dit vanaf die intranet, internet, ens. afgelaai is. Sommige sagteware (soos webblaaier) sit gewoonlik selfs **meer** **inligting** soos die **URL** van waar die lêer afgelaai is.

## **Lêeragteruitkopieë**

### Stortmandjie

In Vista/Win7/Win8/Win10 kan die **Stortmandjie** gevind word in die vouer **`$Recycle.bin`** in die hoof van die aandrywing (`C:\$Recycle.bin`).\
Wanneer 'n lêer in hierdie vouer uitgevee word, word 2 spesifieke lêers geskep:

* `$I{id}`: Lêerinligting (datum van wanneer dit uitgevee is}
* `$R{id}`: Inhoud van die lêer

![](<../../../.gitbook/assets/image (1029).png>)

Met hierdie lêers kan jy die instrument [**Rifiuti**](https://github.com/abelcheung/rifiuti2) gebruik om die oorspronklike adres van die uitgevee lêers en die datum waarop dit uitgevee is, te kry (gebruik `rifiuti-vista.exe` vir Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Skadukopieë

Skadukopie is 'n tegnologie wat ingesluit is in Microsoft Windows wat **agterkopieë** of afskrifte van rekenaar lêers of volumes kan skep, selfs wanneer hulle in gebruik is.

Hierdie agterkopieë is gewoonlik geleë in die `\System Volume Information` van die wortel van die lêersisteem en die naam is saamgestel uit **UID's** soos in die volgende afbeelding:

![](<../../../.gitbook/assets/image (94).png>)

Deur die forensiese beeld te monteer met die **ArsenalImageMounter**, kan die hulpmiddel [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) gebruik word om 'n skadukopie te ondersoek en selfs **die lêers** uit die skadukopie-agterkopieë te onttrek.

![](<../../../.gitbook/assets/image (576).png>)

Die registerinskrywing `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` bevat die lêers en sleutels **wat nie agtergekopieer moet word nie**:

![](<../../../.gitbook/assets/image (254).png>)

Die register `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` bevat ook konfigurasie-inligting oor die `Volume Shadow Copies`.

### Kantoor Opgeslane Lêers

Jy kan die kantoor opgeslane lêers vind in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Skuldelemente

'n Skuldelement is 'n item wat inligting bevat oor hoe om toegang tot 'n ander lêer te verkry.

### Onlangse Dokumente (LNK)

Windows **skep outomaties** hierdie **afkortings** wanneer die gebruiker 'n lêer **open, gebruik of skep** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Kantoor: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wanneer 'n vouer geskep word, word 'n skakel na die vouer, na die ouervouer en die ouerouervouer ook geskep.

Hierdie outomaties geskepte skakellêers bevat inligting oor die oorsprong soos of dit 'n **lêer** **of** 'n **vouer** is, **MAC** **tye** van daardie lêer, **volume-inligting** van waar die lêer gestoor word en **vouer van die teikenvouer**. Hierdie inligting kan nuttig wees om daardie lêers te herstel in die geval dat hulle verwyder is.

Ook is die **skepingsdatum van die skakel** lêer die eerste **keer** wat die oorspronklike lêer **eerste** **gebruik** is en die **datum** **gewysig** van die skakel lêer is die **laaste** **keer** dat die oorspronklike lêer gebruik is.

Om hierdie lêers te ondersoek, kan jy [**LinkParser**](http://4discovery.com/our-tools/) gebruik.

In hierdie hulpmiddels sal jy **2 stelle** tydmerke vind:

* **Eerste Stel:**
1. LêerGewysigDatum
2. LêerToegangsDatum
3. LêerSkepingsDatum
* **Tweede Stel:**
1. SkakelGewysigDatum
2. SkakelToegangsDatum
3. SkakelSkepingsDatum.

Die eerste stel tydmerke verwys na die **tydmerke van die lêer self**. Die tweede stel verwys na die **tydmerke van die gekoppelde lêer**.

Jy kan dieselfde inligting kry deur die Windows CLI-hulpmiddel uit te voer: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### Springlêers

Dit is die onlangse lêers wat per toepassing aangedui word. Dit is die lys van **onlangse lêers wat deur 'n toepassing gebruik is** wat jy op elke toepassing kan raadpleeg. Hulle kan **outomaties geskep word of aangepas wees**.

Die **springlêers** wat outomaties geskep word, word gestoor in `C:\Users\{gebruikersnaam}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Die springlêers word genoem volgens die formaat `{id}.autmaticDestinations-ms` waar die aanvanklike ID die ID van die toepassing is.

Die aangepaste springlêers word gestoor in `C:\Users\{gebruikersnaam}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` en hulle word deur die toepassing geskep omdat iets **belangrik** met die lêer gebeur het (miskien as gunsteling gemerk).

Die **geskepte tyd** van enige springlys dui die **eerste keer aan dat die lêer benader is** en die **gewysigde tyd die laaste keer**.

Jy kan die springlêers inspekteer met behulp van [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Let daarop dat die tye wat deur JumplistExplorer voorsien word, verband hou met die springlys-lêer self_)

### Shellbags

[**Volg hierdie skakel om uit te vind wat die shellbags is.**](interesting-windows-registry-keys.md#shellbags)

## Gebruik van Windows USB's

Dit is moontlik om te identifiseer dat 'n USB-toestel gebruik is danksy die skepping van:

* Windows Onlangse Vouer
* Microsoft Office Onlangse Vouer
* Springlêers

Let daarop dat sommige LNK-lêers in plaas van na die oorspronklike pad te verwys, na die WPDNSE-vouer verwys:

![](<../../../.gitbook/assets/image (218).png>)

Die lêers in die WPDNSE-vouer is 'n kopie van die oorspronklike lêers, sal dus nie 'n herbegin van die rekenaar oorleef nie en die GUID word uit 'n shellbag geneem.

### Registreer Inligting

[Kyk op hierdie bladsy om te leer](interesting-windows-registry-keys.md#usb-information) watter register sleutels interessante inligting oor USB-aangeslote toestelle bevat.

### setupapi

Kyk na die lêer `C:\Windows\inf\setupapi.dev.log` om die tye te kry wanneer die USB-verbinding plaasgevind het (soek na `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kan gebruik word om inligting oor die USB-toestelle wat aan 'n beeld gekoppel is, te verkry.

![](<../../../.gitbook/assets/image (452).png>)

### Inprop en Speel Skoonmaak

Die geskeduleerde taak wat bekend staan as 'Inprop en Speel Skoonmaak' is hoofsaaklik ontwerp vir die verwydering van verouderde drywerversione. In teenstelling met sy gespesifiseerde doel om die jongste drywerpakketweergawe te behou, suggereer aanlynbronne dat dit ook drywers teiken wat vir 30 dae onaktief was. Gevolglik kan drywers vir verwyderbare toestelle wat nie in die afgelope 30 dae aangesluit is nie, onderwerp word aan uitvee.

Die taak is geleë op die volgende pad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

'n Skermkiekie wat die inhoud van die taak uitbeeld, word voorsien: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kernkomponente en Instellings van die Taak:**

* **pnpclean.dll**: Hierdie DLL is verantwoordelik vir die werklike skoonmaakproses.
* **UseUnifiedSchedulingEngine**: Gestel op `TRUE`, wat dui op die gebruik van die generiese taakbeplanningsenjin.
* **MaintenanceSettings**:
* **Tydperk ('P1M')**: Stuur die Taakbeplanner om die skoonmaaktaak maandeliks tydens gereelde Outomatiese instandhouding te begin.
* **Deurnooi ('P2M')**: Instrueer die Taakbeplanner, as die taak vir twee agtereenvolgende maande misluk, om die taak tydens noodsaaklike Outomatiese instandhouding uit te voer.

Hierdie konfigurasie verseker gereelde instandhouding en skoonmaak van drywers, met bepalings vir 'n herpoging van die taak in geval van agtereenvolgende mislukkings.

**Vir meer inligting kyk:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-posse

E-posse bevat **2 interessante dele: Die koppe en die inhoud** van die e-pos. In die **koppe** kan jy inligting soos vind:

* **Wie** het die e-posse gestuur (e-posadres, IP, posdiensers wat die e-pos omgelei het)
* **Wanneer** is die e-pos gestuur

Ook kan jy binne die `Verwysings` en `In-Reply-To` koppe die ID van die boodskappe vind:

![](<../../../.gitbook/assets/image (593).png>)

### Windows Pos App

Hierdie toepassing stoor e-posse in HTML of teks. Jy kan die e-posse binne subvouers vind binne `\Users\<gebruikersnaam>\AppData\Local\Comms\Unistore\data\3\`. Die e-posse word gestoor met die `.dat`-uitbreiding.

Die **metadata** van die e-posse en die **kontakbesonderhede** kan binne die **EDB-databasis** gevind word: `\Users\<gebruikersnaam>\AppData\Local\Comms\UnistoreDB\store.vol`

**Verander die uitbreiding** van die lêer van `.vol` na `.edb` en jy kan die instrument [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) gebruik om dit oop te maak. Binne die `Boodskap`-tabel kan jy die e-posse sien.

### Microsoft Outlook

Wanneer Exchange-bedieners of Outlook-kliënte gebruik word, gaan daar 'n paar MAPI-koppe wees:

* `Mapi-Client-Submit-Time`: Tyd van die stelsel toe die e-pos gestuur is
* `Mapi-Conversation-Index`: Aantal kinderboodskappe van die draad en tydstempel van elke boodskap van die draad
* `Mapi-Entry-ID`: Boodskapidentifiseerder.
* `Mappi-Message-Flags` en `Pr_last_Verb-Executed`: Inligting oor die MAPI-kliënt (boodskap gelees? nie gelees nie? geantwoord? omgelei? uit die kantoor?)

In die Microsoft Outlook-kliënt word al die gestuurde/ontvangsboodskappe, kontakdata, en kalenderdata gestoor in 'n PST-lêer in:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Die registerpad `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` dui aan watter lêer gebruik word.

Jy kan die PST-lêer oopmaak met die instrument [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)
### Microsoft Outlook OST-lêers

'n **OST-lêer** word gegenereer deur Microsoft Outlook wanneer dit gekonfigureer is met **IMAP** of 'n **Exchange**-bediener, wat soortgelyke inligting as 'n PST-lêer stoor. Hierdie lêer word gesinkroniseer met die bediener, behou data vir **die laaste 12 maande** tot 'n **maksimum grootte van 50GB**, en word in dieselfde gids as die PST-lêer gevind. Om 'n OST-lêer te sien, kan die [**Kernel OST-aansig**](https://www.nucleustechnologies.com/ost-viewer.html) gebruik word.

### Terugwinning van Aanhegsels

Verlore aanhegsels kan herwin word vanaf:

* Vir **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Vir **IE11 en hoër**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX-lêers

**Thunderbird** maak gebruik van **MBOX-lêers** om data te stoor, geleë by `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Beeld Duimnaels

* **Windows XP en 8-8.1**: Toegang tot 'n gids met duimnaels genereer 'n `thumbs.db`-lêer wat beeldvoorbeelde stoor, selfs ná skrapping.
* **Windows 7/10**: `thumbs.db` word geskep wanneer dit oor 'n netwerk via 'n UNC-paadjie benader word.
* **Windows Vista en nuwer**: Duimnaelvoorbeelde is gesentraliseer in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` met lêers genaamd **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) en [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) is gereedskap vir die sien van hierdie lêers.

### Windows Registerinligting

Die Windows-register, wat omvattende stelsel- en gebruikersaktiwiteitsdata stoor, word bevat binne lêers in:

* `%windir%\System32\Config` vir verskeie `HKEY_LOCAL_MACHINE` subklasse.
* `%UserProfile%{User}\NTUSER.DAT` vir `HKEY_CURRENT_USER`.
* Windows Vista en nuwer weergawes maak 'n rugsteun van `HKEY_LOCAL_MACHINE` registerlêers in `%Windir%\System32\Config\RegBack\`.
* Daarbenewens word programuitvoerinligting gestoor in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` vanaf Windows Vista en Windows 2008 Server aan.

### Gereedskap

Sommige gereedskap is nuttig om die registerlêers te analiseer:

* **Registerredigeerder**: Dit is geïnstalleer in Windows. Dit is 'n GUI om deur die Windows-register van die huidige sessie te navigeer.
* [**Registerontdekker**](https://ericzimmerman.github.io/#!index.md): Dit laat jou toe om die registerlêer te laai en daardeur te navigeer met 'n GUI. Dit bevat ook Bladmerke wat sleutels met interessante inligting beklemtoon.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Weereens, dit het 'n GUI wat toelaat om deur die gelaai register te navigeer en bevat ook aanvullings wat interessante inligting binne die gelaai register beklemtoon.
* [**Windows Registerherwinning**](https://www.mitec.cz/wrr.html): 'n Ander GUI-toepassing wat in staat is om die belangrike inligting uit die gelaai register te onttrek.

### Herstel van Verwyderde Element

Wanneer 'n sleutel verwyder word, word dit as sodanig gemerk, maar totdat die spasie wat dit beset benodig word, sal dit nie verwyder word nie. Daarom is dit moontlik om hierdie verwyderde sleutels te herwin deur gereedskap soos **Registerontdekker** te gebruik.

### Laaste Skryftyd

Elke Sleutel-Waarde bevat 'n **tydstempel** wat aandui wanneer dit laas gewysig is.

### SAM

Die lêer/hive **SAM** bevat die **gebruikers, groepe en gebruikerswagwoorde** hasjies van die stelsel.

In `SAM\Domains\Account\Users` kan jy die gebruikersnaam, die RID, laaste aanmelding, laaste mislukte aanmelding, aanmeldingteller, wagwoordbeleid en wanneer die rekening geskep is, verkry. Om die **hasjies** te kry, het jy ook die lêer/hive **SYSTEM** nodig.

### Interessante inskrywings in die Windows-register

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programme Uitgevoer

### Basiese Windows Prosesse

In [hierdie pos](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) kan jy leer oor die algemene Windows prosesse om verdagte gedrag te identifiseer.

### Windows Onlangse Toepassings

Binne die register `NTUSER.DAT` in die paadjie `Software\Microsoft\Current Version\Search\RecentApps` kan jy subklasse met inligting oor die **uitgevoerde toepassing**, **laaste tyd** wat dit uitgevoer is, en **aantal kere** wat dit afgeskop is, vind.

### BAM (Agtergrondaktiwiteitsmoderator)

Jy kan die `SYSTEM`-lêer oopmaak met 'n registerredigeerder en binne die paadjie `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` kan jy die inligting oor die **toepassings wat deur elke gebruiker uitgevoer is** vind (let op die `{SID}` in die paadjie) en op **watter tyd** hulle uitgevoer is (die tyd is binne die Data-waarde van die register).

### Windows Prefetch

Prefetching is 'n tegniek wat 'n rekenaar toelaat om stilweg die nodige hulpbronne te **haal wat nodig is om inhoud te vertoon** wat 'n gebruiker **moontlik binnekort sal toegang** sodat hulpbronne vinniger toeganklik kan wees.

Windows prefetch bestaan uit die skep van **kasgeheues van die uitgevoerde programme** om hulle vinniger te kan laai. Hierdie geheues word geskep as `.pf`-lêers binne die paadjie: `C:\Windows\Prefetch`. Daar is 'n limiet van 128 lêers in XP/VISTA/WIN7 en 1024 lêers in Win8/Win10.

Die lêernaam word geskep as `{program_naam}-{hasj}.pf` (die hasj is gebaseer op die paadjie en argumente van die uitvoerbare lêer). In W10 is hierdie lêers saamgedruk. Let daarop dat die enkele teenwoordigheid van die lêer aandui dat **die program op 'n stadium uitgevoer is**.

Die lêer `C:\Windows\Prefetch\Layout.ini` bevat die **name van die gids van die lêers wat geprefetch is**. Hierdie lêer bevat **inligting oor die aantal uitvoerings**, **datums** van die uitvoering en **lêers** **wat oop** is deur die program.

Om hierdie lêers te ondersoek, kan jy die gereedskap [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) gebruik:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** het dieselfde doel as prefetch, **laai programme vinniger** deur te voorspel wat die volgende gelaaide item sal wees. Dit vervang egter nie die prefetch-diens nie.\
Hierdie diens sal databasislêers genereer in `C:\Windows\Prefetch\Ag*.db`.

In hierdie databasisse kan jy die **naam** van die **program**, **aantal** **uitvoerings**, **lêers** **geopen**, **volume** **toegang**, **volledige** **pad**, **tydraamwerke** en **tydstempels** vind.

Jy kan toegang tot hierdie inligting verkry deur die instrument [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) te gebruik.

### SRUM

**System Resource Usage Monitor** (SRUM) **monitor** die **hulpbronne** **verbruik** **deur 'n proses**. Dit het in W8 verskyn en stoor die data in 'n ESE-databasis wat geleë is in `C:\Windows\System32\sru\SRUDB.dat`.

Dit verskaf die volgende inligting:

* AppID en Pad
* Gebruiker wat die proses uitgevoer het
* Gestuurde grepe
* Ontvangs grepe
* Netwerk koppelvlak
* Koppelingsduur
* Prosesduur

Hierdie inligting word elke 60 minute opgedateer.

Jy kan die datum uit hierdie lêer verkry deur die instrument [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) te gebruik.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Die **AppCompatCache**, ook bekend as **ShimCache**, vorm deel van die **Toepassingsverenigbaarheidsdatabasis** wat deur **Microsoft** ontwikkel is om toepassingsverenigbaarheidsprobleme aan te spreek. Hierdie stelselkomponent neem verskeie stukke lêermetadatabestand op, wat onder meer insluit:

* Volledige pad van die lêer
* Grootte van die lêer
* Laaste gewysigde tyd onder **$Standard\_Information** (SI)
* Laaste opgedateerde tyd van die ShimCache
* Proseshanteringvlag

Hierdie data word binne die register gestoor op spesifieke plekke gebaseer op die weergawe van die bedryfstelsel:

* Vir XP word die data gestoor onder `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` met 'n kapasiteit vir 96 inskrywings.
* Vir Server 2003, sowel as vir Windows-weergawes 2008, 2012, 2016, 7, 8, en 10, is die stoorpad `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, wat onderskeidelik 512 en 1024 inskrywings akkommodeer.

Om die gestoorde inligting te ontled, word die [**AppCompatCacheParser**-werktuig](https://github.com/EricZimmerman/AppCompatCacheParser) aanbeveel vir gebruik.

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

Die **Amcache.hve**-lêer is essensieel 'n registerhive wat besonderhede oor toepassings wat op 'n stelsel uitgevoer is, log. Dit word tipies gevind by `C:\Windows\AppCompat\Programas\Amcache.hve`.

Hierdie lêer is opmerklik vir die stoor van rekords van onlangs uitgevoerde prosesse, insluitend die paaie na die uitvoerbare lêers en hul SHA1-hasies. Hierdie inligting is van onskatbare waarde vir die opsporing van die aktiwiteit van toepassings op 'n stelsel.

Om die data uit **Amcache.hve** te onttrek en te analiseer, kan die [**AmcacheParser**-werktuig](https://github.com/EricZimmerman/AmcacheParser) gebruik word. Die volgende bevel is 'n voorbeeld van hoe AmcacheParser gebruik kan word om die inhoud van die **Amcache.hve**-lêer te ontled en die resultate in CSV-formaat uit te voer:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Onder die gegenereerde CSV-lêers is die `Amcache_Unassociated file entries` veral merkwaardig weens die ryk inligting wat dit bied oor ongeassosieerde lêerinskrywings.

Die mees interessante CVS-lêer wat gegenereer word, is die `Amcache_Unassociated file entries`.

### RecentFileCache

Hierdie artefak kan slegs in W7 gevind word in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` en dit bevat inligting oor die onlangse uitvoering van sekere binêre lêers.

Jy kan die werktuig [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) gebruik om die lêer te ontled.

### Beplande take

Jy kan hulle onttrek uit `C:\Windows\Tasks` of `C:\Windows\System32\Tasks` en dit as XML lees.

### Dienste

Jy kan hulle in die register vind onder `SYSTEM\ControlSet001\Services`. Jy kan sien wat gaan uitgevoer word en wanneer.

### **Windows Store**

Die geïnstalleerde toepassings kan gevind word in `\ProgramData\Microsoft\Windows\AppRepository\`\
Hierdie argief het 'n **log** met **elke toepassing wat geïnstalleer is** in die stelsel binne die databasis **`StateRepository-Machine.srd`**.

Binne die Toepassingstabel van hierdie databasis is dit moontlik om die kolomme te vind: "Toepassings-ID", "Pakketnommer", en "Vertoonnaam". Hierdie kolomme het inligting oor vooraf geïnstalleerde en geïnstalleerde toepassings en dit kan gevind word as sommige toepassings ongeïnstalleer is omdat die ID's van geïnstalleerde toepassings opeenvolgend moet wees.

Dit is ook moontlik om **geïnstalleerde toepassing** binne die registerpad te vind: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
En **ongeïnstalleerde toepassings** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Gebeure

Inligting wat binne Windows-gebeure verskyn, is:

* Wat gebeur het
* Tydstempel (UTC + 0)
* Betrokke Gebruikers
* Gasheer wat betrokke is (gasheernaam, IP)
* Bates wat benader is (lêers, vouer, drukker, dienste)

Die logboeke is geleë in `C:\Windows\System32\config` voor Windows Vista en in `C:\Windows\System32\winevt\Logs` na Windows Vista. Voor Windows Vista was die gebeurtenislogboeke in binêre formaat en daarna is hulle in **XML-formaat** en gebruik die **.evtx**-uitbreiding.

Die ligging van die gebeurtenis lêers kan gevind word in die SYSTEM-register in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Hulle kan gesien word vanuit die Windows-gebeurtenis kyker (**`eventvwr.msc`**) of met ander gereedskap soos [**Event Log Explorer**](https://eventlogxp.com) **of** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Begrip van Windows Sekuriteit Gebeurtenislogging

Toeganggebeure word aangeteken in die sekuriteitskonfigurasie-lêer wat geleë is by `C:\Windows\System32\winevt\Security.evtx`. Hierdie lêer se grootte is aanpasbaar, en wanneer sy kapasiteit bereik is, word ouer gebeure oorskryf. Aangetekende gebeure sluit in gebruikersaanmeldings en -afmeldings, gebruikeraksies, en veranderinge aan sekuriteitsinstellings, sowel as toegang tot lêers, vouers, en gedeelde bates.

### Sleutel Gebeurtenis-ID's vir Gebruiker-Verifikasie:

* **Gebeurtenis-ID 4624**: Dui aan dat 'n gebruiker suksesvol geverifieer is.
* **Gebeurtenis-ID 4625**: Dui op 'n verifikasie-mislukking.
* **Gebeurntenis-ID's 4634/4647**: Verteenwoordig gebruiker-afmeldgebeure.
* **Gebeurtenis-ID 4672**: Dui op aanmelding met administratiewe voorregte.

#### Sub-tipes binne Gebeurtenis-ID 4634/4647:

* **Interaktief (2)**: Direkte gebruiker aanmelding.
* **Netwerk (3)**: Toegang tot gedeelde vouers.
* **Batch (4)**: Uitvoering van lotprosesse.
* **Diens (5)**: Diensbeginne.
* **Proksi (6)**: Proksi-verifikasie.
* **Ontsluit (7)**: Skerm ontgrendel met 'n wagwoord.
* **Netwerkteks (8)**: Duidelike teks wagwoord oordrag, dikwels vanaf IIS.
* **Nuwe Gelde (9)**: Gebruik van verskillende gelde vir toegang.
* **Verre Interaktief (10)**: Verre skerm of terminaaldiens aanmelding.
* **Gekas Interaktief (11)**: Aanmelding met gekas gelde sonder domeinbeheerderkontak.
* **Gekas Verre Interaktief (12)**: Verre aanmelding met gekas gelde.
* **Gekas Ontsluit (13)**: Ontsluiting met gekas gelde.

#### Status en Sub-status Kodes vir Gebeurntenis-ID 4625:

* **0xC0000064**: Gebruikersnaam bestaan nie - Kan dui op 'n gebruikersnaam enumerasie aanval.
* **0xC000006A**: Korrekte gebruikersnaam maar verkeerde wagwoord - Moontlike wagwoord raai of bruto-kragpoging.
* **0xC0000234**: Gebruikersrekening gesluit - Mag volg op 'n bruto-krag aanval wat lei tot meervoudige mislukte aanmeldings.
* **0xC0000072**: Rekening gedeaktiveer - Onbevoegde pogings om toegang te verkry tot gedeaktiveerde rekeninge.
* **0xC000006F**: Aanmelding buite toegelate tyd - Dui op pogings om toegang te verkry buite die vasgestelde aanmeldingstye, 'n moontlike teken van onbevoegde toegang.
* **0xC0000070**: Oortreding van werkstasiebeperkings - Kan 'n poging wees om vanaf 'n onbevoegde plek aan te meld.
* **0xC0000193**: Rekening verval - Toegangspogings met vervalde gebruikersrekeninge.
* **0xC0000071**: Vervalde wagwoord - Aanmeldingspogings met verouderde wagwoorde.
* **0xC0000133**: Tydsinkronisasieprobleme - Groot tydverskille tussen klient en bediener kan dui op meer gesofistikeerde aanvalle soos pass-the-ticket.
* **0xC0000224**: Verpligte wagwoordverandering vereis - Gereelde verpligte veranderinge mag dui op 'n poging om rekeningsekuriteit te destabiliseer.
* **0xC0000225**: Dui op 'n stelsel fout eerder as 'n sekuriteitskwessie.
* **0xC000015b**: Geweierde aanmeldtipe - Toegangspoging met ongemagtigde aanmeldtipe, soos 'n gebruiker wat probeer om 'n diensaanmelding uit te voer.

#### Gebeurtenis-ID 4616:

* **Tydverandering**: Wysiging van die stelseltyd, kan die tydlyn van gebeure verduister.

#### Gebeurtenis-ID's 6005 en 6006:

* **Stelselbegin en -afsluiting**: Gebeurtenis-ID 6005 dui op die stelsel wat begin, terwyl Gebeurtenis-ID 6006 dit aandui wat afsluit.

#### Gebeurtenis-ID 1102:

* **Log Skrapping**: Sekuriteitslogboeke wat skoongemaak word, wat dikwels 'n rooi vlag is vir die bedekking van onwettige aktiwiteite.

#### Gebeurtenis-ID's vir USB-toestelopsporing:

* **20001 / 20003 / 10000**: USB-toestel eerste koppeling.
* **10100**: USB-bestuursteroptatering.
* **Gebeurtenis-ID 112**: Tyd van USB-toestelinskakeling.

Vir praktiese voorbeelde oor die simulasie van hierdie aanmeldingstipes en gelde dumpingsgeleenthede, verwys na [Altered Security se gedetailleerde gids](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Gebeurtenisbesonderhede, insluitend status- en substatuskodes, bied verdere insigte in gebeureoorzake, veral opmerklik in Gebeurtenis-ID 4625.

### Herstel van Windows Gebeure

Om die kanse op die herwinning van geskrapte Windows-gebeure te verbeter, word dit aanbeveel om die verdagte rekenaar af te skakel deur dit direk uit te trek. **Bulk\_extractor**, 'n herstelwerktuig wat die `.evtx`-uitbreiding spesifiseer, word aanbeveel vir die poging om sulke gebeure te herwin.

### Identifisering van Algemene Aanvalle via Windows Gebeure

Vir 'n omvattende gids oor die gebruik van Windows-gebeurtenis-ID's om algemene siber aanvalle te identifiseer, besoek [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Bruto Krag Aanvalle

Identifiseerbaar deur meervoudige Gebeurtenis-ID 4625 rekords, gevolg deur 'n Gebeurtenis-ID 4624 as die aanval slaag.

#### Tydverandering

Aangeteken deur Gebeurtenis-ID 4616, veranderinge aan stelseltyd kan forensiese analise kompliseer.

#### USB Toestelopsporing

Nuttige Stelsel Gebeurtenis-ID's vir USB-toestelopsporing sluit 20001/20003/10000 vir aanvanklike gebruik, 10100 vir bestuursteroptaterings, en Gebeurtenis-ID 112 van DeviceSetupManager vir inskakelingstydpeile.
#### Stelselkraggebeure

GebeurtenisID 6005 dui op stelselbegin, terwyl GebeurtenisID 6006 afsluiting aandui.

#### Logverwydering

Sekuriteit GebeurtenisID 1102 dui op die verwydering van logboeke, 'n kritieke gebeurtenis vir forensiese analise.
