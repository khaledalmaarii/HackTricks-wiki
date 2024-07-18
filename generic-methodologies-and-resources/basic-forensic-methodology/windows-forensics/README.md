# Windows Artifacts

## Windows Artifacts

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Generic Windows Artifacts

### Windows 10 Notifications

U putanji `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` možete pronaći bazu podataka `appdb.dat` (pre Windows godišnjice) ili `wpndatabase.db` (posle Windows godišnjice).

Unutar ove SQLite baze podataka, možete pronaći tabelu `Notification` sa svim obaveštenjima (u XML formatu) koja mogu sadržati zanimljive podatke.

### Timeline

Timeline je karakteristika Windows-a koja pruža **hronološku istoriju** web stranica koje su posećene, uređivanih dokumenata i izvršenih aplikacija.

Baza podataka se nalazi u putanji `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Ova baza podataka može se otvoriti sa SQLite alatom ili sa alatom [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **koji generiše 2 datoteke koje se mogu otvoriti sa alatom** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Datoteke preuzete mogu sadržati **ADS Zone.Identifier** koji ukazuje **kako** je **preuzeta** sa intraneta, interneta itd. Neki softver (kao što su pregledači) obično dodaju čak i **više** **informacija** kao što je **URL** sa kojeg je datoteka preuzeta.

## **File Backups**

### Recycle Bin

U Vista/Win7/Win8/Win10 **Recycle Bin** se može pronaći u folderu **`$Recycle.bin`** u korenu diska (`C:\$Recycle.bin`).\
Kada se datoteka obriše u ovom folderu, kreiraju se 2 specifične datoteke:

* `$I{id}`: Informacije o datoteci (datum kada je obrisana)
* `$R{id}`: Sadržaj datoteke

![](<../../../.gitbook/assets/image (1029).png>)

Imajući ove datoteke, možete koristiti alat [**Rifiuti**](https://github.com/abelcheung/rifiuti2) da dobijete originalnu adresu obrisanih datoteka i datum kada je obrisana (koristite `rifiuti-vista.exe` za Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy je tehnologija uključena u Microsoft Windows koja može da kreira **rezervne kopije** ili snimke računarskih datoteka ili volumena, čak i kada su u upotrebi.

Ove rezervne kopije se obično nalaze u `\System Volume Information` iz korena datotečnog sistema, a naziv se sastoji od **UID-ova** prikazanih na sledećoj slici:

![](<../../../.gitbook/assets/image (94).png>)

Montiranjem forenzičke slike sa **ArsenalImageMounter**, alat [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) može se koristiti za inspekciju shadow copy i čak **izvlačenje datoteka** iz rezervnih kopija shadow copy.

![](<../../../.gitbook/assets/image (576).png>)

Unos u registru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` sadrži datoteke i ključeve **koje ne treba praviti rezervne kopije**:

![](<../../../.gitbook/assets/image (254).png>)

Registar `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` takođe sadrži informacije o konfiguraciji `Volume Shadow Copies`.

### Office AutoSaved Files

Možete pronaći automatski sačuvane datoteke u: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item je stavka koja sadrži informacije o tome kako pristupiti drugoj datoteci.

### Recent Documents (LNK)

Windows **automatski** **kreira** ove **prečice** kada korisnik **otvori, koristi ili kreira datoteku** u:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Kada se kreira folder, takođe se kreira veza do foldera, do roditeljskog foldera i do foldera bake.

Ove automatski kreirane datoteke sa linkovima **sadrže informacije o poreklu** kao što su da li je to **datoteka** **ili** **folder**, **MAC** **vremena** te datoteke, **informacije o volumenu** gde je datoteka smeštena i **folder ciljne datoteke**. Ove informacije mogu biti korisne za oporavak tih datoteka u slučaju da su uklonjene.

Takođe, **datum kreiranja linka** datoteke je prvi **put** kada je originalna datoteka **prvi put** **korišćena**, a **datum** **modifikacije** link datoteke je **poslednji** **put** kada je originalna datoteka korišćena.

Da biste inspekciju ovih datoteka, možete koristiti [**LinkParser**](http://4discovery.com/our-tools/).

U ovom alatu ćete pronaći **2 skupa** vremenskih oznaka:

* **Prvi skup:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Drugi skup:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Prvi skup vremenskih oznaka se odnosi na **vremenske oznake same datoteke**. Drugi skup se odnosi na **vremenske oznake povezane datoteke**.

Istu informaciju možete dobiti pokretanjem Windows CLI alata: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In this case, the information is going to be saved inside a CSV file.

### Jumplists

Ovo su nedavne datoteke koje su označene po aplikaciji. To je lista **nedavnih datoteka korišćenih od strane aplikacije** kojoj možete pristupiti u svakoj aplikaciji. Mogu biti kreirane **automatski ili po meri**.

**Jumplists** kreirane automatski se čuvaju u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplisti su imenovani prema formatu `{id}.autmaticDestinations-ms` gde je početni ID ID aplikacije.

Prilagođeni jumplisti se čuvaju u `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i obično ih kreira aplikacija jer se nešto **važnog** dogodilo sa datotekom (možda označeno kao omiljeno).

**Vreme kreiranja** bilo kog jumplista označava **prvi put kada je datoteka pristupljena** i **vreme modifikacije poslednji put**.

Možete pregledati jumpliste koristeći [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Napomena: vremenski oznake koje pruža JumplistExplorer su povezane sa samom datotekom jumplist_)

### Shellbags

[**Pratite ovaj link da saznate šta su shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Upotreba Windows USB-a

Moguće je identifikovati da je USB uređaj korišćen zahvaljujući kreiranju:

* Windows Recent Folder
* Microsoft Office Recent Folder
* Jumplists

Napomena da neka LNK datoteka umesto da pokazuje na originalni put, pokazuje na WPDNSE folder:

![](<../../../.gitbook/assets/image (218).png>)

Datoteke u folderu WPDNSE su kopije originalnih, stoga neće preživeti restart PC-a i GUID se uzima iz shellbaga.

### Registry Information

[Proverite ovu stranicu da saznate](interesting-windows-registry-keys.md#usb-information) koji registry ključevi sadrže zanimljive informacije o USB povezanim uređajima.

### setupapi

Proverite datoteku `C:\Windows\inf\setupapi.dev.log` da dobijete vremenske oznake o tome kada je USB konekcija napravljena (potražite `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) može se koristiti za dobijanje informacija o USB uređajima koji su bili povezani sa slikom.

![](<../../../.gitbook/assets/image (452).png>)

### Plug and Play Cleanup

Zakazana aktivnost poznata kao 'Plug and Play Cleanup' prvenstveno je dizajnirana za uklanjanje zastarelih verzija drajvera. Suprotno njenoj specificiranoj svrsi zadržavanja najnovije verzije paketa drajvera, online izvori sugerišu da takođe cilja drajvere koji su bili neaktivni 30 dana. Kao rezultat, drajveri za uklonjive uređaje koji nisu povezani u poslednjih 30 dana mogu biti podložni brisanju.

Zadatak se nalazi na sledećem putu: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Prikazana je slika koja prikazuje sadržaj zadatka: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Ključne komponente i podešavanja zadatka:**

* **pnpclean.dll**: Ova DLL je odgovorna za stvarni proces čišćenja.
* **UseUnifiedSchedulingEngine**: Podešeno na `TRUE`, što ukazuje na korišćenje generičkog mehanizma za zakazivanje zadataka.
* **MaintenanceSettings**:
* **Period ('P1M')**: Usmerava Task Scheduler da pokrene zadatak čišćenja mesečno tokom redovnog automatskog održavanja.
* **Deadline ('P2M')**: Upravlja Task Scheduler-om, ako zadatak ne uspe dva uzastopna meseca, da izvrši zadatak tokom hitnog automatskog održavanja.

Ova konfiguracija osigurava redovno održavanje i čišćenje drajvera, sa odredbama za ponovni pokušaj zadatka u slučaju uzastopnih neuspeha.

**Za više informacija proverite:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Emailovi sadrže **2 zanimljiva dela: zaglavlja i sadržaj** emaila. U **zaglavljima** možete pronaći informacije kao što su:

* **Ko** je poslao emailove (email adresa, IP, mail serveri koji su preusmerili email)
* **Kada** je email poslat

Takođe, unutar `References` i `In-Reply-To` zaglavlja možete pronaći ID poruka:

![](<../../../.gitbook/assets/image (593).png>)

### Windows Mail App

Ova aplikacija čuva emailove u HTML-u ili tekstu. Možete pronaći emailove unutar podfoldera unutar `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Emailovi se čuvaju sa ekstenzijom `.dat`.

**Metapodaci** emailova i **kontakti** mogu se naći unutar **EDB baze podataka**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Promenite ekstenziju** datoteke sa `.vol` na `.edb` i možete koristiti alat [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) da je otvorite. Unutar `Message` tabele možete videti emailove.

### Microsoft Outlook

Kada se koriste Exchange serveri ili Outlook klijenti, biće prisutni neki MAPI zaglavlja:

* `Mapi-Client-Submit-Time`: Vreme sistema kada je email poslat
* `Mapi-Conversation-Index`: Broj poruka u thread-u i vremenska oznaka svake poruke u thread-u
* `Mapi-Entry-ID`: Identifikator poruke.
* `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacije o MAPI klijentu (poruka pročitana? nije pročitana? odgovoreno? preusmereno? van kancelarije?)

U Microsoft Outlook klijentu, sve poslate/primljene poruke, podaci o kontaktima i podaci o kalendaru čuvaju se u PST datoteci u:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Putanja u registru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` ukazuje na datoteku koja se koristi.

Možete otvoriti PST datoteku koristeći alat [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)

### Microsoft Outlook OST Files

**OST datoteka** se generiše od strane Microsoft Outlook-a kada je konfigurisan sa **IMAP** ili **Exchange** serverom, čuvajući slične informacije kao PST datoteka. Ova datoteka se sinhronizuje sa serverom, zadržavajući podatke za **poslednjih 12 meseci** do **maksimalne veličine od 50GB**, i nalazi se u istom direktorijumu kao PST datoteka. Da biste pregledali OST datoteku, može se koristiti [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Retrieving Attachments

Izgubljeni dodaci mogu biti oporavljeni iz:

* Za **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Za **IE11 i više**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** koristi **MBOX datoteke** za čuvanje podataka, smeštene u `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Image Thumbnails

* **Windows XP i 8-8.1**: Pristup folderu sa sličicama generiše `thumbs.db` datoteku koja čuva prikaze slika, čak i nakon brisanja.
* **Windows 7/10**: `thumbs.db` se kreira kada se pristupa preko mreže putem UNC puta.
* **Windows Vista i novije**: Prikazi sličica su centralizovani u `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` sa datotekama imenovanim **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) su alati za pregled ovih datoteka.

### Windows Registry Information

Windows Registry, koji čuva opsežne podatke o sistemu i korisničkim aktivnostima, sadrži se unutar datoteka u:

* `%windir%\System32\Config` za razne `HKEY_LOCAL_MACHINE` podključeve.
* `%UserProfile%{User}\NTUSER.DAT` za `HKEY_CURRENT_USER`.
* Windows Vista i novije verzije prave rezervne kopije `HKEY_LOCAL_MACHINE` registry datoteka u `%Windir%\System32\Config\RegBack\`.
* Pored toga, informacije o izvršenju programa se čuvaju u `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server nadalje.

### Tools

Neki alati su korisni za analizu registry datoteka:

* **Registry Editor**: Instaliran je u Windows-u. To je GUI za navigaciju kroz Windows registry trenutne sesije.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Omogućava vam da učitate registry datoteku i navigirate kroz njih sa GUI-jem. Takođe sadrži oznake koje ističu ključeve sa zanimljivim informacijama.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponovo, ima GUI koji omogućava navigaciju kroz učitani registry i takođe sadrži dodatke koji ističu zanimljive informacije unutar učitanog registry-a.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Još jedna GUI aplikacija sposobna da izvuče važne informacije iz učitanog registry-a.

### Recovering Deleted Element

Kada se ključ obriše, označen je kao takav, ali dok prostor koji zauzima nije potreban, neće biti uklonjen. Stoga, korišćenjem alata kao što je **Registry Explorer** moguće je povratiti ove obrisane ključeve.

### Last Write Time

Svaki Key-Value sadrži **vremensku oznaku** koja označava poslednji put kada je modifikovan.

### SAM

Datoteka/hive **SAM** sadrži **korisnike, grupe i heširane lozinke korisnika** sistema.

U `SAM\Domains\Account\Users` možete dobiti korisničko ime, RID, poslednju prijavu, poslednji neuspešni pokušaj prijave, brojač prijava, politiku lozinki i kada je nalog kreiran. Da biste dobili **hešove** takođe **trebate** datoteku/hive **SYSTEM**.

### Interesting entries in the Windows Registry

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programs Executed

### Basic Windows Processes

U [ovom postu](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) možete saznati o uobičajenim Windows procesima za otkrivanje sumnjivih ponašanja.

### Windows Recent APPs

Unutar registra `NTUSER.DAT` na putu `Software\Microsoft\Current Version\Search\RecentApps` možete pronaći podključeve sa informacijama o **izvršenoj aplikaciji**, **poslednjem putu** kada je izvršena, i **broju puta** kada je pokrenuta.

### BAM (Background Activity Moderator)

Možete otvoriti datoteku `SYSTEM` sa registry editorom i unutar puta `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` možete pronaći informacije o **aplikacijama koje je izvršio svaki korisnik** (napomena na `{SID}` u putu) i **u koje vreme** su izvršene (vreme je unutar Data vrednosti registra).

### Windows Prefetch

Prefetching je tehnika koja omogućava računaru da tiho **preuzme potrebne resurse potrebne za prikazivanje sadržaja** koji korisnik **može pristupiti u bliskoj budućnosti** kako bi se resursi mogli brže pristupiti.

Windows prefetch se sastoji od kreiranja **kešova izvršenih programa** kako bi ih mogli brže učitati. Ovi keševi se kreiraju kao `.pf` datoteke unutar puta: `C:\Windows\Prefetch`. Postoji limit od 128 datoteka u XP/VISTA/WIN7 i 1024 datoteka u Win8/Win10.

Ime datoteke se kreira kao `{program_name}-{hash}.pf` (heš se zasniva na putu i argumentima izvršne datoteke). U W10 ove datoteke su kompresovane. Imajte na umu da sama prisutnost datoteke ukazuje da je **program izvršen** u nekom trenutku.

Datoteka `C:\Windows\Prefetch\Layout.ini` sadrži **imena foldera datoteka koje su preuzete**. Ova datoteka sadrži **informacije o broju izvršenja**, **datumima** izvršenja i **datotekama** **otvorenim** od strane programa.

Da biste pregledali ove datoteke, možete koristiti alat [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** ima isti cilj kao i prefetch, **brže učitavanje programa** predviđanjem šta će biti učitano sledeće. Međutim, ne zamenjuje prefetch servis.\
Ova usluga će generisati datoteke baze podataka u `C:\Windows\Prefetch\Ag*.db`.

U ovim bazama podataka možete pronaći **ime** **programa**, **broj** **izvršavanja**, **otvorene** **datoteke**, **pristup** **volumenu**, **potpunu** **putanju**, **vremenske okvire** i **vremenske oznake**.

Možete pristupiti ovim informacijama koristeći alat [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**Monitor korišćenja sistemskih resursa** (SRUM) **prati** **resurse** **koje koristi** **proces**. Pojavio se u W8 i čuva podatke u ESE bazi podataka smeštenoj u `C:\Windows\System32\sru\SRUDB.dat`.

Daje sledeće informacije:

* AppID i Putanja
* Korisnik koji je izvršio proces
* Poslati bajtovi
* Primljeni bajtovi
* Mrežni interfejs
* Trajanje veze
* Trajanje procesa

Ove informacije se ažuriraju svake 60 minuta.

Možete dobiti podatke iz ove datoteke koristeći alat [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, poznat i kao **ShimCache**, deo je **Baze podataka o kompatibilnosti aplikacija** koju je razvila **Microsoft** kako bi se rešili problemi sa kompatibilnošću aplikacija. Ova sistemska komponenta beleži razne delove metapodataka o datotekama, koji uključuju:

* Puni put do datoteke
* Veličinu datoteke
* Vreme poslednje izmene pod **$Standard\_Information** (SI)
* Vreme poslednje ažuriranja ShimCache-a
* Zastavicu izvršenja procesa

Ovi podaci se čuvaju u registru na specifičnim lokacijama u zavisnosti od verzije operativnog sistema:

* Za XP, podaci se čuvaju pod `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` sa kapacitetom za 96 unosa.
* Za Server 2003, kao i za Windows verzije 2008, 2012, 2016, 7, 8 i 10, putanja za skladištenje je `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, sa kapacitetom od 512 i 1024 unosa, respektivno.

Za parsiranje sačuvanih informacija, preporučuje se korišćenje [**AppCompatCacheParser** alata](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

**Amcache.hve** datoteka je u suštini registri hives koji beleži detalje o aplikacijama koje su izvršene na sistemu. Obično se nalazi na `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ova datoteka je značajna jer čuva zapise o nedavno izvršenim procesima, uključujući puteve do izvršnih datoteka i njihove SHA1 heš vrednosti. Ove informacije su neprocenjive za praćenje aktivnosti aplikacija na sistemu.

Za ekstrakciju i analizu podataka iz **Amcache.hve**, može se koristiti [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) alat. Sledeća komanda je primer kako koristiti AmcacheParser za parsiranje sadržaja **Amcache.hve** datoteke i izlaz rezultata u CSV formatu:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Među generisanim CSV datotekama, `Amcache_Unassociated file entries` je posebno značajan zbog bogatih informacija koje pruža o neudruženim unosima datoteka.

Najzanimljivija CVS datoteka koja je generisana je `Amcache_Unassociated file entries`.

### RecentFileCache

Ovaj artefakt se može naći samo u W7 u `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` i sadrži informacije o nedavnoj izvršavanju nekih binarnih datoteka.

Možete koristiti alat [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) za analizu datoteke.

### Zakazane aktivnosti

Možete ih izvući iz `C:\Windows\Tasks` ili `C:\Windows\System32\Tasks` i pročitati ih kao XML.

### Servisi

Možete ih pronaći u registru pod `SYSTEM\ControlSet001\Services`. Možete videti šta će biti izvršeno i kada.

### **Windows Store**

Instalirane aplikacije se mogu naći u `\ProgramData\Microsoft\Windows\AppRepository\`\
Ova biblioteka ima **log** sa **svakom instaliranom aplikacijom** u sistemu unutar baze podataka **`StateRepository-Machine.srd`**.

Unutar tabele aplikacija ove baze podataka, moguće je pronaći kolone: "Application ID", "PackageNumber" i "Display Name". Ove kolone imaju informacije o unapred instaliranim i instaliranim aplikacijama i može se utvrditi da li su neke aplikacije deinstalirane jer bi ID-ovi instaliranih aplikacija trebali biti sekvencijalni.

Takođe je moguće **pronaći instaliranu aplikaciju** unutar registra na putanji: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
I **deinstalirane** **aplikacije** u: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows događaji

Informacije koje se pojavljuju unutar Windows događaja su:

* Šta se desilo
* Vreme (UTC + 0)
* Uključeni korisnici
* Uključeni hostovi (hostname, IP)
* Pristupeni resursi (datoteke, folderi, štampači, servisi)

Logovi se nalaze u `C:\Windows\System32\config` pre Windows Vista i u `C:\Windows\System32\winevt\Logs` nakon Windows Vista. Pre Windows Vista, logovi događaja su bili u binarnom formatu, a nakon toga su u **XML formatu** i koriste **.evtx** ekstenziju.

Lokacija datoteka događaja može se pronaći u SYSTEM registru u **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Mogu se vizualizovati iz Windows Event Viewer-a (**`eventvwr.msc`**) ili sa drugim alatima kao što su [**Event Log Explorer**](https://eventlogxp.com) **ili** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Razumevanje Windows sigurnosnog logovanja događaja

Događaji pristupa se beleže u datoteci sigurnosne konfiguracije koja se nalazi na `C:\Windows\System32\winevt\Security.evtx`. Veličina ove datoteke je prilagodljiva, a kada se dostigne njena kapacitet, stariji događaji se prepisuju. Beleženi događaji uključuju prijave i odjave korisnika, korisničke akcije i promene u sigurnosnim postavkama, kao i pristup datotekama, folderima i zajedničkim resursima.

### Ključni ID-evi događaja za autentifikaciju korisnika:

* **EventID 4624**: Ukazuje na to da je korisnik uspešno autentifikovan.
* **EventID 4625**: Signalizira neuspeh autentifikacije.
* **EventIDs 4634/4647**: Predstavljaju događaje odjave korisnika.
* **EventID 4672**: Označava prijavu sa administratorskim privilegijama.

#### Podtipovi unutar EventID 4634/4647:

* **Interaktivno (2)**: Direktna prijava korisnika.
* **Mrežno (3)**: Pristup zajedničkim folderima.
* **Serijski (4)**: Izvršenje serijskih procesa.
* **Servis (5)**: Pokretanje servisa.
* **Proxy (6)**: Proxy autentifikacija.
* **Otključavanje (7)**: Ekran otključan lozinkom.
* **Mrežni čist tekst (8)**: Prenos lozinke u čistom tekstu, često iz IIS-a.
* **Nove kredencijale (9)**: Korišćenje različitih kredencijala za pristup.
* **Daljinsko interaktivno (10)**: Prijava putem daljinske radne površine ili terminalskih usluga.
* **Keširano interaktivno (11)**: Prijava sa keširanim kredencijalima bez kontakta sa kontrolerom domena.
* **Keširano daljinsko interaktivno (12)**: Daljinska prijava sa keširanim kredencijalima.
* **Keširano otključavanje (13)**: Otključavanje sa keširanim kredencijalima.

#### Status i podstatus kodovi za EventID 4625:

* **0xC0000064**: Korisničko ime ne postoji - Može ukazivati na napad na enumeraciju korisničkog imena.
* **0xC000006A**: Tačno korisničko ime, ali pogrešna lozinka - Mogući pokušaj pogađanja lozinke ili brute-force napad.
* **0xC0000234**: Korisnički nalog je zaključan - Može uslediti nakon brute-force napada koji rezultira višestrukim neuspelim prijavama.
* **0xC0000072**: Nalog onemogućen - Neovlašćeni pokušaji pristupa onemogućenim nalozima.
* **0xC000006F**: Prijava van dozvoljenog vremena - Ukazuje na pokušaje pristupa van postavljenih sati prijave, mogući znak neovlašćenog pristupa.
* **0xC0000070**: Kršenje ograničenja radne stanice - Može biti pokušaj prijave sa neovlašćenog mesta.
* **0xC0000193**: Istek naloga - Pokušaji pristupa sa isteklim korisničkim nalozima.
* **0xC0000071**: Istekla lozinka - Pokušaji prijave sa zastarelim lozinkama.
* **0xC0000133**: Problemi sa sinhronizacijom vremena - Velike vremenske razlike između klijenta i servera mogu ukazivati na sofisticiranije napade poput pass-the-ticket.
* **0xC0000224**: Obavezna promena lozinke potrebna - Česte obavezne promene mogu sugerisati pokušaj destabilizacije sigurnosti naloga.
* **0xC0000225**: Ukazuje na grešku u sistemu, a ne na sigurnosni problem.
* **0xC000015b**: Odbijeni tip prijave - Pokušaj pristupa sa neovlašćenim tipom prijave, kao što je korisnik koji pokušava da izvrši prijavu servisa.

#### EventID 4616:

* **Promena vremena**: Izmena sistemskog vremena, može zamagliti hronologiju događaja.

#### EventID 6005 i 6006:

* **Pokretanje i gašenje sistema**: EventID 6005 označava pokretanje sistema, dok EventID 6006 označava gašenje.

#### EventID 1102:

* **Brisanje logova**: Brisanje sigurnosnih logova, što je često crvena zastava za prikrivanje nezakonitih aktivnosti.

#### EventIDs za praćenje USB uređaja:

* **20001 / 20003 / 10000**: Prva konekcija USB uređaja.
* **10100**: Ažuriranje USB drajvera.
* **EventID 112**: Vreme umetanja USB uređaja.

Za praktične primere simulacije ovih tipova prijava i mogućnosti iskopavanja kredencijala, pogledajte [detaljni vodič Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Detalji događaja, uključujući status i podstatus kodove, pružaju dodatne uvide u uzroke događaja, posebno u Event ID 4625.

### Oporavak Windows događaja

Da biste povećali šanse za oporavak obrisanih Windows događaja, preporučuje se da isključite sumnjivi računar direktnim isključivanjem. **Bulk\_extractor**, alat za oporavak koji specificira ekstenziju `.evtx`, se preporučuje za pokušaj oporavka takvih događaja.

### Identifikacija uobičajenih napada putem Windows događaja

Za sveobuhvatan vodič o korišćenju Windows Event ID-ova u identifikaciji uobičajenih sajber napada, posetite [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force napadi

Identifikovani višestrukim zapisima EventID 4625, praćenim EventID 4624 ako napad uspe.

#### Promena vremena

Zabeležena EventID 4616, promene u sistemskom vremenu mogu otežati forenzičku analizu.

#### Praćenje USB uređaja

Korisni sistemski EventIDs za praćenje USB uređaja uključuju 20001/20003/10000 za početnu upotrebu, 10100 za ažuriranja drajvera, i EventID 112 iz DeviceSetupManager-a za vremenske oznake umetanja.

#### Događaji napajanja sistema

EventID 6005 označava pokretanje sistema, dok EventID 6006 označava gašenje.

#### Brisanje logova

Sigurnosni EventID 1102 signalizira brisanje logova, kritičan događaj za forenzičku analizu.

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
