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

W ścieżce `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` można znaleźć bazę danych `appdb.dat` (przed rocznicą Windows) lub `wpndatabase.db` (po rocznicy Windows).

Wewnątrz tej bazy danych SQLite można znaleźć tabelę `Notification` z wszystkimi powiadomieniami (w formacie XML), które mogą zawierać interesujące dane.

### Timeline

Timeline to cecha Windows, która zapewnia **chronologiczną historię** odwiedzanych stron internetowych, edytowanych dokumentów i uruchamianych aplikacji.

Baza danych znajduje się w ścieżce `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Ta baza danych może być otwarta za pomocą narzędzia SQLite lub za pomocą narzędzia [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **które generuje 2 pliki, które można otworzyć za pomocą narzędzia** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Pobrane pliki mogą zawierać **ADS Zone.Identifier**, wskazujący **jak** został **pobrany** z intranetu, internetu itp. Niektóre oprogramowanie (jak przeglądarki) zazwyczaj dodaje nawet **więcej** **informacji**, takich jak **URL**, z którego plik został pobrany.

## **File Backups**

### Recycle Bin

W Vista/Win7/Win8/Win10 **Kosz** można znaleźć w folderze **`$Recycle.bin`** w głównym katalogu dysku (`C:\$Recycle.bin`).\
Gdy plik jest usuwany w tym folderze, tworzone są 2 specyficzne pliki:

* `$I{id}`: Informacje o pliku (data, kiedy został usunięty)
* `$R{id}`: Zawartość pliku

![](<../../../.gitbook/assets/image (1029).png>)

Mając te pliki, można użyć narzędzia [**Rifiuti**](https://github.com/abelcheung/rifiuti2), aby uzyskać oryginalny adres usuniętych plików oraz datę ich usunięcia (użyj `rifiuti-vista.exe` dla Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Kopie zapasowe Shadow

Kopia zapasowa Shadow to technologia zawarta w systemie Microsoft Windows, która może tworzyć **kopie zapasowe** lub migawki plików lub woluminów komputerowych, nawet gdy są one używane.

Te kopie zapasowe zazwyczaj znajdują się w `\System Volume Information` z katalogu głównego systemu plików, a ich nazwa składa się z **UID-ów** pokazanych na poniższym obrazie:

![](<../../../.gitbook/assets/image (94).png>)

Montaż obrazu forensycznego za pomocą **ArsenalImageMounter**, narzędzie [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) może być użyte do inspekcji kopii zapasowej shadow i nawet **wyodrębnienia plików** z kopii zapasowych shadow.

![](<../../../.gitbook/assets/image (576).png>)

Wpis rejestru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` zawiera pliki i klucze **do niekopiowania**:

![](<../../../.gitbook/assets/image (254).png>)

Rejestr `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` zawiera również informacje konfiguracyjne dotyczące `Kopii zapasowych Shadow`.

### Automatycznie zapisywane pliki Office

Możesz znaleźć automatycznie zapisywane pliki Office w: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementy powłoki

Element powłoki to element, który zawiera informacje o tym, jak uzyskać dostęp do innego pliku.

### Ostatnie dokumenty (LNK)

Windows **automatycznie** **tworzy** te **skrót** gdy użytkownik **otwiera, używa lub tworzy plik** w:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Gdy folder jest tworzony, tworzony jest również link do folderu, do folderu nadrzędnego i folderu dziadka.

Te automatycznie tworzone pliki linków **zawierają informacje o pochodzeniu**, takie jak czy to jest **plik** **czy** **folder**, **czasy MAC** tego pliku, **informacje o woluminie** gdzie plik jest przechowywany oraz **folder pliku docelowego**. Te informacje mogą być przydatne do odzyskania tych plików w przypadku ich usunięcia.

Ponadto, **data utworzenia linku** to pierwszy **raz**, kiedy oryginalny plik był **po raz pierwszy** **używany**, a **data** **zmodyfikowana** pliku linku to **ostatni** **raz**, kiedy plik źródłowy był używany.

Aby zbadać te pliki, możesz użyć [**LinkParser**](http://4discovery.com/our-tools/).

W tym narzędziu znajdziesz **2 zestawy** znaczników czasu:

* **Pierwszy zestaw:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Drugi zestaw:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Pierwszy zestaw znaczników czasu odnosi się do **znaczników czasu samego pliku**. Drugi zestaw odnosi się do **znaczników czasu pliku linku**.

Możesz uzyskać te same informacje, uruchamiając narzędzie CLI Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In this case, the information is going to be saved inside a CSV file.

### Jumplists

To są ostatnie pliki, które są wskazywane dla każdej aplikacji. To lista **ostatnich plików używanych przez aplikację**, do której możesz uzyskać dostęp w każdej aplikacji. Mogą być tworzone **automatycznie lub być dostosowane**.

**Jumplisty** tworzone automatycznie są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplisty są nazwane według formatu `{id}.autmaticDestinations-ms`, gdzie początkowy ID to ID aplikacji.

Dostosowane jumplisty są przechowywane w `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i są tworzone przez aplikację zazwyczaj, ponieważ coś **ważnego** wydarzyło się z plikiem (może oznaczone jako ulubione).

**Czas utworzenia** dowolnego jumplista wskazuje **pierwszy czas, kiedy plik był otwarty** oraz **czas modyfikacji ostatni raz**.

Możesz sprawdzić jumplisty używając [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Zauważ, że znaczniki czasowe podane przez JumplistExplorer odnoszą się do samego pliku jumplist_)

### Shellbags

[**Śledź ten link, aby dowiedzieć się, czym są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie USB w systemie Windows

Możliwe jest zidentyfikowanie, że urządzenie USB było używane dzięki utworzeniu:

* Folderu Ostatnie w systemie Windows
* Folderu Ostatnie w Microsoft Office
* Jumplistów

Zauważ, że niektóre pliki LNK zamiast wskazywać na oryginalną ścieżkę, wskazują na folder WPDNSE:

![](<../../../.gitbook/assets/image (218).png>)

Pliki w folderze WPDNSE są kopią oryginalnych, więc nie przetrwają ponownego uruchomienia PC, a GUID jest pobierany z shellbag.

### Informacje rejestru

[Sprawdź tę stronę, aby dowiedzieć się](interesting-windows-registry-keys.md#usb-information), które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

Sprawdź plik `C:\Windows\inf\setupapi.dev.log`, aby uzyskać znaczniki czasowe dotyczące momentu, w którym połączenie USB zostało nawiązane (szukaj `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) może być używany do uzyskania informacji o urządzeniach USB, które były podłączone do obrazu.

![](<../../../.gitbook/assets/image (452).png>)

### Czyszczenie Plug and Play

Zadanie zaplanowane znane jako 'Czyszczenie Plug and Play' jest głównie zaprojektowane do usuwania przestarzałych wersji sterowników. Wbrew swojemu określonemu celowi, aby zachować najnowszą wersję pakietu sterowników, źródła online sugerują, że celuje również w sterowniki, które były nieaktywne przez 30 dni. W związku z tym, sterowniki dla urządzeń przenośnych, które nie były podłączone w ciągu ostatnich 30 dni, mogą być poddane usunięciu.

Zadanie znajduje się pod następującą ścieżką: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Zrzut ekranu przedstawiający zawartość zadania jest dostarczony: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kluczowe komponenty i ustawienia zadania:**

* **pnpclean.dll**: Ten DLL jest odpowiedzialny za rzeczywisty proces czyszczenia.
* **UseUnifiedSchedulingEngine**: Ustawione na `TRUE`, co wskazuje na użycie ogólnego silnika planowania zadań.
* **MaintenanceSettings**:
* **Okres ('P1M')**: Nakazuje Harmonogramowi Zadań uruchomienie zadania czyszczenia co miesiąc podczas regularnej automatycznej konserwacji.
* **Termin ('P2M')**: Nakazuje Harmonogramowi Zadań, jeśli zadanie nie powiedzie się przez dwa kolejne miesiące, aby wykonać zadanie podczas awaryjnej automatycznej konserwacji.

Ta konfiguracja zapewnia regularną konserwację i czyszczenie sterowników, z postanowieniami o ponownym podejmowaniu próby zadania w przypadku kolejnych niepowodzeń.

**Aby uzyskać więcej informacji, sprawdź:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-maile

E-maile zawierają **2 interesujące części: nagłówki i treść** e-maila. W **nagłówkach** możesz znaleźć informacje takie jak:

* **Kto** wysłał e-maile (adres e-mail, IP, serwery pocztowe, które przekierowały e-mail)
* **Kiedy** e-mail został wysłany

Ponadto, w nagłówkach `References` i `In-Reply-To` możesz znaleźć ID wiadomości:

![](<../../../.gitbook/assets/image (593).png>)

### Aplikacja Poczta systemu Windows

Ta aplikacja zapisuje e-maile w formacie HTML lub tekstowym. Możesz znaleźć e-maile w podfolderach w `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. E-maile są zapisywane z rozszerzeniem `.dat`.

**Metadane** e-maili i **kontakty** można znaleźć w **bazie danych EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Zmień rozszerzenie** pliku z `.vol` na `.edb`, a możesz użyć narzędzia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), aby go otworzyć. W tabeli `Message` możesz zobaczyć e-maile.

### Microsoft Outlook

Gdy używane są serwery Exchange lub klienci Outlook, będą tam pewne nagłówki MAPI:

* `Mapi-Client-Submit-Time`: Czas systemu, kiedy e-mail został wysłany
* `Mapi-Conversation-Index`: Liczba wiadomości dziecięcych w wątku i znacznik czasu każdej wiadomości w wątku
* `Mapi-Entry-ID`: Identyfikator wiadomości.
* `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacje o kliencie MAPI (wiadomość przeczytana? nieprzeczytana? odpowiedziano? przekierowano? nieobecny w biurze?)

W kliencie Microsoft Outlook wszystkie wysłane/odebrane wiadomości, dane kontaktowe i dane kalendarza są przechowywane w pliku PST w:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` wskazuje na plik, który jest używany.

Możesz otworzyć plik PST używając narzędzia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)

### Pliki Microsoft Outlook OST

Plik **OST** jest generowany przez Microsoft Outlook, gdy jest skonfigurowany z **IMAP** lub serwerem **Exchange**, przechowując podobne informacje do pliku PST. Ten plik jest synchronizowany z serwerem, zachowując dane przez **ostatnie 12 miesięcy** do **maksymalnego rozmiaru 50 GB**, i znajduje się w tym samym katalogu co plik PST. Aby wyświetlić plik OST, można wykorzystać [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Przywracanie załączników

Zgubione załączniki mogą być odzyskiwane z:

* Dla **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Dla **IE11 i nowszych**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Pliki MBOX Thunderbirda

**Thunderbird** wykorzystuje **pliki MBOX** do przechowywania danych, znajdujące się w `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatury obrazów

* **Windows XP i 8-8.1**: Uzyskanie dostępu do folderu z miniaturami generuje plik `thumbs.db`, który przechowuje podglądy obrazów, nawet po usunięciu.
* **Windows 7/10**: `thumbs.db` jest tworzony, gdy uzyskuje się dostęp przez sieć za pomocą ścieżki UNC.
* **Windows Vista i nowsze**: Podglądy miniatur są centralizowane w `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` z plikami nazwanymi **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) to narzędzia do przeglądania tych plików.

### Informacje rejestru systemu Windows

Rejestr systemu Windows, przechowujący obszerne dane o aktywności systemu i użytkownika, znajduje się w plikach w:

* `%windir%\System32\Config` dla różnych podkluczy `HKEY_LOCAL_MACHINE`.
* `%UserProfile%{User}\NTUSER.DAT` dla `HKEY_CURRENT_USER`.
* Windows Vista i nowsze wersje tworzą kopie zapasowe plików rejestru `HKEY_LOCAL_MACHINE` w `%Windir%\System32\Config\RegBack\`.
* Dodatkowo, informacje o wykonaniu programów są przechowywane w `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server wzwyż.

### Narzędzia

Niektóre narzędzia są przydatne do analizy plików rejestru:

* **Edytor rejestru**: Jest zainstalowany w systemie Windows. To GUI do nawigacji przez rejestr Windows bieżącej sesji.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Umożliwia załadowanie pliku rejestru i nawigację przez nie za pomocą GUI. Zawiera również zakładki podkreślające klucze z interesującymi informacjami.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponownie, ma GUI, które pozwala na nawigację przez załadowany rejestr i zawiera również wtyczki, które podkreślają interesujące informacje w załadowanym rejestrze.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Inna aplikacja GUI zdolna do wydobywania ważnych informacji z załadowanego rejestru.

### Odzyskiwanie usuniętego elementu

Gdy klucz jest usuwany, jest oznaczany jako taki, ale dopóki przestrzeń, którą zajmuje, nie jest potrzebna, nie zostanie usunięty. Dlatego używając narzędzi takich jak **Registry Explorer**, możliwe jest odzyskanie tych usuniętych kluczy.

### Ostatni czas zapisu

Każda para klucz-wartość zawiera **znacznik czasu** wskazujący ostatni czas, kiedy została zmodyfikowana.

### SAM

Plik/hive **SAM** zawiera **użytkowników, grupy i hashe haseł użytkowników** systemu.

W `SAM\Domains\Account\Users` możesz uzyskać nazwę użytkownika, RID, ostatnie logowanie, ostatnie nieudane logowanie, licznik logowania, politykę haseł i kiedy konto zostało utworzone. Aby uzyskać **hashe**, musisz również **mieć** plik/hive **SYSTEM**.

### Interesujące wpisy w rejestrze systemu Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Wykonane programy

### Podstawowe procesy systemu Windows

W [tym poście](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) możesz dowiedzieć się o wspólnych procesach systemu Windows, aby wykryć podejrzane zachowania.

### Ostatnie aplikacje systemu Windows

W rejestrze `NTUSER.DAT` w ścieżce `Software\Microsoft\Current Version\Search\RecentApps` możesz znaleźć podklucze z informacjami o **wykonanej aplikacji**, **ostatnim czasie**, kiedy była wykonywana, oraz **liczbie razy**, kiedy była uruchamiana.

### BAM (Moderator Aktywności w Tle)

Możesz otworzyć plik `SYSTEM` za pomocą edytora rejestru, a w ścieżce `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` możesz znaleźć informacje o **aplikacjach wykonywanych przez każdego użytkownika** (zauważ `{SID}` w ścieżce) oraz **o której godzinie** były wykonywane (czas znajduje się w wartości danych rejestru).

### Prefetch systemu Windows

Prefetching to technika, która pozwala komputerowi cicho **pobierać niezbędne zasoby potrzebne do wyświetlenia treści**, do której użytkownik **może uzyskać dostęp w niedalekiej przyszłości**, aby zasoby mogły być szybciej dostępne.

Prefetch systemu Windows polega na tworzeniu **cache'ów wykonanych programów**, aby móc je ładować szybciej. Te cache są tworzone jako pliki `.pf` w ścieżce: `C:\Windows\Prefetch`. Istnieje limit 128 plików w XP/VISTA/WIN7 i 1024 plików w Win8/Win10.

Nazwa pliku jest tworzona jako `{program_name}-{hash}.pf` (hash jest oparty na ścieżce i argumentach wykonywalnych). W W10 te pliki są skompresowane. Zauważ, że sama obecność pliku wskazuje, że **program był wykonywany** w pewnym momencie.

Plik `C:\Windows\Prefetch\Layout.ini` zawiera **nazwy folderów plików, które są prefetchowane**. Ten plik zawiera **informacje o liczbie wykonania**, **datach** wykonania i **plikach** **otwartych** przez program.

Aby sprawdzić te pliki, możesz użyć narzędzia [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** ma ten sam cel co prefetch, **szybsze ładowanie programów** poprzez przewidywanie, co będzie ładowane następnie. Jednak nie zastępuje usługi prefetch.\
Ta usługa generuje pliki bazy danych w `C:\Windows\Prefetch\Ag*.db`.

W tych bazach danych można znaleźć **nazwę** **programu**, **liczbę** **wykonań**, **otwarte** **pliki**, **dostępny** **wolumin**, **pełną** **ścieżkę**, **ramy czasowe** i **znaczniki czasu**.

Możesz uzyskać dostęp do tych informacji za pomocą narzędzia [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitoruje** **zasoby** **zużywane** **przez proces**. Pojawił się w W8 i przechowuje dane w bazie danych ESE znajdującej się w `C:\Windows\System32\sru\SRUDB.dat`.

Daje następujące informacje:

* AppID i Ścieżka
* Użytkownik, który wykonał proces
* Wysłane bajty
* Odebrane bajty
* Interfejs sieciowy
* Czas trwania połączenia
* Czas trwania procesu

Te informacje są aktualizowane co 60 minut.

Możesz uzyskać datę z tego pliku za pomocą narzędzia [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, jest częścią **Bazy Danych Zgodności Aplikacji** opracowanej przez **Microsoft** w celu rozwiązania problemów z kompatybilnością aplikacji. Ten komponent systemowy rejestruje różne elementy metadanych plików, które obejmują:

* Pełna ścieżka do pliku
* Rozmiar pliku
* Czas ostatniej modyfikacji w **$Standard\_Information** (SI)
* Czas ostatniej aktualizacji ShimCache
* Flaga wykonania procesu

Takie dane są przechowywane w rejestrze w określonych lokalizacjach w zależności od wersji systemu operacyjnego:

* Dla XP dane są przechowywane pod `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` z pojemnością 96 wpisów.
* Dla Server 2003, a także dla wersji Windows 2008, 2012, 2016, 7, 8 i 10, ścieżka przechowywania to `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, mieszcząca odpowiednio 512 i 1024 wpisy.

Aby przeanalizować przechowywane informacje, zaleca się użycie narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

Plik **Amcache.hve** jest zasadniczo hives rejestru, który rejestruje szczegóły dotyczące aplikacji, które zostały uruchomione w systemie. Zwykle znajduje się w `C:\Windows\AppCompat\Programas\Amcache.hve`.

Plik ten jest znany z przechowywania zapisów niedawno uruchomionych procesów, w tym ścieżek do plików wykonywalnych i ich skrótów SHA1. Informacje te są nieocenione do śledzenia aktywności aplikacji w systemie.

Aby wyodrębnić i przeanalizować dane z **Amcache.hve**, można użyć narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Poniższe polecenie jest przykładem, jak użyć AmcacheParser do analizy zawartości pliku **Amcache.hve** i wyjścia wyników w formacie CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Wśród wygenerowanych plików CSV, `Amcache_Unassociated file entries` jest szczególnie godny uwagi ze względu na bogate informacje, jakie dostarcza o niepowiązanych wpisach plików.

Najciekawszym plikiem CVS jest `Amcache_Unassociated file entries`.

### RecentFileCache

Ten artefakt można znaleźć tylko w W7 w `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` i zawiera informacje o niedawnych wykonaniach niektórych binariów.

Możesz użyć narzędzia [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) do analizy pliku.

### Zaplanowane zadania

Możesz je wyodrębnić z `C:\Windows\Tasks` lub `C:\Windows\System32\Tasks` i odczytać jako XML.

### Usługi

Możesz je znaleźć w rejestrze pod `SYSTEM\ControlSet001\Services`. Możesz zobaczyć, co ma być wykonane i kiedy.

### **Windows Store**

Zainstalowane aplikacje można znaleźć w `\ProgramData\Microsoft\Windows\AppRepository\`\
To repozytorium ma **log** z **każdą zainstalowaną aplikacją** w systemie wewnątrz bazy danych **`StateRepository-Machine.srd`**.

W tabeli Aplikacji tej bazy danych można znaleźć kolumny: "Application ID", "PackageNumber" i "Display Name". Kolumny te zawierają informacje o aplikacjach wstępnie zainstalowanych i zainstalowanych, a także można sprawdzić, czy niektóre aplikacje zostały odinstalowane, ponieważ identyfikatory zainstalowanych aplikacji powinny być sekwencyjne.

Można również **znaleźć zainstalowane aplikacje** w ścieżce rejestru: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
A **odinstalowane** **aplikacje** w: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Wydarzenia Windows

Informacje, które pojawiają się w wydarzeniach Windows, to:

* Co się stało
* Znacznik czasu (UTC + 0)
* Użytkownicy zaangażowani
* Hosty zaangażowane (nazwa hosta, IP)
* Zasoby dostępne (pliki, folder, drukarka, usługi)

Logi znajdują się w `C:\Windows\System32\config` przed Windows Vista i w `C:\Windows\System32\winevt\Logs` po Windows Vista. Przed Windows Vista logi zdarzeń były w formacie binarnym, a po nim są w **formacie XML** i używają rozszerzenia **.evtx**.

Lokalizacja plików zdarzeń może być znaleziona w rejestrze SYSTEM w **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Mogą być wizualizowane z Podglądu zdarzeń Windows (**`eventvwr.msc`**) lub za pomocą innych narzędzi, takich jak [**Event Log Explorer**](https://eventlogxp.com) **lub** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Zrozumienie rejestrowania zdarzeń zabezpieczeń Windows

Zdarzenia dostępu są rejestrowane w pliku konfiguracyjnym zabezpieczeń znajdującym się w `C:\Windows\System32\winevt\Security.evtx`. Rozmiar tego pliku jest regulowany, a gdy jego pojemność zostanie osiągnięta, starsze zdarzenia są nadpisywane. Zarejestrowane zdarzenia obejmują logowania i wylogowania użytkowników, działania użytkowników oraz zmiany w ustawieniach zabezpieczeń, a także dostęp do plików, folderów i wspólnych zasobów.

### Kluczowe identyfikatory zdarzeń dla uwierzytelniania użytkowników:

* **EventID 4624**: Wskazuje, że użytkownik pomyślnie się uwierzytelnił.
* **EventID 4625**: Sygnalizuje niepowodzenie uwierzytelnienia.
* **EventIDs 4634/4647**: Reprezentują zdarzenia wylogowania użytkownika.
* **EventID 4672**: Oznacza logowanie z uprawnieniami administracyjnymi.

#### Podtypy w EventID 4634/4647:

* **Interaktywny (2)**: Bezpośrednie logowanie użytkownika.
* **Sieciowy (3)**: Dostęp do wspólnych folderów.
* **Partia (4)**: Wykonanie procesów wsadowych.
* **Usługa (5)**: Uruchomienia usług.
* **Proxy (6)**: Uwierzytelnienie proxy.
* **Odblokowanie (7)**: Ekran odblokowany hasłem.
* **Sieciowy tekst jawny (8)**: Przesyłanie hasła w postaci jawnej, często z IIS.
* **Nowe poświadczenia (9)**: Użycie różnych poświadczeń do uzyskania dostępu.
* **Zdalny interaktywny (10)**: Logowanie do pulpitu zdalnego lub usług terminalowych.
* **Interaktywny z pamięci podręcznej (11)**: Logowanie z pamięci podręcznej bez kontaktu z kontrolerem domeny.
* **Zdalny interaktywny z pamięci podręcznej (12)**: Zdalne logowanie z pamięci podręcznej.
* **Odblokowanie z pamięci podręcznej (13)**: Odblokowanie z pamięci podręcznej.

#### Kody statusu i podstatusu dla EventID 4625:

* **0xC0000064**: Nazwa użytkownika nie istnieje - Może wskazywać na atak enumeracji nazw użytkowników.
* **0xC000006A**: Poprawna nazwa użytkownika, ale błędne hasło - Możliwa próba zgadywania hasła lub atak brute-force.
* **0xC0000234**: Konto użytkownika zablokowane - Może nastąpić po ataku brute-force skutkującym wieloma nieudanymi logowaniami.
* **0xC0000072**: Konto wyłączone - Nieautoryzowane próby dostępu do wyłączonych kont.
* **0xC000006F**: Logowanie poza dozwolonym czasem - Wskazuje na próby dostępu poza ustalonymi godzinami logowania, co może być oznaką nieautoryzowanego dostępu.
* **0xC0000070**: Naruszenie ograniczeń stacji roboczej - Może być próbą logowania z nieautoryzowanej lokalizacji.
* **0xC0000193**: Wygasłe konto - Próby dostępu z wygasłymi kontami użytkowników.
* **0xC0000071**: Wygasłe hasło - Próby logowania z przestarzałymi hasłami.
* **0xC0000133**: Problemy z synchronizacją czasu - Duże różnice czasowe między klientem a serwerem mogą wskazywać na bardziej zaawansowane ataki, takie jak pass-the-ticket.
* **0xC0000224**: Wymagana zmiana hasła - Częste obowiązkowe zmiany mogą sugerować próbę destabilizacji bezpieczeństwa konta.
* **0xC0000225**: Wskazuje na błąd systemowy, a nie problem z bezpieczeństwem.
* **0xC000015b**: Odrzucony typ logowania - Próba dostępu z nieautoryzowanym typem logowania, na przykład użytkownik próbujący wykonać logowanie usługi.

#### EventID 4616:

* **Zmiana czasu**: Modyfikacja czasu systemowego, co może zaciemnić chronologię zdarzeń.

#### EventID 6005 i 6006:

* **Uruchomienie i zamknięcie systemu**: EventID 6005 wskazuje na uruchomienie systemu, podczas gdy EventID 6006 oznacza jego zamknięcie.

#### EventID 1102:

* **Usunięcie logów**: Czyszczenie logów zabezpieczeń, co często jest sygnałem do ukrywania nielegalnych działań.

#### EventIDs do śledzenia urządzeń USB:

* **20001 / 20003 / 10000**: Pierwsze połączenie urządzenia USB.
* **10100**: Aktualizacja sterownika USB.
* **EventID 112**: Czas włożenia urządzenia USB.

Aby uzyskać praktyczne przykłady symulacji tych typów logowania i możliwości zrzutu poświadczeń, zapoznaj się z [szczegółowym przewodnikiem Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Szczegóły zdarzeń, w tym kody statusu i podstatusu, dostarczają dalszych informacji na temat przyczyn zdarzeń, szczególnie zauważalnych w Event ID 4625.

### Przywracanie zdarzeń Windows

Aby zwiększyć szanse na odzyskanie usuniętych zdarzeń Windows, zaleca się wyłączenie podejrzanego komputera poprzez bezpośrednie odłączenie go od zasilania. **Bulk\_extractor**, narzędzie do odzyskiwania, które specyfikuje rozszerzenie `.evtx`, jest zalecane do próby odzyskania takich zdarzeń.

### Identyfikacja powszechnych ataków za pomocą zdarzeń Windows

Aby uzyskać kompleksowy przewodnik po wykorzystaniu identyfikatorów zdarzeń Windows w identyfikacji powszechnych ataków cybernetycznych, odwiedź [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataki brute force

Można je zidentyfikować po wielu rekordach EventID 4625, a następnie po EventID 4624, jeśli atak się powiedzie.

#### Zmiana czasu

Rejestrowana przez EventID 4616, zmiany czasu systemowego mogą skomplikować analizę kryminalistyczną.

#### Śledzenie urządzeń USB

Użyteczne identyfikatory zdarzeń systemowych do śledzenia urządzeń USB to 20001/20003/10000 dla pierwszego użycia, 10100 dla aktualizacji sterowników i EventID 112 z DeviceSetupManager dla znaczników czasowych włożenia.

#### Wydarzenia zasilania systemu

EventID 6005 wskazuje na uruchomienie systemu, podczas gdy EventID 6006 oznacza zamknięcie.

#### Usunięcie logów

Zdarzenie zabezpieczeń EventID 1102 sygnalizuje usunięcie logów, co jest krytycznym zdarzeniem dla analizy kryminalistycznej.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
