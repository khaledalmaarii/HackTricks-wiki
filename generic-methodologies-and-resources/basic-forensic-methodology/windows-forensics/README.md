# Windows Artifacts

## Artefakty systemu Windows

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

## Ogólne artefakty systemu Windows

### Powiadomienia systemu Windows 10

W ścieżce `\Users\<nazwa_użytkownika>\AppData\Local\Microsoft\Windows\Notifications` można znaleźć bazę danych `appdb.dat` (przed rocznicą systemu Windows) lub `wpndatabase.db` (po rocznicy systemu Windows).

W tej bazie danych SQLite można znaleźć tabelę `Notification` z wszystkimi powiadomieniami (w formacie XML), które mogą zawierać interesujące dane.

### Harmonogram

Harmonogram to cecha systemu Windows, która zapewnia **chronologiczną historię** odwiedzanych stron internetowych, edytowanych dokumentów i uruchamianych aplikacji.

Baza danych znajduje się w ścieżce `\Users\<nazwa_użytkownika>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Tę bazę danych można otworzyć za pomocą narzędzia SQLite lub narzędzia [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **które generuje 2 pliki, które można otworzyć za pomocą narzędzia** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Pobrane pliki mogą zawierać **strefę ADS Zone.Identifier**, wskazującą **sposób**, w jaki został **pobrany** z sieci wewnętrznej, internetu, itp. Niektóre oprogramowanie (np. przeglądarki) zwykle dodaje nawet **więcej** **informacji**, takich jak **URL**, z którego pobrano plik.

## **Kopie zapasowe plików**

### Kosz

W systemach Vista/Win7/Win8/Win10 **Kosz** znajduje się w folderze **`$Recycle.bin`** w głównym katalogu dysku (`C:\$Recycle.bin`).\
Po usunięciu pliku w tym folderze tworzone są 2 konkretne pliki:

* `$I{id}`: Informacje o pliku (data usunięcia)
* `$R{id}`: Zawartość pliku

![](<../../../.gitbook/assets/image (486).png>)

Posiadając te pliki, można użyć narzędzia [**Rifiuti**](https://github.com/abelcheung/rifiuti2), aby uzyskać oryginalny adres usuniętych plików i datę ich usunięcia (użyj `rifiuti-vista.exe` dla systemów Vista – Win10).

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Kopie woluminu cieni

Shadow Copy to technologia zawarta w systemie Microsoft Windows, która może tworzyć **kopie zapasowe** lub migawki plików lub woluminów, nawet gdy są one używane.

Kopie zapasowe zazwyczaj znajdują się w folderze `\System Volume Information` w głównym katalogu systemu plików, a nazwa składa się z **UID**, jak pokazano na poniższym obrazku:

![](<../../../.gitbook/assets/image (520).png>)

Montując obraz forensyki za pomocą narzędzia **ArsenalImageMounter**, narzędzie [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) można użyć do sprawdzenia kopii cienia i nawet **wydobycia plików** z kopii zapasowych kopii cienia.

![](<../../../.gitbook/assets/image (521).png>)

Wpisy rejestru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` zawierają pliki i klucze, **które nie są tworzone kopii zapasowych**:

![](<../../../.gitbook/assets/image (522).png>)

Rejestr `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` zawiera również informacje konfiguracyjne dotyczące `Volume Shadow Copies`.

### Automatycznie zapisane pliki Office

Pliki automatycznie zapisane przez Office można znaleźć w: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementy powłoki

Element powłoki to element zawierający informacje o tym, jak uzyskać dostęp do innego pliku.

### Ostatnie dokumenty (LNK)

System Windows **automatycznie tworzy** te **skróty** po otwarciu, użyciu lub utworzeniu pliku przez użytkownika w:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Podczas tworzenia folderu tworzony jest również skrót do folderu, folderu nadrzędnego i folderu pradziadka.

Automatycznie tworzone pliki skrótów **zawierają informacje o pochodzeniu** takie jak, czy to jest **plik** **czy** **folder**, **czasy MAC** tego pliku, **informacje o woluminie**, w którym plik jest przechowywany, oraz **folder pliku docelowego**. Te informacje mogą być przydatne do odzyskania tych plików, jeśli zostaną usunięte.

Ponadto, **data utworzenia skrótu** to pierwszy **czas**, kiedy oryginalny plik został **pierwszy raz użyty**, a **data modyfikacji skrótu** to **ostatni czas**, kiedy plik źródłowy był używany.

Aby sprawdzić te pliki, można użyć narzędzia [**LinkParser**](http://4discovery.com/our-tools/).

W tym narzędziu znajdziesz **2 zestawy** znaczników czasowych:

* **Pierwszy zestaw:**

1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate

* **Drugi zestaw:**

1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Pierwszy zestaw znaczników czasowych odnosi się do **znaczników czasowych samego pliku**. Drugi zestaw odnosi się do **znaczników czasowych połączonego pliku**.

Można uzyskać te same informacje, uruchamiając narzędzie wiersza poleceń systemu Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

W tym przypadku informacje zostaną zapisane w pliku CSV.

### Jumplisty

Są to ostatnio używane pliki wskazywane dla każdej aplikacji. To lista **ostatnio używanych plików przez aplikację**, do której można uzyskać dostęp w każdej aplikacji. Mogą być tworzone **automatycznie lub dostosowane**.

Automatycznie tworzone jumplisty są przechowywane w `C:\Users\{nazwa_użytkownika}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplisty mają nazwy zgodne z formatem `{id}.autmaticDestinations-ms`, gdzie początkowe ID to ID aplikacji.

Dostosowane jumplisty są przechowywane w `C:\Users\{nazwa_użytkownika}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i są tworzone przez aplikację zazwyczaj dlatego, że coś **ważnego** wydarzyło się z plikiem (może być oznaczony jako ulubiony).

Czas utworzenia dowolnego jumplistu wskazuje **pierwszy raz, gdy plik był otwierany**, a czas modyfikacji wskazuje **ostatni raz**.

Możesz sprawdzić jumplisty za pomocą [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Należy zauważyć, że znaczniki czasowe dostarczane przez JumplistExplorer odnoszą się do samego pliku jumplist_)

### Shellbags

[**Kliknij tutaj, aby dowiedzieć się, czym są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie urządzeń USB w systemie Windows

Możliwe jest zidentyfikowanie użycia urządzenia USB dzięki utworzeniu:

* Folderu Ostatnie w systemie Windows
* Folderu Ostatnie w programie Microsoft Office
* Jumplistów

Należy zauważyć, że niektóre pliki LNK zamiast wskazywać na oryginalną ścieżkę, wskazują na folder WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

Pliki w folderze WPDNSE są kopią oryginalnych plików i nie przetrwają restartu komputera, a GUID jest pobierany z shellbag.

### Informacje z rejestru

[Sprawdź tę stronę, aby dowiedzieć się](interesting-windows-registry-keys.md#usb-information), które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

Sprawdź plik `C:\Windows\inf\setupapi.dev.log`, aby uzyskać znaczniki czasu dotyczące momentu podłączenia urządzenia USB (wyszukaj `Section start`).

![](https://github.com/carlospolop/hacktricks/blob/pl/.gitbook/assets/image%20\(477\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(3\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(14\).png)

### USB Detective

[**USBDetective**](https://usbdetective.com) można użyć do uzyskania informacji o urządzeniach USB, które były podłączone do obrazu.

![](<../../../.gitbook/assets/image (483).png>)

### Czyszczenie Plug and Play

Zaplanowane zadanie o nazwie "Czyszczenie Plug and Play" jest przeznaczone głównie do usuwania przestarzałych wersji sterowników. Wbrew określonym celom zachowania najnowszej wersji pakietu sterowników, źródła internetowe sugerują, że zadanie to również dotyczy sterowników, które były nieaktywne przez 30 dni. W rezultacie sterowniki dla urządzeń wymiennych, które nie były podłączone w ciągu ostatnich 30 dni, mogą zostać usunięte.

Zadanie znajduje się pod następującą ścieżką: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Poniżej przedstawiono zrzut ekranu zawartości zadania: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kluczowe składniki i ustawienia zadania:**

* **pnpclean.dll**: Ta biblioteka DLL jest odpowiedzialna za proces czyszczenia.
* **UseUnifiedSchedulingEngine**: Ustawione na `TRUE`, wskazuje na użycie ogólnego silnika harmonogramowania zadań.
* **MaintenanceSettings**:
* **Okres ('P1M')**: Nakazuje Harmonogramowi zadań uruchomienie zadania czyszczenia co miesiąc podczas regularnego konserwowania automatycznego.
* **Termin ('P2M')**: Instruuje Harmonogram zadań, że w przypadku dwóch kolejnych miesięcy niepowodzenia zadania, należy je wykonać podczas awaryjnego konserwowania automatycznego.

Ta konfiguracja zapewnia regularne konserwowanie i czyszczenie sterowników, z możliwością ponownej próby wykonania zadania w przypadku kolejnych niepowodzeń.

**Aby uzyskać więcej informacji, sprawdź:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-maile

E-maile zawierają **2 interesujące części: nagłówki i treść** e-maila. W **nagłówkach** można znaleźć informacje takie jak:

* **Kto** wysłał e-maile (adres e-mail, adres IP, serwery poczty, które przekierowały e-mail)
* **Kiedy** e-mail został wysłany

Ponadto, w nagłówkach `References` i `In-Reply-To` można znaleźć identyfikator wiadomości:

![](<../../../.gitbook/assets/image (484).png>)

### Aplikacja Poczta w systemie Windows

Ta aplikacja zapisuje e-maile w formacie HTML lub tekstowym. E-maile można znaleźć w podfolderach wewnątrz `\Users\<nazwa_użytkownika>\AppData\Local\Comms\Unistore\data\3\`. E-maile są zapisywane z rozszerzeniem `.dat`.

**Metadane** e-maili i **kontakty** można znaleźć w bazie danych **EDB**: `\Users\<nazwa_użytkownika>\AppData\Local\Comms\UnistoreDB\store.vol`

**Zmień rozszerzenie** pliku z `.vol` na `.edb`, a następnie możesz użyć narzędzia [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), aby je otworzyć. W tabeli `Message` można zobaczyć e-maile.

### Microsoft Outlook

Podczas korzystania z serwerów Exchange lub klientów Outlook będą dostępne niektóre nagłówki MAPI:

* `Mapi-Client-Submit-Time`: Czas systemowy, kiedy e-mail został wysłany
* `Mapi-Conversation-Index`: Liczba wiadomości potomnych wątku i znacznik czasowy każdej wiadomości wątku
* `Mapi-Entry-ID`: Identyfikator wiadomości.
* `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacje o kliencie MAPI (wiadomość przeczytana? nieprzeczytana? odpowiedziana? przekierowana? poza biurem?)

W kliencie Microsoft Outlook wszystkie wysłane/odebrane wiadomości, dane kontaktów i dane kalendarza są przechowywane w pliku PST w:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` wskazuje na używany plik.

Możesz otworzyć plik PST za pomocą narzędzia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)

### Pliki OST Microsoft Outlook

Plik **OST** jest generowany przez Microsoft Outlook, gdy jest skonfigurowany z serwerem **IMAP** lub **Exchange** i przechowuje podobne informacje jak plik PST. Ten plik jest zsynchronizowany z serwerem, przechowując dane z ostatnich **12 miesięcy** do **maksymalnego rozmiaru 50 GB** i znajduje się w tym samym katalogu co plik PST. Aby wyświetlić plik OST, można użyć [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Odzyskiwanie załączników

Utracone załączniki mogą być odzyskiwane z:

* Dla **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Dla **IE11 i nowszych**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Pliki MBOX Thunderbird

**Thunderbird** używa plików **MBOX** do przechowywania danych, które znajdują się w `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatury obrazów

* **Windows XP i 8-8.1**: Przeglądanie folderu z miniaturami generuje plik `thumbs.db`, który przechowuje podgląd obrazów, nawet po ich usunięciu.
* **Windows 7/10**: `thumbs.db` jest tworzony podczas dostępu przez sieć za pomocą ścieżki UNC.
* **Windows Vista i nowsze**: Podgląd miniatur jest przechowywany w `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` w plikach o nazwie **thumbcache\_xxx.db**. Narzędzia [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) służą do wyświetlania tych plików.

### Informacje z rejestru systemu Windows

Rejestr systemu Windows, przechowujący rozległe dane dotyczące działalności systemu i użytkownika, znajduje się w plikach:

* `%windir%\System32\Config` dla różnych podkluczy `HKEY_LOCAL_MACHINE`.
* `%UserProfile%{User}\NTUSER.DAT` dla `HKEY_CURRENT_USER`.
* Windows Vista i nowsze wersje tworzą kopie zapasowe plików rejestru `HKEY_LOCAL_MACHINE` w `%Windir%\System32\Config\RegBack\`.
* Dodatkowo, informacje o wykonaniu programu są przechowywane w `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server.

### Narzędzia

Niektóre narzędzia są przydatne do analizy plików rejestru:

* **Edytor rejestru**: Jest zainstalowany w systemie Windows. Jest to interfejs graficzny do nawigacji po rejestrze systemu Windows bieżącej sesji.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Pozwala na wczytanie pliku rejestru i nawigację po nim za pomocą interfejsu graficznego. Zawiera również zakładki, które wyróżniają klucze zawierające interesujące informacje.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponownie, posiada interfejs graficzny, który umożliwia nawigację po wczytanym rejestrze i zawiera wtyczki, które wyróżniają interesujące informacje w wczytanym rejestrze.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kolejna aplikacja z interfejsem graficznym, która umożliwia wydobycie ważnych informacji z wczytanego rejestru.

### Odzyskiwanie usuniętych elementów

Po usunięciu klucza jest on oznaczany jako usunięty, ale nie zostanie usunięty, dopóki przestrzeń, którą zajmuje, nie będzie potrzebna. Dlatego za pomocą narzędzi takich jak **Registry Explorer** można odzyskać te usunięte klucze.

### Czas ostatniej modyfikacji

Każdy klucz-wartość zawiera **znacznik czasu**, który wskazuje ostatnią modyfikację.

### SAM

Plik/hive **SAM** zawiera hashe **użytkowników, grup i haseł użytkowników** systemu.

W `SAM\Domains\Account\Users` można uzyskać nazwę użytkownika, RID, ostatnie logowanie, ostatnie nieudane logowanie, licznik logowań, politykę hasła i datę utworzenia konta. Aby uzyskać **hashe**, potrzebny jest również plik/hive **SYSTEM**.

### Interesujące wpisy w rejestrze systemu Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Wykonane programy

### Podstawowe procesy systemu Windows

W [tym poście](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) można dowiedzieć się o powszechnych procesach systemu Windows, które można wykryć podejrzane zachowanie.

### Ostatnio uruchomione aplikacje systemu Windows

W rejestrze `NTUSER.DAT` w ścieżce `Software\Microsoft\Current Version\Search\RecentApps` można znaleźć podklucze zawierające informacje o **uruchomionej aplikacji**, **ostatnim czasie** jej uruchomienia i **liczbie uruchomień**.

### BAM (Background Activity Moderator)

Można otworzyć plik `SYSTEM` za pomocą edytora rejestru i w ścieżce `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` można znaleźć informacje o **aplikacjach uruchomionych przez każdego użytkownika** (zauważ `{SID}` w ścieżce) i **czasie** ich uruchomienia (czas znajduje się w wartości Data rejestru).

### Prefetch systemu Windows

Prefetching to technika, która pozwala komputerowi w sposób niezauważalny **pobrać niezbędne zasoby potrzebne do wyświetlenia zawartości**, do której użytkownik **może mieć dostęp w niedalekiej przyszłości**, aby zasoby można było szybciej uzyskać.

Prefetch systemu Windows polega na tworzeniu **pamięci podręcznych wykonanych programów**, aby można je było szybciej wczytać. Te pamięci podręczne są tworzone jako pliki `.pf` w ścieżce: `C:\Windows\Prefetch`. W systemach XP/VISTA/WIN7 istnieje limit 128 plików, a w systemach Win8/Win10 - 1024 pliki.

Nazwa pliku jest tworzona jako `{nazwa_programu}-{hash}.pf` (hash jest oparty na ścieżce i argumentach wykonywalnego pliku). W systemie W10 te pliki są skompresowane. Należy jednak zauważyć, że sama obecność pliku wskazuje, że **program został uruchomiony** w pewnym momencie.

Plik `C:\Windows\Prefetch\Layout.ini` zawiera **nazwy folderów plików, które są prefetched**. Ten plik zawiera **informacje o liczbie uruchomień**, **datach** uruchomienia i **plikach** **otwartych** przez program.

Aby sprawdzić te pliki, można użyć narzędzia [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** ma ten sam cel co prefetch, **szybsze ładowanie programów** przez przewidywanie, co zostanie załadowane następne. Jednak nie zastępuje usługi prefetch.\
Ta usługa generuje pliki bazy danych w `C:\Windows\Prefetch\Ag*.db`.

W tych bazach danych można znaleźć **nazwę programu**, **liczbę uruchomień**, **otwarte pliki**, **dostęp do woluminu**, **pełną ścieżkę**, **ramy czasowe** i **znaczniki czasu**.

Można uzyskać dostęp do tych informacji za pomocą narzędzia [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitoruje** **zasoby** **zużywane przez proces**. Pojawił się w W8 i przechowuje dane w bazie danych ESE znajdującej się w `C:\Windows\System32\sru\SRUDB.dat`.

Dostarcza następujące informacje:

* AppID i ścieżka
* Użytkownik, który uruchomił proces
* Wysłane bajty
* Odebrane bajty
* Interfejs sieciowy
* Czas trwania połączenia
* Czas trwania procesu

Te informacje są aktualizowane co 60 minut.

Można uzyskać dane z tego pliku za pomocą narzędzia [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```

### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, stanowi część **Bazy danych zgodności aplikacji** opracowanej przez **Microsoft** w celu rozwiązywania problemów zgodności aplikacji. Ten komponent systemu rejestruje różne metadane plików, które obejmują:

* Pełna ścieżka pliku
* Rozmiar pliku
* Czas ostatniej modyfikacji w ramach **$Standard\_Information** (SI)
* Czas ostatniej aktualizacji ShimCache
* Flaga wykonania procesu

Takie dane są przechowywane w rejestrze w określonych lokalizacjach, w zależności od wersji systemu operacyjnego:

* Dla systemu XP dane są przechowywane w `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` z pojemnością 96 wpisów.
* Dla serwera 2003, a także dla wersji systemów Windows 2008, 2012, 2016, 7, 8 i 10, ścieżka przechowywania to `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, z pojemnością odpowiednio 512 i 1024 wpisów.

Do analizy przechowywanych informacji zaleca się użycie narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Plik **Amcache.hve** to w zasadzie rejestr, który rejestruje szczegóły dotyczące uruchomionych aplikacji w systemie. Zazwyczaj znajduje się on pod adresem `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ten plik jest znaczący, ponieważ przechowuje informacje o ostatnio uruchomionych procesach, w tym ścieżki do plików wykonywalnych i ich skróty SHA1. Te informacje są niezwykle cenne do śledzenia aktywności aplikacji w systemie.

Aby wyodrębnić i analizować dane z pliku **Amcache.hve**, można użyć narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Poniższa komenda jest przykładem użycia AmcacheParser do analizy zawartości pliku **Amcache.hve** i wygenerowania wyników w formacie CSV:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Wśród wygenerowanych plików CSV szczególnie warto zwrócić uwagę na `Amcache_Unassociated file entries`, ponieważ zawiera bogate informacje dotyczące niepowiązanych wpisów plików.

Najciekawszy plik CVS to `Amcache_Unassociated file entries`.

### RecentFileCache

Ten artefakt można znaleźć tylko w systemie W7 w `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` i zawiera informacje o ostatnim uruchomieniu niektórych plików binarnych.

Możesz użyć narzędzia [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) do analizy pliku.

### Zaplanowane zadania

Można je wyodrębnić z `C:\Windows\Tasks` lub `C:\Windows\System32\Tasks` i odczytać jako pliki XML.

### Usługi

Można je znaleźć w rejestrze pod `SYSTEM\ControlSet001\Services`. Można zobaczyć, co zostanie wykonane i kiedy.

### **Sklep Windows**

Zainstalowane aplikacje można znaleźć w `\ProgramData\Microsoft\Windows\AppRepository\`\
Ten repozytorium zawiera **dziennik** z **każdą zainstalowaną aplikacją** w systemie w bazie danych **`StateRepository-Machine.srd`**.

W tabeli Application tej bazy danych można znaleźć kolumny: "Application ID", "PackageNumber" i "Display Name". Te kolumny zawierają informacje o aplikacjach zainstalowanych i odinstalowanych, a można znaleźć, czy niektóre aplikacje zostały odinstalowane, ponieważ identyfikatory zainstalowanych aplikacji powinny być sekwencyjne.

Można również **znaleźć zainstalowane aplikacje** w ścieżce rejestru: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
A **odinstalowane aplikacje** w: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Zdarzenia systemowe Windows

Informacje, które pojawiają się w zdarzeniach systemowych Windows, to:

* Co się stało
* Sygnatura czasowa (UTC + 0)
* Użytkownicy zaangażowani
* Hosty zaangażowane (nazwa hosta, IP)
* Zasoby dostępne (pliki, foldery, drukarki, usługi)

Dzienniki znajdują się w `C:\Windows\System32\config` przed systemem Windows Vista i w `C:\Windows\System32\winevt\Logs` po systemie Windows Vista. Przed systemem Windows Vista dzienniki zdarzeń były w formacie binarnym, a po nim są w formacie **XML** i mają rozszerzenie **.evtx**.

Lokalizację plików zdarzeń można znaleźć w rejestrze SYSTEM w **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Można je wyświetlić za pomocą Windows Event Viewer (**`eventvwr.msc`**) lub innymi narzędziami, takimi jak [**Event Log Explorer**](https://eventlogxp.com) **lub** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Zrozumienie rejestracji zdarzeń zabezpieczeń systemu Windows

Zdarzenia dostępu są rejestrowane w pliku konfiguracyjnym zabezpieczeń znajdującym się w `C:\Windows\System32\winevt\Security.evtx`. Rozmiar tego pliku jest możliwy do dostosowania, a gdy osiągnie swoją pojemność, starsze zdarzenia są nadpisywane. Rejestrowane zdarzenia obejmują logowanie i wylogowywanie użytkowników, działania użytkowników oraz zmiany ustawień zabezpieczeń, a także dostęp do plików, folderów i udostępnionych zasobów.

### Kluczowe identyfikatory zdarzeń dla uwierzytelniania użytkownika:

* **EventID 4624**: Wskazuje na pomyślne uwierzytelnienie użytkownika.
* **EventID 4625**: Sygnalizuje niepowodzenie uwierzytelnienia.
* **EventIDs 4634/4647**: Oznaczają zdarzenia wylogowania użytkownika.
* **EventID 4672**: Oznacza logowanie z uprawnieniami administratora.

#### Podtypy w ramach EventID 4634/4647:

* **Interactive (2)**: Bezpośrednie logowanie użytkownika.
* **Network (3)**: Dostęp do udostępnionych folderów.
* **Batch (4)**: Wykonywanie procesów wsadowych.
* **Service (5)**: Uruchamianie usług.
* **Proxy (6)**: Uwierzytelnianie proxy.
* **Unlock (7)**: Odblokowanie ekranu za pomocą hasła.
* **Network Cleartext (8)**: Przesyłanie hasła w postaci tekstu jawnego, często z IIS.
* **New Credentials (9)**: Użycie innych poświadczeń do uzyskania dostępu.
* **Remote Interactive (10)**: Logowanie zdalne pulpitu lub usług terminalowych.
* **Cache Interactive (11)**: Logowanie za pomocą buforowanych poświadczeń bez kontaktu z kontrolerem domeny.
* **Cache Remote Interactive (12)**: Zdalne logowanie za pomocą buforowanych poświadczeń.
* **Cached Unlock (13)**: Odblokowanie za pomocą buforowanych poświadczeń.

#### Kody stanu i podkody dla EventID 4625:

* **0xC0000064**: Nazwa użytkownika nie istnieje - Może wskazywać na atak wyliczania nazw użytkowników.
* **0xC000006A**: Poprawna nazwa użytkownika, ale niepoprawne hasło - Może wskazywać na próbę zgadywania hasła lub atak brutalnej siły.
* **0xC0000234**: Konto użytkownika zablokowane - Może być wynikiem ataku brutalnej siły, który spowodował wiele nieudanych logowań.
* **0xC0000072**: Konto wyłączone - Nieautoryzowane próby dostępu do wyłączonych kont.
* **0xC000006F**: Logowanie poza dozwolonym czasem - Wskazuje na próby dostępu poza ustawionymi godzinami logowania, co może być oznaką nieautoryzowanego dostępu.
* **0xC0000070**: Naruszenie ograniczeń stacji roboczej - Może być próbą logowania z nieautoryzowanego miejsca.
* **0xC0000193**: Wygaśnięcie konta - Próby dostępu przy wygasłych kontach użytkowników.
* **0xC0000071**: Wygasłe hasło - Próby logowania przy przestarzałych hasłach.
* **0xC0000133**: Problemy z synchronizacją czasu - Duże rozbieżności czasowe między klientem a serwerem mogą wskazywać na bardziej zaawansowane ataki, takie jak pass-the-ticket.
* **0xC0000224**: Wymagana jest wymiana hasła - Częste wymuszanie zmiany hasła może sugerować próbę destabilizacji bezpieczeństwa konta.
* **0xC0000225**: Wskazuje na problem systemowy, a nie problem związany z bezpieczeństwem.
* **0xC000015b**: Odmowa typu logowania - Próba dostępu z nieautoryzowanym typem logowania, na przykład użytkownik próbujący wykonać logowanie usługi.

#### EventID 4616:

* **Zmiana czasu**: Modyfikacja czasu systemowego, może utrudnić analizę śladów zdarzeń.

#### EventID 6005 i 6006:

* **Uruchomienie i wyłączenie systemu**: EventID 6005 oznacza uruchomienie systemu, a EventID 6006 oznacza jego wyłączenie.

#### EventID 1102:

* **Usuwanie dziennika**: Czyszczenie dzienników zabezpieczeń, co często jest sygnałem ostrzegawczym o ukrywaniu nielegalnych działań.

#### EventID dotyczące śledzenia urządzeń USB:

* **20001 / 20003 / 10000**: Pierwsze podłączenie urządzenia USB.
* **10100**: Aktualizacja sterownika USB.
* **EventID 112**: Czas wstawienia urządzenia USB.

Praktyczne przykłady symulowania tych typów logowania i możliwości wydobywania poświadczeń można znaleźć w szczegółowym przewodniku [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Szczegóły zdarzeń, w tym kody stanu i podkody, dostarczają dalszych informacji na temat przyczyn zdarzeń, co jest szczególnie istotne w przypadku Event

#### Zdarzenia zasilania systemu

EventID 6005 oznacza uruchomienie systemu, podczas gdy EventID 6006 oznacza wyłączenie.

#### Usuwanie logów

Zdarzenie Security EventID 1102 sygnalizuje usunięcie logów, co jest istotnym wydarzeniem dla analizy śledczej.

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
