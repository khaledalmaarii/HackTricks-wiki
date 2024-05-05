# Artefakty systemu Windows

## Artefakty systemu Windows

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Ogólne artefakty systemu Windows

### Powiadomienia systemu Windows 10

W ścieżce `\Users\<nazwa_użytkownika>\AppData\Local\Microsoft\Windows\Notifications` znajduje się baza danych `appdb.dat` (przed rocznicą systemu Windows) lub `wpndatabase.db` (po rocznicy systemu Windows).

Wewnątrz tej bazy danych SQLite znajduje się tabela `Notification` z wszystkimi powiadomieniami (w formacie XML), które mogą zawierać interesujące dane.

### Linia czasu

Linia czasu to charakterystyka systemu Windows, która zapewnia **chronologiczną historię** odwiedzonych stron internetowych, edytowanych dokumentów i uruchomionych aplikacji.

Baza danych znajduje się w ścieżce `\Users\<nazwa_użytkownika>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Tę bazę danych można otworzyć za pomocą narzędzia SQLite lub narzędzia [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **które generuje 2 pliki, które można otworzyć za pomocą narzędzia** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### Strumienie danych alternatywnych (ADS)

Pliki pobrane mogą zawierać **strefę danych alternatywnych (ADS) Zone.Identifier**, wskazującą **sposób** pobrania pliku z sieci wewnętrznej, internetu itp. Niektóre oprogramowanie (np. przeglądarki) zazwyczaj umieszczają nawet **więcej** **informacji**, takich jak **adres URL**, z którego pobrano plik.

## **Kopie zapasowe plików**

### Kosz

W systemach Vista/Win7/Win8/Win10 **Kosz** znajduje się w folderze **`$Recycle.bin`** w głównym katalogu dysku (`C:\$Recycle.bin`).\
Gdy plik jest usuwany z tego folderu, tworzone są 2 konkretne pliki:

* `$I{id}`: Informacje o pliku (data usunięcia}
* `$R{id}`: Zawartość pliku

![](<../../../.gitbook/assets/image (1029).png>)

Posiadając te pliki, można użyć narzędzia [**Rifiuti**](https://github.com/abelcheung/rifiuti2), aby uzyskać oryginalny adres usuniętych plików i datę usunięcia (użyj `rifiuti-vista.exe` dla Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Kopie woluminów cieni

Shadow Copy to technologia zawarta w systemie Microsoft Windows, która może tworzyć **kopie zapasowe** lub migawki plików lub woluminów komputerowych, nawet gdy są one w użyciu.

Te kopie zapasowe zazwyczaj znajdują się w `\System Volume Information` z poziomu systemu plików, a nazwa jest złożona z **UID**, jak pokazano na poniższym obrazku:

![](<../../../.gitbook/assets/image (94).png>)

Montując obraz forensyczny za pomocą **ArsenalImageMounter**, narzędzie [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) można użyć do sprawdzenia kopii cienia i nawet **wyodrębnienia plików** z kopii zapasowych cienia.

![](<../../../.gitbook/assets/image (576).png>)

Wpisy rejestru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` zawierają pliki i klucze **do nie tworzenia kopii zapasowych**:

![](<../../../.gitbook/assets/image (254).png>)

Rejestr `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` zawiera również informacje konfiguracyjne dotyczące `Kopii Woluminów Cieni`.

### Pliki automatycznie zapisane w programach Office

Pliki automatycznie zapisane w programach Office można znaleźć w: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Elementy powłoki

Element powłoki to element zawierający informacje o tym, jak uzyskać dostęp do innego pliku.

### Ostatnie dokumenty (LNK)

System Windows **automatycznie tworzy** te **skróty** gdy użytkownik **otwiera, używa lub tworzy plik** w:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Gdy utworzony zostanie folder, tworzony jest również link do folderu, do folderu nadrzędnego i do folderu dziadka.

Te automatycznie tworzone pliki linków **zawierają informacje o pochodzeniu**, czy to jest **plik** **czy** **folder**, **czasy MAC** tego pliku, **informacje o woluminie**, gdzie plik jest przechowywany oraz **folder docelowy pliku**. Te informacje mogą być przydatne do odzyskania tych plików w przypadku ich usunięcia.

Ponadto **data utworzenia linku** to pierwszy **czas**, kiedy oryginalny plik został **pierwszy** **raz** **użyty**, a **data** **modyfikacji** linku to **ostatni** **czas**, kiedy plik źródłowy był używany.

Aby sprawdzić te pliki, można użyć [**LinkParser**](http://4discovery.com/our-tools/).

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

Można uzyskać te same informacje uruchamiając narzędzie wiersza poleceń systemu Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### Jumplists

To są ostatnie pliki wskazane dla każdej aplikacji. To lista **ostatnio używanych plików przez aplikację**, do której można uzyskać dostęp w każdej aplikacji. Mogą być tworzone **automatycznie lub niestandardowo**.

**Jumplisty** tworzone automatycznie są przechowywane w `C:\Users\{nazwa_użytkownika}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplisty są nazwane zgodnie z formatem `{id}.autmaticDestinations-ms`, gdzie początkowe ID to ID aplikacji.

Niestandardowe jumplisty są przechowywane w `C:\Users\{nazwa_użytkownika}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` i są tworzone przez aplikację zazwyczaj dlatego, że coś jest **ważnego** związane z plikiem (być może oznaczone jako ulubione).

**Czas utworzenia** dowolnego jumplista wskazuje **pierwszy raz, gdy plik był otwierany** oraz **czas modyfikacji ostatni raz**.

Możesz sprawdzić jumplisty za pomocą [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Zauważ, że znaczniki czasowe dostarczone przez JumplistExplorer odnoszą się do samego pliku jumplista_)

### Shellbags

[**Kliknij ten link, aby dowiedzieć się, co to są shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Użycie urządzeń USB w systemie Windows

Możliwe jest zidentyfikowanie, że urządzenie USB zostało użyte dzięki utworzeniu:

* Folderu Ostatnie w systemie Windows
* Folderu Ostatnie w programie Microsoft Office
* Jumplistów

Zauważ, że niektóre pliki LNK zamiast wskazywać na oryginalną ścieżkę, wskazują na folder WPDNSE:

![](<../../../.gitbook/assets/image (218).png>)

Pliki w folderze WPDNSE są kopią oryginalnych plików, więc nie przetrwają restartu komputera, a GUID jest pobierany z shellbaga.

### Informacje z rejestru

[Sprawdź tę stronę, aby dowiedzieć się](interesting-windows-registry-keys.md#usb-information), które klucze rejestru zawierają interesujące informacje o podłączonych urządzeniach USB.

### setupapi

Sprawdź plik `C:\Windows\inf\setupapi.dev.log`, aby uzyskać znaczniki czasu, kiedy nastąpiło połączenie USB (szukaj `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### Detektyw USB

[**USBDetective**](https://usbdetective.com) można użyć do uzyskania informacji o urządzeniach USB, które były podłączone do obrazu.

![](<../../../.gitbook/assets/image (452).png>)

### Czyszczenie wtyczki i gry

Zaplanowane zadanie znane jako 'Czyszczenie wtyczki i gry' jest przeznaczone głównie do usuwania przestarzałych wersji sterowników. Wbrew określonym celom zachowania najnowszej wersji pakietu sterowników, źródła internetowe sugerują, że celuje również w sterowniki, które były nieaktywne przez 30 dni. W rezultacie sterowniki dla urządzeń wymiennych niepodłączonych w ciągu ostatnich 30 dni mogą zostać usunięte.

Zadanie znajduje się pod ścieżką: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Zamieszczono zrzut ekranu przedstawiający zawartość zadania: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Kluczowe składniki i ustawienia zadania:**

* **pnpclean.dll**: Ta biblioteka DLL jest odpowiedzialna za rzeczywisty proces czyszczenia.
* **UseUnifiedSchedulingEngine**: Ustawione na `TRUE`, wskazujące na użycie ogólnego silnika harmonogramowania zadań.
* **MaintenanceSettings**:
* **Okres ('P1M')**: Nakazuje Harmonogramowi zadań uruchomienie zadania czyszczenia miesięcznie podczas regularnego konserwacji automatycznej.
* **Termin ('P2M')**: Instruuje Harmonogram zadań, że w przypadku dwóch kolejnych niepowodzeń zadania, ma ono zostać wykonane podczas awaryjnej konserwacji automatycznej.

Ta konfiguracja zapewnia regularną konserwację i czyszczenie sterowników, z postanowieniami dotyczącymi ponownej próby wykonania zadania w przypadku kolejnych niepowodzeń.

**Aby uzyskać więcej informacji, sprawdź:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emaile

Emaile zawierają **2 interesujące części: Nagłówki i treść** emaila. W **nagłówkach** można znaleźć informacje takie jak:

* **Kto** wysłał emaile (adres email, IP, serwery poczty, które przekierowały email)
* **Kiedy** email został wysłany

Ponadto, w nagłówkach `References` i `In-Reply-To` można znaleźć ID wiadomości:

![](<../../../.gitbook/assets/image (593).png>)

### Aplikacja Poczty w systemie Windows

Ta aplikacja zapisuje emaile w formacie HTML lub tekstowym. Emaile można znaleźć w podfolderach w `\Users\<nazwa_użytkownika>\AppData\Local\Comms\Unistore\data\3\`. Emaile są zapisywane z rozszerzeniem `.dat`.

**Metadane** emaili i **kontakty** można znaleźć w bazie danych **EDB**: `\Users\<nazwa_użytkownika>\AppData\Local\Comms\UnistoreDB\store.vol`

**Zmień rozszerzenie** pliku z `.vol` na `.edb`, a następnie możesz użyć narzędzia [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), aby go otworzyć. W tabeli `Message` można zobaczyć emaile.

### Microsoft Outlook

Kiedy są używane serwery Exchange lub klienci Outlook, będą pewne nagłówki MAPI:

* `Mapi-Client-Submit-Time`: Czas systemowy, kiedy email został wysłany
* `Mapi-Conversation-Index`: Liczba wiadomości potomnych wątku i znacznik czasu każdej wiadomości wątku
* `Mapi-Entry-ID`: Identyfikator wiadomości.
* `Mappi-Message-Flags` i `Pr_last_Verb-Executed`: Informacje o kliencie MAPI (wiadomość przeczytana? nieprzeczytana? odpowiedziana? przekierowana? poza biurem?)

W kliencie Microsoft Outlook, wszystkie wysłane/odebrane wiadomości, dane kontaktów i kalendarza są przechowywane w pliku PST w:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Ścieżka rejestru `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` wskazuje na używany plik.

Możesz otworzyć plik PST za pomocą narzędzia [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)
### Pliki OST programu Microsoft Outlook

Plik **OST** jest generowany przez program Microsoft Outlook, gdy jest skonfigurowany z serwerem **IMAP** lub **Exchange**, przechowując podobne informacje jak plik PST. Ten plik jest zsynchronizowany z serwerem, przechowując dane z **ostatnich 12 miesięcy** do **maksymalnego rozmiaru 50 GB**, i znajduje się w tym samym katalogu co plik PST. Aby wyświetlić plik OST, można skorzystać z [**przeglądarki Kernel OST**](https://www.nucleustechnologies.com/ost-viewer.html).

### Odzyskiwanie załączników

Zgubione załączniki mogą być odzyskiwalne z:

* Dla **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Dla **IE11 i nowszych**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Pliki MBOX programu Thunderbird

**Thunderbird** wykorzystuje pliki **MBOX** do przechowywania danych, znajdujące się w `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatury obrazów

* **Windows XP i 8-8.1**: Otwarcie folderu z miniaturami generuje plik `thumbs.db`, przechowujący podglądy obrazów, nawet po ich usunięciu.
* **Windows 7/10**: `thumbs.db` jest tworzony podczas dostępu przez sieć za pomocą ścieżki UNC.
* **Windows Vista i nowsze**: Podglądy miniatur są skoncentrowane w `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` z plikami o nazwach **thumbcache\_xxx.db**. Narzędzia [**Thumbsviewer**](https://thumbsviewer.github.io) i [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) służą do przeglądania tych plików.

### Informacje z Rejestru systemu Windows

Rejestr systemu Windows, przechowujący rozległe dane dotyczące działalności systemu i użytkownika, znajduje się w plikach:

* `%windir%\System32\Config` dla różnych podkluczy `HKEY_LOCAL_MACHINE`.
* `%UserProfile%{User}\NTUSER.DAT` dla `HKEY_CURRENT_USER`.
* Windows Vista i nowsze wersje tworzą kopie zapasowe plików rejestru `HKEY_LOCAL_MACHINE` w `%Windir%\System32\Config\RegBack\`.
* Dodatkowo, informacje o wykonaniu programu są przechowywane w `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` od Windows Vista i Windows 2008 Server.

### Narzędzia

Niektóre narzędzia są przydatne do analizy plików rejestru:

* **Edytor rejestru**: Zainstalowany w systemie Windows. Jest to interfejs graficzny do nawigacji po rejestrze systemu Windows bieżącej sesji.
* [**Eksplorator rejestru**](https://ericzimmerman.github.io/#!index.md): Pozwala na załadowanie pliku rejestru i nawigację po nim za pomocą interfejsu graficznego. Zawiera zakładki z wyróżnionymi kluczami zawierającymi interesujące informacje.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Ponownie, posiada interfejs graficzny umożliwiający nawigację po załadowanym rejestrze i zawiera wtyczki wyróżniające interesujące informacje w załadowanym rejestrze.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kolejna aplikacja z interfejsem graficznym zdolna do wyodrębniania istotnych informacji z załadowanego rejestru.

### Odzyskiwanie usuniętego elementu

Gdy klucz jest usunięty, jest oznaczony jako taki, ale dopóki zajmowane przez niego miejsce nie jest potrzebne, nie zostanie usunięty. Dlatego, korzystając z narzędzi takich jak **Eksplorator rejestru**, możliwe jest odzyskanie tych usuniętych kluczy.

### Czas ostatniej modyfikacji

Każdy klucz-wartość zawiera **znacznik czasu**, wskazujący ostatni czas modyfikacji.

### SAM

Plik/hive **SAM** zawiera hashe **użytkowników, grup i haseł użytkowników** systemu.

W `SAM\Domains\Account\Users` można uzyskać nazwę użytkownika, RID, ostatnie logowanie, ostatnie nieudane logowanie, licznik logowań, politykę haseł i datę utworzenia konta. Aby uzyskać **hashe**, potrzebny jest również plik/hive **SYSTEM**.

### Interesujące wpisy w rejestrze systemu Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Wykonane programy

### Podstawowe procesy systemu Windows

W [tym poście](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) możesz dowiedzieć się o powszechnych procesach systemu Windows, aby wykryć podejrzane zachowania.

### Ostatnie aplikacje systemu Windows

W rejestrze `NTUSER.DAT` w ścieżce `Software\Microsoft\Current Version\Search\RecentApps` można znaleźć podklucze z informacjami o **uruchomionej aplikacji**, **ostatnim czasie** jej uruchomienia i **liczbie uruchomień**.

### BAM (Moderator aktywności w tle)

Można otworzyć plik `SYSTEM` za pomocą edytora rejestru i w ścieżce `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` znaleźć informacje o **aplikacjach uruchomionych przez każdego użytkownika** (zwróć uwagę na `{SID}` w ścieżce) i **czasie** ich uruchomienia (czas znajduje się w wartości danych rejestru).

### Prefetch systemu Windows

Prefetching to technika, która pozwala komputerowi cicho **pobrać niezbędne zasoby potrzebne do wyświetlenia treści**, do których użytkownik **może mieć dostęp w najbliższej przyszłości**, aby zasoby można było szybciej uzyskać.

Prefetch systemu Windows polega na tworzeniu **pamięci podręcznej wykonanych programów**, aby można je było szybciej załadować. Te pamięci podręczne są tworzone jako pliki `.pf` w ścieżce: `C:\Windows\Prefetch`. Istnieje limit 128 plików w XP/VISTA/WIN7 i 1024 plików w Win8/Win10.

Nazwa pliku jest tworzona jako `{nazwa_programu}-{hash}.pf` (hash jest oparty na ścieżce i argumentach wykonywalnego pliku). W W10 te pliki są skompresowane. Należy zauważyć, że sama obecność pliku wskazuje, że **program został wykonany** w pewnym momencie.

Plik `C:\Windows\Prefetch\Layout.ini` zawiera **nazwy folderów plików prefetched**. Ten plik zawiera **informacje o liczbie uruchomień**, **daty** uruchomienia i **plików** **otwartych** przez program.

Aby przejrzeć te pliki, można użyć narzędzia [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** ma ten sam cel co prefetch, **szybsze ładowanie programów** poprzez przewidywanie, co zostanie załadowane następnie. Jednak nie zastępuje usługi prefetch.\
Ta usługa generuje pliki bazy danych w `C:\Windows\Prefetch\Ag*.db`.

W tych bazach danych można znaleźć **nazwę programu**, **liczbę wykonanych operacji**, **otwarte pliki**, **dostęp do woluminu**, **pełną ścieżkę**, **ramy czasowe** i **znaczniki czasu**.

Możesz uzyskać dostęp do tych informacji za pomocą narzędzia [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Monitor Zużycia Zasobów** (SRUM) **monitoruje** **zasoby zużywane przez proces**. Pojawił się w W8 i przechowuje dane w bazie danych ESE znajdującej się w `C:\Windows\System32\sru\SRUDB.dat`.

Dostarcza następujące informacje:

* AppID i ścieżka
* Użytkownik, który uruchomił proces
* Wysłane bajty
* Odebrane bajty
* Interfejs sieciowy
* Czas trwania połączenia
* Czas trwania procesu

Te informacje są aktualizowane co 60 minut.

Możesz uzyskać dane z tego pliku za pomocą narzędzia [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, znany również jako **ShimCache**, stanowi część **Bazy danych zgodności aplikacji** opracowanej przez **Microsoft** w celu rozwiązywania problemów zgodności aplikacji. Ten komponent systemu rejestruje różne elementy metadanych plików, w tym:

- Pełna ścieżka pliku
- Rozmiar pliku
- Czas ostatniej modyfikacji w **$Standard\_Information** (SI)
- Czas ostatniej aktualizacji ShimCache
- Flagę wykonania procesu

Takie dane są przechowywane w rejestrze w określonych lokalizacjach w zależności od wersji systemu operacyjnego:

- Dla systemu XP dane są przechowywane w `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` z pojemnością na 96 wpisów.
- Dla Servera 2003 oraz dla wersji systemu Windows 2008, 2012, 2016, 7, 8 i 10 ścieżka przechowywania to `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, z pojemnością na odpowiednio 512 i 1024 wpisy.

Do analizy przechowywanych informacji zaleca się użycie narzędzia [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

Plik **Amcache.hve** to w zasadzie rejestr hive, który rejestruje szczegóły dotyczące aplikacji uruchomionych na systemie. Zazwyczaj znajduje się w `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ten plik jest znany z przechowywania rekordów niedawno uruchomionych procesów, w tym ścieżek do plików wykonywalnych i ich skrótów SHA1. Te informacje są nieocenione do śledzenia aktywności aplikacji na systemie.

Aby wydobyć i przeanalizować dane z pliku **Amcache.hve**, można użyć narzędzia [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Poniższa komenda jest przykładem użycia AmcacheParser do analizy zawartości pliku **Amcache.hve** i wyświetlenia wyników w formacie CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Wśród wygenerowanych plików CSV szczególnie godne uwagi są `Amcache_Unassociated file entries` ze względu na bogate informacje, jakie dostarcza na temat niepowiązanych wpisów plików.

Najbardziej interesującym plikiem CVS jest `Amcache_Unassociated file entries`.

### RecentFileCache

Ten artefakt można znaleźć tylko w W7 w `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` i zawiera informacje o ostatnim wykonaniu niektórych plików binarnych.

Możesz użyć narzędzia [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) do analizy pliku.

### Zadania zaplanowane

Możesz je wyodrębnić z `C:\Windows\Tasks` lub `C:\Windows\System32\Tasks` i odczytać jako XML.

### Usługi

Możesz je znaleźć w rejestrze pod `SYSTEM\ControlSet001\Services`. Możesz zobaczyć, co ma zostać wykonane i kiedy.

### **Sklep Windows**

Zainstalowane aplikacje można znaleźć w `\ProgramData\Microsoft\Windows\AppRepository\`\
Ten repozytorium zawiera **dziennik** z **każdą zainstalowaną aplikacją** w systemie wewnątrz bazy danych **`StateRepository-Machine.srd`**.

W tabeli Aplikacji tej bazy danych można znaleźć kolumny: "ID aplikacji", "Numer pakietu" i "Nazwa wyświetlana". Te kolumny zawierają informacje o aplikacjach preinstalowanych i zainstalowanych, a można znaleźć informacje, czy niektóre aplikacje zostały odinstalowane, ponieważ identyfikatory zainstalowanych aplikacji powinny być sekwencyjne.

Możliwe jest również **znalezienie zainstalowanej aplikacji** w ścieżce rejestru: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
A **odinstalowane** **aplikacje** w: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Zdarzenia systemu Windows

Informacje pojawiające się w zdarzeniach systemu Windows to:

* Co się stało
* Znacznik czasu (UTC + 0)
* Użytkownicy zaangażowani
* Hosty zaangażowane (nazwa hosta, IP)
* Zasoby dostępne (pliki, folder, drukarki, usługi)

Dzienniki znajdują się w `C:\Windows\System32\config` przed Windows Vista i w `C:\Windows\System32\winevt\Logs` po Windows Vista. Przed Windows Vista dzienniki zdarzeń były w formacie binarnym, a po nim są w **formacie XML** i używają rozszerzenia **.evtx**.

Lokalizację plików zdarzeń można znaleźć w rejestrze SYSTEM w **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Mogą być wizualizowane za pomocą Podglądu zdarzeń systemu Windows (**`eventvwr.msc`**) lub za pomocą innych narzędzi, takich jak [**Event Log Explorer**](https://eventlogxp.com) **lub** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Zrozumienie Logowania Zdarzeń Bezpieczeństwa Windows

Zdarzenia dostępu są rejestrowane w pliku konfiguracji zabezpieczeń znajdującym się w `C:\Windows\System32\winevt\Security.evtx`. Rozmiar tego pliku jest możliwy do dostosowania, a gdy osiągnie swoją pojemność, starsze zdarzenia są nadpisywane. Rejestrowane zdarzenia obejmują logowanie i wylogowanie użytkowników, działania użytkowników, zmiany ustawień zabezpieczeń, a także dostęp do plików, folderów i zasobów udostępnionych.

### Kluczowe identyfikatory zdarzeń dla uwierzytelniania użytkownika:

* **EventID 4624**: Wskazuje na pomyślne uwierzytelnienie użytkownika.
* **EventID 4625**: Sygnalizuje niepowodzenie uwierzytelnienia.
* **EventIDs 4634/4647**: Oznaczają zdarzenia wylogowania użytkownika.
* **EventID 4672**: Oznacza logowanie z uprawnieniami administracyjnymi.

#### Podtypy wewnątrz EventID 4634/4647:

* **Interaktywne (2)**: Bezpośrednie logowanie użytkownika.
* **Sieciowe (3)**: Dostęp do udostępnionych folderów.
* **Partia (4)**: Wykonywanie procesów wsadowych.
* **Usługa (5)**: Uruchomienia usług.
* **Proxy (6)**: Uwierzytelnianie proxy.
* **Odblokuj (7)**: Odblokowanie ekranu za pomocą hasła.
* **Sieć czystym tekstem (8)**: Przesyłanie hasła w czystym tekście, często z IIS.
* **Nowe poświadczenia (9)**: Użycie innych poświadczeń do dostępu.
* **Zdalne interaktywne (10)**: Logowanie zdalne pulpitu zdalnego lub usług terminalowych.
* **Interaktywne pamięci podręcznej (11)**: Logowanie z pamięcią podręczną bez kontaktu z kontrolerem domeny.
* **Zdalne interaktywne pamięci podręcznej (12)**: Zdalne logowanie z pamięcią podręczną.
* **Odblokowanie z pamięci podręcznej (13)**: Odblokowanie z pamięcią podręczną.

#### Kody stanu i podkody stanu dla EventID 4625:

* **0xC0000064**: Nazwa użytkownika nie istnieje - Może wskazywać na atak polegający na wyliczaniu nazw użytkowników.
* **0xC000006A**: Poprawna nazwa użytkownika, ale złe hasło - Możliwa próba zgadywania hasła lub atak brutalnej siły.
* **0xC0000234**: Konto użytkownika zablokowane - Może być wynikiem ataku brutalnej siły prowadzącego do wielu nieudanych logowań.
* **0xC0000072**: Konto wyłączone - Nieautoryzowane próby dostępu do wyłączonych kont.
* **0xC000006F**: Logowanie poza dozwolonym czasem - Wskazuje na próby dostępu poza ustalonymi godzinami logowania, co może być oznaką nieautoryzowanego dostępu.
* **0xC0000070**: Naruszenie ograniczeń stacji roboczej - Może być próbą logowania z nieautoryzowanego miejsca.
* **0xC0000193**: Wygaśnięcie konta - Próby dostępu do kont z wygasłymi kontami użytkowników.
* **0xC0000071**: Wygasłe hasło - Próby logowania przy przestarzałych hasłach.
* **0xC0000133**: Problemy z synchronizacją czasu - Duże rozbieżności czasowe między klientem a serwerem mogą wskazywać na bardziej zaawansowane ataki, takie jak pass-the-ticket.
* **0xC0000224**: Wymagana zmiana hasła obowiązkowa - Częste obowiązkowe zmiany mogą sugerować próbę destabilizacji bezpieczeństwa konta.
* **0xC0000225**: Wskazuje na błąd systemu, a nie problem z bezpieczeństwem.
* **0xC000015b**: Odmowa typu logowania - Próba dostępu z nieautoryzowanym typem logowania, na przykład użytkownik próbujący wykonać logowanie usługi.

#### EventID 4616:

* **Zmiana czasu**: Modyfikacja czasu systemowego, która może zaciemnić chronologię zdarzeń.

#### EventID 6005 i 6006:

* **Uruchomienie i Wyłączenie Systemu**: EventID 6005 oznacza uruchomienie systemu, a EventID 6006 oznacza jego wyłączenie.

#### EventID 1102:

* **Usuwanie logów**: Czyszczenie logów zabezpieczeń, co często jest sygnałem ostrzegawczym ukrywania nielegalnych działań.

#### EventID dla Śledzenia Urządzeń USB:

* **20001 / 20003 / 10000**: Pierwsze podłączenie urządzenia USB.
* **10100**: Aktualizacja sterownika USB.
* **EventID 112**: Czas włożenia urządzenia USB.

Dla praktycznych przykładów symulowania tych typów logowań i możliwości wydobywania poświadczeń, zapoznaj się z [szczegółowym przewodnikiem Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Szczegóły zdarzeń, w tym kody stanu i podkody stanu, dostarczają dalszych informacji na temat przyczyn zdarzeń, szczególnie istotne w przypadku Event ID 4625.

### Odzyskiwanie Zdarzeń Systemu Windows

Aby zwiększyć szanse na odzyskanie usuniętych zdarzeń systemu Windows, zaleca się wyłączenie podejrzanego komputera, odłączając go bezpośrednio. Zalecane jest użycie narzędzia do odzyskiwania **Bulk\_extractor**, które obsługuje rozszerzenie `.evtx`, aby spróbować odzyskać takie zdarzenia.

### Identyfikacja Powszechnych Ataków za Pośrednictwem Zdarzeń Systemu Windows

Aby uzyskać kompleksowy przewodnik dotyczący wykorzystania identyfikatorów zdarzeń systemu Windows w identyfikowaniu powszechnych ataków cybernetycznych, odwiedź [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataki Brutalnej Siły

Można je zidentyfikować poprzez wielokrotne zapisy EventID 4625, a następnie EventID 4624, jeśli atak się powiedzie.

#### Zmiana Czasu

Rejestrowana przez EventID 4616, zmiany czasu systemowego mogą utrudnić analizę śledzenia.

#### Śledzenie Urządzeń USB

Przydatne EventID systemowe dla śledzenia urządzeń USB obejmują 20001/20003/10000 dla pierwszego użycia, 10100 dla aktualizacji sterowników oraz EventID 112 z DeviceSetupManager dla znaczników czasowych włożenia urządzenia.
#### Zdarzenia zasilania systemu

EventID 6005 wskazuje na uruchomienie systemu, podczas gdy EventID 6006 oznacza wyłączenie.

#### Usuwanie logów

Zdarzenie bezpieczeństwa EventID 1102 sygnalizuje usunięcie logów, co jest istotne dla analizy śledczej.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
