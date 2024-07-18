# Techniki Antyforensyczne

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Znaczniki Czasu

Atakujący może być zainteresowany **zmianą znaczników czasu plików**, aby uniknąć wykrycia.\
Możliwe jest znalezienie znaczników czasu w MFT w atrybutach `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atrybuty mają 4 znaczniki czasu: **Modyfikacja**, **dostęp**, **tworzenie** i **modyfikacja rejestru MFT** (MACE lub MACB).

**Eksplorator Windows** i inne narzędzia pokazują informacje z **`$STANDARD_INFORMATION`**.

### TimeStomp - Narzędzie Antyforensyczne

To narzędzie **modyfikuje** informacje o znaczniku czasu wewnątrz **`$STANDARD_INFORMATION`**, **ale** **nie** modyfikuje informacji wewnątrz **`$FILE_NAME`**. Dlatego możliwe jest **zidentyfikowanie** **podejrzanej** **aktywności**.

### Usnjrnl

**Dziennik USN** (Dziennik Numeru Sekwencyjnego Aktualizacji) to funkcja NTFS (system plików Windows NT), która śledzi zmiany w woluminie. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia badanie tych zmian.

![](<../../.gitbook/assets/image (801).png>)

Poprzedni obrazek to **wyjście** pokazane przez **narzędzie**, gdzie można zaobserwować, że **wprowadzono pewne zmiany** w pliku.

### $LogFile

**Wszystkie zmiany metadanych w systemie plików są rejestrowane** w procesie znanym jako [logowanie przed zapisaniem](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Narzędzia takie jak [LogFileParser](https://github.com/jschicht/LogFileParser) mogą być używane do analizy tego pliku i identyfikacji zmian.

![](<../../.gitbook/assets/image (137).png>)

Ponownie, w wyjściu narzędzia można zobaczyć, że **wprowadzono pewne zmiany**.

Używając tego samego narzędzia, można zidentyfikować, **do którego czasu zmieniono znaczniki czasu**:

![](<../../.gitbook/assets/image (1089).png>)

* CTIME: Czas utworzenia pliku
* ATIME: Czas modyfikacji pliku
* MTIME: Modyfikacja rejestru MFT pliku
* RTIME: Czas dostępu do pliku

### Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem na zidentyfikowanie podejrzanych zmodyfikowanych plików byłoby porównanie czasu w obu atrybutach w poszukiwaniu **rozbieżności**.

### Nanosekundy

**Znaczniki czasu NTFS** mają **precyzję** **100 nanosekund**. Dlatego znalezienie plików z znacznikami czasu takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

### SetMace - Narzędzie Antyforensyczne

To narzędzie może modyfikować oba atrybuty `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednak od Windows Vista, konieczne jest, aby system operacyjny był uruchomiony, aby zmodyfikować te informacje.

## Ukrywanie Danych

NFTS używa klastra i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje i używa klastra i pół, **pozostała połowa nigdy nie będzie używana** aż do usunięcia pliku. Wtedy możliwe jest **ukrycie danych w tej przestrzeni slack**.

Istnieją narzędzia takie jak slacker, które pozwalają na ukrywanie danych w tej "ukrytej" przestrzeni. Jednak analiza `$logfile` i `$usnjrnl` może pokazać, że dodano pewne dane:

![](<../../.gitbook/assets/image (1060).png>)

Wtedy możliwe jest odzyskanie przestrzeni slack za pomocą narzędzi takich jak FTK Imager. Zauważ, że tego rodzaju narzędzie może zapisać zawartość w sposób zniekształcony lub nawet zaszyfrowany.

## UsbKill

To narzędzie, które **wyłączy komputer, jeśli wykryje jakiekolwiek zmiany w portach USB**.\
Sposobem na odkrycie tego byłoby sprawdzenie uruchomionych procesów i **przejrzenie każdego uruchomionego skryptu python**.

## Dystrybucje Live Linux

Te dystrybucje są **uruchamiane w pamięci RAM**. Jedynym sposobem na ich wykrycie jest **jeśli system plików NTFS jest zamontowany z uprawnieniami do zapisu**. Jeśli jest zamontowany tylko z uprawnieniami do odczytu, nie będzie możliwe wykrycie intruzji.

## Bezpieczne Usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Konfiguracja Windows

Możliwe jest wyłączenie kilku metod logowania w Windows, aby znacznie utrudnić dochodzenie forensyczne.

### Wyłącz Znaczniki Czasu - UserAssist

To klucz rejestru, który przechowuje daty i godziny, kiedy każdy plik wykonywalny był uruchamiany przez użytkownika.

Wyłączenie UserAssist wymaga dwóch kroków:

1. Ustawienie dwóch kluczy rejestru, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na zero, aby sygnalizować, że chcemy wyłączyć UserAssist.
2. Wyczyść swoje poddrzewa rejestru, które wyglądają jak `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Wyłącz Znaczniki Czasu - Prefetch

To zapisze informacje o aplikacjach uruchamianych w celu poprawy wydajności systemu Windows. Jednak może to być również przydatne w praktykach forensycznych.

* Uruchom `regedit`
* Wybierz ścieżkę pliku `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Kliknij prawym przyciskiem myszy na `EnablePrefetcher` i `EnableSuperfetch`
* Wybierz Modyfikuj dla każdego z nich, aby zmienić wartość z 1 (lub 3) na 0
* Uruchom ponownie

### Wyłącz Znaczniki Czasu - Czas Ostatniego Dostępu

Kiedy folder jest otwierany z woluminu NTFS na serwerze Windows NT, system zajmuje czas na **aktualizację pola znacznika czasu w każdym wymienionym folderze**, nazywanego czasem ostatniego dostępu. Na mocno używanym woluminie NTFS może to wpływać na wydajność.

1. Otwórz Edytor Rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Poszukaj `NtfsDisableLastAccessUpdate`. Jeśli nie istnieje, dodaj ten DWORD i ustaw jego wartość na 1, co wyłączy ten proces.
4. Zamknij Edytor Rejestru i uruchom ponownie serwer.

### Usuń Historię USB

Wszystkie **Wpisy Urządzeń USB** są przechowywane w Rejestrze Windows pod kluczem **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączasz urządzenie USB do swojego komputera lub laptopa. Możesz znaleźć ten klucz tutaj H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie tego** spowoduje usunięcie historii USB.\
Możesz również użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że je usunąłeś (i aby je usunąć).

Innym plikiem, który zapisuje informacje o USB, jest plik `setupapi.dev.log` w `C:\Windows\INF`. Ten plik również powinien zostać usunięty.

### Wyłącz Kopie Cieni

**Wylistuj** kopie cieni za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz również usunąć je za pomocą GUI, postępując zgodnie z krokami opisanymi w [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie cieni [kroki stąd](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Usługi, wpisując "usługi" w polu wyszukiwania tekstowego po kliknięciu przycisku start w Windows.
2. Z listy znajdź "Kopia Cienia Woluminu", wybierz ją, a następnie uzyskaj dostęp do Właściwości, klikając prawym przyciskiem myszy.
3. Wybierz Wyłączony z rozwijanego menu "Typ uruchomienia", a następnie potwierdź zmianę, klikając Zastosuj i OK.

Możliwe jest również modyfikowanie konfiguracji, które pliki będą kopiowane w kopii cienia w rejestrze `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Nadpisz usunięte pliki

* Możesz użyć **narzędzia Windows**: `cipher /w:C` To polecenie wskaże cipherowi, aby usunął wszelkie dane z dostępnej nieużywanej przestrzeni dyskowej w dysku C.
* Możesz również użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

### Usuń dzienniki zdarzeń Windows

* Windows + R --> eventvwr.msc --> Rozwiń "Dzienniki Windows" --> Kliknij prawym przyciskiem myszy na każdą kategorię i wybierz "Wyczyść dziennik"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Wyłącz dzienniki zdarzeń Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* W sekcji usług wyłącz usługę "Dziennik Zdarzeń Windows"
* `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

### Wyłącz $UsnJrnl

* `fsutil usn deletejournal /d c:`

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
