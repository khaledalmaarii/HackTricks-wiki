{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# Znaczniki czasu

Atakujący może być zainteresowany **zmianą znaczników czasu plików** w celu uniknięcia wykrycia.\
Możliwe jest znalezienie znaczników czasu wewnątrz MFT w atrybutach `$STANDARD_INFORMATION` __ i __ `$FILE_NAME`.

Oba atrybuty mają 4 znaczniki czasu: **Modyfikację**, **dostęp**, **tworzenie** i **modyfikację rejestru MFT** (MACE lub MACB).

**Eksplorator Windowsa** i inne narzędzia pokazują informacje z **`$STANDARD_INFORMATION`**.

## TimeStomp - Narzędzie antyforensyczne

To narzędzie **modyfikuje** informacje o znacznikach czasu wewnątrz **`$STANDARD_INFORMATION`** **ale** **nie** informacje wewnątrz **`$FILE_NAME`**. Dlatego możliwe jest **zidentyfikowanie** **podejrzanej** **aktywności**.

## Usnjrnl

**Dziennik USN** (Update Sequence Number Journal) to funkcja systemu plików NTFS (system plików Windows NT), która śledzi zmiany woluminu. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia analizę tych zmian.

![](<../../.gitbook/assets/image (449).png>)

Poprzedni obraz jest **wyjściem** pokazanym przez **narzędzie**, gdzie można zauważyć, że dokonano pewnych **zmian w pliku**.

## $LogFile

**Wszystkie zmiany metadanych w systemie plików są rejestrowane** w procesie znanym jako [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Narzędzia takie jak [LogFileParser](https://github.com/jschicht/LogFileParser) mogą być używane do analizy tego pliku i identyfikacji zmian.

![](<../../.gitbook/assets/image (450).png>)

Ponownie, w wyniku działania narzędzia można zobaczyć, że **dokonano pewnych zmian**.

Za pomocą tego samego narzędzia można zidentyfikować **kiedy zostały zmodyfikowane znaczniki czasu**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Czas utworzenia pliku
* ATIME: Czas modyfikacji pliku
* MTIME: Modyfikacja rejestru MFT pliku
* RTIME: Czas dostępu do pliku

## Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem na zidentyfikowanie podejrzanych zmodyfikowanych plików byłoby porównanie czasu w obu atrybutach w poszukiwaniu **niezgodności**.

## Nanosekundy

Znaczniki czasu **NTFS** mają **precyzję** na poziomie **100 nanosekund**. Znalezienie plików z znacznikami czasu takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

## SetMace - Narzędzie antyforensyczne

To narzędzie może modyfikować oba atrybuty `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednakże, począwszy od Windows Vista, konieczne jest użycie działającego systemu operacyjnego na żywo do modyfikacji tych informacji.

# Ukrywanie danych

NTFS używa klastra i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje jeden klaster i pół, **pozostała połowa nigdy nie zostanie wykorzystana** do momentu usunięcia pliku. Dlatego możliwe jest **ukrycie danych w tej przestrzeni rezerwowej**.

Istnieją narzędzia takie jak slacker, które pozwalają na ukrywanie danych w tej "ukrytej" przestrzeni. Jednak analiza `$logfile` i `$usnjrnl` może pokazać, że dodano pewne dane:

![](<../../.gitbook/assets/image (452).png>)

Następnie możliwe jest odzyskanie przestrzeni rezerwowej za pomocą narzędzi takich jak FTK Imager. Należy zauważyć, że tego rodzaju narzędzie może zapisać zawartość zasłoniętą lub nawet zaszyfrowaną.

# UsbKill

To narzędzie **wyłączy komputer, jeśli wykryta zostanie jakakolwiek zmiana w portach USB**.\
Sposobem na odkrycie tego byłoby sprawdzenie działających procesów i **przejrzenie każdego skryptu pythona działającego**.

# Dystrybucje Live Linux

Te dystrybucje są **wykonywane w pamięci RAM**. Jedynym sposobem na ich wykrycie jest **w przypadku, gdy system plików NTFS jest zamontowany z uprawnieniami do zapisu**. Jeśli jest zamontowany tylko z uprawnieniami do odczytu, nie będzie możliwe wykrycie intruzji.

# Bezpieczne usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Konfiguracja Windows

Możliwe jest wyłączenie kilku metod logowania systemu Windows, aby utrudnić dochodzenie w dziedzinie informatyki śledczej.

## Wyłączanie znaczników czasu - UserAssist

To klucz rejestru przechowuje daty i godziny, kiedy każde wykonywalne było uruchamiane przez użytkownika.

Wyłączenie UserAssist wymaga dwóch kroków:

1. Ustawienie dwóch kluczy rejestru, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na zero, aby sygnalizować, że chcemy wyłączyć UserAssist.
2. Wyczyść gałęzie rejestru, które wyglądają jak `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Wyłączanie znaczników czasu - Prefetch

To zapisze informacje o aplikacjach uruchomionych w celu poprawy wydajności systemu Windows. Jednakże może to być również przydatne w praktykach śledczych.

* Uruchom `regedit`
* Wybierz ścieżkę pliku `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Kliknij prawym przyciskiem myszy na `EnablePrefetcher` i `EnableSuperfetch`
* Wybierz Modyfikuj dla każdego z nich, aby zmienić wartość z 1 (lub 3) na 0
* Zrestartuj

## Wyłączanie znaczników czasu - Czas ostatniego dostępu

Za każdym razem, gdy folder jest otwierany z woluminu NTFS na serwerze Windows NT, system zajmuje czas na **aktualizację pola znacznika czasu na każdym wymienionym folderze**, zwane czasem ostatniego dostępu. Na intensywnie używanym woluminie NTFS może to wpłynąć na wydajność.

1. Otwórz Edytor rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Znajdź `NtfsDisableLastAccessUpdate`. Jeśli nie istnieje, dodaj tę wartość DWORD i ustaw jej wartość na 1, co wyłączy proces.
4. Zamknij Edytor rejestru i zrestartuj serwer.
## Usuń historię USB

Wszystkie **wpisy urządzeń USB** są przechowywane w rejestrze systemu Windows pod kluczem rejestru **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączysz urządzenie USB do komputera lub laptopa. Możesz znaleźć ten klucz tutaj `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie tego** spowoduje usunięcie historii USB.\
Możesz także użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że je usunąłeś (i je usunąć).

Innym plikiem, który zapisuje informacje o urządzeniach USB, jest plik `setupapi.dev.log` wewnątrz `C:\Windows\INF`. Należy go również usunąć.

## Wyłącz cienie kopii

**Wyświetl** cienie kopii za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz także je usunąć za pomocą interfejsu graficznego, postępując zgodnie z krokami zaproponowanymi w [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć cienie kopii [kroki stąd](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Usługi, wpisując "services" w pole wyszukiwania tekstu po kliknięciu przycisku start w systemie Windows.
2. Z listy znajdź "Kopia woluminu cienia", wybierz ją, a następnie uzyskaj dostęp do właściwości, klikając prawym przyciskiem myszy.
3. Wybierz opcję Wyłączone z rozwijanego menu "Typ uruchamiania", a następnie potwierdź zmianę, klikając Zastosuj i OK.

Możliwe jest również zmodyfikowanie konfiguracji, które pliki zostaną skopiowane w kopii cienia w rejestrze `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Nadpisz usunięte pliki

* Możesz użyć narzędzia **Windows**: `cipher /w:C` Spowoduje to, że cipher usunie wszystkie dane z dostępnej nieużywanej przestrzeni dyskowej w dysku C.
* Możesz także użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

## Usuń dzienniki zdarzeń systemu Windows

* Windows + R --> eventvwr.msc --> Rozwiń "Dzienniki systemu Windows" --> Kliknij prawym przyciskiem myszy każdą kategorię i wybierz "Wyczyść dziennik"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Wyłącz dzienniki zdarzeń systemu Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* W sekcji usług wyłącz usługę "Dziennik zdarzeń systemu Windows"
* `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

## Wyłącz $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
