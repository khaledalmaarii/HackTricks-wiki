<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


# Znaczniki czasowe

Atakujący może być zainteresowany **zmianą znaczników czasowych plików**, aby uniknąć wykrycia.\
Można znaleźć znaczniki czasowe wewnątrz MFT w atrybutach `$STANDARD_INFORMATION` __ i __ `$FILE_NAME`.

Oba atrybuty mają 4 znaczniki czasowe: **modyfikację**, **dostęp**, **tworzenie** i **modyfikację rejestru MFT** (MACE lub MACB).

**Eksplorator Windowsa** i inne narzędzia pokazują informacje z **`$STANDARD_INFORMATION`**.

## TimeStomp - Narzędzie antyforensyczne

To narzędzie **modyfikuje** informacje o znacznikach czasowych wewnątrz **`$STANDARD_INFORMATION`** **ale nie** informacje wewnątrz **`$FILE_NAME`**. Dlatego możliwe jest **zidentyfikowanie** **podejrzanej** **aktywności**.

## Usnjrnl

**Dziennik USN** (Update Sequence Number Journal) to funkcja systemu plików NTFS (system plików Windows NT), która śledzi zmiany woluminu. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia badanie tych zmian.

![](<../../.gitbook/assets/image (449).png>)

Poprzedni obrazek to **wyjście** pokazane przez **narzędzie**, gdzie można zauważyć, że dokonano pewnych **zmian w pliku**.

## $LogFile

**Wszystkie zmiany metadanych w systemie plików są rejestrowane** w procesie znanym jako [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w głównym katalogu systemu plików NTFS. Narzędzia takie jak [LogFileParser](https://github.com/jschicht/LogFileParser) można użyć do analizy tego pliku i identyfikacji zmian.

![](<../../.gitbook/assets/image (450).png>)

Ponownie, w wyniku narzędzia można zobaczyć, że **dokonano pewnych zmian**.

Za pomocą tego samego narzędzia można zidentyfikować, **kiedy zostały zmodyfikowane znaczniki czasowe**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Czas utworzenia pliku
* ATIME: Czas modyfikacji pliku
* MTIME: Czas modyfikacji rejestru MFT pliku
* RTIME: Czas dostępu do pliku

## Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem na identyfikację podejrzanych zmodyfikowanych plików byłoby porównanie czasu w obu atrybutach w poszukiwaniu **niezgodności**.

## Nanosekundy

Znaczniki czasowe **NTFS** mają **precyzję** **100 nanosekund**. Znalezienie plików ze znacznikami czasowymi takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

## SetMace - Narzędzie antyforensyczne

To narzędzie może modyfikować oba atrybuty `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednak od Windows Vista konieczne jest użycie działającego systemu operacyjnego do modyfikacji tych informacji.

# Ukrywanie danych

NFTS używa klastra i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje jeden i pół klastra, **pozostała połowa nigdy nie zostanie użyta**, dopóki plik nie zostanie usunięty. Wówczas możliwe jest **ukrycie danych w tej przestrzeni slack**.

Istnieją narzędzia takie jak slacker, które umożliwiają ukrywanie danych w tej "ukrytej" przestrzeni. Jednak analiza `$logfile` i `$usnjrnl` może pokazać, że dodano pewne dane:

![](<../../.gitbook/assets/image (452).png>)

Następnie można odzyskać przestrzeń slack za pomocą narzędzi takich jak FTK Imager. Należy jednak zauważyć, że tego rodzaju narzędzie może zapisać zawartość zaszyfrowaną lub nawet zaszyfrowaną.

# UsbKill

Jest to narzędzie, które **wyłączy komputer, jeśli zostanie wykryta jakakolwiek zmiana w portach USB**.\
Sposobem na odkrycie tego byłoby sprawdzenie działających procesów i **przejrzenie każdego uruchomionego skryptu python**.

# Dystrybucje Live Linux

Te dystrybucje są **wykonywane w pamięci RAM**. Jedynym sposobem na ich wykrycie jest **w przypadku zamontowania systemu plików NTFS z uprawnieniami do zapisu**. Jeśli jest zamontowany tylko z uprawnieniami do odczytu, nie będzie możliwe wykrycie włamania.

# Bezpieczne usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Konfiguracja systemu Windows

Można wyłączyć kilka metod rejestrowania zdarzeń systemu Windows, aby utrudnić śledzenie śladów.

## Wyłączanie znaczników czasowych - UserAssist

Jest to klucz rejestru, który przechowuje daty i godziny uruchomienia każdego pliku wykonywalnego przez użytkownika.

Wyłączenie UserAssist wymaga dwóch kroków:

1. Ustawienie dwóch kluczy rejestru, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na zero, aby wskazać, że chcemy wyłączyć UserAssist.
2. Wyczyść poddrzewa rejestru, które wyglądają jak `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Wyłączanie znaczników czasowych - Prefetch

Spowoduje to zapisywanie informacji o uruchomionych aplikacjach w celu poprawy wydajności systemu Windows. Jednak może to również być przydatne w praktykach związanych z forensyką.

* Uruchom `regedit`
* Wybierz ścieżkę pliku `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Kliknij prawym przyciskiem myszy na `EnablePrefetcher` i `EnableSuperfetch`
* Wybierz Modyfikuj dla każdego z nich, aby zmienić wartość z 1 (lub 3) na 0
* Uruchom ponownie

## Wyłączanie znaczników czasowych - Czas ostatniego dostępu

Za każdym razem, gdy folder jest otwierany z woluminu NTFS na serwerze Windows NT, system aktualizuje
## Usuń historię USB

Wszystkie **wpisy urządzeń USB** są przechowywane w rejestrze systemu Windows pod kluczem rejestru **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączasz urządzenie USB do komputera lub laptopa. Możesz znaleźć ten klucz tutaj: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie tego** spowoduje usunięcie historii USB.\
Możesz również użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html), aby upewnić się, że je usunąłeś (i je usunąć).

Innym plikiem, który przechowuje informacje o urządzeniach USB, jest plik `setupapi.dev.log` w folderze `C:\Windows\INF`. Należy go również usunąć.

## Wyłącz kopie woluminów

**Wyświetl** kopie woluminów za pomocą polecenia `vssadmin list shadowstorage`\
**Usuń** je, wykonując polecenie `vssadmin delete shadow`

Możesz również usunąć je za pomocą interfejsu graficznego, postępując zgodnie z krokami opisanymi w [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie woluminów, postępuj zgodnie z krokami opisanymi tutaj: [https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Usługi, wpisując "services" w pole wyszukiwania tekstu po kliknięciu przycisku start w systemie Windows.
2. Z listy znajdź "Kopię woluminu", wybierz go, a następnie uzyskaj dostęp do właściwości, klikając prawym przyciskiem myszy.
3. Wybierz opcję Wyłączone z menu rozwijanego "Typ uruchamiania", a następnie potwierdź zmianę, klikając Zastosuj i OK.

Możliwe jest również zmodyfikowanie konfiguracji, które pliki zostaną skopiowane w kopii woluminu w rejestrze `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Nadpisz usunięte pliki

* Możesz użyć narzędzia **Windows**: `cipher /w:C` Spowoduje to, że cipher usunie wszystkie dane z dostępnej nieużywanej przestrzeni dyskowej na dysku C.
* Możesz również użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

## Usuń dzienniki zdarzeń systemu Windows

* Windows + R --> eventvwr.msc --> Rozwiń "Dzienniki systemu Windows" --> Kliknij prawym przyciskiem myszy na każdą kategorię i wybierz "Wyczyść dziennik"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Wyłącz dzienniki zdarzeń systemu Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* W sekcji usług wyłącz usługę "Dziennik zdarzeń systemu Windows"
* `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

## Wyłącz $UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
