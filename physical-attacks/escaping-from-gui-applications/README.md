<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


# Sprawdź możliwe działania w aplikacji GUI

**Wspólne okna dialogowe** to opcje takie jak **zapisywanie pliku**, **otwieranie pliku**, wybieranie czcionki, koloru... Większość z nich **oferuje pełną funkcjonalność Eksploratora**. Oznacza to, że będziesz mógł uzyskać dostęp do funkcji Eksploratora, jeśli będziesz mógł uzyskać dostęp do tych opcji:

* Zamknij/Zamknij jako
* Otwórz/Otwórz za pomocą
* Drukuj
* Eksportuj/Importuj
* Szukaj
* Skanuj

Powinieneś sprawdzić, czy możesz:

* Modyfikować lub tworzyć nowe pliki
* Tworzyć dowiązania symboliczne
* Uzyskać dostęp do ograniczonych obszarów
* Wykonywać inne aplikacje

## Wykonanie polecenia

Być może **korzystając z opcji `Otwórz za pomocą`** możesz otworzyć/wykonac pewnego rodzaju powłokę.

### Windows

Na przykład _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ znajdź więcej binarnych plików, które można użyć do wykonywania poleceń (i wykonywania nieoczekiwanych działań) tutaj: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Więcej tutaj: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Omijanie ograniczeń ścieżki

* **Zmienne środowiskowe**: Istnieje wiele zmiennych środowiskowych, które wskazują na pewną ścieżkę
* **Inne protokoły**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Dowiązania symboliczne**
* **Skróty**: CTRL+N (otwórz nową sesję), CTRL+R (Wykonaj polecenia), CTRL+SHIFT+ESC (Menedżer zadań),  Windows+E (otwórz eksplorator), CTRL-B, CTRL-I (Ulubione), CTRL-H (Historia), CTRL-L, CTRL-O (Okno/Otwórz), CTRL-P (Okno/Drukuj), CTRL-S (Okno/Zapisz jako)
* Ukryte menu administracyjne: CTRL-ALT-F8, CTRL-ESC-F9
* **URI powłoki**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **Ścieżki UNC**: Ścieżki do połączenia z udostępnionymi folderami. Spróbuj połączyć się z C$ lokalnej maszyny ("\\\127.0.0.1\c$\Windows\System32")
* **Więcej ścieżek UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Pobierz swoje pliki binarne

Konsola: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Eksplorator: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Edytor rejestru: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Dostęp do systemu plików z przeglądarki

| ŚCIEŻKA             | ŚCIEŻKA           | ŚCIEŻKA            | ŚCIEŻKA             |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Skróty

* Sticky Keys – Naciśnij SHIFT 5 razy
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Przytrzymaj NUMLOCK przez 5 sekund
* Filter Keys – Przytrzymaj prawy SHIFT przez 12 sekund
* WINDOWS+F1 – Wyszukiwanie w systemie Windows
* WINDOWS+D – Pokaż pulpit
* WINDOWS+E – Uruchom Eksploratora Windows
* WINDOWS+R – Uruchom
* WINDOWS+U – Centrum ułatwień dostępu
* WINDOWS+F – Wyszukiwanie
* SHIFT+F10 – Menu kontekstowe
* CTRL+SHIFT+ESC – Menedżer zadań
* CTRL+ALT+DEL – Ekran powitalny w nowszych wersjach systemu Windows
* F1 – Pomoc F3 – Wyszukiwanie
* F6 – Pasek adresu
* F11 – Przełącz pełny ekran w przeglądarce Internet Explorer
* CTRL+H – Historia przeglądarki Internet Explorer
* CTRL+T – Internet Explorer – Nowa karta
* CTRL+N – Internet Explorer – Nowa strona
* CTRL+O – Otwórz plik
* CTRL+S – Zapisz CTRL+N – Nowe RDP / Citrix
## Swipy

* Przesuń palcem z lewej strony na prawą, aby zobaczyć wszystkie otwarte okna, minimalizując aplikację KIOSK i uzyskując bezpośredni dostęp do całego systemu operacyjnego;
* Przesuń palcem z prawej strony na lewą, aby otworzyć Centrum akcji, minimalizując aplikację KIOSK i uzyskując bezpośredni dostęp do całego systemu operacyjnego;
* Przesuń palcem od górnego brzegu, aby wyświetlić pasek tytułu dla aplikacji otwartej w trybie pełnoekranowym;
* Przesuń palcem w górę od dołu, aby pokazać pasek zadań w aplikacji pełnoekranowej.

## Triki Internet Explorera

### 'Pasek narzędzi obrazu'

To pasek narzędzi, który pojawia się w lewym górnym rogu obrazu po jego kliknięciu. Będziesz mógł zapisać, wydrukować, wysłać wiadomość e-mail, otworzyć "Moje obrazy" w Eksploratorze. Kiosk musi korzystać z przeglądarki Internet Explorer.

### Protokół Shell

Wpisz te adresy URL, aby uzyskać widok Eksploratora:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panel sterowania
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mój komputer
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Moje miejsca sieciowe
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Pokaż rozszerzenia plików

Sprawdź tę stronę, aby uzyskać więcej informacji: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Triki przeglądarek

Kopia zapasowa wersji iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Utwórz wspólny dialog za pomocą JavaScript i uzyskaj dostęp do eksploratora plików: `document.write('<input/type=file>')`
Źródło: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gesty i przyciski

* Przesuń palcem w górę z czterema (lub pięcioma) palcami / Podwójne kliknięcie przycisku Home: Aby wyświetlić widok wielozadaniowy i zmienić aplikację

* Przesuń palcem w jedną lub drugą stronę z czterema lub pięcioma palcami: Aby przejść do następnej/ostatniej aplikacji

* Ściśnij ekran pięcioma palcami / Dotknij przycisku Home / Przesuń palcem w górę jednym palcem od dołu ekranu w szybkim ruchu do góry: Aby uzyskać dostęp do ekranu głównego

* Przesuń palcem jeden cal od dołu ekranu (powoli): Pojawi się pasek dokowania

* Przesuń palcem w dół od góry ekranu jednym palcem: Aby wyświetlić powiadomienia

* Przesuń palcem w dół jednym palcem w prawym górnym rogu ekranu: Aby zobaczyć centrum sterowania iPad Pro

* Przesuń palcem jeden cal od lewej strony ekranu (1-2 cale): Aby zobaczyć widok dzisiejszy

* Szybko przesuń palcem jeden cal od środka ekranu w prawo lub lewo: Aby przejść do następnej/ostatniej aplikacji

* Przytrzymaj przycisk Włącz/Wyłącz/Uśpij w prawym górnym rogu iPada + Przesuń suwak "Wyłącz" aż do końca w prawo: Aby wyłączyć zasilanie

* Naciśnij przycisk Włącz/Wyłącz/Uśpij w prawym górnym rogu iPada i przycisk Home przez kilka sekund: Aby wymusić twardy wyłącznik

* Naciśnij przycisk Włącz/Wyłącz/Uśpij w prawym górnym rogu iPada i przycisk Home szybko: Aby zrobić zrzut ekranu, który pojawi się w lewym dolnym rogu ekranu. Naciśnij oba przyciski jednocześnie bardzo krótko, jeśli przytrzymasz je przez kilka sekund, zostanie wykonane twardy wyłączenie.

## Skróty

Powinieneś mieć klawiaturę do iPada lub adapter USB do klawiatury. Tylko skróty, które mogą pomóc w wyjściu z aplikacji, zostaną tutaj pokazane.

| Klawisz | Nazwa         |
| ------- | ------------- |
| ⌘       | Command       |
| ⌥       | Option (Alt)  |
| ⇧       | Shift         |
| ↩       | Return        |
| ⇥       | Tab           |
| ^       | Control       |
| ←       | Strzałka w lewo   |
| →       | Strzałka w prawo  |
| ↑       | Strzałka w górę    |
| ↓       | Strzałka w dół  |

### Skróty systemowe

Te skróty dotyczą ustawień wizualnych i ustawień dźwięku, w zależności od sposobu korzystania z iPada.

| Skrót    | Działanie                                                                 |
| -------- | ------------------------------------------------------------------------ |
| F1       | Przyciemnij ekran                                                         |
| F2       | Rozjaśnij ekran                                                           |
| F7       | Poprzedni utwór                                                            |
| F8       | Odtwarzaj/wstrzymaj                                                        |
| F9       | Pomijaj utwór                                                              |
| F10      | Wycisz                                                                     |
| F11      | Zmniejsz głośność                                                          |
| F12      | Zwiększ głośność                                                           |
| ⌘ Spacja | Wyświetl listę dostępnych języków; aby wybrać jeden, ponownie naciśnij spację. |

### Nawigacja w iPadzie

| Skrót                                              | Działanie                                                      |
| -------------------------------------------------- | -------------------------------------------------------------- |
| ⌘H                                                 | Przejdź do ekranu głównego                                      |
| ⌘⇧H (Command-Shift-H)                              | Przejdź do ekranu głównego                                      |
| ⌘ (Spacja)                                         | Otwórz Spotlight                                                |
| ⌘⇥ (Command-Tab)                                   | Wyświetl listę ostatnio używanych aplikacji                     |
| ⌘\~                                                | Przejdź do ostatniej aplikacji                                  |
| ⌘⇧3 (Command-Shift-3)                              | Zrzut ekranu (pojawia się w lewym dolnym rogu do zapisania lub działania) |
| ⌘⇧4                                                | Zrzut ekranu i otwórz go w edytorze                             |
| Przytrzymaj ⌘                                       | Lista dostępnych skrótów dla aplikacji                          |
| ⌘⌥D (Command-Option/Alt-D)                         | Wyświetl dokowanie                                              |
| ^⌥H (Control-Option-H)                             | Przycisk Home                                                   |
| ^⌥H H (Control-Option-H-H)                         | Pokaż pasek wielozadaniowy                                      |
| ^⌥I (Control-Option-i)                             | Wybór elementu                                                  |
| Escape                                             | Przycisk Wstecz                                                 |
| → (Strzałka w prawo)                                    | Następny element                                                |
| ← (Strzałka w lewo)                                     | Poprzedni element                                              |
| ↑↓ (Strzałka w górę, Strzałka w dół)                    | Jednocześnie dotknij wybranego elementu                         |
| ⌥ ↓ (Option-Strzałka w dół)                            | Przewiń w dół                                                   |
| ⌥↑ (Option-Strzałka w górę)                             | Przewiń w górę                                                  |
### Skróty klawiszowe w Safari

| Skrót                   | Działanie                                      |
| ----------------------- | ---------------------------------------------- |
| ⌘L (Command-L)          | Otwórz lokalizację                              |
| ⌘T                      | Otwórz nową kartę                               |
| ⌘W                      | Zamknij bieżącą kartę                           |
| ⌘R                      | Odśwież bieżącą kartę                           |
| ⌘.                      | Zatrzymaj ładowanie bieżącej karty               |
| ^⇥                      | Przełącz się do następnej karty                  |
| ^⇧⇥ (Control-Shift-Tab) | Przejdź do poprzedniej karty                     |
| ⌘L                      | Wybierz pole tekstowe/URL do modyfikacji         |
| ⌘⇧T (Command-Shift-T)   | Otwórz ostatnio zamkniętą kartę (można użyć kilka razy) |
| ⌘\[                     | Wróć do poprzedniej strony w historii przeglądania |
| ⌘]                      | Przejdź do następnej strony w historii przeglądania |
| ⌘⇧R                     | Aktywuj tryb czytnika                            |

### Skróty klawiszowe w Mailu

| Skrót                      | Działanie                     |
| -------------------------- | ----------------------------- |
| ⌘L                         | Otwórz lokalizację             |
| ⌘T                         | Otwórz nową kartę              |
| ⌘W                         | Zamknij bieżącą kartę          |
| ⌘R                         | Odśwież bieżącą kartę          |
| ⌘.                         | Zatrzymaj ładowanie bieżącej karty |
| ⌘⌥F (Command-Option/Alt-F) | Szukaj w skrzynce odbiorczej    |

# Odwołania

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
