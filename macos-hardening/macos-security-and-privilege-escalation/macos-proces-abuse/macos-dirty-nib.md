# macOS Dirty NIB

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Aby uzyskać więcej szczegółów na temat techniki, sprawdź oryginalny post z:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) oraz następujący post od [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Oto podsumowanie:

### Czym są pliki Nib

Pliki Nib (skrót od NeXT Interface Builder), część ekosystemu deweloperskiego Apple, są przeznaczone do definiowania **elementów UI** i ich interakcji w aplikacjach. Zawierają zserializowane obiekty, takie jak okna i przyciski, i są ładowane w czasie wykonywania. Pomimo ich ciągłego użycia, Apple obecnie zaleca korzystanie z Storyboardów dla bardziej kompleksowej wizualizacji przepływu UI.

Główny plik Nib jest odniesiony w wartości **`NSMainNibFile`** wewnątrz pliku `Info.plist` aplikacji i jest ładowany przez funkcję **`NSApplicationMain`** wykonywaną w funkcji `main` aplikacji.

### Proces wstrzykiwania Dirty Nib

#### Tworzenie i konfigurowanie pliku NIB

1. **Wstępna konfiguracja**:
* Utwórz nowy plik NIB za pomocą XCode.
* Dodaj obiekt do interfejsu, ustawiając jego klasę na `NSAppleScript`.
* Skonfiguruj początkową właściwość `source` za pomocą Atrybutów Czasu Wykonania Zdefiniowanych przez Użytkownika.
2. **Gadżet do wykonywania kodu**:
* Konfiguracja umożliwia uruchamianie AppleScript na żądanie.
* Zintegruj przycisk, aby aktywować obiekt `Apple Script`, wywołując selektor `executeAndReturnError:`.
3. **Testowanie**:
* Prosty skrypt Apple do celów testowych:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* Testuj, uruchamiając w debuggerze XCode i klikając przycisk.

#### Celowanie w aplikację (przykład: Pages)

1. **Przygotowanie**:
* Skopiuj docelową aplikację (np. Pages) do osobnego katalogu (np. `/tmp/`).
* Uruchom aplikację, aby obejść problemy z Gatekeeperem i zbuforować ją.
2. **Nadpisywanie pliku NIB**:
* Zastąp istniejący plik NIB (np. NIB panelu "O programie") stworzonym plikiem DirtyNIB.
3. **Wykonanie**:
* Wywołaj wykonanie, wchodząc w interakcję z aplikacją (np. wybierając element menu `O programie`).

#### Dowód koncepcji: Uzyskiwanie dostępu do danych użytkownika

* Zmodyfikuj AppleScript, aby uzyskać dostęp i wyodrębnić dane użytkownika, takie jak zdjęcia, bez zgody użytkownika.

### Przykład kodu: Złośliwy plik .xib

* Uzyskaj dostęp i przeglądaj [**przykład złośliwego pliku .xib**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4), który demonstruje wykonywanie dowolnego kodu.

### Inny przykład

W poście [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) możesz znaleźć samouczek na temat tworzenia dirty nib.&#x20;

### Rozwiązywanie ograniczeń uruchamiania

* Ograniczenia uruchamiania utrudniają wykonywanie aplikacji z nieoczekiwanych lokalizacji (np. `/tmp`).
* Możliwe jest zidentyfikowanie aplikacji, które nie są chronione przez ograniczenia uruchamiania i celowanie w nie w celu wstrzyknięcia pliku NIB.

### Dodatkowe zabezpieczenia macOS

Od macOS Sonoma wprowadzone zostały ograniczenia dotyczące modyfikacji wewnątrz pakietów aplikacji. Jednak wcześniejsze metody obejmowały:

1. Skopiowanie aplikacji do innej lokalizacji (np. `/tmp/`).
2. Zmiana nazw katalogów w pakiecie aplikacji, aby obejść początkowe zabezpieczenia.
3. Po uruchomieniu aplikacji w celu zarejestrowania się w Gatekeeperze, modyfikacja pakietu aplikacji (np. zastąpienie MainMenu.nib plikiem Dirty.nib).
4. Przywrócenie nazw katalogów i ponowne uruchomienie aplikacji w celu wykonania wstrzykniętego pliku NIB.

**Uwaga**: Ostatnie aktualizacje macOS złagodziły ten exploit, uniemożliwiając modyfikacje plików w pakietach aplikacji po buforowaniu Gatekeepera, co czyni exploit nieskutecznym.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
