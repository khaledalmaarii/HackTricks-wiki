# macOS Dirty NIB

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

**Aby uzyskać więcej szczegółów na temat techniki, sprawdź oryginalny post pod adresem: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Oto podsumowanie:

Pliki NIB, będące częścią ekosystemu deweloperskiego Apple, służą do definiowania **elementów UI** i ich interakcji w aplikacjach. Zawierają zserializowane obiekty, takie jak okna i przyciski, i są ładowane w czasie wykonywania. Pomimo ich ciągłego użycia, Apple obecnie zaleca korzystanie z Storyboardów dla bardziej kompleksowej wizualizacji przepływu UI.

### Problemy z bezpieczeństwem związane z plikami NIB
Ważne jest, aby zauważyć, że **pliki NIB mogą stanowić zagrożenie dla bezpieczeństwa**. Mają potencjał do **wykonywania dowolnych poleceń**, a zmiany w plikach NIB w aplikacji nie uniemożliwiają Gatekeeperowi uruchomienia aplikacji, co stanowi poważne zagrożenie.

### Proces wstrzykiwania Dirty NIB
#### Tworzenie i konfigurowanie pliku NIB
1. **Wstępna konfiguracja**:
- Utwórz nowy plik NIB za pomocą XCode.
- Dodaj obiekt do interfejsu, ustawiając jego klasę na `NSAppleScript`.
- Skonfiguruj początkową właściwość `source` za pomocą atrybutów czasu wykonywania zdefiniowanych przez użytkownika.

2. **Gadżet do wykonywania kodu**:
- Konfiguracja umożliwia uruchamianie AppleScript na żądanie.
- Zintegruj przycisk, aby aktywować obiekt `Apple Script`, wywołując selektor `executeAndReturnError:`.

3. **Testowanie**:
- Prosty skrypt Apple do celów testowych:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Przetestuj, uruchamiając w debuggerze XCode i klikając przycisk.

#### Celowanie w aplikację (przykład: Pages)
1. **Przygotowanie**:
- Skopiuj docelową aplikację (np. Pages) do osobnego katalogu (np. `/tmp/`).
- Uruchom aplikację, aby obejść problemy z Gatekeeperem i zbuforować ją.

2. **Nadpisywanie pliku NIB**:
- Zastąp istniejący plik NIB (np. NIB panelu "O programie") stworzonym plikiem DirtyNIB.

3. **Wykonanie**:
- Uruchom wykonanie, wchodząc w interakcję z aplikacją (np. wybierając element menu `O programie`).

#### Dowód koncepcji: Uzyskiwanie dostępu do danych użytkownika
- Zmodyfikuj AppleScript, aby uzyskać dostęp i wyodrębnić dane użytkownika, takie jak zdjęcia, bez zgody użytkownika.

### Przykład kodu: Złośliwy plik .xib
- Uzyskaj dostęp i przeglądaj [**przykład złośliwego pliku .xib**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4), który demonstruje wykonywanie dowolnego kodu.

### Rozwiązywanie ograniczeń uruchamiania
- Ograniczenia uruchamiania utrudniają wykonywanie aplikacji z nieoczekiwanych lokalizacji (np. `/tmp`).
- Możliwe jest zidentyfikowanie aplikacji, które nie są chronione przez ograniczenia uruchamiania i celowanie w nie w celu wstrzykiwania plików NIB.

### Dodatkowe zabezpieczenia macOS
Od macOS Sonoma wprowadzone zostały ograniczenia dotyczące modyfikacji wewnątrz pakietów aplikacji. Jednak wcześniejsze metody obejmowały:
1. Skopiowanie aplikacji do innej lokalizacji (np. `/tmp/`).
2. Zmiana nazw katalogów w pakiecie aplikacji, aby obejść początkowe zabezpieczenia.
3. Po uruchomieniu aplikacji w celu zarejestrowania się w Gatekeeperze, modyfikacja pakietu aplikacji (np. zastąpienie MainMenu.nib plikiem Dirty.nib).
4. Przywrócenie nazw katalogów i ponowne uruchomienie aplikacji w celu wykonania wstrzykniętego pliku NIB.

**Uwaga**: Ostatnie aktualizacje macOS złagodziły ten exploit, uniemożliwiając modyfikacje plików w pakietach aplikacji po buforowaniu przez Gatekeeper, co czyni exploit nieskutecznym.


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
