# macOS Dirty NIB

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Aby uzyskać więcej szczegółów na temat techniki, sprawdź oryginalny post na stronie: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Oto streszczenie:

Pliki NIB, będące częścią ekosystemu Apple do tworzenia aplikacji, służą do definiowania **elementów interfejsu użytkownika** i ich interakcji. Obejmują zserializowane obiekty, takie jak okna i przyciski, i są ładowane w czasie wykonywania. Pomimo ich ciągłego użycia, Apple obecnie zaleca korzystanie z Storyboards do bardziej kompleksowej wizualizacji przepływu interfejsu użytkownika.

### Zagrożenia związane z plikami NIB
Warto zauważyć, że **pliki NIB mogą stanowić ryzyko dla bezpieczeństwa**. Mają potencjał do **wykonywania dowolnych poleceń**, a zmiany w plikach NIB wewnątrz aplikacji nie powstrzymują Gatekeepera przed uruchomieniem aplikacji, co stanowi poważne zagrożenie.

### Proces wstrzykiwania brudnego NIB
#### Tworzenie i konfiguracja pliku NIB
1. **Początkowa konfiguracja**:
- Utwórz nowy plik NIB za pomocą XCode.
- Dodaj obiekt do interfejsu, ustawiając jego klasę na `NSAppleScript`.
- Skonfiguruj początkową właściwość `source` za pomocą atrybutów czasu wykonania zdefiniowanych przez użytkownika.

2. **Gadżet wykonujący kod**:
- Konfiguracja umożliwia uruchamianie skryptów AppleScript na żądanie.
- Dodaj przycisk, który aktywuje obiekt `Apple Script`, wywołując specyficzny selektor `executeAndReturnError:`.

3. **Testowanie**:
- Prosty skrypt AppleScript do celów testowych:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Przetestuj, uruchamiając go w debuggerze XCode i klikając przycisk.

#### Celowanie w aplikację (Przykład: Pages)
1. **Przygotowanie**:
- Skopiuj docelową aplikację (np. Pages) do osobnego katalogu (np. `/tmp/`).
- Uruchom aplikację, aby ominąć problemy z Gatekeeperem i zbuforować ją.

2. **Nadpisanie pliku NIB**:
- Zastąp istniejący plik NIB (np. About Panel NIB) przygotowanym plikiem DirtyNIB.

3. **Wykonanie**:
- Uruchom wykonanie, oddziałując na aplikację (np. wybierając pozycję menu `About`).

#### Dowód koncepcji: Dostęp do danych użytkownika
- Zmodyfikuj skrypt AppleScript, aby uzyskać dostęp i wyodrębnić dane użytkownika, takie jak zdjęcia, bez zgody użytkownika.

### Przykład kodu: Złośliwy plik .xib
- Uzyskaj dostęp i przejrzyj [**przykład złośliwego pliku .xib**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4), który demonstruje wykonywanie dowolnego kodu.

### Rozwiązywanie ograniczeń uruchamiania
- Ograniczenia uruchamiania uniemożliwiają uruchamianie aplikacji z nieoczekiwanych lokalizacji (np. `/tmp`).
- Możliwe jest zidentyfikowanie aplikacji niechronionych przez ograniczenia uruchamiania i celowanie w nie do wstrzykiwania plików NIB.

### Dodatkowe zabezpieczenia macOS
Od macOS Sonoma w górę, modyfikacje wewnątrz paczek aplikacji są ograniczone. Jednak wcześniejsze metody obejmowały:
1. Skopiowanie aplikacji do innego miejsca (np. `/tmp/`).
2. Zmiana nazw katalogów wewnątrz paczki aplikacji w celu obejścia początkowych zabezpieczeń.
3. Po uruchomieniu aplikacji w celu zarejestrowania jej w Gatekeeperze, modyfikacja paczki aplikacji (np. zastąpienie MainMenu.nib przez Dirty.nib).
4. Przywrócenie pierwotnych nazw katalogów i ponowne uruchomienie aplikacji w celu wykonania wstrzykniętego pliku NIB.

**Uwaga**: Ostatnie aktualizacje macOS zabezpieczyły tę luki, uniemożliwiając modyfikacje plików wewnątrz paczek aplikacji po zbuforowaniu przez Gatekeepera, co czyni tę luki nieskuteczną.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
