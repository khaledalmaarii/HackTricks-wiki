# Paczki macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

## Podstawowe informacje

Paczki w macOS służą jako kontenery dla różnych zasobów, w tym aplikacji, bibliotek i innych niezbędnych plików, dzięki czemu wyglądają jak pojedyncze obiekty w Finderze, takie jak znane pliki `*.app`. Najczęściej spotykaną paczką jest paczka `.app`, choć inne typy, takie jak `.framework`, `.systemextension` i `.kext`, są również powszechne.

### Podstawowe składniki paczki

Wewnątrz paczki, szczególnie w katalogu `<aplikacja>.app/Contents/`, znajduje się wiele ważnych zasobów:

- **_CodeSignature**: Ten katalog przechowuje szczegóły podpisu kodu niezbędne do weryfikacji integralności aplikacji. Możesz sprawdzić informacje o podpisie kodu za pomocą poleceń takich jak:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Zawiera wykonywalny plik binarny aplikacji, który uruchamia się po interakcji użytkownika.
- **Resources**: Repozytorium dla komponentów interfejsu użytkownika aplikacji, w tym obrazów, dokumentów i opisów interfejsu (pliki nib/xib).
- **Info.plist**: Pełni rolę głównego pliku konfiguracyjnego aplikacji, niezbędnego do rozpoznawania i interakcji z aplikacją przez system.

#### Ważne klucze w pliku Info.plist

Plik `Info.plist` jest fundamentem konfiguracji aplikacji i zawiera klucze takie jak:

- **CFBundleExecutable**: Określa nazwę głównego pliku wykonywalnego znajdującego się w katalogu `Contents/MacOS`.
- **CFBundleIdentifier**: Zapewnia globalny identyfikator aplikacji, szeroko wykorzystywany przez macOS do zarządzania aplikacjami.
- **LSMinimumSystemVersion**: Wskazuje minimalną wersję macOS wymaganą do uruchomienia aplikacji.

### Eksploracja paczek

Aby zbadać zawartość paczki, takiej jak `Safari.app`, można użyć następującego polecenia:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Ta eksploracja ujawnia katalogi takie jak `_CodeSignature`, `MacOS`, `Resources`, oraz pliki takie jak `Info.plist`, z których każdy pełni unikalną rolę, od zabezpieczania aplikacji po definiowanie jej interfejsu użytkownika i parametrów operacyjnych.

#### Dodatkowe katalogi paczek

Poza wspólnymi katalogami, paczki mogą również zawierać:

- **Frameworks**: Zawiera dołączone frameworki używane przez aplikację.
- **PlugIns**: Katalog dla wtyczek i rozszerzeń, które rozszerzają możliwości aplikacji.
- **XPCServices**: Przechowuje usługi XPC używane przez aplikację do komunikacji międzyprocesowej.

Ta struktura zapewnia, że wszystkie niezbędne komponenty są zamknięte wewnątrz paczki, ułatwiając modułowe i bezpieczne środowisko aplikacji.

Aby uzyskać bardziej szczegółowe informacje na temat kluczy `Info.plist` i ich znaczenia, dokumentacja dla deweloperów Apple udostępnia obszerne zasoby: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
