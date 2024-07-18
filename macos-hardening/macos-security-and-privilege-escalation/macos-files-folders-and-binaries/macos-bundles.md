# Pliki pakietów macOS

{% hint style="success" %}
Dowiedz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## Podstawowe informacje

Pakiety w macOS służą jako kontenery dla różnorodnych zasobów, w tym aplikacji, bibliotek i innych niezbędnych plików, sprawiając, że wyglądają jak pojedyncze obiekty w Finderze, takie jak znane pliki `*.app`. Najczęściej spotykanym pakietem jest pakiet `.app`, choć inne typy, takie jak `.framework`, `.systemextension` i `.kext`, również są powszechne.

### Podstawowe składniki pakietu

Wewnątrz pakietu, szczególnie w katalogu `<aplikacja>.app/Contents/`, znajduje się wiele ważnych zasobów:

* **\_CodeSignature**: Ten katalog przechowuje szczegóły podpisu kodu niezbędne do weryfikacji integralności aplikacji. Możesz sprawdzić informacje o podpisie kodu za pomocą poleceń takich jak: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Zawiera wykonywalny plik binarny aplikacji, który uruchamia się po interakcji użytkownika.
* **Resources**: Repozytorium komponentów interfejsu użytkownika aplikacji, w tym obrazy, dokumenty i opisy interfejsu (pliki nib/xib).
* **Info.plist**: Działa jako główny plik konfiguracyjny aplikacji, kluczowy dla systemu w celu rozpoznania i interakcji z aplikacją w odpowiedni sposób.

#### Ważne klucze w pliku Info.plist

Plik `Info.plist` jest fundamentem konfiguracji aplikacji, zawierając klucze takie jak:

* **CFBundleExecutable**: Określa nazwę głównego pliku wykonywalnego znajdującego się w katalogu `Contents/MacOS`.
* **CFBundleIdentifier**: Zapewnia globalny identyfikator aplikacji, szeroko używany przez macOS do zarządzania aplikacjami.
* **LSMinimumSystemVersion**: Wskazuje minimalną wersję macOS wymaganą do uruchomienia aplikacji.

### Eksploracja pakietów

Aby zbadać zawartość pakietu, takiego jak `Safari.app`, można użyć następującego polecenia: `bash ls -lR /Applications/Safari.app/Contents`

Ta eksploracja ujawnia katalogi takie jak `_CodeSignature`, `MacOS`, `Resources`, oraz pliki takie jak `Info.plist`, z każdym pełniącym unikalną rolę od zabezpieczania aplikacji po definiowanie interfejsu użytkownika i parametrów operacyjnych.

#### Dodatkowe katalogi pakietów

Poza powszechnymi katalogami, pakiety mogą również zawierać:

* **Frameworks**: Zawiera spakowane frameworki używane przez aplikację. Frameworki są podobne do dylibs z dodatkowymi zasobami.
* **PlugIns**: Katalog dla wtyczek i rozszerzeń, które zwiększają możliwości aplikacji.
* **XPCServices**: Przechowuje usługi XPC używane przez aplikację do komunikacji międzyprocesowej.

Ta struktura zapewnia, że wszystkie niezbędne komponenty są zamknięte w pakiecie, ułatwiając modularne i bezpieczne środowisko aplikacji.

Aby uzyskać bardziej szczegółowe informacje na temat kluczy `Info.plist` i ich znaczenia, dokumentacja deweloperska Apple oferuje obszerne zasoby: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Dowiedz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}
