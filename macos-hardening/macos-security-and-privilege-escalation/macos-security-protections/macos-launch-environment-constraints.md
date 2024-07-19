# macOS Launch/Environment Constraints & Trust Cache

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

## Podstawowe informacje

Ograniczenia uruchamiania w macOS zostały wprowadzone w celu zwiększenia bezpieczeństwa poprzez **regulowanie, jak, kto i skąd proces może być inicjowany**. Wprowadzone w macOS Ventura, zapewniają ramy, które klasyfikują **każdy systemowy plik binarny w różne kategorie ograniczeń**, które są zdefiniowane w **pamięci zaufania**, liście zawierającej pliki binarne systemu i ich odpowiednie hashe. Ograniczenia te obejmują każdy wykonywalny plik binarny w systemie, co wiąże się z zestawem **reguł** określających wymagania dotyczące **uruchamiania konkretnego pliku binarnego**. Reguły obejmują ograniczenia własne, które musi spełnić plik binarny, ograniczenia rodzica, które musi spełnić jego proces nadrzędny, oraz ograniczenia odpowiedzialności, które muszą być przestrzegane przez inne odpowiednie podmioty.

Mechanizm ten rozszerza się na aplikacje firm trzecich poprzez **Ograniczenia Środowiskowe**, począwszy od macOS Sonoma, umożliwiając programistom ochronę swoich aplikacji poprzez określenie **zestawu kluczy i wartości dla ograniczeń środowiskowych.**

Definiujesz **ograniczenia środowiskowe i biblioteczne** w słownikach ograniczeń, które zapisujesz w **plikach listy właściwości `launchd`**, lub w **osobnych plikach listy właściwości**, które używasz w podpisywaniu kodu.

Istnieją 4 typy ograniczeń:

* **Ograniczenia własne**: Ograniczenia stosowane do **uruchamianego** pliku binarnego.
* **Proces nadrzędny**: Ograniczenia stosowane do **rodzica procesu** (na przykład **`launchd`** uruchamiającego usługę XP)
* **Ograniczenia odpowiedzialności**: Ograniczenia stosowane do **procesu wywołującego usługę** w komunikacji XPC
* **Ograniczenia ładowania biblioteki**: Użyj ograniczeń ładowania biblioteki, aby selektywnie opisać kod, który może być załadowany

Gdy proces próbuje uruchomić inny proces — wywołując `execve(_:_:_:)` lub `posix_spawn(_:_:_:_:_:_:)` — system operacyjny sprawdza, czy plik **wykonywalny** **spełnia** swoje **własne ograniczenie własne**. Sprawdza również, czy plik wykonywalny **procesu nadrzędnego** **spełnia** **ograniczenie nadrzędne** pliku wykonywalnego oraz czy plik wykonywalny **procesu odpowiedzialnego** **spełnia ograniczenie procesu odpowiedzialnego** pliku wykonywalnego. Jeśli którekolwiek z tych ograniczeń uruchamiania nie jest spełnione, system operacyjny nie uruchamia programu.

Jeśli podczas ładowania biblioteki jakakolwiek część **ograniczenia biblioteki nie jest prawdziwa**, twój proces **nie ładuje** biblioteki.

## Kategorie LC

LC składa się z **faktów** i **operacji logicznych** (i, lub..) łączących fakty.

[**Fakty, które LC może wykorzystać, są udokumentowane**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Na przykład:

* is-init-proc: Wartość logiczna, która wskazuje, czy plik wykonywalny musi być procesem inicjalizacji systemu operacyjnego (`launchd`).
* is-sip-protected: Wartość logiczna, która wskazuje, czy plik wykonywalny musi być plikiem chronionym przez System Integrity Protection (SIP).
* `on-authorized-authapfs-volume:` Wartość logiczna, która wskazuje, czy system operacyjny załadował plik wykonywalny z autoryzowanego, uwierzytelnionego woluminu APFS.
* `on-authorized-authapfs-volume`: Wartość logiczna, która wskazuje, czy system operacyjny załadował plik wykonywalny z autoryzowanego, uwierzytelnionego woluminu APFS.
* Wolumin Cryptexes
* `on-system-volume:` Wartość logiczna, która wskazuje, czy system operacyjny załadował plik wykonywalny z aktualnie uruchomionego woluminu systemowego.
* Wewnątrz /System...
* ...

Gdy plik binarny Apple jest podpisany, **przypisuje go do kategorii LC** wewnątrz **pamięci zaufania**.

* **Kategorie LC iOS 16** zostały [**odwrócone i udokumentowane tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Aktualne **Kategorie LC (macOS 14 - Sonoma)** zostały odwrócone, a ich [**opisy można znaleźć tutaj**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Na przykład Kategoria 1 to:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Musi być w woluminie System lub Cryptexes.
* `launch-type == 1`: Musi być usługą systemową (plist w LaunchDaemons).
* `validation-category == 1`: Wykonywalny plik systemu operacyjnego.
* `is-init-proc`: Launchd

### Odwracanie kategorii LC

Masz więcej informacji [**na ten temat tutaj**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), ale zasadniczo są one zdefiniowane w **AMFI (AppleMobileFileIntegrity)**, więc musisz pobrać Zestaw Narzędzi do Rozwoju Jądra, aby uzyskać **KEXT**. Symbole zaczynające się od **`kConstraintCategory`** są **interesujące**. Ekstrahując je, otrzymasz strumień zakodowany w DER (ASN.1), który musisz zdekodować za pomocą [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) lub biblioteki python-asn1 i jej skryptu `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), co da ci bardziej zrozumiały ciąg.

## Ograniczenia środowiskowe

To są Ograniczenia Uruchamiania skonfigurowane w **aplikacjach firm trzecich**. Programista może wybrać **fakty** i **operandy logiczne do użycia** w swojej aplikacji, aby ograniczyć dostęp do niej samej.

Możliwe jest enumerowanie Ograniczeń Środowiskowych aplikacji za pomocą:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

W **macOS** istnieje kilka pamięci podręcznych zaufania:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

A w iOS wygląda to na **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
Na macOS działającym na urządzeniach Apple Silicon, jeśli binarny plik podpisany przez Apple nie znajduje się w pamięci podręcznej zaufania, AMFI odmówi jego załadowania.
{% endhint %}

### Enumerating Trust Caches

Poprzednie pliki pamięci podręcznej zaufania są w formacie **IMG4** i **IM4P**, przy czym IM4P to sekcja ładunku formatu IMG4.

Możesz użyć [**pyimg4**](https://github.com/m1stadev/PyIMG4) do wyodrębnienia ładunku baz danych:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Inną opcją może być użycie narzędzia [**img4tool**](https://github.com/tihmstar/img4tool), które będzie działać nawet na M1, nawet jeśli wydanie jest stare, oraz na x86\_64, jeśli zainstalujesz je w odpowiednich lokalizacjach).

Teraz możesz użyć narzędzia [**trustcache**](https://github.com/CRKatri/trustcache), aby uzyskać informacje w czytelnym formacie:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Cache zaufania ma następującą strukturę, więc **kategoria LC to 4. kolumna**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Then, you could use a script such as [**this one**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) to extract data.

From that data you can check the Apps with a **launch constraints value of `0`**, which are the ones that aren't constrained ([**check here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) for what each value is).

## Ataki i ich łagodzenie

Launch Constrains mogłyby złagodzić kilka starych ataków poprzez **zapewnienie, że proces nie będzie wykonywany w nieoczekiwanych warunkach:** Na przykład z nieoczekiwanych lokalizacji lub wywoływany przez nieoczekiwany proces nadrzędny (jeśli tylko launchd powinien go uruchamiać).

Ponadto, Launch Constraints również **łagodzi ataki typu downgrade.**

Jednakże, **nie łagodzą one powszechnych nadużyć XPC**, **wstrzyknięć** kodu **Electron** ani **wstrzyknięć dylib** bez walidacji biblioteki (chyba że znane są identyfikatory zespołów, które mogą ładować biblioteki).

### Ochrona Daemonów XPC

W wydaniu Sonoma, istotnym punktem jest **konfiguracja odpowiedzialności** usługi daemon XPC. Usługa XPC jest odpowiedzialna za siebie, w przeciwieństwie do klienta łączącego się, który jest odpowiedzialny. Jest to udokumentowane w raporcie zwrotnym FB13206884. Ta konfiguracja może wydawać się wadliwa, ponieważ pozwala na pewne interakcje z usługą XPC:

- **Uruchamianie usługi XPC**: Jeśli uznać to za błąd, ta konfiguracja nie pozwala na inicjowanie usługi XPC za pomocą kodu atakującego.
- **Łączenie z aktywną usługą**: Jeśli usługa XPC już działa (prawdopodobnie aktywowana przez swoją oryginalną aplikację), nie ma przeszkód w łączeniu się z nią.

Chociaż wprowadzenie ograniczeń na usłudze XPC może być korzystne poprzez **zawężenie okna dla potencjalnych ataków**, nie rozwiązuje to podstawowego problemu. Zapewnienie bezpieczeństwa usługi XPC zasadniczo wymaga **skutecznej walidacji łączącego się klienta**. To pozostaje jedyną metodą na wzmocnienie bezpieczeństwa usługi. Warto również zauważyć, że wspomniana konfiguracja odpowiedzialności jest obecnie operacyjna, co może nie być zgodne z zamierzonym projektem.

### Ochrona Electron

Nawet jeśli wymagane jest, aby aplikacja była **otwierana przez LaunchService** (w ograniczeniach rodziców). Można to osiągnąć za pomocą **`open`** (które może ustawiać zmienne środowiskowe) lub korzystając z **API Launch Services** (gdzie można wskazać zmienne środowiskowe).

## Odniesienia

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
