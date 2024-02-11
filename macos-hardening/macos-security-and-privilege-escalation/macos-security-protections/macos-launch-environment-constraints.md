# Ograniczenia uruchamiania/środowiska macOS i pamięć podręczna zaufania

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Podstawowe informacje

Ograniczenia uruchamiania w macOS zostały wprowadzone w celu zwiększenia bezpieczeństwa poprzez **regulowanie, jak, kto i z jakiego miejsca może zostać uruchomiony proces**. Wprowadzone w macOS Ventura, zapewniają one ramy, które kategoryzują **każdy binarny systemowy do odrębnych kategorii ograniczeń**, zdefiniowanych w **pamięci podręcznej zaufania**, która zawiera binarne systemowe i ich odpowiednie skróty​. Ograniczenia te dotyczą każdego wykonywalnego pliku binarnego w systemie i obejmują zestaw **reguł**, które określają wymagania dotyczące **uruchamiania danego pliku binarnego**. Reguły obejmują ograniczenia własne, które musi spełnić dany plik binarny, ograniczenia rodzica, które muszą być spełnione przez proces nadrzędny, oraz ograniczenia odpowiedzialności, które muszą być przestrzegane przez inne istotne podmioty​.

Mechanizm ten dotyczy również aplikacji firm trzecich poprzez **Ograniczenia środowiskowe**, wprowadzone od macOS Sonoma, które umożliwiają programistom ochronę ich aplikacji poprzez określenie **zbioru kluczy i wartości dla ograniczeń środowiskowych**.

Definiujesz **ograniczenia uruchamiania i bibliotek** w słownikach ograniczeń, które zapisujesz w plikach **właściwości `launchd`**, lub w **oddzielnych plikach** właściwości, które używasz w podpisach kodu.

Istnieją 4 rodzaje ograniczeń:

* **Ograniczenia własne**: Ograniczenia dotyczące **uruchamianego** pliku binarnego.
* **Ograniczenia procesu nadrzędnego**: Ograniczenia dotyczące **procesu nadrzędnego** (na przykład **`launchd`** uruchamiającego usługę XP)
* **Ograniczenia odpowiedzialności**: Ograniczenia dotyczące **procesu wywołującego usługę** w komunikacji XPC
* **Ograniczenia ładowania bibliotek**: Użyj ograniczeń ładowania bibliotek, aby selektywnie opisać kod, który może być ładowany

Kiedy proces próbuje uruchomić inny proces - poprzez wywołanie `execve(_:_:_:)` lub `posix_spawn(_:_:_:_:_:_:)` - system operacyjny sprawdza, czy **plik wykonywalny** spełnia **własne ograniczenia**. Sprawdza również, czy **plik wykonywalny procesu nadrzędnego** spełnia ograniczenia **rodzica pliku wykonywalnego**, oraz czy **plik wykonywalny procesu odpowiedzialnego** spełnia ograniczenia **pliku wykonywalnego odpowiedzialnego procesu**. Jeśli któreś z tych ograniczeń uruchamiania nie zostanie spełnione, system operacyjny nie uruchamia programu.

Jeśli podczas ładowania biblioteki jakakolwiek część **ograniczenia biblioteki nie jest prawdziwa**, twój proces **nie ładuje** biblioteki.

## Kategorie LC

LC składa się z **faktów** i **operacji logicznych** (and, or...), które łączą fakty.

[**Fakty, które może wykorzystać LC, są udokumentowane**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Na przykład:

* is-init-proc: Wartość logiczna wskazująca, czy plik wykonywalny musi być procesem inicjalizacji systemu operacyjnego (`launchd`).
* is-sip-protected: Wartość logiczna wskazująca, czy plik wykonywalny musi być plikiem chronionym przez System Integrity Protection (SIP).
* `on-authorized-authapfs-volume:` Wartość logiczna wskazująca, czy system operacyjny załadował plik wykonywalny z autoryzowanego, uwierzytelnionego woluminu APFS.
* `on-authorized-authapfs-volume`: Wartość logiczna wskazująca, czy system operacyjny załadował plik wykonywalny z autoryzowanego, uwierzytelnionego woluminu APFS.
* Wolumin Cryptexes
* `on-system-volume:` Wartość logiczna wskazująca, czy system operacyjny załadował plik wykonywalny z obecnie uruchomionego woluminu systemowego.
* Wewnątrz /System...
* ...

Gdy binarny plik Apple jest podpisany, **przypisuje go do kategorii LC** w **pamięci podręcznej zaufania**.

* **Kategorie LC dla iOS 16** zostały [**odwrócone i udokumentowane tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Obecne **kategorie LC (macOS 14** - Somona) zostały odwrócone, a ich [**opisy można znaleźć tutaj**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Na przykład Kategoria 1 to:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Musi znajdować się w woluminie Systemowym lub Cryptexes.
* `launch-type == 1`: Musi być usługą systemową (plist w LaunchDaemons).
* `validation-category == 1`: Wykonywalny plik systemowy.
* `is-init-proc`: Launchd

### Odwracanie kategorii LC

Więcej informacji [**o tym tutaj**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), ale w skrócie, są one zdefiniowane w **AMFI (AppleMobileFileIntegrity)**, więc musisz pobrać zestaw narzędzi do rozwoju jądra, aby uzyskać **KEXT**. Symbole zaczynające się od **`kConstraintCategory`** są tymi **interesującymi**. Wyodrębniając je, otrzymasz zakodowany strumień DER (ASN.1), który będziesz musiał zdekodować za pomocą [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) lub biblioteki python-asn1 i jej skryptu `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), co da ci bardziej zrozumiały ciąg znaków.

## Ograniczenia środowiska

To są ustawione Ograniczenia Uruchamiania skonfigurowane w **aplikacjach innych firm**. Deweloper może wybrać **fakty** i **operandy logiczne**, które będą używane w jego aplikacji do ograniczenia dostępu do niej.

Możliwe jest wyliczenie Ograniczeń Środowiska aplikacji za pomocą:
```bash
codesign -d -vvvv app.app
```
## Pamięć podręczna zaufania

W systemie **macOS** istnieje kilka pamięci podręcznych zaufania:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Natomiast w systemie iOS wygląda to tak: **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
W przypadku systemu macOS działającego na urządzeniach Apple Silicon, jeśli podpisany przez Apple plik binarny nie znajduje się w pamięci podręcznej zaufania, AMFI odmówi jego wczytania.
{% endhint %}

### Wyliczanie pamięci podręcznej zaufania

Poprzednie pliki pamięci podręcznej zaufania mają format **IMG4** i **IM4P**, przy czym IM4P to sekcja ładunku formatu IMG4.

Możesz użyć [**pyimg4**](https://github.com/m1stadev/PyIMG4), aby wyodrębnić ładunek baz danych:

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

(Inną opcją może być użycie narzędzia [**img4tool**](https://github.com/tihmstar/img4tool), które będzie działać nawet na M1, nawet jeśli wersja jest stara i dla x86\_64, jeśli zainstalujesz je w odpowiednich lokalizacjach).

Teraz możesz użyć narzędzia [**trustcache**](https://github.com/CRKatri/trustcache), aby uzyskać informacje w czytelnej formie:
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
Pamięć podręczna zaufania ma następującą strukturę, więc **kategoria LC to czwarta kolumna**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Następnie możesz użyć skryptu, takiego jak [**ten**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30), aby wyodrębnić dane.

Na podstawie tych danych możesz sprawdzić aplikacje o **wartości ograniczeń uruchamiania `0`**, które nie są ograniczone ([**sprawdź tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), co oznacza każda wartość).

## Zabezpieczenia przed atakami

Ograniczenia uruchamiania mogłyby złagodzić wiele starszych ataków, **zapewniając, że proces nie zostanie uruchomiony w nieoczekiwanych warunkach**: na przykład z nieoczekiwanych lokalizacji lub wywołany przez nieoczekiwany proces nadrzędny (jeśli tylko launchd powinien go uruchamiać).

Ponadto, ograniczenia uruchamiania również **łagodzą ataki obniżające wersję**.

Jednakże, **nie łagodzą powszechnych nadużyć XPC**, wstrzykiwania kodu **Electron** ani wstrzykiwania bibliotek **dylib bez weryfikacji biblioteki** (chyba że znane są identyfikatory zespołów, które mogą ładować biblioteki).

### Ochrona przed demonami XPC

W wydaniu Sonoma istotnym punktem jest **konfiguracja odpowiedzialności** usługi XPC demona. Usługa XPC jest odpowiedzialna za siebie, a nie za klienta łączącego się z nią. Jest to udokumentowane w raporcie zwrotnym FB13206884. Taka konfiguracja może wydawać się wadliwa, ponieważ umożliwia pewne interakcje z usługą XPC:

- **Uruchamianie usługi XPC**: Jeśli założyć, że jest to błąd, taka konfiguracja nie pozwala na uruchomienie usługi XPC za pomocą kodu atakującego.
- **Łączenie z aktywną usługą**: Jeśli usługa XPC jest już uruchomiona (może być aktywowana przez swoją pierwotną aplikację), nie ma żadnych barier dla połączenia z nią.

Choć wprowadzenie ograniczeń dla usługi XPC może być korzystne, **skracając okno potencjalnych ataków**, nie rozwiązuje to podstawowego problemu. Zapewnienie bezpieczeństwa usługi XPC wymaga przede wszystkim **efektywnej weryfikacji klienta łączącego się**. To jest jedyny sposób na wzmocnienie bezpieczeństwa usługi. Warto również zauważyć, że wspomniana konfiguracja odpowiedzialności jest obecnie funkcjonalna, co może nie być zgodne z zamierzonym projektem.

### Ochrona przed Electronem

Nawet jeśli wymagane jest, aby aplikacja była **otwierana przez LaunchService** (w ograniczeniach rodzica), można to osiągnąć za pomocą polecenia **`open`** (które może ustawiać zmienne środowiskowe) lub za pomocą interfejsu API **Launch Services** (gdzie można wskazać zmienne środowiskowe).

## Odwołania

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>
