# Pliki, Foldery, Binarki i Pamięć w macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Układ hierarchii plików

* **/Applications**: Zainstalowane aplikacje powinny znajdować się tutaj. Wszyscy użytkownicy będą miały do nich dostęp.
* **/bin**: Binarki wiersza poleceń
* **/cores**: Jeśli istnieje, służy do przechowywania zrzutów pamięci jądra
* **/dev**: Wszystko jest traktowane jako plik, więc tutaj można znaleźć urządzenia sprzętowe.
* **/etc**: Pliki konfiguracyjne
* **/Library**: Wiele podkatalogów i plików związanych z preferencjami, pamięci podręcznej i dziennikami można znaleźć tutaj. Istnieje folder Library w katalogu głównym i w katalogu każdego użytkownika.
* **/private**: Nieudokumentowane, ale wiele wymienionych folderów to dowiązania symboliczne do katalogu private.
* **/sbin**: Podstawowe binarki systemowe (związane z administracją)
* **/System**: Plik do uruchamiania OS X. Tutaj powinny znajdować się głównie pliki specyficzne dla Apple (nie firm trzecich).
* **/tmp**: Pliki są usuwane po 3 dniach (to miękie połączenie do /private/tmp)
* **/Users**: Katalog domowy użytkowników.
* **/usr**: Konfiguracje i binarki systemowe
* **/var**: Pliki dziennika
* **/Volumes**: Zamontowane dyski pojawią się tutaj.
* **/.vol**: Uruchomienie `stat a.txt` daje coś takiego jak `16777223 7545753 -rw-r--r-- 1 nazwaużytkownika grupa ...`, gdzie pierwsza liczba to numer identyfikacyjny woluminu, w którym znajduje się plik, a druga to numer i-węzła. Możesz uzyskać dostęp do zawartości tego pliku za pomocą /.vol/ z tymi informacjami, uruchamiając `cat /.vol/16777223/7545753`

### Foldery aplikacji

* **Aplikacje systemowe** znajdują się w `/System/Applications`
* **Zainstalowane** aplikacje zazwyczaj są instalowane w `/Applications` lub w `~/Applications`
* **Dane aplikacji** można znaleźć w `/Library/Application Support` dla aplikacji działających jako root i `~/Library/Application Support` dla aplikacji działających jako użytkownik.
* Aplikacje **sandboxed** są mapowane do folderu `~/Library/Containers`. Każda aplikacja ma folder o nazwie zgodnej z identyfikatorem pakietu aplikacji (`com.apple.Safari`).
* **Jądro** znajduje się w `/System/Library/Kernels/kernel`
* **Rozszerzenia jądra Apple** znajdują się w `/System/Library/Extensions`
* **Rozszerzenia jądra firm trzecich** są przechowywane w `/Library/Extensions`

### Pliki z Wrażliwymi Informacjami

macOS przechowuje informacje, takie jak hasła, w kilku miejscach:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Podatne instalatory pkg

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Rozszerzenia Specyficzne dla OS X

* **`.dmg`**: Pliki obrazów dysków Apple są bardzo częste dla instalatorów.
* **`.kext`**: Musi mieć określoną strukturę i jest to wersja OS X sterownika. (to jest paczka)
* **`.plist`**: Znany również jako lista właściwości, przechowuje informacje w formacie XML lub binarnym.
* Może być XML lub binarny. Binarne można odczytać za pomocą:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplikacje Apple, które mają strukturę katalogu (to jest paczka).
* **`.dylib`**: Biblioteki dynamiczne (podobne do plików DLL w systemie Windows)
* **`.pkg`**: Są takie same jak xar (format rozszerzalnego archiwum). Polecenie installer może być używane do instalacji zawartości tych plików.
* **`.DS_Store`**: Ten plik znajduje się w każdym katalogu, zapisuje atrybuty i dostosowania katalogu.
* **`.Spotlight-V100`**: Ten folder pojawia się w katalogu głównym każdego woluminu w systemie.
* **`.metadata_never_index`**: Jeśli ten plik znajduje się w głównym katalogu woluminu, Spotlight nie będzie indeksować tego woluminu.
* **`.noindex`**: Pliki i foldery z tym rozszerzeniem nie będą indeksowane przez Spotlight.

### Paczki macOS

Paczka to **katalog**, który **wygląda jak obiekt w Finderze** (przykładem paczki są pliki `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

W macOS (i iOS) wszystkie współdzielone biblioteki systemowe, takie jak frameworki i dyliby, są **łączone w pojedynczy plik**, zwany **dyld shared cache**. Poprawia to wydajność, ponieważ kod może być ładowany szybciej.

Podobnie jak dyld shared cache, jądro i rozszerzenia jądra również są kompilowane do pamięci podręcznej jądra, która jest ładowana podczas uruchamiania systemu.

Aby wyodrębnić biblioteki z pojedynczego pliku dylib shared cache, można było użyć binarnego narzędzia [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip), które obecnie może nie działać, ale można również użyć [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

W starszych wersjach możesz znaleźć **współdzielone dane podręczne** w **`/System/Library/dyld/`**.

W systemie iOS możesz je znaleźć w **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Należy zauważyć, że nawet jeśli narzędzie `dyld_shared_cache_util` nie działa, można przekazać **współdzielony plik dyld do Hoppera**, a Hopper będzie w stanie zidentyfikować wszystkie biblioteki i pozwolić na **wybór** tej, którą chcesz zbadać:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Specjalne uprawnienia plików

### Uprawnienia folderów

W **folderze**, **odczyt** pozwala na **wyświetlanie zawartości**, **zapis** pozwala na **usuwanie** i **zapisywanie** plików w nim, a **wykonanie** pozwala na **przechodzenie** przez katalog. Na przykład, użytkownik z **uprawnieniami do odczytu pliku** wewnątrz katalogu, w którym nie ma **uprawnienia do wykonania**, **nie będzie mógł odczytać** pliku.

### Modyfikatory flag

Istnieją pewne flagi, które można ustawić w plikach, które sprawią, że plik będzie zachowywał się inaczej. Możesz **sprawdzić flagi** plików wewnątrz katalogu za pomocą polecenia `ls -lO /ścieżka/do/katalogu`

* **`uchg`**: Znana jako flaga **uchange**, uniemożliwia **zmianę lub usunięcie** pliku. Aby ją ustawić, wykonaj: `chflags uchg plik.txt`
* Użytkownik root może **usunąć flagę** i zmodyfikować plik
* **`restricted`**: Ta flaga powoduje, że plik jest **chroniony przez SIP** (nie można dodać tej flagi do pliku).
* **`Sticky bit`**: Jeśli katalog ma ustawiony sticky bit, **tylko** właściciel katalogu lub root może **zmieniać nazwę lub usuwać** pliki. Zazwyczaj jest to ustawiane w katalogu /tmp, aby zwykli użytkownicy nie mogli usuwać ani przenosić plików innych użytkowników.

### **ACL plików**

ACL plików zawiera **ACE** (Access Control Entries), w których można przypisać bardziej **szczegółowe uprawnienia** różnym użytkownikom.

Można nadać **katalogowi** następujące uprawnienia: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
A plikowi: `read`, `write`, `append`, `execute`.

Gdy plik zawiera ACL, **znajdziesz znak "+" przy wyświetlaniu uprawnień, jak w**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Możesz **odczytać ACL** pliku za pomocą:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Poniżej znajduje się **spis wszystkich plików z ACL** (to jest baaardzo wolne):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Resource Forks | macOS ADS

To jest sposób na uzyskanie **Alternatywnych Strumieni Danych w systemach MacOS**. Możesz zapisać zawartość wewnątrz rozszerzonego atrybutu o nazwie **com.apple.ResourceFork** w pliku, zapisując go w **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Możesz **znaleźć wszystkie pliki zawierające ten rozszerzony atrybut** za pomocą:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Uniwersalne pliki binarne i** Format Mach-o

Binarki systemu Mac OS zazwyczaj są kompilowane jako **uniwersalne pliki binarne**. **Uniwersalny plik binarny** może **obsługiwać wiele architektur w tym samym pliku**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumpowanie pamięci macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Pliki kategorii ryzyka w systemie Mac OS

Katalog `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` to miejsce, gdzie przechowywane są informacje na temat **ryzyka związanego z różnymi rozszerzeniami plików**. Ten katalog kategoryzuje pliki na różne poziomy ryzyka, wpływając na to, w jaki sposób Safari obsługuje te pliki po pobraniu. Kategorie są następujące:

- **LSRiskCategorySafe**: Pliki w tej kategorii są uważane za **całkowicie bezpieczne**. Safari automatycznie otwiera te pliki po pobraniu.
- **LSRiskCategoryNeutral**: Te pliki nie wywołują żadnych ostrzeżeń i **nie są automatycznie otwierane** przez Safari.
- **LSRiskCategoryUnsafeExecutable**: Pliki w tej kategorii **wywołują ostrzeżenie**, wskazujące, że plik jest aplikacją. Jest to środek bezpieczeństwa mający na celu poinformowanie użytkownika.
- **LSRiskCategoryMayContainUnsafeExecutable**: Ta kategoria dotyczy plików, takich jak archiwa, które mogą zawierać plik wykonywalny. Safari **wywołuje ostrzeżenie**, chyba że może zweryfikować, że wszystkie zawartości są bezpieczne lub neutralne.

## Pliki dzienników

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Zawiera informacje o pobranych plikach, takie jak adres URL, z którego zostały pobrane.
* **`/var/log/system.log`**: Główny dziennik systemowy systemów OSX. com.apple.syslogd.plist jest odpowiedzialny za wykonywanie sysloggingu (możesz sprawdzić, czy jest wyłączony, szukając "com.apple.syslogd" w `launchctl list`.
* **`/private/var/log/asl/*.asl`**: To są dzienniki systemowe Apple, które mogą zawierać interesujące informacje.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Przechowuje informacje o ostatnio używanych plikach i aplikacjach za pośrednictwem "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Przechowuje elementy do uruchomienia podczas uruchamiania systemu.
* **`$HOME/Library/Logs/DiskUtility.log`**: Plik dziennika dla aplikacji DiskUtility (informacje o dyskach, w tym USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dane dotyczące punktów dostępu do sieci bezprzewodowej.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista dezaktywowanych demonów.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
