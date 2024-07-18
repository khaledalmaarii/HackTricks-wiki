# macOS Pliki, Foldery, Binaria i Pamięć

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Układ hierarchii plików

* **/Applications**: Zainstalowane aplikacje powinny być tutaj. Wszyscy użytkownicy będą miały do nich dostęp.
* **/bin**: Binaria wiersza poleceń
* **/cores**: Jeśli istnieje, jest używane do przechowywania zrzutów pamięci
* **/dev**: Wszystko jest traktowane jako plik, więc tutaj można zobaczyć urządzenia sprzętowe.
* **/etc**: Pliki konfiguracyjne
* **/Library**: Można tu znaleźć wiele podkatalogów i plików związanych z preferencjami, pamięci podręcznej i logami. Istnieje folder Library w głównym katalogu i w katalogu każdego użytkownika.
* **/private**: Nieudokumentowany, ale wiele wspomnianych folderów to łącza symboliczne do katalogu private.
* **/sbin**: Istotne binaria systemowe (związane z administracją)
* **/System**: Plik do uruchamiania OS X. Powinieneś tutaj znaleźć głównie pliki specyficzne dla Apple (nie firm trzecich).
* **/tmp**: Pliki są usuwane po 3 dniach (to miękkie łącze do /private/tmp)
* **/Users**: Katalog domowy użytkowników.
* **/usr**: Konfiguracje i binaria systemowe
* **/var**: Pliki dziennika
* **/Volumes**: Zamontowane dyski pojawią się tutaj.
* **/.vol**: Uruchamiając `stat a.txt` otrzymasz coś w rodzaju `16777223 7545753 -rw-r--r-- 1 nazwa_użytkownika wheel ...`, gdzie pierwsza liczba to numer id woluminu, w którym plik istnieje, a druga to numer i-węzła. Możesz uzyskać dostęp do zawartości tego pliku poprzez /.vol/ z tymi informacjami, uruchamiając `cat /.vol/16777223/7545753`

### Foldery Aplikacji

* **Aplikacje systemowe** znajdują się w `/System/Applications`
* **Zainstalowane** aplikacje zazwyczaj są instalowane w `/Applications` lub w `~/Applications`
* Dane aplikacji można znaleźć w `/Library/Application Support` dla aplikacji działających jako root oraz w `~/Library/Application Support` dla aplikacji działających jako użytkownik.
* Aplikacje **demona** firm trzecich, które **muszą działać jako root**, zazwyczaj znajdują się w `/Library/PrivilegedHelperTools/`
* **Aplikacje z piaskownicą** są mapowane do folderu `~/Library/Containers`. Każda aplikacja ma folder nazwany zgodnie z identyfikatorem pakietu aplikacji (`com.apple.Safari`).
* **Jądro** znajduje się w `/System/Library/Kernels/kernel`
* **Rozszerzenia jądra Apple'a** znajdują się w `/System/Library/Extensions`
* **Rozszerzenia jądra firm trzecich** są przechowywane w `/Library/Extensions`

### Pliki z Wrażliwymi Informacjami

macOS przechowuje informacje takie jak hasła w kilku miejscach:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Narażeni instalatorzy pkg

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Rozszerzenia Specyficzne dla OS X

* **`.dmg`**: Pliki obrazów dysków Apple są bardzo częste dla instalatorów.
* **`.kext`**: Musi przestrzegać określonej struktury i jest to wersja sterownika dla OS X. (jest to pakiet)
* **`.plist`**: Znany również jako lista właściwości, przechowuje informacje w formacie XML lub binarnym.
* Może być XML lub binarny. Binarny można odczytać za pomocą:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplikacje Apple'a, które podążają za strukturą katalogów (jest to pakiet).
* **`.dylib`**: Biblioteki dynamiczne (podobne do plików DLL w systemie Windows)
* **`.pkg`**: Są takie same jak xar (format archiwum rozszerzalny). Polecenie instalatora może być użyte do zainstalowania zawartości tych plików.
* **`.DS_Store`**: Ten plik znajduje się w każdym katalogu, zapisuje atrybuty i dostosowania katalogu.
* **`.Spotlight-V100`**: Ten folder pojawia się w głównym katalogu każdego woluminu w systemie.
* **`.metadata_never_index`**: Jeśli ten plik znajduje się w głównym katalogu woluminu, Spotlight nie zaindeksuje tego woluminu.
* **`.noindex`**: Pliki i foldery z tym rozszerzeniem nie będą indeksowane przez Spotlight.
* **`.sdef`**: Pliki w pakietach określające, w jaki sposób można wchodzić w interakcje z aplikacją za pomocą AppleScript.

### Pakiety macOS

Pakiet to **katalog**, który **wygląda jak obiekt w Finderze** (przykładem pakietu są pliki `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Bufor Bibliotek Współdzielonych Dyld (SLC)

Na macOS (i iOS) wszystkie systemowe biblioteki współdzielone, takie jak ramki i dyliby, są **łączone w pojedynczy plik**, zwany **buforem bibliotek współdzielonych dyld**. Poprawia to wydajność, ponieważ kod może być ładowany szybciej.

Znajduje się to w macOS w `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, a w starszych wersjach możesz znaleźć **bufor współdzielony** w **`/System/Library/dyld/`**.\
W iOS można je znaleźć w **`/System/Library/Caches/com.apple.dyld/`**.

Podobnie jak bufor bibliotek współdzielonych dyld, jądro i rozszerzenia jądra są również kompilowane do bufora jądra, który jest ładowany podczas uruchamiania systemu.

Aby wyodrębnić biblioteki z pojedynczego pliku bufora współdzielonych dylibów, można było użyć binarnego [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip), który obecnie może nie działać, ale można również użyć [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

{% hint style="success" %}
Zauważ, że nawet jeśli narzędzie `dyld_shared_cache_util` nie działa, możesz przekazać **wspólny binarny dyld do Hoppera** i Hopper będzie w stanie zidentyfikować wszystkie biblioteki i pozwolić Ci **wybrać, którą** chcesz zbadać:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Niektóre ekstraktory nie będą działać, ponieważ dylibs są wstępnie połączone z twardymi adresami, dlatego mogą skakać do nieznanych adresów.

{% hint style="success" %}
Możliwe jest również pobranie Udostępnionego Cache Bibliotek innych urządzeń \*OS w systemie macOS za pomocą emulatora w Xcode. Zostaną one pobrane do: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, np.: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### Mapowanie SLC

**`dyld`** używa wywołania systemowego **`shared_region_check_np`** aby sprawdzić, czy SLC został zmapowany (co zwraca adres) oraz **`shared_region_map_and_slide_np`** aby zmapować SLC.

Zauważ, że nawet jeśli SLC jest przesuwany przy pierwszym użyciu, wszystkie **procesy** używają **tej samej kopii**, co **eliminuje ochronę ASLR**, jeśli atakujący był w stanie uruchomić procesy w systemie. Faktycznie było to wykorzystywane w przeszłości i naprawione za pomocą wspólnego regionu pagera.

Pule gałęzi to małe Mach-O dylibs, które tworzą małe przestrzenie między mapowaniami obrazów, co uniemożliwia interweniowanie w funkcje.

### Nadpisywanie SLC

Korzystając z zmiennych środowiskowych:

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> To pozwoli na załadowanie nowego wspólnego cache bibliotek
* **`DYLD_SHARED_CACHE_DIR=avoid`** i ręczne zastąpienie bibliotek dowiązaniami symbolicznymi do cache bibliotek z rzeczywistymi (będziesz musiał je wyodrębnić)

## Specjalne Uprawnienia Plików

### Uprawnienia folderów

W **folderze**, **odczyt** pozwala na **wylistowanie go**, **zapis** pozwala na **usunięcie** i **zapis** plików w nim, a **wykonanie** pozwala na **przejście** przez katalog. Na przykład użytkownik z **uprawnieniem do odczytu pliku** wewnątrz katalogu, w którym nie ma uprawnienia **do wykonania**, **nie będzie w stanie odczytać** pliku.

### Modyfikatory flag

Istnieją pewne flagi, które można ustawić w plikach, które sprawią, że plik będzie zachowywał się inaczej. Możesz **sprawdzić flagi** plików w katalogu za pomocą `ls -lO /ścieżka/do/katalogu`

* **`uchg`**: Znana jako flaga **uchange** uniemożliwi **dokonanie jakiejkolwiek zmiany** lub usunięcie **pliku**. Aby ją ustawić, wykonaj: `chflags uchg plik.txt`
* Użytkownik root może **usunąć flagę** i zmodyfikować plik
* **`restricted`**: Ta flaga sprawia, że plik jest **chroniony przez SIP** (nie można dodać tej flagi do pliku).
* **`Sticky bit`**: Jeśli katalog ma ustawiony bit sticky, **tylko** właściciel katalogów lub root mogą zmienić nazwę lub usunąć pliki. Zazwyczaj jest to ustawione w katalogu /tmp, aby zapobiec zwykłym użytkownikom usuwania lub przenoszenia plików innych użytkowników.

Wszystkie flagi można znaleźć w pliku `sys/stat.h` (znajdź go za pomocą `mdfind stat.h | grep stat.h`) i są:

* `UF_SETTABLE` 0x0000ffff: Maska flag, które można zmienić właścicielowi.
* `UF_NODUMP` 0x00000001: Nie zapisuj pliku.
* `UF_IMMUTABLE` 0x00000002: Plik nie może być zmieniany.
* `UF_APPEND` 0x00000004: Zapisywanie do pliku może być tylko dodawane.
* `UF_OPAQUE` 0x00000008: Katalog jest nieprzezroczysty w stosunku do unii.
* `UF_COMPRESSED` 0x00000020: Plik jest skompresowany (niektóre systemy plików).
* `UF_TRACKED` 0x00000040: Brak powiadomień o usuwaniu/zmianie nazwy dla plików z tym ustawieniem.
* `UF_DATAVAULT` 0x00000080: Wymagane uprawnienie do odczytu i zapisu.
* `UF_HIDDEN` 0x00008000: Wskazuje, że ten element nie powinien być wyświetlany w interfejsie GUI.
* `SF_SUPPORTED` 0x009f0000: Maska flag obsługiwanych przez superużytkownika.
* `SF_SETTABLE` 0x3fff0000: Maska flag zmienialnych przez superużytkownika.
* `SF_SYNTHETIC` 0xc0000000: Maska flag systemowych tylko do odczytu.
* `SF_ARCHIVED` 0x00010000: Plik jest zarchiwizowany.
* `SF_IMMUTABLE` 0x00020000: Plik nie może być zmieniany.
* `SF_APPEND` 0x00040000: Zapisywanie do pliku może być tylko dodawane.
* `SF_RESTRICTED` 0x00080000: Wymagane uprawnienie do zapisu.
* `SF_NOUNLINK` 0x00100000: Element nie może być usunięty, zmieniony lub zamontowany.
* `SF_FIRMLINK` 0x00800000: Plik jest łączem stałym.
* `SF_DATALESS` 0x40000000: Plik jest obiektem bez danych.

### **ACL plików**

ACL plików zawiera **ACE** (Access Control Entries), gdzie można przypisać różne **bardziej szczegółowe uprawnienia** różnym użytkownikom.

Możliwe jest przyznanie **katalogowi** tych uprawnień: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
A plikowi: `read`, `write`, `append`, `execute`.

Gdy plik zawiera ACL, zobaczysz **"+" podczas listowania uprawnień jak w**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Możesz **odczytać ACL-e** pliku za pomocą:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Możesz znaleźć **wszystkie pliki z ACL** za pomocą (to jest baaardzo wolne):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Rozszerzone atrybuty

Rozszerzone atrybuty posiadają nazwę i wartość oraz można je zobaczyć za pomocą `ls -@` i manipulować nimi za pomocą polecenia `xattr`. Niektóre wspólne rozszerzone atrybuty to:

- `com.apple.resourceFork`: Zgodność z widłami zasobów. Widoczne także jako `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Mechanizm kwarantanny Gatekeepera (III/6)
- `metadata:*`: MacOS: różne metadane, takie jak `_backup_excludeItem` lub `kMD*`
- `com.apple.lastuseddate` (#PS): Data ostatniego użycia pliku
- `com.apple.FinderInfo`: MacOS: Informacje Findera (np. kolorowe tagi)
- `com.apple.TextEncoding`: Określa kodowanie tekstu plików tekstowych ASCII
- `com.apple.logd.metadata`: Używane przez logd w plikach w `/var/db/diagnostics`
- `com.apple.genstore.*`: Przechowywanie generacyjne (`/.DocumentRevisions-V100` w głównym katalogu systemu plików)
- `com.apple.rootless`: MacOS: Używane przez System Integrity Protection do oznaczania pliku (III/10)
- `com.apple.uuidb.boot-uuid`: Oznaczenia logd epok uruchomień z unikalnym UUID
- `com.apple.decmpfs`: MacOS: Transparentna kompresja plików (II/7)
- `com.apple.cprotect`: \*OS: Dane szyfrowania plików (III/11)
- `com.apple.installd.*`: \*OS: Metadane używane przez installd, np. `installType`, `uniqueInstallID`

### Widły zasobów | macOS ADS

To sposób na uzyskanie **Alternatywnych Strumieni Danych w systemach MacOS**. Możesz zapisać zawartość wewnątrz rozszerzonego atrybutu o nazwie **com.apple.ResourceFork** w pliku, zapisując go w **file/..namedfork/rsrc**.
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

### decmpfs

Rozszerzony atrybut `com.apple.decmpfs` wskazuje, że plik jest przechowywany zaszyfrowany, `ls -l` będzie raportować **rozmiar 0** a skompresowane dane znajdują się w tym atrybucie. Za każdym razem, gdy plik jest dostępny, zostanie zdeszyfrowany w pamięci.

Ten atrybut można zobaczyć za pomocą `ls -lO` oznaczonego jako skompresowany, ponieważ skompresowane pliki są również oznaczone flagą `UF_COMPRESSED`. Jeśli skompresowany plik zostanie usunięty z tą flagą za pomocą `chflags nocompressed </ścieżka/do/pliku>`, system nie będzie wiedział, że plik był skompresowany i dlatego nie będzie w stanie go zdekompresować i uzyskać dostępu do danych (będzie myślał, że jest pusty).

Narzędzie afscexpand może być użyte do wymuszenia dekompresji pliku.

## **Uniwersalne binarne &** Format Mach-o

Binarki systemu Mac OS zazwyczaj są kompilowane jako **uniwersalne binarne**. **Uniwersalny binarny** może **obsługiwać wiele architektur w tym samym pliku**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Pamięć procesu macOS

## Zrzucanie pamięci macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Pliki kategorii ryzyka w systemie Mac OS

Katalog `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` to miejsce, gdzie przechowywane są informacje o **ryzyku związanym z różnymi rozszerzeniami plików**. Ten katalog kategoryzuje pliki na różne poziomy ryzyka, wpływając na to, w jaki sposób Safari traktuje te pliki po pobraniu. Kategorie to:

* **LSRiskCategorySafe**: Pliki w tej kategorii są uważane za **całkowicie bezpieczne**. Safari automatycznie otworzy te pliki po pobraniu.
* **LSRiskCategoryNeutral**: Te pliki nie wyświetlają żadnych ostrzeżeń i nie są **automatycznie otwierane** przez Safari.
* **LSRiskCategoryUnsafeExecutable**: Pliki w tej kategorii **wywołują ostrzeżenie**, wskazując, że plik jest aplikacją. Jest to środek bezpieczeństwa mający na celu poinformowanie użytkownika.
* **LSRiskCategoryMayContainUnsafeExecutable**: Ta kategoria jest przeznaczona dla plików, takich jak archiwa, które mogą zawierać plik wykonywalny. Safari **wywoła ostrzeżenie**, chyba że może zweryfikować, że wszystkie zawartości są bezpieczne lub neutralne.

## Pliki dzienników

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Zawiera informacje o pobranych plikach, takie jak adres URL, z którego zostały pobrane.
* **`/var/log/system.log`**: Główny dziennik systemów OSX. com.apple.syslogd.plist jest odpowiedzialny za wykonywanie sysloggingu (możesz sprawdzić, czy jest wyłączony, szukając "com.apple.syslogd" w `launchctl list`.
* **`/private/var/log/asl/*.asl`**: To Apple System Logs, które mogą zawierać interesujące informacje.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Przechowuje niedawno odwiedzane pliki i aplikacje za pośrednictwem "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Przechowuje elementy do uruchomienia po uruchomieniu systemu.
* **`$HOME/Library/Logs/DiskUtility.log`**: Plik dziennika dla aplikacji DiskUtility (informacje o dyskach, w tym USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dane o punktach dostępu bezprzewodowego.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista dezaktywowanych demonów.

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępnij sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
