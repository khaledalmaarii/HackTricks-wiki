# macOS Library Injection

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

{% hint style="danger" %}
Kod **dyld jest open source** i można go znaleźć pod adresem [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) i można go pobrać jako tar, używając **URL takiego jak** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Proces Dyld**

Zobacz, jak Dyld ładuje biblioteki wewnątrz binariów w:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

To jest jak [**LD\_PRELOAD na Linuxie**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Umożliwia wskazanie procesu, który ma być uruchomiony, aby załadować konkretną bibliotekę z określonej ścieżki (jeśli zmienna env jest włączona).

Ta technika może być również **używana jako technika ASEP**, ponieważ każda zainstalowana aplikacja ma plist o nazwie "Info.plist", która pozwala na **przypisanie zmiennych środowiskowych** za pomocą klucza o nazwie `LSEnvironmental`.

{% hint style="info" %}
Od 2012 roku **Apple drastycznie ograniczyło moc** **`DYLD_INSERT_LIBRARIES`**.

Przejdź do kodu i **sprawdź `src/dyld.cpp`**. W funkcji **`pruneEnvironmentVariables`** możesz zobaczyć, że **`DYLD_*`** zmienne są usuwane.

W funkcji **`processRestricted`** ustalana jest przyczyna ograniczenia. Sprawdzając ten kod, możesz zobaczyć, że przyczyny to:

* Binarne jest `setuid/setgid`
* Istnienie sekcji `__RESTRICT/__restrict` w binarnym macho.
* Oprogramowanie ma uprawnienia (wzmocniony czas działania) bez uprawnienia [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Sprawdź **uprawnienia** binarnego za pomocą: `codesign -dv --entitlements :- </path/to/bin>`

W bardziej aktualnych wersjach możesz znaleźć tę logikę w drugiej części funkcji **`configureProcessRestrictions`.** Jednak to, co jest wykonywane w nowszych wersjach, to **sprawdzenia na początku funkcji** (możesz usunąć ify związane z iOS lub symulacją, ponieważ te nie będą używane w macOS).
{% endhint %}

### Walidacja Bibliotek

Nawet jeśli binarny pozwala na użycie zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`**, jeśli binarny sprawdza podpis biblioteki do załadowania, nie załaduje niestandardowej.

Aby załadować niestandardową bibliotekę, binarny musi mieć **jedno z następujących uprawnień**:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

lub binarny **nie powinien** mieć **flagi wzmocnionego czasu działania** ani **flagi walidacji bibliotek**.

Możesz sprawdzić, czy binarny ma **wzmocniony czas działania** za pomocą `codesign --display --verbose <bin>`, sprawdzając flagę runtime w **`CodeDirectory`** jak: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Możesz również załadować bibliotekę, jeśli jest **podpisana tym samym certyfikatem co binarny**.

Znajdź przykład, jak (nadużyć) tego i sprawdź ograniczenia w:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Hijacking

{% hint style="danger" %}
Pamiętaj, że **wcześniejsze ograniczenia walidacji bibliotek również mają zastosowanie** do przeprowadzania ataków Dylib hijacking.
{% endhint %}

Podobnie jak w Windows, w MacOS możesz również **przechwytywać dyliby**, aby sprawić, że **aplikacje** **wykonają** **dowolny** **kod** (właściwie, z konta zwykłego użytkownika może to nie być możliwe, ponieważ możesz potrzebować zgody TCC, aby pisać wewnątrz pakietu `.app` i przechwycić bibliotekę).\
Jednak sposób, w jaki **aplikacje MacOS** **ładują** biblioteki, jest **bardziej ograniczony** niż w Windows. Oznacza to, że **twórcy złośliwego oprogramowania** mogą nadal używać tej techniki do **ukrycia**, ale prawdopodobieństwo, że będą mogli **nadużyć tego do eskalacji uprawnień, jest znacznie niższe**.

Przede wszystkim, jest **bardziej powszechne**, że **binarne MacOS wskazują pełną ścieżkę** do bibliotek do załadowania. Po drugie, **MacOS nigdy nie przeszukuje** folderów **$PATH** w poszukiwaniu bibliotek.

**Główna** część **kodu** związana z tą funkcjonalnością znajduje się w **`ImageLoader::recursiveLoadLibraries`** w `ImageLoader.cpp`.

Istnieją **4 różne polecenia nagłówkowe**, które binarny macho może użyć do załadowania bibliotek:

* **`LC_LOAD_DYLIB`** to standardowe polecenie do ładowania dylibu.
* **`LC_LOAD_WEAK_DYLIB`** działa jak poprzednie, ale jeśli dylib nie zostanie znaleziony, wykonanie kontynuuje bez żadnego błędu.
* **`LC_REEXPORT_DYLIB`** polecenie proxy (lub re-eksportuje) symbole z innej biblioteki.
* **`LC_LOAD_UPWARD_DYLIB`** polecenie jest używane, gdy dwie biblioteki zależą od siebie (nazywa się to _zależnością w górę_).

Jednak istnieją **2 typy przechwytywania dylib**:

* **Brakujące słabo powiązane biblioteki**: Oznacza to, że aplikacja spróbuje załadować bibliotekę, która nie istnieje skonfigurowana z **LC\_LOAD\_WEAK\_DYLIB**. Następnie, **jeśli atakujący umieści dylib tam, gdzie jest oczekiwany, zostanie załadowany**.
* Fakt, że link jest "słaby", oznacza, że aplikacja będzie kontynuować działanie, nawet jeśli biblioteka nie zostanie znaleziona.
* **Kod związany** z tym znajduje się w funkcji `ImageLoaderMachO::doGetDependentLibraries` w `ImageLoaderMachO.cpp`, gdzie `lib->required` jest tylko `false`, gdy `LC_LOAD_WEAK_DYLIB` jest prawdziwe.
* **Znajdź słabo powiązane biblioteki** w binarnych za pomocą (masz później przykład, jak tworzyć biblioteki do przechwytywania):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Skonfigurowane z @rpath**: Binarne Mach-O mogą mieć polecenia **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na podstawie **wartości** tych poleceń, **biblioteki** będą **ładowane** z **różnych katalogów**.
* **`LC_RPATH`** zawiera ścieżki do niektórych folderów używanych do ładowania bibliotek przez binarny.
* **`LC_LOAD_DYLIB`** zawiera ścieżkę do konkretnych bibliotek do załadowania. Te ścieżki mogą zawierać **`@rpath`**, które zostanie **zastąpione** wartościami w **`LC_RPATH`**. Jeśli w **`LC_RPATH`** znajduje się kilka ścieżek, każda z nich będzie używana do wyszukiwania biblioteki do załadowania. Przykład:
* Jeśli **`LC_LOAD_DYLIB`** zawiera `@rpath/library.dylib`, a **`LC_RPATH`** zawiera `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`. Oba foldery będą używane do ładowania `library.dylib`**.** Jeśli biblioteka nie istnieje w `[...]/v1/`, a atakujący mógłby ją tam umieścić, aby przechwycić ładowanie biblioteki w `[...]/v2/`, ponieważ kolejność ścieżek w **`LC_LOAD_DYLIB`** jest przestrzegana.
* **Znajdź ścieżki rpath i biblioteki** w binarnych za pomocą: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: To **ścieżka** do katalogu zawierającego **główny plik wykonywalny**.

**`@loader_path`**: To **ścieżka** do **katalogu** zawierającego **binarny Mach-O**, który zawiera polecenie ładowania.

* Gdy jest używane w pliku wykonywalnym, **`@loader_path`** jest w zasadzie **tym samym** co **`@executable_path`**.
* Gdy jest używane w **dylib**, **`@loader_path`** daje **ścieżkę** do **dylib**.
{% endhint %}

Sposób na **escalację uprawnień** nadużywając tej funkcjonalności byłby w rzadkim przypadku, gdy **aplikacja** uruchamiana **przez** **root** **szuka** jakiejś **biblioteki w jakimś folderze, w którym atakujący ma uprawnienia do zapisu.**

{% hint style="success" %}
Fajny **skaner** do znajdowania **brakujących bibliotek** w aplikacjach to [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) lub [**wersja CLI**](https://github.com/pandazheng/DylibHijack).\
Fajny **raport z technicznymi szczegółami** na temat tej techniki można znaleźć [**tutaj**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Przykład**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Pamiętaj, że **wcześniejsze ograniczenia walidacji bibliotek również mają zastosowanie** do przeprowadzania ataków Dlopen hijacking.
{% endhint %}

Z **`man dlopen`**:

* Gdy ścieżka **nie zawiera znaku ukośnika** (tj. jest tylko nazwą liścia), **dlopen() będzie szukać**. Jeśli **`$DYLD_LIBRARY_PATH`** był ustawiony przy uruchomieniu, dyld najpierw **spojrzy w tym katalogu**. Następnie, jeśli plik mach-o wywołujący lub główny plik wykonywalny określają **`LC_RPATH`**, dyld **spojrzy w tych** katalogach. Następnie, jeśli proces jest **nieograniczony**, dyld będzie szukać w **bieżącym katalogu roboczym**. Na koniec, dla starych binarnych, dyld spróbuje kilku alternatyw. Jeśli **`$DYLD_FALLBACK_LIBRARY_PATH`** był ustawiony przy uruchomieniu, dyld będzie szukać w **tych katalogach**, w przeciwnym razie dyld spojrzy w **`/usr/local/lib/`** (jeśli proces jest nieograniczony), a następnie w **`/usr/lib/`** (te informacje zostały wzięte z **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(jeśli nieograniczony)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (jeśli nieograniczony)
6. `/usr/lib/`

{% hint style="danger" %}
Jeśli nie ma ukośników w nazwie, istnieją 2 sposoby na przechwycenie:

* Jeśli jakiekolwiek **`LC_RPATH`** jest **zapisywalne** (ale podpis jest sprawdzany, więc do tego potrzebujesz również, aby binarny był nieograniczony)
* Jeśli binarny jest **nieograniczony**, a następnie możliwe jest załadowanie czegoś z CWD (lub nadużywając jednej z wymienionych zmiennych env)
{% endhint %}

* Gdy ścieżka **wygląda jak ścieżka frameworku** (np. `/stuff/foo.framework/foo`), jeśli **`$DYLD_FRAMEWORK_PATH`** był ustawiony przy uruchomieniu, dyld najpierw spojrzy w tym katalogu w poszukiwaniu **częściowej ścieżki frameworku** (np. `foo.framework/foo`). Następnie dyld spróbuje **podanej ścieżki tak, jak jest** (używając bieżącego katalogu roboczego dla ścieżek względnych). Na koniec, dla starych binarnych, dyld spróbuje kilku alternatyw. Jeśli **`$DYLD_FALLBACK_FRAMEWORK_PATH`** był ustawiony przy uruchomieniu, dyld będzie szukać w tych katalogach. W przeciwnym razie, będzie szukać **`/Library/Frameworks`** (na macOS, jeśli proces jest nieograniczony), a następnie **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. podana ścieżka (używając bieżącego katalogu roboczego dla ścieżek względnych, jeśli nieograniczony)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (jeśli nieograniczony)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Jeśli ścieżka frameworku, sposób na jej przechwycenie byłby:

* Jeśli proces jest **nieograniczony**, nadużywając **względnej ścieżki z CWD** wymienionych zmiennych env (nawet jeśli nie jest to powiedziane w dokumentacji, jeśli proces jest ograniczony, zmienne DYLD\_\* są usuwane)
{% endhint %}

* Gdy ścieżka **zawiera ukośnik, ale nie jest ścieżką frameworku** (tj. pełną ścieżką lub częściową ścieżką do dylibu), dlopen() najpierw sprawdza (jeśli ustawione) w **`$DYLD_LIBRARY_PATH`** (z częścią liścia z ścieżki). Następnie dyld **próbuje podaną ścieżkę** (używając bieżącego katalogu roboczego dla ścieżek względnych (ale tylko dla nieograniczonych procesów)). Na koniec, dla starszych binarnych, dyld spróbuje alternatyw. Jeśli **`$DYLD_FALLBACK_LIBRARY_PATH`** był ustawiony przy uruchomieniu, dyld będzie szukać w tych katalogach, w przeciwnym razie dyld spojrzy w **`/usr/local/lib/`** (jeśli proces jest nieograniczony), a następnie w **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. podana ścieżka (używając bieżącego katalogu roboczego dla ścieżek względnych, jeśli nieograniczony)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (jeśli nieograniczony)
5. `/usr/lib/`

{% hint style="danger" %}
Jeśli w nazwie są ukośniki i nie jest to framework, sposób na przechwycenie to:

* Jeśli binarny jest **nieograniczony**, a następnie możliwe jest załadowanie czegoś z CWD lub `/usr/local/lib` (lub nadużywając jednej z wymienionych zmiennych env)
{% endhint %}

{% hint style="info" %}
Uwaga: Nie ma **plików konfiguracyjnych, aby **kontrolować wyszukiwanie dlopen**.

Uwaga: Jeśli główny plik wykonywalny jest **set\[ug]id binarny lub podpisany z uprawnieniami**, to **wszystkie zmienne środowiskowe są ignorowane**, a tylko pełna ścieżka może być używana ([sprawdź ograniczenia DYLD\_INSERT\_LIBRARIES](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) dla bardziej szczegółowych informacji)

Uwaga: Platformy Apple używają "uniwersalnych" plików do łączenia bibliotek 32-bitowych i 64-bitowych. Oznacza to, że nie ma **osobnych ścieżek wyszukiwania dla 32-bitowych i 64-bitowych**.

Uwaga: Na platformach Apple większość dylibów systemowych jest **połączona w pamięci podręcznej dyld** i nie istnieje na dysku. Dlatego wywołanie **`stat()`** w celu sprawdzenia, czy dylib systemowy istnieje, **nie zadziała**. Jednak **`dlopen_preflight()`** używa tych samych kroków co **`dlopen()`**, aby znaleźć kompatybilny plik mach-o.
{% endhint %}

**Sprawdź ścieżki**

Sprawdźmy wszystkie opcje za pomocą następującego kodu:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Jeśli skompilujesz i uruchomisz, zobaczysz **gdzie każda biblioteka była bezskutecznie poszukiwana**. Możesz również **filtrować logi FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Jeśli **uprzywilejowany binarny/aplikacja** (jak SUID lub jakiś binarny z potężnymi uprawnieniami) **ładował bibliotekę z relatywną ścieżką** (na przykład używając `@executable_path` lub `@loader_path`) i ma **wyłączoną walidację bibliotek**, może być możliwe przeniesienie binarnego do lokalizacji, w której atakujący mógłby **zmodyfikować ładowaną bibliotekę z relatywną ścieżką**, i wykorzystać to do wstrzyknięcia kodu do procesu.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

W pliku `dyld-dyld-832.7.1/src/dyld2.cpp` można znaleźć funkcję **`pruneEnvironmentVariables`**, która usunie każdą zmienną środowiskową, która **zaczyna się od `DYLD_`** i **`LD_LIBRARY_PATH=`**.

Ustawi również na **null** konkretnie zmienne środowiskowe **`DYLD_FALLBACK_FRAMEWORK_PATH`** i **`DYLD_FALLBACK_LIBRARY_PATH`** dla **suid** i **sgid** binarnych.

Funkcja ta jest wywoływana z funkcji **`_main`** tego samego pliku, jeśli celuje w OSX w ten sposób:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
i te flagi boolean są ustawione w tym samym pliku w kodzie:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Które zasadniczo oznacza, że jeśli binarka jest **suid** lub **sgid**, lub ma segment **RESTRICT** w nagłówkach, lub została podpisana flagą **CS\_RESTRICT**, to **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** jest prawdziwe, a zmienne środowiskowe są usuwane.

Zauważ, że jeśli CS\_REQUIRE\_LV jest prawdziwe, to zmienne nie będą usuwane, ale walidacja biblioteki sprawdzi, czy używają tej samej certyfikatu co oryginalna binarka.

## Sprawdź Ograniczenia

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Sekcja `__RESTRICT` z segmentem `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Wzmocniony czas działania

Utwórz nowy certyfikat w Pęku kluczy i użyj go do podpisania binarnego: 

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Zauważ, że nawet jeśli istnieją binaria podpisane flagami **`0x0(none)`**, mogą one dynamicznie uzyskać flagę **`CS_RESTRICT`** podczas wykonywania, a zatem ta technika nie zadziała w ich przypadku.

Możesz sprawdzić, czy proces ma tę flagę za pomocą (pobierz [**csops tutaj**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
i sprawdź, czy flaga 0x800 jest włączona.  
{% endhint %}

## Odniesienia

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)  
* [**\*OS Internals, Volume I: User Mode. Autor: Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)  

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)  

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!  
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**  
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.  

</details>  
{% endhint %}
