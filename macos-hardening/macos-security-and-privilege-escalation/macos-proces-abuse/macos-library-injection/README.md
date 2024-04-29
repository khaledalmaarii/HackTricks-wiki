# Wstrzykiwanie biblioteki macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

{% hint style="danger" %}
Kod **dyld jest otwarto źródłowy** i można go znaleźć pod adresem [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) oraz pobrać jako archiwum tar za pomocą **URL, takiego jak** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Proces Dyld**

Zobacz, jak Dyld ładuje biblioteki wewnątrz binarnych plików w:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

To jest jak [**LD\_PRELOAD na Linuxie**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Pozwala wskazać proces, który ma zostać uruchomiony, aby załadować określoną bibliotekę z ścieżki (jeśli zmienna środowiskowa jest włączona).

Ta technika może być również **używana jako technika ASEP**, ponieważ każda zainstalowana aplikacja ma plik plist o nazwie "Info.plist", który pozwala na **przypisanie zmiennych środowiskowych** za pomocą klucza o nazwie `LSEnvironmental`.

{% hint style="info" %}
Od 2012 roku **Apple drastycznie ograniczył moc** **`DYLD_INSERT_LIBRARIES`**.

Przejdź do kodu i **sprawdź `src/dyld.cpp`**. W funkcji **`pruneEnvironmentVariables`** można zobaczyć, że zmienne **`DYLD_*`** są usuwane.

W funkcji **`processRestricted`** ustawiono powód ograniczenia. Sprawdzając ten kod, można zobaczyć, że powody to:

* Binarne są `setuid/setgid`
* Istnienie sekcji `__RESTRICT/__restrict` w binarnym pliku macho.
* Oprogramowanie ma uprawnienia (zmodyfikowany czas wykonania) bez uprawnienia [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Sprawdź **uprawnienia** binarne za pomocą: `codesign -dv --entitlements :- </ścieżka/do/bin>`

W bardziej zaktualizowanych wersjach tę logikę można znaleźć w drugiej części funkcji **`configureProcessRestrictions`.** Jednakże, to co jest wykonywane w nowszych wersjach to **początkowe sprawdzenia funkcji** (możesz usunąć warunki związane z iOS lub symulacją, ponieważ nie będą one używane w macOS.
{% endhint %}

### Walidacja biblioteki

Nawet jeśli binarny plik pozwala na użycie **`DYLD_INSERT_LIBRARIES`** zmiennej środowiskowej, jeśli binarny plik sprawdza podpis biblioteki, aby ją załadować, nie załaduje niestandardowej biblioteki.

Aby załadować niestandardową bibliotekę, binarny plik musi mieć **jedno z następujących uprawnień**:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

lub binarny plik **nie powinien** mieć flagi **zmodyfikowanego czasu wykonania** ani flagi **walidacji biblioteki**.

Możesz sprawdzić, czy binarny plik ma **zmodyfikowany czas wykonania** za pomocą `codesign --display --verbose <bin>` sprawdzając flagę czasu wykonania w **`CodeDirectory`** jak: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Możesz również załadować bibliotekę, jeśli jest **podpisana tym samym certyfikatem co binarny**.

Znajdź przykład, jak (nadużyć) wykorzystać to i sprawdź ograniczenia w:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Przechwytywanie Dylib

{% hint style="danger" %}
Pamiętaj, że **wcześniejsze ograniczenia walidacji biblioteki** również mają zastosowanie do przeprowadzania ataków przechwytywania Dylib.
{% endhint %}

Tak jak w systemie Windows, w systemie MacOS również można **przechwycić dyliby**, aby sprawić, że **aplikacje wykonają** **arbitralny** **kod** (no cóż, tak naprawdę od zwykłego użytkownika to nie byłoby możliwe, ponieważ mogą być wymagane uprawnienia TCC do zapisu wewnątrz pakietu `.app` i przechwycenia biblioteki).\
Jednakże, sposób, w jaki **aplikacje MacOS** **ładują** **biblioteki** jest **bardziej ograniczony** niż w systemie Windows. Oznacza to, że **twórcy złośliwego oprogramowania** nadal mogą używać tej techniki dla **ukrycia**, ale prawdopodobieństwo **nadużycia tego do eskalacji uprawnień jest znacznie niższe**.

Po pierwsze, **częściej** można znaleźć, że **binarne pliki MacOS wskazują pełną ścieżkę** do bibliotek do załadowania. Po drugie, **system MacOS nigdy nie szuka** w folderach **$PATH** bibliotek.

Główna część **kodu** związana z tą funkcjonalnością znajduje się w **`ImageLoader::recursiveLoadLibraries`** w `ImageLoader.cpp`.

Istnieją **4 różne polecenia nagłówka**, które binarny plik macho może użyć do ładowania bibliotek:

* Polecenie **`LC_LOAD_DYLIB`** to powszechne polecenie do ładowania dylibów.
* Polecenie **`LC_LOAD_WEAK_DYLIB`** działa podobnie jak poprzednie, ale jeśli dylib nie zostanie znaleziony, wykonanie kontynuuje się bez żadnego błędu.
* Polecenie **`LC_REEXPORT_DYLIB`** przechwytuje (lub ponownie eksportuje) symbole z innej biblioteki.
* Polecenie **`LC_LOAD_UPWARD_DYLIB`** jest używane, gdy dwie biblioteki zależą od siebie nawzajem (nazywa się to _zależnością w górę_).

Jednakże istnieją **2 rodzaje przechwytywania dylibów**:

* **Brakujące słabe połączone biblioteki**: Oznacza to, że aplikacja spróbuje załadować bibliotekę, której nie ma skonfigurowanej z **LC\_LOAD\_WEAK\_DYLIB**. Następnie, **jeśli atakujący umieści dylib tam, gdzie się spodziewa, zostanie załadowany**.
* Fakt, że połączenie jest "słabe" oznacza, że aplikacja będzie nadal działać, nawet jeśli biblioteka nie zostanie znaleziona.
* **Kod związany** z tym znajduje się w funkcji `ImageLoaderMachO::doGetDependentLibraries` w `ImageLoaderMachO.cpp`, gdzie `lib->required` jest prawdziwe tylko wtedy, gdy `LC_LOAD_WEAK_DYLIB` jest prawdziwe.
* **Znajdź słabe połączone biblioteki** w binariach (później masz przykład, jak tworzyć biblioteki przechwytywania):
* ```bash
otool -l </ścieżka/do/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Skonfigurowane z @rpath**: Binaria Mach-O mogą zawierać polecenia **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na podstawie **wartości** tych poleceń, **biblioteki** będą **ładowane** z **różnych katalogów**.
* **`LC_RPATH`** zawiera ścieżki niektórych folderów używanych do ładowania bibliotek przez binarny plik.
* **`LC_LOAD_DYLIB`** zawiera ścieżkę do konkretnych bibliotek do załadowania. Te ścieżki mogą zawierać **`@rpath`**, które zostaną **zastąpione** przez wartości w **`LC_RPATH`**. Jeśli w **`LC_RPATH`** jest kilka ścieżek, każda z nich będzie używana do wyszukiwania biblioteki do załadowania. Przykład:
* Jeśli **`LC_LOAD_DYLIB`** zawiera `@rpath/library.dylib`, a **`LC_RPATH`** zawiera `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`. Oba foldery zostaną użyte do załadowania `library.dylib`. Jeśli biblioteka nie istnieje w `[...]/v1/` i atakujący mógłby ją umieścić tam, aby przejąć ładowanie biblioteki w `[...]/v2/`, ponieważ zachowywana jest kolejność ścieżek w **`LC_LOAD_DYLIB`**.
* **Znajdź ścieżki rpath i biblioteki** w plikach binarnych za pomocą: `otool -l </ścieżka/do/binarnego> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Jest to **ścieżka** do katalogu zawierającego **główny plik wykonywalny**.

**`@loader_path`**: Jest to **ścieżka** do **katalogu** zawierającego **binarny Mach-O**, który zawiera polecenie ładowania.

* Gdy jest używane w pliku wykonywalnym, **`@loader_path`** jest efektywnie **takie samo** jak **`@executable_path`**.
* Gdy jest używane w **dylib**, **`@loader_path`** podaje **ścieżkę** do **dylib**.
{% endhint %}

Sposobem na **eskalację uprawnień** wykorzystującą tę funkcjonalność byłoby w rzadkim przypadku, gdy **aplikacja** uruchamiana przez **roota** poszukuje pewnej **biblioteki w folderze, w którym atakujący ma uprawnienia do zapisu.**

{% hint style="success" %}
Świetnym **skanerem** do znajdowania **brakujących bibliotek** w aplikacjach jest [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) lub [**wersja CLI**](https://github.com/pandazheng/DylibHijack).\
Świetny **raport z technicznymi szczegółami** na temat tej techniki można znaleźć [**tutaj**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Przykład**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Pamiętaj, że **wcześniejsze ograniczenia walidacji bibliotek** również mają zastosowanie do przeprowadzania ataków Dlopen hijacking.
{% endhint %}

Z **`man dlopen`**:

* Gdy ścieżka **nie zawiera znaku ukośnika** (czyli jest to tylko nazwa liścia), **dlopen() będzie przeszukiwać**. Jeśli **`$DYLD_LIBRARY_PATH`** był ustawiony przy starcie, dyld najpierw **sprawdzi ten katalog**. Następnie, jeśli plik mach-o wywołujący lub główny plik wykonywalny określają **`LC_RPATH`**, to dyld będzie **szukać w tych** katalogach. Następnie, jeśli proces jest **nieograniczony**, dyld będzie szukać w **bieżącym katalogu**. Na koniec, dla starych binarnych plików, dyld spróbuje kilka alternatyw. Jeśli **`$DYLD_FALLBACK_LIBRARY_PATH`** był ustawiony przy starcie, dyld będzie szukać w **tych katalogach**, w przeciwnym razie dyld będzie szukać w **`/usr/local/lib/`** (jeśli proces jest nieograniczony), a następnie w **`/usr/lib/`** (te informacje zostały zaczerpnięte z **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (jeśli nieograniczony)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (jeśli nieograniczony)
6. `/usr/lib/`

{% hint style="danger" %}
Jeśli brak znaków ukośnika w nazwie, istnieją 2 sposoby na wykonanie ataku hijacking:

* Jeśli którykolwiek **`LC_RPATH`** jest **zapisywalny** (ale sygnatura jest sprawdzana, więc do tego potrzebujesz również nieregowanego binarnego)
* Jeśli binarny jest **nieograniczony**, wówczas możliwe jest załadowanie czegoś z CWD (lub wykorzystanie jednej z wymienionych zmiennych środowiskowych)
{% endhint %}

* Gdy ścieżka **wygląda jak ścieżka do frameworka** (np. `/stuff/foo.framework/foo`), jeśli **`$DYLD_FRAMEWORK_PATH`** był ustawiony przy starcie, dyld najpierw będzie szukać w tym katalogu dla **częściowej ścieżki frameworka** (np. `foo.framework/foo`). Następnie dyld spróbuje **podanej ścieżki takiej jak jest** (używając bieżącego katalogu roboczego dla ścieżek względnych). Na koniec, dla starych binarnych plików, dyld spróbuje kilka alternatyw. Jeśli **`$DYLD_FALLBACK_FRAMEWORK_PATH`** był ustawiony przy starcie, dyld będzie szukać w tych katalogach. W przeciwnym razie będzie szukać w **`/Library/Frameworks`** (na macOS, jeśli proces jest nieograniczony), a następnie w **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. podana ścieżka (używając bieżącego katalogu roboczego dla ścieżek względnych, jeśli nieograniczony)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (jeśli nieograniczony)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Jeśli ścieżka frameworka, sposób na jej przejęcie byłby:

* Jeśli proces jest **nieograniczony**, wykorzystując **ścieżkę względną z CWD** wspomniane zmienne środowiskowe (nawet jeśli nie jest to powiedziane w dokumentacji, czy proces jest ograniczony, zmienne środowiskowe DYLD\_\* są usuwane)
{% endhint %}

* Gdy ścieżka **zawiera ukośnik, ale nie jest to ścieżka do frameworka** (czyli pełna ścieżka lub częściowa ścieżka do dylib), dlopen() najpierw szuka (jeśli ustawione) w **`$DYLD_LIBRARY_PATH`** (z częścią liścia z ścieżki). Następnie dyld **sprawdza podaną ścieżkę** (używając bieżącego katalogu roboczego dla ścieżek względnych (ale tylko dla nieograniczonych procesów)). Na koniec, dla starych binarnych plików, dyld spróbuje alternatyw. Jeśli **`$DYLD_FALLBACK_LIBRARY_PATH`** był ustawiony przy starcie, dyld będzie szukać w tych katalogach, w przeciwnym razie dyld będzie szukać w **`/usr/local/lib/`** (jeśli proces jest nieograniczony), a następnie w **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. podana ścieżka (używając bieżącego katalogu roboczego dla ścieżek względnych, jeśli nieograniczony)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (jeśli nieograniczony)
5. `/usr/lib/`

{% hint style="danger" %}
Jeśli są ukośniki w nazwie i nie jest to framework, sposób na jej przejęcie byłby:

* Jeśli binarny jest **nieograniczony**, wówczas możliwe jest załadowanie czegoś z CWD lub `/usr/local/lib` (lub wykorzystanie jednej z wymienionych zmiennych środowiskowych)
{% endhint %}

{% hint style="info" %}
Uwaga: Nie ma plików konfiguracyjnych do **kontroli wyszukiwania dlopen**.

Uwaga: Jeśli główny plik wykonywalny jest **binarnym ustawionym na set\[ug]id lub podpisanym z uprawnieniami**, wtedy **wszystkie zmienne środowiskowe są ignorowane**, i można użyć tylko pełnej ścieżki ([sprawdź ograniczenia DYLD\_INSERT\_LIBRARIES](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) dla bardziej szczegółowych informacji)

Uwaga: Platformy Apple używają plików „uniwersalnych” do łączenia bibliotek 32-bitowych i 64-bitowych. Oznacza to, że nie ma **oddzielnych ścieżek wyszukiwania 32-bitowych i 64-bitowych**.

Uwaga: Na platformach Apple większość dylibów systemowych jest **łączona w pamięć podręczną dyld** i nie istnieje na dysku. Dlatego wywołanie **`stat()`** wstępnie, aby sprawdzić, czy dylib systemowy istnieje, **nie zadziała**. Jednak **`dlopen_preflight()`** używa tych samych kroków co **`dlopen()`** do znalezienia zgodnego pliku mach-o.
{% endhint %}

**Sprawdź ścieżki**

Sprawdźmy wszystkie opcje za pomocą poniższego kodu:
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
Jeśli go skompilujesz i wykonasz, możesz zobaczyć **gdzie nieudanie próbowano wyszukać każdą bibliotekę**. Ponadto, możesz **filtrować dzienniki systemu plików**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Jeśli **binarny/aplikacja z uprawnieniami** (takie jak SUID lub jakiś binarny z potężnymi uprawnieniami) **ładuje bibliotekę za pomocą ścieżki względnej** (na przykład używając `@executable_path` lub `@loader_path`) i ma wyłączoną **Walidację Biblioteki**, może być możliwe przeniesienie binarnego pliku do lokalizacji, w której atakujący mógłby **zmodyfikować załadowaną bibliotekę ze ścieżki względnej** i wykorzystać ją do wstrzyknięcia kodu w procesie.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

W pliku `dyld-dyld-832.7.1/src/dyld2.cpp` można znaleźć funkcję **`pruneEnvironmentVariables`**, która usunie dowolną zmienną środowiskową, która **zaczyna się od `DYLD_`** i **`LD_LIBRARY_PATH=`**.

Zostanie również ustawione na **null** specjalnie zmienne środowiskowe **`DYLD_FALLBACK_FRAMEWORK_PATH`** i **`DYLD_FALLBACK_LIBRARY_PATH`** dla binarnych plików **suid** i **sgid**.

Ta funkcja jest wywoływana z funkcji **`_main`** tego samego pliku, jeśli jest to system operacyjny OSX, w ten sposób:
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
Co w zasadzie oznacza, że jeśli binarny plik jest **suid** lub **sgid**, lub ma segment **RESTRICT** w nagłówkach lub został podpisany flagą **CS\_RESTRICT**, to **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** jest prawdziwe, a zmienne środowiskowe są przycinane.

Należy zauważyć, że jeśli CS\_REQUIRE\_LV jest prawdziwe, to zmienne nie zostaną przycięte, ale walidacja biblioteki sprawdzi, czy używają tego samego certyfikatu co oryginalny plik binarny.

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
### Zabezpieczony runtime

Utwórz nowy certyfikat w Keychain i użyj go do podpisania pliku binarnego:

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
Należy zauważyć, że nawet jeśli istnieją pliki binarne podpisane flagami **`0x0(none)`**, mogą one dynamicznie otrzymać flagę **`CS_RESTRICT`** podczas wykonywania i dlatego ta technika w nich nie zadziała.

Możesz sprawdzić, czy proces ma tę flagę za pomocą (pobierz [**tutaj csops**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
## Odnośniki

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Tom I: Tryb Użytkownika. Autor: Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
