# macOS Library Injection

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub**.

</details>

{% hint style="danger" %}
Kod **dyld jest open source** i można go znaleźć pod adresem [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/), a można go pobrać jako tar za pomocą **URL-a takiego jak** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Jest to odpowiednik [**LD\_PRELOAD w Linuxie**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Pozwala wskazać procesowi, który ma zostać uruchomiony, aby załadować określoną bibliotekę z określonej ścieżki (jeśli zmienna środowiskowa jest włączona).

Ta technika może być również **używana jako technika ASEP**, ponieważ każda zainstalowana aplikacja ma plik plist o nazwie "Info.plist", który umożliwia **przypisanie zmiennych środowiskowych** za pomocą klucza `LSEnvironmental`.

{% hint style="info" %}
Od 2012 roku **Apple znacznie ograniczył moc** **`DYLD_INSERT_LIBRARIES`**.

Przejdź do kodu i **sprawdź `src/dyld.cpp`**. W funkcji **`pruneEnvironmentVariables`** można zobaczyć, że zmienne **`DYLD_*`** są usuwane.

W funkcji **`processRestricted`** ustawiono powód ograniczenia. Sprawdzając ten kod, można zobaczyć, że powodami są:

* Binarny plik jest `setuid/setgid`
* Istnienie sekcji `__RESTRICT/__restrict` w binarnym pliku macho.
* Oprogramowanie ma uprawnienia (hardened runtime) bez uprawnienia [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Sprawdź **uprawnienia** binarnego pliku za pomocą polecenia: `codesign -dv --entitlements :- </path/to/bin>`

W nowszych wersjach tej logiki można znaleźć w drugiej części funkcji **`configureProcessRestrictions`.** Jednakże, to, co jest wykonywane w nowszych wersjach, to **początkowe sprawdzenia funkcji** (można usunąć ify związane z iOS lub symulacją, ponieważ nie będą one używane w macOS.
{% endhint %}

### Walidacja bibliotek

Nawet jeśli binarny plik pozwala na użycie zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`**, jeśli binarny plik sprawdza podpis biblioteki, aby ją załadować, nie załaduje niestandardowej biblioteki.

Aby załadować niestandardową bibliotekę, binarny plik musi mieć **jedno z następujących uprawnień**:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

lub binarny plik **nie powinien** mieć flagi **hardened runtime** ani flagi **walidacji biblioteki**.

Możesz sprawdzić, czy binarny plik ma **hardened runtime** za pomocą polecenia `codesign --display --verbose <bin>`, sprawdzając flagę runtime w **`CodeDirectory`** tak jak: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Możesz również załadować bibliotekę, jeśli jest **podpisana tym samym certyfikatem co binarny plik**.

Znajdź przykład, jak (nadużywać) to wykorzystać i sprawdzić ograniczenia w:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Przechwytywanie dylib

{% hint style="danger" %}
Pamiętaj, że **dotyczą cię również wcześniejsze ograniczenia walidacji bibliotek**, aby przeprowadzić ataki przechwytywania dylib.
{% endhint %}

Podobnie jak w systemie Windows, w systemie MacOS można również **przechwycić dyliby**, aby **aplikacje wykonywały** **arbitralny** **kod** (w rzeczywistości od zwykłego użytkownika to może być niemożliwe, ponieważ może być wymagane uprawnienie TCC do zapisu wewnątrz pakietu `.app` i przechwycenia biblioteki).\
Jednak sposób, w jaki **aplikacje MacOS** ładują **biblioteki**, jest **bardziej ograniczony** niż w systemie Windows. Oznacza to, że deweloperzy **złośliwego oprogramowania** wciąż mogą używać tej techniki w celu **ukrycia**, ale prawdopodobieństwo wykorzystania jej do **eskalacji uprawnień jest znacznie niższe**.

Po pierwsze, **częściej** można znaleźć, że **binarne pliki MacOS wskazują pełną ścieżkę** do bibliotek do załadowania. Po drugie, **MacOS nigdy nie przeszukuje** folderów **$PATH** w poszukiwaniu bibliotek.

**Główna** część **kodu** związana z tą funkcjonalnością znajduje się w **`ImageLoader::recursiveLoadLibraries`** w pliku `ImageLoader.cpp`.

Istnieją **4 różne polecenia nagłówka**, które binarny pl

* Jeśli **`LC_LOAD_DYLIB`** zawiera `@rpath/library.dylib`, a **`LC_RPATH`** zawiera `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`, oba foldery zostaną użyte do załadowania `library.dylib`. Jeśli biblioteka nie istnieje w `[...]/v1/`, atakujący może umieścić ją tam, aby przejąć załadowanie biblioteki w `[...]/v2/`, ponieważ ścieżki w **`LC_LOAD_DYLIB`** są przestrzegane.
* **Znajdź ścieżki rpath i biblioteki** w plikach binarnych za pomocą polecenia: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Jest to **ścieżka** do katalogu zawierającego **główny plik wykonywalny**.

**`@loader_path`**: Jest to **ścieżka** do **katalogu** zawierającego **binarny Mach-O**, który zawiera polecenie ładowania.

* Gdy jest używane w pliku wykonywalnym, **`@loader_path`** jest efektywnie **takie samo** jak **`@executable_path`**.
* Gdy jest używane w **dylib**, **`@loader_path`** daje **ścieżkę** do **dylib**.
{% endhint %}

Sposób na **przywileje eskalacji** poprzez wykorzystanie tej funkcjonalności polega na rzadkim przypadku, gdy **aplikacja** uruchamiana **przez** **roota** poszukuje pewnej **biblioteki w folderze, w którym atakujący ma uprawnienia do zapisu**.

{% hint style="success" %}
Świetnym **skanerem** do znajdowania **brakujących bibliotek** w aplikacjach jest [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) lub [**wersja CLI**](https://github.com/pandazheng/DylibHijack).\
Świetny **raport z technicznymi szczegółami** na temat tej techniki można znaleźć [**tutaj**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Przykład**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Przechwytywanie Dlopen

{% hint style="danger" %}
Pamiętaj, że **dotyczą również wcześniejsze ograniczenia weryfikacji bibliotek**, aby przeprowadzić ataki przechwytywania Dlopen.
{% endhint %}

Z dokumentacji **`man dlopen`**:

* Gdy ścieżka **nie zawiera znaku ukośnika** (czyli jest to tylko nazwa pliku), **dlopen() będzie przeszukiwać**. Jeśli **`$DYLD_LIBRARY_PATH`** został ustawiony podczas uruchamiania, dyld najpierw **sprawdzi ten katalog**. Następnie, jeśli wywołujący plik mach-o lub główny plik wykonywalny określają **`LC_RPATH`**, dyld będzie **szukać w tych** katalogach. Następnie, jeśli proces jest **nierestrykcyjny**, dyld będzie szukać w **bieżącym katalogu roboczym**. Na koniec, dla starych plików binarnych, dyld spróbuje kilku alternatyw. Jeśli **`$DYLD_FALLBACK_LIBRARY_PATH`** został ustawiony podczas uruchamiania, dyld będzie szukać w **tych katalogach**, w przeciwnym razie dyld będzie szukać w **`/usr/local/lib/`** (jeśli proces jest nierestrykcyjny), a następnie w **`/usr/lib/`** (te informacje zostały zaczerpnięte z **`man dlopen`**).

1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (jeśli nierestrykcyjny)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (jeśli nierestrykcyjny)
6. `/usr/lib/`

{% hint style="danger" %}
Jeśli brak ukośników w nazwie, istnieją 2 sposoby na przechwycenie:

* Jeśli dowolne **`LC_RPATH`** jest **zapisywalne** (ale podpis jest sprawdzany, więc do tego potrzebujesz również, aby plik binarny był nierestrykcyjny)
* Jeśli plik binarny jest **nierestrykcyjny**, a następnie można załadować coś z CWD (lub nadużyć jednej z wymienionych zmiennych środowiskowych)
{% endhint %}

* Gdy ścieżka **wygląda jak ścieżka do frameworka** (np. `/stuff/foo.framework/foo`), jeśli **`$DYLD_FRAMEWORK_PATH`** został ustawiony podczas uruchamiania, dyld najpierw będzie szukać w tym katalogu **częściowej ścieżki frameworka** (np. `foo.framework/foo`). Następnie dyld spróbuje **podanej ścieżki** (używając bieżącego katalogu roboczego dla ścieżek względnych). Na koniec, dla starych plików binarnych, dyld spróbuje kilku alternatyw. Jeśli **`$DYLD_FALLBACK_FRAMEWORK_PATH`** został ustawiony podczas uruchamiania, dyld będzie szukać w tych katalogach. W przeciwnym razie, dyld będzie szukać w **`/Library/Frameworks`** (na macOS, jeśli proces jest nierestrykcyjny), a następnie w **`/System/Library/Frameworks`**.

1. `$DYLD_FRAMEWORK_PATH`
2. podana ścieżka (używając bieżącego katalogu roboczego dla ścieżek względnych, jeśli nierestrykcyjny)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (jeśli nierestrykcyjny)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Jeśli ścieżka frameworka, sposób na przechwycenie to:

* Jeśli proces jest **nierestrykcyjny**, nadużywając **ścieżki względnej z CWD** i wspomnianych zmiennych środowiskowych (nawet jeśli nie jest to wspomniane w dokumentacji, czy proces jest ograniczony, zmienne środowiskowe DYLD\_\* są usuwane)
{% endhint %}

* Gdy ścieżka **zawiera ukośnik, ale nie jest ścieżką do frameworka** (czyli pełna ścieżka lub częściowa ścieżka do dylib), dlopen() najpierw szuka (jeśli ustawiono) w **`$DYLD_LIBRARY_PATH`** (z częścią liściową ze ścieżki). Następnie dyld **sprawdza podaną ścieżkę** (używając bieżącego katalogu roboczego dla ścieżek względnych (ale tylko dla nierestrykcyjnych procesów)). Na koniec, dla starszych plików binarnych, dyld spróbuje kilku alternatyw. Jeśli **`$DYLD_FALLBACK_LIBRARY_PATH`** został ustawiony podczas uruchamiania, dyld będzie szukać w tych katalogach, w przeciwnym razie dyld będzie szukać w **`/usr/local/lib/`** (jeśli proces jest nierestrykcyjny), a następnie w **`/usr/lib/`**.

1. `$DYLD_LIBRARY_PATH`
2. podana ścieżka (używając bieżącego katalogu roboczego dla ścieżek względnych, jeśli nierestrykcyjny)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (jeśli nierestrykcyjny)
5. `/usr/lib/`

Jeśli w nazwie są ukośniki i nie jest to ścieżka do frameworka, sposób na przechwycenie to:

* Jeśli plik binarny jest **nierestrykcyjny**, a następnie można załadować coś z CWD lub `/usr/local/lib` (l

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

Jeśli go skompilujesz i uruchomisz, możesz zobaczyć **gdzie nieudanie wyszukiwano każdej biblioteki**. Możesz również **filtrować dzienniki systemu plików**:

```bash
sudo fs_usage | grep "dlopentest"
```

## Wykorzystywanie względnej ścieżki

Jeśli **uprzywilejowany plik/aplikacja** (takie jak SUID lub jakiś plik binarny z potężnymi uprawnieniami) **ładuje bibliotekę za pomocą względnej ścieżki** (na przykład używając `@executable_path` lub `@loader_path`) i ma wyłączoną weryfikację bibliotek, możliwe jest przeniesienie pliku binarnego do lokalizacji, w której atakujący może **modyfikować ładowaną bibliotekę o względnej ścieżce** i wykorzystać ją do wstrzykiwania kodu w proces.

## Usuwanie zmiennych środowiskowych `DYLD_*` i `LD_LIBRARY_PATH`

W pliku `dyld-dyld-832.7.1/src/dyld2.cpp` można znaleźć funkcję **`pruneEnvironmentVariables`**, która usuwa wszystkie zmienne środowiskowe, które **zaczynają się od `DYLD_`** i **`LD_LIBRARY_PATH=`**.

Funkcja ta również ustawia na **null** konkretne zmienne środowiskowe **`DYLD_FALLBACK_FRAMEWORK_PATH`** i **`DYLD_FALLBACK_LIBRARY_PATH`** dla plików binarnych **suid** i **sgid**.

Ta funkcja jest wywoływana z funkcji **`_main`** tego samego pliku, jeśli jest ukierunkowana na system operacyjny OSX w ten sposób:

```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```

i te flagi boolean są ustawiane w tym samym pliku w kodzie:

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

Co w zasadzie oznacza, że jeśli binarny plik jest **suid** lub **sgid**, lub ma segment **RESTRICT** w nagłówkach lub został podpisany flagą **CS\_RESTRICT**, to **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** jest prawdziwe i zmienne środowiskowe są usuwane.

Należy zauważyć, że jeśli CS\_REQUIRE\_LV jest prawdziwe, to zmienne nie zostaną usunięte, ale weryfikacja biblioteki sprawdzi, czy używają tego samego certyfikatu co oryginalny plik binarny.

## Sprawdź ograniczenia

### SUID i SGID

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

The `__RESTRICT` section is a segment in macOS that is used to restrict the loading of libraries into a process. This section is designed to prevent library injection attacks, where an attacker injects malicious code into a process by loading a malicious library.

When a library is loaded into a process, the dynamic linker checks if the library has a `__RESTRICT` section. If it does, the dynamic linker will refuse to load the library into the process. This prevents any unauthorized libraries from being loaded and executed within the process.

The `__RESTRICT` section is typically used by system libraries and frameworks to protect themselves from library injection attacks. By including a `__RESTRICT` section in their binaries, these libraries ensure that only trusted libraries are loaded into their processes.

It is important for developers to be aware of the `__RESTRICT` section and use it in their own libraries to enhance the security of their applications. By including a `__RESTRICT` section, developers can prevent unauthorized libraries from being loaded into their processes, thereby reducing the risk of library injection attacks.

To summarize, the `__RESTRICT` section with the segment `__restrict` is a security feature in macOS that helps prevent library injection attacks by restricting the loading of libraries into a process. Developers should utilize this feature to enhance the security of their applications.

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
Należy zauważyć, że nawet jeśli istnieją binarne pliki podpisane flagami **`0x0(none)`**, mogą one dynamicznie otrzymać flagę **`CS_RESTRICT`** podczas wykonywania i dlatego ta technika w nich nie zadziała.

Możesz sprawdzić, czy proces ma tę flagę za pomocą (pobierz [**csops tutaj**](https://github.com/axelexic/CSOps)):

```bash
csops -status <pid>
```

a następnie sprawdź, czy flaga 0x800 jest włączona.
{% endhint %}

## Referencje

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
