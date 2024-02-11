# macOS Biblioteekinspuiting

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

{% hint style="danger" %}
Die kode van **dyld is oopbron** en kan gevind word by [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) en kan afgelaai word as 'n tar met behulp van 'n **URL soos** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Dit is soos die [**LD\_PRELOAD op Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload). Dit maak dit moontlik om 'n proses aan te dui wat uitgevoer gaan word om 'n spesifieke biblioteek van 'n pad te laai (as die omgewingsveranderlike geaktiveer is).

Hierdie tegniek kan ook **gebruik word as 'n ASEP-tegniek** aangesien elke geïnstalleerde toepassing 'n plist genaamd "Info.plist" het wat die **toewysing van omgewingsveranderlikes** moontlik maak deur gebruik te maak van 'n sleutel genaamd `LSEnvironmental`.

{% hint style="info" %}
Vanaf 2012 het **Apple die krag van die `DYLD_INSERT_LIBRARIES` drasties verminder**.

Gaan na die kode en **kyk na `src/dyld.cpp`**. In die funksie **`pruneEnvironmentVariables`** kan jy sien dat **`DYLD_*`** veranderlikes verwyder word.

In die funksie **`processRestricted`** word die rede vir die beperking gestel. Deur daardie kode te ondersoek, kan jy sien dat die redes is:

* Die binêre lêer is `setuid/setgid`
* Die bestaan van 'n `__RESTRICT/__restrict`-afdeling in die macho-binêre.
* Die sagteware het toekennings (gehardloop-tyd) sonder die [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) toekennings
* Kontroleer **toekennings** van 'n binêre lêer met: `codesign -dv --entitlements :- </path/to/bin>`

In meer opgedateerde weergawes kan jy hierdie logika vind in die tweede deel van die funksie **`configureProcessRestrictions`.** Wat egter in nuwer weergawes uitgevoer word, is die **begin van die funksie** (jy kan die ifs wat verband hou met iOS of simulasie verwyder, aangesien dit nie in macOS gebruik sal word nie.
{% endhint %}

### Biblioteekvalidering

Selfs as die binêre lêer die **`DYLD_INSERT_LIBRARIES`** omgewingsveranderlike toelaat, sal dit nie 'n aangepaste biblioteek laai as die binêre lêer die handtekening van die biblioteek kontroleer nie.

Om 'n aangepaste biblioteek te laai, moet die binêre lêer een van die volgende toekennings hê:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

of die binêre lêer **moet nie** die **gehardloop-tyd-vlag** of die **biblioteekvalideringsvlag** hê nie.

Jy kan nagaan of 'n binêre lêer **gehardloop-tyd** het met `codesign --display --verbose <bin>` deur die vlag runtime in **`CodeDirectory`** te kontroleer, soos: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Jy kan ook 'n biblioteek laai as dit **onderteken is met dieselfde sertifikaat as die binêre lêer**.

Vind 'n voorbeeld van hoe om dit (mis)tebruik en die beperkings te kontroleer in:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib-hacking

{% hint style="danger" %}
Onthou dat **vorige biblioteekvalideringsbeperkings ook van toepassing is** om Dylib-hacking-aanvalle uit te voer.
{% endhint %}

Soos in Windows kan jy in MacOS ook **dylibs kaap** om **toepassings** **arbitrêre kodes** te laat **uitvoer** (wel, eintlik mag dit nie moontlik wees vir 'n gewone gebruiker nie, aangesien jy 'n TCC-toestemming nodig mag hê om binne 'n `.app`-pakket te skryf en 'n biblioteek te kaap).\
Die manier waarop **MacOS-toepassings** biblioteke **laai**, is egter **meer beperk** as in Windows. Dit beteken dat **kwaadwillige** ontwikkelaars steeds hierdie tegniek vir **steelsheid** kan gebruik, maar die waarskynlikheid om dit te **misbruik om voorregte te verhoog, is baie laer**.

Eerstens is dit **meer algemeen** om te vind dat **MacOS-binêre lêers die volledige pad** na die biblioteke aandui wat gelaai moet word. En tweedens **soek MacOS nooit** in die **$PATH**-velde vir biblioteke nie.

Die **hoofgedeelte** van die **kode** wat met hierdie funksionaliteit verband hou, is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Daar is **4 verskillende opdragopdragte** wat 'n macho-binêre lêer kan gebruik om biblioteke te laai:

* Die **`LC_LOAD_DYLIB`**-opdrag is die algemene opdrag om 'n
* As **`LC_LOAD_DYLIB`** bevat `@rpath/library.dylib` en **`LC_RPATH`** bevat `/application/app.app/Contents/Framework/v1/` en `/application/app.app/Contents/Framework/v2/`. Beide mappe sal gebruik word om `library.dylib` te laai. As die biblioteek nie in `[...]/v1/` bestaan nie en die aanvaller dit daar kan plaas om die laai van die biblioteek in `[...]/v2/` te kap, aangesien die volgorde van paaie in **`LC_LOAD_DYLIB`** gevolg word.
* **Vind rpath-paaie en biblioteke** in binnerwerke met: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Is die **pad** na die gids wat die **hoof uitvoerbare lêer** bevat.

**`@loader_path`**: Is die **pad** na die **gids** wat die **Mach-O binêre** bevat wat die laaibestuursopdrag bevat.

* Wanneer dit in 'n uitvoerbare gebruik word, is **`@loader_path`** effektief dieselfde as **`@executable_path`**.
* Wanneer dit in 'n **dylib** gebruik word, gee **`@loader_path`** die **pad** na die **dylib**.
{% endhint %}

Die manier om voorregte te verhoog deur hierdie funksionaliteit te misbruik, sou wees in die seldsame geval dat 'n toepassing wat deur root uitgevoer word, op soek is na 'n biblioteek in 'n gids waar die aanvaller skryfregte het.

{% hint style="success" %}
'n Goeie **skandeerder** om ontbrekende biblioteke in programme te vind, is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) of 'n [**CLI-weergawe**](https://github.com/pandazheng/DylibHijack).\
'n Goeie **verslag met tegniese besonderhede** oor hierdie tegniek kan [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) gevind word.
{% endhint %}

**Voorbeeld**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Onthou dat **vorige Biblioteekvalideringsbeperkings ook van toepassing is** om Dlopen-hakingsaanvalle uit te voer.
{% endhint %}

Vanaf **`man dlopen`**:

* Wanneer die pad **nie 'n sku
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
As jy dit saamstel en uitvoer, kan jy sien **waar elke biblioteek onsuksesvol gesoek is**. Jy kan ook **die FS-logboeke filter**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relatiewe Pad Kaping

As 'n **bevoorregte binêre toepassing** (soos 'n SUID of 'n binêre toepassing met kragtige toestemmings) 'n relatiewe pad biblioteek laai (byvoorbeeld deur gebruik te maak van `@executable_path` of `@loader_path`) en Biblioteekvalidering gedeaktiveer is, kan dit moontlik wees om die binêre toepassing na 'n plek te skuif waar die aanvaller die relatiewe pad biblioteek kan wysig en dit misbruik om kode in die proses in te spuit.

## Snoei `DYLD_*` en `LD_LIBRARY_PATH` omgewingsveranderlikes

In die lêer `dyld-dyld-832.7.1/src/dyld2.cpp` is dit moontlik om die funksie **`pruneEnvironmentVariables`** te vind, wat enige omgewingsveranderlike wat begin met `DYLD_` en `LD_LIBRARY_PATH=` sal verwyder.

Dit sal ook spesifiek die omgewingsveranderlikes **`DYLD_FALLBACK_FRAMEWORK_PATH`** en **`DYLD_FALLBACK_LIBRARY_PATH`** nul stel vir **suid** en **sgid** binêre toepassings.

Hierdie funksie word vanuit die **`_main`** funksie van dieselfde lêer geroep as dit op OSX gemik word, soos hier:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
en daardie booleaanse vlae word in dieselfde lêer in die kode ingestel:
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
Dit beteken basies dat as die binêre lêer **suid** of **sgid** is, of 'n **RESTRICT** segment in die koppe het, of onderteken is met die **CS\_RESTRICT** vlag, dan is **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** waar en word die omgewingsveranderlikes uitgesny.

Let daarop dat as CS\_REQUIRE\_LV waar is, sal die veranderlikes nie uitgesny word nie, maar die biblioteekvalidering sal nagaan of hulle dieselfde sertifikaat as die oorspronklike binêre lêer gebruik. 

## Kontroleer Beperkings

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
### Afdeling `__RESTRICT` met segment `__restrict`

In macOS, the `__RESTRICT` section is a special section in the Mach-O binary format that is used to mark memory regions as restricted. This section is typically used to protect sensitive code or data from being modified or accessed by unauthorized processes.

The `__RESTRICT` section is implemented using the `__restrict` segment, which is a memory protection mechanism provided by the macOS kernel. When a process attempts to access or modify memory within the `__RESTRICT` section, the kernel will enforce strict access controls and prevent unauthorized actions.

By leveraging the `__RESTRICT` section and the `__restrict` segment, developers can enhance the security of their macOS applications by restricting access to critical code and data. This can help prevent privilege escalation attacks and unauthorized modifications to sensitive information.

It is important to note that the `__RESTRICT` section and the `__restrict` segment are not foolproof and should not be solely relied upon for securing an application. They should be used in conjunction with other security measures, such as proper input validation, secure coding practices, and regular security updates.

Overall, the `__RESTRICT` section with the `__restrict` segment provides a valuable security feature in macOS that can help protect critical code and data from unauthorized access or modification.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Geharde uitvoering

Skep 'n nuwe sertifikaat in die Sleutelbos en gebruik dit om die binêre lêer te onderteken:

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
Let daarop dat selfs as daar bineêre lêers is wat onderteken is met vlae **`0x0(none)`**, kan hulle dinamies die **`CS_RESTRICT`** vlag kry wanneer hulle uitgevoer word en daarom sal hierdie tegniek nie in hulle werk nie.

Jy kan nagaan of 'n pros hierdie vlag het met (kry [**csops hier**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
en dan kontroleer of die vlag 0x800 geaktiveer is.
{% endhint %}

## Verwysings
* [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
