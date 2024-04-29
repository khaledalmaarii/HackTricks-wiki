# macOS Biblioteekinspuiting

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

{% hint style="danger" %}
Die kode van **dyld is oopbron** en kan gevind word op [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) en kan afgelaai word as 'n tar deur 'n **URL soos** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Dyld-proses**

Neem 'n kyk na hoe Dyld biblioteke binne bineêre lêers laai in:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

Dit is soos die [**LD\_PRELOAD op Linux**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Dit maak dit moontlik om 'n proses aan te dui wat uitgevoer gaan word om 'n spesifieke biblioteek van 'n pad te laai (as die omgewingsveranderlike geaktiveer is)

Hierdie tegniek kan ook **gebruik word as 'n ASEP-tegniek** aangesien elke geïnstalleerde aansoek 'n plist genaamd "Info.plist" het wat die **toewysing van omgewingsveranderlikes** moontlik maak deur 'n sleutel genaamd `LSEnvironmental` te gebruik.

{% hint style="info" %}
Aangesien 2012 het **Apple drasties die krag van die** **`DYLD_INSERT_LIBRARIES`** **verminder**.

Gaan na die kode en **kyk na `src/dyld.cpp`**. In die funksie **`pruneEnvironmentVariables`** kan jy sien dat **`DYLD_*`** veranderlikes verwyder word.

In die funksie **`processRestricted`** word die rede vir die beperking gestel. Deur daardie kode te kontroleer, kan jy sien dat die redes is:

* Die bineêre lêer is `setuid/setgid`
* Bestaan van `__RESTRICT/__restrict` afdeling in die macho-bineêre lêer.
* Die sagteware het toekennings (geharde hardlooptyd) sonder [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) toekenning
* Kontroleer **toekennings** van 'n bineêre lêer met: `codesign -dv --entitlements :- </path/to/bin>`

In meer opgedateerde weergawes kan jy hierdie logika vind aan die tweede deel van die funksie **`configureProcessRestrictions`.** Wat egter in nuwer weergawes uitgevoer word, is die **begin kontroles van die funksie** (jy kan die ifs verwyder wat verband hou met iOS of simulasie aangesien dit nie in macOS gebruik sal word nie.
{% endhint %}

### Biblioteekvalidering

Selfs al laat die bineêre lêer toe om die **`DYLD_INSERT_LIBRARIES`** omgewingsveranderlike te gebruik, as die bineêre lêer die handtekening van die biblioteek nagaan om dit te laai, sal dit nie 'n aangepaste een laai nie.

Om 'n aangepaste biblioteek te laai, moet die bineêre lêer een van die volgende toekennings hê:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

of die bineêre lêer **moet nie** die **geharde hardlooptyd-vlag** of die **biblioteekvalideringsvlag** hê nie.

Jy kan nagaan of 'n bineêre lêer **geharde hardlooptyd** het met `codesign --display --verbose <bin>` deur die vlag hardlooptyd in **`CodeDirectory`** te kontroleer soos: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Jy kan ook 'n biblioteek laai as dit **onderteken is met dieselfde sertifikaat as die bineêre lêer**.

Vind 'n voorbeeld oor hoe om hierdie tegniek te (mis)bruik en kontroleer die beperkings in:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

## Dylib-hacking

{% hint style="danger" %}
Onthou dat **vorige Biblioteekvalideringsbeperkings ook van toepassing is** om Dylib-hacking-aanvalle uit te voer.
{% endhint %}

Soos in Windows, in MacOS kan jy ook **dylibs kaap** om **toepassings** **willekeurige kode te laat uitvoer** (wel, eintlik vanaf 'n gewone gebruiker mag dit nie moontlik wees nie aangesien jy 'n TCC-toestemming nodig mag hê om binne 'n `.app`-bundel te skryf en 'n biblioteek te kaap).\
Nietemin, die manier waarop **MacOS-toepassings** biblioteke **laai** is **meer beperk** as in Windows. Dit impliseer dat **malware-ontwikkelaars** steeds hierdie tegniek vir **steelsheid** kan gebruik, maar die waarskynlikheid om hierdie tegniek te **misbruik om voorregte te eskaleer is baie laer**.

Eerstens is dit **meer algemeen** om te vind dat **MacOS-bineêre lêers die volledige pad aandui** na die biblioteke wat gelaai moet word. En tweedens **soek MacOS nooit** in die lêers van die **$PATH** vir biblioteke nie.

Die **hoofgedeelte** van die **kode** wat verband hou met hierdie funksionaliteit is in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Daar is **4 verskillende kopbevele** wat 'n macho-bineêre lêer kan gebruik om biblioteke te laai:

* **`LC_LOAD_DYLIB`**-bevel is die algemene bevel om 'n dylib te laai.
* **`LC_LOAD_WEAK_DYLIB`**-bevel werk soos die vorige een, maar as die dylib nie gevind word nie, gaan die uitvoering voort sonder enige fout.
* **`LC_REEXPORT_DYLIB`**-bevel prokureer (of heruitvoer) die simbole van 'n ander biblioteek.
* **`LC_LOAD_UPWARD_DYLIB`**-bevel word gebruik wanneer twee biblioteke van mekaar afhanklik is (dit word 'n _opwaartse afhanklikheid_ genoem).

Daar is egter **2 soorte dylib-hacking**:

* **Ontbrekende swak gekoppelde biblioteke**: Dit beteken dat die toepassing sal probeer om 'n biblioteek te laai wat nie bestaan nie, gekonfigureer met **LC\_LOAD\_WEAK\_DYLIB**. Dan, **as 'n aanvaller 'n dylib plaas waar dit verwag word, sal dit gelaai word**.
* Die feit dat die skakel "swak" is, beteken dat die toepassing sal bly loop selfs as die biblioteek nie gevind word nie.
* Die **kode wat verband hou** met hierdie is in die funksie `ImageLoaderMachO::doGetDependentLibraries` van `ImageLoaderMachO.cpp` waar `lib->required` slegs `false` is wanneer `LC_LOAD_WEAK_DYLIB` waar is.
* **Vind swak gekoppelde biblioteke** in bineêre lêers met (jy het later 'n voorbeeld oor hoe om kaapbiblioteke te skep):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Gekonfigureer met @rpath**: Mach-O-bineêre lêers kan die bevele **`LC_RPATH`** en **`LC_LOAD_DYLIB`** hê. Gebaseer op die **waardes** van daardie bevele, gaan **biblioteke** vanuit **verskillende lêers** gelaai word.
* **`LC_RPATH`** bevat die paaie van sekere lêers wat gebruik word om biblioteke deur die bineêre lêer te laai.
* **`LC_LOAD_DYLIB`** bevat die pad na spesifieke biblioteke om te laai. Hierdie paaie kan **`@rpath`** bevat, wat **vervang** sal word deur die waardes in **`LC_RPATH`**. As daar verskeie paaie in **`LC_RPATH`** is, sal almal gebruik word om die biblioteek te soek om te laai. Voorbeeld:
* As **`LC_LOAD_DYLIB`** `@rpath/library.dylib` bevat en **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` en `/application/app.app/Contents/Framework/v2/` bevat. Beide folders sal gebruik word om `library.dylib` te laai. As die biblioteek nie in `[...]/v1/` bestaan nie en 'n aanvaller dit daar kan plaas om die laai van die biblioteek in `[...]/v2/` te kap, aangesien die volgorde van paaie in **`LC_LOAD_DYLIB`** gevolg word.
* **Vind rpath-paaie en biblioteke** in bineêre met: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Is die **pad** na die gids wat die **hoof uitvoerbare lêer** bevat.

**`@loader_path`**: Is die **pad** na die **gids** wat die **Mach-O bineêre** bevat wat die laaibevel bevat.

* Wanneer dit in 'n uitvoerbare lêer gebruik word, is **`@loader_path`** effektief dieselfde as **`@executable_path`**.
* Wanneer dit in 'n **dylib** gebruik word, gee **`@loader_path`** die **pad** na die **dylib**.
{% endhint %}

Die manier om **voorregte te eskaleer** deur hierdie funksionaliteit te misbruik, sou in die seldsame geval wees dat 'n **toepassing** wat deur **root** uitgevoer word, op soek is na 'n sekere **biblioteek in 'n sekere gids waar die aanvaller skryfregte het.**

{% hint style="success" %}
'n Goeie **skenner** om **ontbrekende biblioteke** in toepassings te vind is [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) of 'n [**CLI weergawe**](https://github.com/pandazheng/DylibHijack).\
'n Goeie **verslag met tegniese besonderhede** oor hierdie tegniek kan gevind word [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Voorbeeld**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Onthou dat **vorige Biblioteekvalideringsbeperkings ook van toepassing is** om Dlopen-hyjacking-aanvalle uit te voer.
{% endhint %}

Vanaf **`man dlopen`**:

* Wanneer die pad **geen skuiwekenmerk bevat** nie (m.a.w. dit is net 'n blaar naam), sal **dlopen() soek**. As **`$DYLD_LIBRARY_PATH`** by aanvang ingestel was, sal dyld eers in daardie gids **kyk**. Daarna, as die aanroepende mach-o-lêer of die hoof uitvoerbare spesifiseer 'n **`LC_RPATH`**, sal dyld in daardie gidse **kyk**. Daarna, as die proses **onbeperk** is, sal dyld in die **huidige werksgids** soek. Laastens, vir ouer bineêre lêers, sal dyld 'n paar terugslae probeer. As **`$DYLD_FALLBACK_LIBRARY_PATH`** by aanvang ingestel was, sal dyld in daardie gidse soek, anders sal dyld in **`/usr/local/lib/`** kyk (as die proses onbeperk is), en dan in **`/usr/lib/`** (hierdie inligting is geneem van **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(indien onbeperk)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (indien onbeperk)
6. `/usr/lib/`

{% hint style="danger" %}
As daar geen skuiwe in die naam is nie, sou daar 2 maniere wees om 'n hyjacking te doen:

* As enige **`LC_RPATH`** **skryfbaar** is (maar handtekening word nagegaan, dus hiervoor het jy ook nodig dat die bineêre onbeperk is)
* As die bineêre **onbeperk** is en dan is dit moontlik om iets van die CWD te laai (of een van die genoemde omgewingsveranderlikes te misbruik)
{% endhint %}

* Wanneer die pad **lyk soos 'n raamwerk** pad (bv. `/stuff/foo.framework/foo`), as **`$DYLD_FRAMEWORK_PATH`** by aanvang ingestel was, sal dyld eers in daardie gids kyk vir die **raamwerk gedeeltelike pad** (bv. `foo.framework/foo`). Daarna sal dyld die **verskafte pad soek soos dit is** (gebruik die huidige werksgids vir relatiewe paaie). Laastens, vir ouer bineêre lêers, sal dyld 'n paar terugslae probeer. As **`$DYLD_FALLBACK_FRAMEWORK_PATH`** by aanvang ingestel was, sal dyld in daardie gidse soek. Anders sal dit soek in **`/Library/Frameworks`** (op macOS as die proses onbeperk is), dan in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. verskafte pad (gebruik die huidige werksgids vir relatiewe paaie indien onbeperk)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (indien onbeperk)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
As 'n raamwerk pad, sou die manier om dit te kap wees:

* As die proses **onbeperk** is, misbruik die **relatiewe pad vanaf CWD** die genoemde omgewingsveranderlikes (selfs al word nie in die dokumente genoem of die proses beperk is nie, word DYLD\_\* omgewingsveranderlikes verwyder)
{% endhint %}

* Wanneer die pad **'n skuiwe bevat maar nie 'n raamwerk pad is** nie (m.a.w. 'n volledige pad of 'n gedeeltelike pad na 'n dylib), kyk dlopen() eerste in (indien ingestel) in **`$DYLD_LIBRARY_PATH`** (met die blaar deel van die pad). Daarna probeer dyld die verskafte pad (gebruik die huidige werksgids vir relatiewe paaie (maar slegs vir onbeperkte prosesse)). Laastens, vir ouer bineêre lêers, sal dyld 'n paar terugslae probeer. As **`$DYLD_FALLBACK_LIBRARY_PATH`** by aanvang ingestel was, sal dyld in daardie gidse soek, anders sal dyld in **`/usr/local/lib/`** kyk (as die proses onbeperk is), en dan in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. verskafte pad (gebruik die huidige werksgids vir relatiewe paaie indien onbeperk)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (indien onbeperk)
5. `/usr/lib/`

{% hint style="danger" %}
As daar skuiwe in die naam is en nie 'n raamwerk is nie, sou die manier om dit te kap wees:

* As die bineêre **onbeperk** is en dan is dit moontlik om iets van die CWD of `/usr/local/lib` te laai (of een van die genoemde omgewingsveranderlikes te misbruik)
{% endhint %}

{% hint style="info" %}
Nota: Daar is **geen** konfigurasie lêers om **dlopen soek** te beheer nie.

Nota: As die hoof uitvoerbare lêer 'n **set\[ug]id bineêre of met toestemmings onderteken** is, word **alle omgewingsveranderlikes geïgnoreer**, en slegs 'n volledige pad kan gebruik word ([kontroleer DYLD\_INSERT\_LIBRARIES beperkings](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) vir meer gedetailleerde inligting)

Nota: Apple platforms gebruik "universele" lêers om 32-bis en 64-bis biblioteke te kombineer. Dit beteken daar is **geen aparte 32-bis en 64-bis soekpaaie** nie.

Nota: Op Apple platforms word die meeste OS-dylibs **gekombineer in die dyld-cache** en bestaan nie op die skyf nie. Daarom sal die aanroep van **`stat()`** om vooraf te kyk of 'n OS-dylib bestaan **nie werk nie**. Nietemin, **`dlopen_preflight()`** gebruik dieselfde stappe as **`dlopen()`** om 'n verenigbare mach-o-lêer te vind.
{% endhint %}

**Kontroleer paaie**

Laat ons al die opsies nagaan met die volgende kode:
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
As jy dit saamstel en uitvoer, kan jy sien **waar elke biblioteek tevergeefs gesoek is**. Ook kan jy **die FS-logboeke filter**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relatiewe Pad Ontvoering

Indien 'n **bevoorregte binêre toepassing** (soos 'n SUID of 'n binêre toepassing met kragtige toestemmings) 'n relatiewe pad-biblioteek laai (byvoorbeeld deur `@executable_path` of `@loader_path` te gebruik) en **Biblioteekvalidering gedeaktiveer** is, kan dit moontlik wees om die binêre toepassing na 'n plek te skuif waar die aanvaller die relatiewe pad-gelaaide biblioteek kan **verander en misbruik om kode in die proses in te spuit**.

## Snoei `DYLD_*` en `LD_LIBRARY_PATH` omgewingsveranderlikes

In die lêer `dyld-dyld-832.7.1/src/dyld2.cpp` is dit moontlik om die funksie **`pruneEnvironmentVariables`** te vind, wat enige omgewingsveranderlike wat **met `DYLD_` begin** en **`LD_LIBRARY_PATH=`** verwyder.

Dit sal ook spesifiek die omgewingsveranderlikes **`DYLD_FALLBACK_FRAMEWORK_PATH`** en **`DYLD_FALLBACK_LIBRARY_PATH`** vir **suid** en **sgid** binêre lêers na **nul** stel.

Hierdie funksie word vanaf die **`_main`** funksie van dieselfde lêer geroep as dit op OSX gemik word, soos hier:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
en daardie booleaanse vlae is ingestel in dieselfde lêer in die kode:
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
Wat basies beteken dat as die binêre lêer **suid** of **sgid** is, of 'n **RESTRICT** segment in die koppe het, of onderteken is met die **CS\_RESTRICT** vlag, dan is **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** waar en word die omgewingsveranderlikes gesnoei.

Merk op dat as CS\_REQUIRE\_LV waar is, sal die veranderlikes nie gesnoei word nie, maar die biblioteekvalidering sal nagaan of hulle dieselfde sertifikaat as die oorspronklike binêre lêer gebruik.

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
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Geharde hardloop

Skep 'n nuwe sertifikaat in die Sleutelhang en gebruik dit om die binêre lêer te teken:

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
Let daarop dat selfs as daar bineêre lêers met vlae **`0x0(none)`** onderteken is, kan hulle dinamies die **`CS_RESTRICT`** vlag kry wanneer hulle uitgevoer word en daarom sal hierdie tegniek nie in hulle werk nie.

Jy kan nagaan of 'n pros hierdie vlag het met (kry [**csops hier**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
## Verwysings

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. Deur Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
