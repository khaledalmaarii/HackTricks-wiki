# Kuingiza Maktaba kwa macOS

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

{% hint style="danger" %}
Msimbo wa **dyld ni wa chanzo wazi** na unaweza kupatikana katika [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) na unaweza kupakuliwa kama tar kwa kutumia **URL kama** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Hii ni kama [**LD\_PRELOAD kwenye Linux**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Inaruhusu kuashiria mchakato ambao utaendeshwa ili kupakia maktaba maalum kutoka kwenye njia (ikiwa env var imewezeshwa)

Mbinu hii inaweza pia **kutumika kama mbinu ya ASEP** kwa kuwa kila programu iliyosakinishwa ina plist inayoitwa "Info.plist" inayoruhusu **kuweka mazingira ya mazingira** kwa kutumia funguo inayoitwa `LSEnvironmental`.

{% hint style="info" %}
Tangu 2012 **Apple imepunguza sana nguvu** ya **`DYLD_INSERT_LIBRARIES`**.

Nenda kwenye msimbo na **angalia `src/dyld.cpp`**. Katika kazi ya **`pruneEnvironmentVariables`** unaweza kuona kuwa **vigezo vya DYLD_*** vinatolewa.

Katika kazi ya **`processRestricted`** sababu ya kizuizi imewekwa. Kwa kuangalia msimbo huo unaweza kuona kuwa sababu ni:

* Msimbo ni `setuid/setgid`
* Kuwepo kwa sehemu ya `__RESTRICT/__restrict` katika binary ya macho.
* Programu ina ruhusa (runtime imedhibitiwa) bila ruhusa ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Angalia **ruhusa** ya binary na: `codesign -dv --entitlements :- </path/to/bin>`

Katika toleo zilizosasishwa zaidi unaweza kupata mantiki hii katika sehemu ya pili ya kazi ya **`configureProcessRestrictions`.** Walakini, kile kinachotekelezwa katika toleo jipya ni **uchunguzi wa mwanzo wa kazi** (unaweza kuondoa ikihusiana na iOS au uigaji kwani hawatatumika katika macOS.
{% endhint %}

### Uthibitishaji wa Maktaba

Hata kama binary inaruhusu kutumia **`DYLD_INSERT_LIBRARIES`** env variable, ikiwa binary inachunguza saini ya maktaba iliyo kwenye mzigo haitapakia maktaba ya desturi.

Ili kupakia maktaba ya desturi, binary inahitaji kuwa na **ruhusa mojawapo ifuatayo**:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

au binary **isipaswi** kuwa na **bendera ya runtime iliyodhibitiwa** au **bendera ya uthibitishaji wa maktaba**.

Unaweza kuchunguza ikiwa binary ina **runtime iliyodhibitiwa** na `codesign --display --verbose <bin>` kwa kuangalia bendera ya runtime katika **`CodeDirectory`** kama: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Unaweza pia kupakia maktaba ikiwa **imesainiwa na cheti sawa na binary**.

Pata mfano wa jinsi ya (kutumia) mbinu hii na angalia vizuizi katika:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Udukuzi wa Dylib

{% hint style="danger" %}
Kumbuka kuwa **vizuizi vya Uthibitishaji wa Maktaba vilivyopita pia hutekelezwa** kufanya mashambulizi ya Udukuzi wa Dylib.
{% endhint %}

Kama katika Windows, kwenye MacOS pia unaweza **kuteka dylibs** ili kufanya **maombi** **yaendeshe** **mimba** **ya** **kificho** **cha** **arbitrary** (vizuri, kwa kweli kutoka kwa mtumiaji wa kawaida hii inaweza isiwezekane kwani unaweza kuhitaji idhini ya TCC kuandika ndani ya mfuko wa `.app` na kuteka maktaba).
Walakini, njia ambayo **maombi ya MacOS** **yanapakia** maktaba ni **iliyozuiliwa zaidi** kuliko kwenye Windows. Hii inamaanisha kwamba **wabunifu wa programu hasidi** bado wanaweza kutumia mbinu hii kwa **siri**, lakini uwezekano wa kuweza **kutumia hii kwa kukuza mamlaka ni mdogo sana**.

Kwanza kabisa, ni **kawaida zaidi** kupata kwamba **binari za MacOS zinaonyesha njia kamili** kwa maktaba za kupakia. Na pili, **MacOS kamwe haitafuta** kwenye folda za **$PATH** kwa maktaba.

Sehemu **kuu** ya **msimbo** inayohusiana na hii ni katika **`ImageLoader::recursiveLoadLibraries`** katika `ImageLoader.cpp`.

Kuna **Amri 4 tofauti za Kichwa** ambazo binary ya macho inaweza kutumia kupakia maktaba:

* Amri ya **`LC_LOAD_DYLIB`** ni amri ya kawaida ya kupakia dylib.
* Amri ya **`LC_LOAD_WEAK_DYLIB`** inafanya kazi kama ile iliyotangulia, lakini ikiwa dylib haipatikani, utekelezaji unaendelea bila kosa lolote.
* Amri ya **`LC_REEXPORT_DYLIB`** inapakia (au kurejeleza) alama kutoka kwa maktaba tofauti.
* Amri ya **`LC_LOAD_UPWARD_DYLIB`** hutumiwa wakati maktaba mbili zinategemeana (hii inaitwa _upward dependency_).

Walakini, kuna **aina 2 za udukuzi wa dylib**:

* **Maktaba zilizounganishwa kwa udhaifu**: Hii inamaanisha kwamba programu itajaribu kupakia maktaba ambayo haipo iliyowekwa na **LC\_LOAD\_WEAK\_DYLIB**. Kisha, **ikiwa mshambuliaji anaweka dylib mahali inapotarajiwa itapakia**.
* Ukweli kwamba kiungo ni "dhaifu" inamaanisha kwamba programu itaendelea kuendesha hata kama maktaba haipatikani.
* **Msimbo unaohusiana** na hii uko katika kazi `ImageLoaderMachO::doGetDependentLibraries` ya `ImageLoaderMachO.cpp` ambapo `lib->required` ni `uwongo` tu wakati `LC_LOAD_WEAK_DYLIB` ni kweli.
* **Pata maktaba zilizounganishwa kwa udhaifu** katika binaries (unayo baadaye mfano wa jinsi ya kuunda maktaba za udukuzi):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Imewekwa na @rpath**: Binari za Mach-O zinaweza kuwa na amri za **`LC_RPATH`** na **`LC_LOAD_DYLIB`**. Kulingana na **thamani** za amri hizo, **maktaba** zitapakia kutoka kwa **folda tofauti**.
* **`LC_RPATH`** ina vijia vya folda zilizotumiwa kupakia maktaba na binary.
* **`LC_LOAD_DYLIB`** ina njia kwa maktaba maalum za kupakia. Njia hizi zinaweza kuwa na **`@rpath`**, ambayo itabadilishwa na thamani katika **`LC_RPATH`**. Ikiwa kuna vijia kadhaa katika **`LC_RPATH`** kila moja itatumika kutafuta maktaba ya kupakia. Mfano:
* Ikiwa **`LC_LOAD_DYLIB`** ina `@rpath/library.dylib` na **`LC_RPATH`** ina `/application/app.app/Contents/Framework/v1/` na `/application/app.app/Contents/Framework/v2/`. Mafolder yote itatumika kwa kupakia `library.dylib`**.** Ikiwa maktaba haipo katika `[...]/v1/` na mshambuliaji anaweza kuweka hapo ili kuteka upakiaji wa maktaba katika `[...]/v2/` kulingana na mpangilio wa njia katika **`LC_LOAD_DYLIB`**.
* **Pata njia za rpath na maktaba** katika binaries na: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Ni **njia** ya saraka inayohifadhi **faili kuu ya kutekelezwa**.

**`@loader_path`**: Ni **njia** ya **saraka** inayohifadhi **Mach-O binary** ambayo ina amri ya kupakia.

* Inapotumiwa katika faili ya kutekelezwa, **`@loader_path`** ni **sawa** na **`@executable_path`**.
* Inapotumiwa katika **dylib**, **`@loader_path`** inatoa **njia** ya **dylib**.
{% endhint %}

Njia ya **kuongeza mamlaka** kwa kutumia hii ingekuwa katika kesi nadra ambapo **programu** inayotekelezwa **na** **root** inatafuta **maktaba katika saraka ambapo mshambuliaji ana ruhusa ya kuandika.**

{% hint style="success" %}
Scanner nzuri ya kupata **maktaba zilizopotea** katika programu ni [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) au [**toleo la CLI**](https://github.com/pandazheng/DylibHijack).\
Ripoti nzuri yenye **maelezo ya kiufundi** kuhusu mbinu hii inaweza kupatikana [**hapa**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Mfano**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Kumbuka kuwa **mipaka ya Uthibitishaji wa Maktaba ya awali pia inatumika** kufanya mashambulizi ya Dlopen hijacking.
{% endhint %}

Kutoka kwa **`man dlopen`**:

* Wakati njia **haionyeshi alama ya mshale** (yaani, ni jina la mwisho tu), **dlopen() itatafuta**. Ikiwa **`$DYLD_LIBRARY_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld kwanza itatafuta katika saraka hiyo. Kisha, ikiwa faili ya mach-o inayopiga simu au faili kuu inabainisha **`LC_RPATH`**, basi dyld itatafuta katika saraka hizo. Kisha, ikiwa mchakato haujazuiliwa, dyld itatafuta katika **saraka ya kufanya kazi ya sasa**. Hatimaye, kwa binaries za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta katika **sarakazi hizo**, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa mchakato haujazuiliwa), na kisha katika **`/usr/lib/`** (habari hii ilitolewa kutoka kwa **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(ikiwa haujazuiliwa)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (ikiwa haujazuiliwa)
6. `/usr/lib/`

{% hint style="danger" %}
Ikiwa hakuna alama ya mshale katika jina, kungekuwa njia 2 za kufanya utekaji:

* Ikiwa **`LC_RPATH`** yoyote ni **inayoweza kuandikwa** ( lakini saini inakaguliwa, kwa hivyo unahitaji pia binary kuwa bila kizuizi)
* Ikiwa binary ni **huru** na kisha inawezekana kupakia kitu kutoka CWD (au kwa kudhuru moja ya mazingira yaliyotajwa)
{% endhint %}

* Wakati njia **inaonekana kama njia ya fremu** (k.m. `/stuff/foo.framework/foo`), ikiwa **`$DYLD_FRAMEWORK_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld kwanza itatafuta katika saraka hiyo kwa **njia ya fremu ya sehemu** (k.m. `foo.framework/foo`). Kisha, dyld itajaribu **njia iliyotolewa kama ilivyo** (ikitumia saraka ya kufanya kazi ya sasa kwa njia za kihusishi). Hatimaye, kwa binaries za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta katika sarakazi hizo. Vinginevyo, itatafuta **`/Library/Frameworks`** (kwenye macOS ikiwa mchakato haujazuiliwa), kisha **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. njia iliyotolewa (ikitumia saraka ya kufanya kazi ya sasa kwa njia za kihusishi ikiwa haujazuiliwa)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (ikiwa haujazuiliwa)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Ikiwa njia ya fremu, njia ya kuteka itakuwa:

* Ikiwa mchakato ni **huru**, kwa kudhuru **njia ya kihusishi kutoka CWD** mazingira yaliyotajwa (hata kama haielezwi katika nyaraka ikiwa mchakato umefungwa DYLD\_\* mazingira yanafutwa)
{% endhint %}

* Wakati njia **ina mshale lakini sio njia ya fremu** (yaani, njia kamili au njia ya sehemu kwa dylib), dlopen() kwanza itatafuta (ikiwa imewekwa) katika **`$DYLD_LIBRARY_PATH`** (na sehemu ya mwisho kutoka kwa njia). Kisha, dyld **jaribu njia iliyotolewa** (ikitumia saraka ya kufanya kazi ya sasa kwa njia za kihusishi ( lakini kwa mchakato usio na kizuizi)). Hatimaye, kwa binaries za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta katika sarakazi hizo, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa mchakato haujazuiliwa), na kisha katika **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. njia iliyotolewa (ikitumia saraka ya kufanya kazi ya sasa kwa njia za kihusishi ikiwa haujazuiliwa)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (ikiwa haujazuiliwa)
5. `/usr/lib/`

{% hint style="danger" %}
Ikiwa kuna mshale katika jina na sio njia ya fremu, njia ya kuteka itakuwa:

* Ikiwa binary ni **huru** na kisha inawezekana kupakia kitu kutoka CWD au `/usr/local/lib` (au kwa kudhuru moja ya mazingira yaliyotajwa)
{% endhint %}

{% hint style="info" %}
Onyo: Hakuna **faili za usanidi** za **kudhibiti utafutaji wa dlopen**.

Onyo: Ikiwa faili kuu ni **binary ya set\[ug]id au imehakikiwa na ruhusa**, basi **mazingira yote ya mazingira yanaachwa**, na inaweza kutumika njia kamili tu ([angalia vikwazo vya DYLD\_INSERT\_LIBRARIES](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) kwa maelezo zaidi)

Onyo: Jukwaa za Apple hutumia faili "za ulimwengu" kuchanganya maktaba za biti 32 na 64. Hii inamaanisha hakuna **njia tofauti za utaftaji wa biti 32 na 64**.

Onyo: Kwenye jukwaa za Apple, maktaba za OS nyingi zimejumuishwa katika **hifadhi ya dyld** na hazipo kwenye diski. Kwa hivyo, kuita **`stat()`** kufanya ukaguzi wa awali ikiwa dylib ya OS ipo **haitafanya kazi**. Walakini, **`dlopen_preflight()`** hutumia hatua sawa na **`dlopen()`** kwa kupata faili sahihi ya mach-o.
{% endhint %}

**Angalia njia**

Hebu tuchunguze chaguo zote na nambari ifuatayo:
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
Ikiwa utaikusanya na kuitekeleza unaweza kuona **ambapo kila maktaba ilipotafutwa bila mafanikio**. Pia, unaweza **kuchuja kumbukumbu za FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Kuteka Njia ya Kiharusi

Ikiwa **binary/app yenye mamlaka** (kama SUID au baadhi ya binary yenye ruhusa kubwa) ina **kupakia maktaba ya njia ya kiharusi** (kwa mfano kutumia `@executable_path` au `@loader_path`) na **Uthibitishaji wa Maktaba umewashwa**, inaweza kuwa inawezekana kuhamisha binary kwenye eneo ambapo mshambuliaji anaweza **kurekebisha maktaba iliyopakiwa kwa njia ya kiharusi**, na kuitumia kuingiza namna ya kuharibu kwenye mchakato.

## Kata `DYLD_*` na `LD_LIBRARY_PATH` env variables

Katika faili `dyld-dyld-832.7.1/src/dyld2.cpp` inawezekana kupata kazi ya **`pruneEnvironmentVariables`**, ambayo itaondoa chochote kwenye mazingira ya env ambacho **kinaanza na `DYLD_`** na **`LD_LIBRARY_PATH=`**.

Pia itaweka kuwa **null** hasa mazingira ya env **`DYLD_FALLBACK_FRAMEWORK_PATH`** na **`DYLD_FALLBACK_LIBRARY_PATH`** kwa binaries za **suid** na **sgid**.

Kazi hii inaitwa kutoka kwa kazi ya **`_main`** ya faili hiyo hiyo ikiwalenga OSX kama ifuatavyo:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
na hizo bendera za boolean zinawekwa katika faili hiyo hiyo katika nambari:
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
Hii inamaanisha kwamba ikiwa binary ni **suid** au **sgid**, au ina sehemu ya **RESTRICT** katika vichwa au ilisainiwa na bendera ya **CS\_RESTRICT**, basi **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** ni kweli na mazingira ya env hukatwa.

Tafadhali kumbuka kwamba ikiwa CS\_REQUIRE\_LV ni kweli, basi mazingira hayatakatiwa lakini uthibitisho wa maktaba utachunguza kwamba wanatumia cheti sawa na binary ya awali.

## Angalia Vizuizi

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
### Sehemu `__RESTRICT` na sehemu `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Mazingira Imara ya Uendeshaji

Tengeneza cheti kipya kwenye Keychain na kitumie kusaini faili ya binary:

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
Tafadhali kumbuka kwamba hata kama kuna binaries zilizosainiwa na bendera **`0x0(none)`**, zinaweza kupata bendera ya **`CS_RESTRICT`** kwa kudhurika wakati zinatekelezwa na kwa hivyo mbinu hii haitafanya kazi kwao.

Unaweza kuangalia ikiwa proc ina bendera hii na (pata [**csops hapa**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
## Marejeo

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
