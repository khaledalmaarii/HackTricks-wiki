# Uingizaji wa Maktaba ya macOS

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

{% hint style="danger" %}
Msimbo wa **dyld ni chanzo wazi** na unaweza kupatikana katika [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) na unaweza kupakuliwa kwa kutumia tar kwa kutumia **URL kama** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Hii ni kama [**LD\_PRELOAD kwenye Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload). Inaruhusu kuonyesha mchakato ambao utatekelezwa ili kupakia maktaba maalum kutoka kwenye njia (ikiwa var ya mazingira imeamilishwa)

Mbinu hii inaweza pia **kutumiwa kama mbinu ya ASEP** kwa sababu kila programu iliyosanikishwa ina plist inayoitwa "Info.plist" ambayo inaruhusu **kuweka mazingira ya mazingira** kwa kutumia funguo inayoitwa `LSEnvironmental`.

{% hint style="info" %}
Tangu 2012 **Apple imepunguza sana nguvu** ya **`DYLD_INSERT_LIBRARIES`**.

Nenda kwenye msimbo na **angalia `src/dyld.cpp`**. Katika kazi ya **`pruneEnvironmentVariables`** unaweza kuona kuwa **`DYLD_*`** huondolewa.

Katika kazi ya **`processRestricted`** sababu ya kizuizi imewekwa. Kwa kuangalia msimbo huo unaweza kuona kuwa sababu ni:

* Programu imekuwa `setuid/setgid`
* Kuwepo kwa sehemu ya `__RESTRICT/__restrict` katika binary ya macho.
* Programu ina haki (runtime imara) bila haki ya [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Angalia **haki** za binary na: `codesign -dv --entitlements :- </path/to/bin>`

Katika toleo zilizosasishwa zaidi unaweza kupata mantiki hii katika sehemu ya pili ya kazi ya **`configureProcessRestrictions`.** Walakini, kile kinachotekelezwa katika toleo jipya ni **uchunguzi wa mwanzo wa kazi** (unaweza kuondoa ikihusiana na iOS au uigaji kwani hizo hazitatumika katika macOS.
{% endhint %}

### Uthibitishaji wa Maktaba

Hata ikiwa binary inaruhusu matumizi ya **`DYLD_INSERT_LIBRARIES`** var ya mazingira, ikiwa binary inachunguza saini ya maktaba iliyo pakia haitapakia maktaba ya desturi.

Ili kupakia maktaba ya desturi, binary inahitaji kuwa na **moja ya haki zifuatazo**:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

au binary **isipaswi** kuwa na **bendera ya runtime imara** au **bendera ya uthibitishaji wa maktaba**.

Unaweza kuangalia ikiwa binary ina **runtime imara** na `codesign --display --verbose <bin>` ukichunguza bendera ya runtime katika **`CodeDirectory`** kama: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Pia unaweza kupakia maktaba ikiwa **imesainiwa na cheti sawa na binary**.

Pata mfano juu ya jinsi ya (ab)use hii na angalia vizuizi katika:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Udukuzi wa Dylib

{% hint style="danger" %}
Kumbuka kuwa **vizuizi vya Uthibitishaji wa Maktaba vilivyotangulia pia hutokea** kutekeleza mashambulizi ya Udukuzi wa Dylib.
{% endhint %}

Kama vile Windows, kwenye MacOS pia unaweza **kuteka dylibs** ili kufanya **programu** **itekeleze** **nambari** **ya kiholela** (vizuri, kwa kweli kutoka kwa mtumiaji wa kawaida hii inaweza isiwezekane kwani unaweza kuhitaji idhini ya TCC kuandika ndani ya mfuko wa `.app` na kuteka maktaba).\
Walakini, njia ambayo programu za **MacOS** zinapakia maktaba ni **mdogo zaidi** kuliko kwenye Windows. Hii inamaanisha kuwa watengenezaji wa **programu hasidi bado wanaweza kutumia mbinu hii kwa **ujanja**, lakini uwezekano wa kuweza **kutumia hii kuongeza mamlaka ni mdogo sana**.

Kwanza kabisa, ni **kawaida zaidi** kupata kuwa **binary za MacOS zinaonyesha njia kamili** kwa maktaba za kupakia. Na pili, **MacOS kamwe haitafuta** katika folda za **$PATH** kwa maktaba.

Sehemu **kuu** ya **msimbo** unaohusiana na kazi hii iko katika **`ImageLoader::recursiveLoadLibraries`** katika `ImageLoader.cpp`.

Kuna **Amri 4 tofauti za kichwa** ambazo binary ya macho inaweza kutum
* Ikiwa **`LC_LOAD_DYLIB`** ina `@rpath/library.dylib` na **`LC_RPATH`** ina `/application/app.app/Contents/Framework/v1/` na `/application/app.app/Contents/Framework/v2/`. Folders zote mbili zitatumika kupakia `library.dylib`**.** Ikiwa maktaba haipo katika `[...]/v1/` na mshambuliaji anaweza kuweka hapo ili kuchukua udhibiti wa kupakia maktaba katika `[...]/v2/` kwa sababu ya utaratibu wa njia katika **`LC_LOAD_DYLIB`**.
* **Tafuta njia za rpath na maktaba** katika faili za binary na: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Ni **njia** ya saraka inayohifadhi **faili kuu ya kutekelezwa**.

**`@loader_path`**: Ni **njia** ya **saraka** inayohifadhi **binary ya Mach-O** ambayo ina amri ya kupakia.

* Inapotumiwa katika faili ya kutekelezwa, **`@loader_path`** ni sawa na **`@executable_path`**.
* Inapotumiwa katika **dylib**, **`@loader_path`** inatoa njia ya **dylib**.
{% endhint %}

Njia ya **kuongeza mamlaka** kwa kutumia utendaji huu itakuwa katika kesi nadra ambapo **programu** inayotekelezwa **na** **root** inatafuta **maktaba fulani katika saraka ambapo mshambuliaji ana ruhusa ya kuandika.**

{% hint style="success" %}
Scanner nzuri ya kupata maktaba zilizopotea katika programu ni [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) au [**toleo la CLI**](https://github.com/pandazheng/DylibHijack).\
Ripoti nzuri na maelezo ya kiufundi kuhusu mbinu hii inaweza kupatikana [**hapa**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Mfano**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Kumbuka kuwa **mipaka ya Uthibitishaji wa Maktaba iliyopita pia inatumika** kutekeleza mashambulizi ya Dlopen hijacking.
{% endhint %}

Kutoka kwa **`man dlopen`**:

* Wakati njia **haina mstari wa kushoto** (yaani, ni jina la mwisho tu), **dlopen() itatafuta**. Ikiwa **`$DYLD_LIBRARY_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta kwanza katika saraka hiyo. Kisha, ikiwa faili ya mach-o inayopiga simu au faili kuu ya kutekelezwa inabainisha **`LC_RPATH`**, basi dyld itatafuta katika saraka hizo. Kisha, ikiwa mchakato haujazuiliwa, dyld itatafuta katika **saraka ya kazi ya sasa**. Hatimaye, kwa faili za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta katika **saraka hizo**, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa mchakato haujazuiliwa), na kisha katika **`/usr/lib/`** (habari hii ilichukuliwa kutoka kwa **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(ikiwa haijazuiliwa)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (ikiwa haijazuiliwa)
6. `/usr/lib/`

{% hint style="danger" %}
Ikiwa hakuna mstari wa kushoto katika jina, kuna njia 2 za kufanya hijacking:

* Ikiwa **`LC_RPATH`** yoyote ni **inayoweza kuandikwa** (lakini saini inakaguliwa, kwa hivyo kwa hii pia unahitaji faili ya binary kuwa haijazuiliwa)
* Ikiwa faili ya binary haijazuiliwa na kisha inawezekana kupakia kitu kutoka CWD (au kwa kudhulumu moja ya mazingira yaliyotajwa)
{% endhint %}

* Wakati njia **inaonekana kama njia ya mfumo** (kwa mfano, `/stuff/foo.framework/foo`), ikiwa **`$DYLD_FRAMEWORK_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta kwanza katika saraka hiyo kwa **njia ya sehemu ya mfumo** (kwa mfano, `foo.framework/foo`). Kisha, dyld itajaribu **njia iliyotolewa kama ilivyo** (kutumia saraka ya kazi ya sasa kwa njia za kulinganisha). Hatimaye, kwa faili za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta katika saraka hizo. Vinginevyo, itatafuta katika **`/Library/Frameworks`** (kwenye macOS ikiwa mchakato haujazuiliwa), kisha katika **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. njia iliyotolewa (kutumia saraka ya kazi ya sasa kwa njia za kulinganisha ikiwa haijazuiliwa)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (ikiwa haijazuiliwa)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Ikiwa njia ya mfumo, njia ya kudukua itakuwa:

* Ikiwa mchakato haujazuiliwa, kwa kudhulumu **njia ya kulinganisha kutoka CWD** na mazingira yaliyotajwa (hata kama haielezewi katika nyaraka ikiwa mchakato umepunguzwa, DYLD\_\* env vars huondolewa)
{% endhint %}

* Wakati njia **ina mstari wa kushoto lakini sio njia ya mfumo** (yaani, njia kamili au njia ya sehemu ya dylib), dlopen() kwanza itatafuta (ikiwa imewekwa) katika **`$DYLD_LIBRARY_PATH`** (na sehemu ya mwisho kutoka kwa njia). Kisha, dyld itajaribu **njia iliyotolewa** (kutumia saraka ya kazi ya sasa kwa njia za kulinganisha (lakini tu kwa michakato isiyojazwa)). Hatimaye, kwa faili za zamani, dyld itajaribu njia mbadala. Ikiwa **`$DYLD_FALLBACK_LIBRARY_PATH`** ilikuwa imewekwa wakati wa uzinduzi, dyld itatafuta katika saraka hizo, vinginevyo, dyld itatafuta katika **`/usr/local/lib/`** (ikiwa mchakato haujazuiliwa), na kisha katika **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. njia iliyotolewa (kutumia saraka ya kazi ya sasa kwa njia za kulinganisha ikiwa haijazuiliwa)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (ikiwa haijazuiliwa)
5. `/usr/lib/`

{% hint style="danger" %}
Ikiwa kuna mstari wa kushoto katika jina na sio njia ya mfumo, njia ya kudukua itakuwa:

* Ikiwa faili ya binary haijazuiliwa na kisha inawezekana kupakia kitu kutoka CWD au `/usr/local/lib` (au kwa kudhulumu moja ya mazingira yaliyotajwa)
{% endhint %}

{% hint style="info" %}
Angalia: Hakuna faili za usanidi za **kudhibiti utafutaji wa dlopen**.
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
Ikiwa utaandaa na kutekeleza, unaweza kuona **mahali ambapo maktaba kila ilikuwa inatafutwa bila mafanikio**. Pia, unaweza **kuchuja kumbukumbu za FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Utekaji wa Njia ya Kihusiano

Ikiwa **binary/app yenye mamlaka** (kama SUID au baadhi ya binary yenye ruhusa kubwa) ina **kupakia maktaba ya njia ya kihusiano** (kwa mfano kwa kutumia `@executable_path` au `@loader_path`) na imelemazwa Uthibitishaji wa Maktaba, inaweza kuwa inawezekana kuhamisha binary kwenye eneo ambapo mshambuliaji anaweza **kurekebisha maktaba ya njia ya kihusiano iliyopakiwa**, na kuitumia kuingiza namna kwenye mchakato.

## Kata `DYLD_*` na `LD_LIBRARY_PATH` env variables

Katika faili `dyld-dyld-832.7.1/src/dyld2.cpp` inawezekana kupata kazi ya **`pruneEnvironmentVariables`**, ambayo itaondoa chochote kipengele cha env ambacho **kinaanza na `DYLD_`** na **`LD_LIBRARY_PATH=`**.

Pia itaweka kuwa **null** hasa vipengele vya env **`DYLD_FALLBACK_FRAMEWORK_PATH`** na **`DYLD_FALLBACK_LIBRARY_PATH`** kwa binary za **suid** na **sgid**.

Kazi hii inaitwa kutoka kwa kazi ya **`_main`** ya faili hiyo hiyo ikiwalenga OSX kama ifuatavyo:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
na alama hizo za boolean zina wekwa katika faili hiyo hiyo katika nambari:
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
Hii inamaanisha kwamba ikiwa binary ni **suid** au **sgid**, au ina sehemu ya **RESTRICT** katika vichwa au ilisainiwa na bendera ya **CS\_RESTRICT**, basi **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** ni kweli na mazingira ya env hupunguzwa.

Tafadhali kumbuka kwamba ikiwa CS\_REQUIRE\_LV ni kweli, basi variables hazitapunguzwa lakini uhakiki wa maktaba utahakikisha kuwa zinatumia cheti sawa na binary ya awali.

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
### Sehemu `__RESTRICT` na kipande `__restrict`

The `__RESTRICT` section is a segment in the macOS library injection technique. It is used to restrict the access of certain functions or variables within a process. By placing these functions or variables in the `__RESTRICT` section, they can only be accessed by specific parts of the code, preventing unauthorized access or modification.

To utilize the `__RESTRICT` section, the `__restrict` keyword is used. This keyword is placed before the declaration of a function or variable that needs to be restricted. By doing so, the function or variable becomes inaccessible to other parts of the code, except for the authorized sections.

This technique enhances the security of the macOS system by limiting the potential abuse of functions or variables within a process. It helps prevent privilege escalation and unauthorized access to sensitive information.

However, it is important to note that the `__RESTRICT` section and the `__restrict` keyword are not foolproof security measures. They should be used in conjunction with other security practices to ensure the overall security of the system.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Unda cheti kipya katika Keychain na tumia kusaini faili ya binary:

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
Tafadhali kumbuka kwamba hata kama kuna binaries zilizosainiwa na bendera **`0x0(none)`**, zinaweza kupata bendera ya **`CS_RESTRICT`** kwa njia ya kudumu wakati zinapotekelezwa na kwa hivyo mbinu hii haitafanya kazi kwao.

Unaweza kuangalia ikiwa proc ina bendera hii na (pata [**csops hapa**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
Kisha angalia ikiwa bendera 0x800 imeamilishwa.
{% endhint %}

## Marejeo
* [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
