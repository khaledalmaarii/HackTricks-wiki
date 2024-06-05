# macOS Apps - Ukaguzi, kurekebisha na Fuzzing

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wame **vamiwa** na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za wizi wa habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

***

## Uchambuzi Stahiki

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}

### jtool2

Zana hii inaweza kutumika kama **mbadala** wa **codesign**, **otool**, na **objdump**, na hutoa baadhi ya vipengele vingine vya ziada. [**Pakua hapa**](http://www.newosxbook.com/tools/jtool.html) au isakinishe kwa kutumia `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** inaweza kupatikana kwenye **macOS** wakati **`ldid`** inaweza kupatikana kwenye **iOS**
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ni chombo kinachofaa kuchunguza faili za **.pkg** (wakufunzi) na kuona kilichomo ndani kabla ya kuiweka.\
Wakufunzi hawa wana skripti za bash za `preinstall` na `postinstall` ambazo waundaji wa programu hasidi kawaida hutumia kuendelea kuwepo kwa **programu hasidi**.

### hdiutil

Chombo hiki kuruhusu kufunga picha za diski za Apple (**.dmg**) ili kuzichunguza kabla ya kuziendesha:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Itakuwa imemountiwa katika `/Volumes`

### Objective-C

#### Metadata

{% hint style="danger" %}
Tafadhali kumbuka kuwa programu zilizoandikwa kwa Objective-C **huhifadhi** matangazo yao ya darasa **wakati** **inapohaririwa** kuwa [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Matangazo hayo ya darasa **ni pamoja na** jina na aina ya:
{% endhint %}

* Darasa
* Njia za darasa
* Vipengele vya kielezo cha darasa

Unaweza kupata habari hii ukitumia [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Kuita Kazi

Wakati kazi inaitwa katika binary inayotumia objective-C, msimbo uliokompiliwa badala ya kuita kazi hiyo, itaita **`objc_msgSend`**. Ambayo itaita kazi ya mwisho:

![](<../../../.gitbook/assets/image (305).png>)

Parameta ambazo kazi hii inatarajia ni:

* Parameta ya kwanza (**self**) ni "kiashiria kinachoelekeza kwa **kifungu cha darasa ambacho kinapaswa kupokea ujumbe**". Au kwa maneno rahisi, ni kitu ambacho mbinu inaitwa juu yake. Ikiwa mbinu ni mbinu ya darasa, hii itakuwa kifungu cha kitu cha darasa (kwa jumla), wakati kwa mbinu ya kifungu, self itaelekeza kwa kifungu kilichoundwa cha darasa kama kitu.
* Parameta ya pili, (**op**), ni "chaguo la mbinu inayoshughulikia ujumbe". Tena, kwa maneno rahisi, hii ni tu **jina la mbinu.**
* Parameta zilizobaki ni **thamani zozote zinazohitajika na mbinu** (op).

Angalia jinsi ya **kupata habari hii kwa urahisi na `lldb` katika ARM64** kwenye ukurasa huu:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Hoja**          | **Kijisajili**                                                  | **(kwa) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **Hoja ya 1**     | **rdi**                                                         | **self: kitu ambacho mbinu inaitwa juu yake**          |
| **Hoja ya 2**     | **rsi**                                                         | **op: jina la mbinu**                                 |
| **Hoja ya 3**     | **rdx**                                                         | **Hoja ya 1 kwa mbinu**                               |
| **Hoja ya 4**     | **rcx**                                                         | **Hoja ya 2 kwa mbinu**                               |
| **Hoja ya 5**     | **r8**                                                          | **Hoja ya 3 kwa mbinu**                               |
| **Hoja ya 6**     | **r9**                                                          | **Hoja ya 4 kwa mbinu**                               |
| **Hoja ya 7+**    | <p><strong>rsp+</strong><br><strong>(kwenye steki)</strong></p> | **Hoja ya 5+ kwa mbinu**                              |

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ni chombo cha kupata Darasa za Objc kutoka kwa dylibs.

### Swift

Kwa binaries za Swift, kwa kuwa kuna utangamano wa Objective-C, mara nyingine unaweza kutoa maelezo kutumia [class-dump](https://github.com/nygard/class-dump/) lakini sio kila wakati.

Kwa kutumia mistari ya amri ya **`jtool -l`** au **`otool -l`** ni rahisi kupata sehemu kadhaa zinazoanza na kiambishi cha **`__swift5`**:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Unaweza kupata habari zaidi kuhusu [**habari zilizohifadhiwa katika sehemu hizi katika chapisho hili la blogi**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Zaidi ya hayo, **Binaries za Swift zinaweza kuwa na alama** (kwa mfano maktaba zinahitaji kuhifadhi alama ili kazi zake ziweze kuitwa). **Alama kwa kawaida zina habari kuhusu jina la kazi** na sifa kwa njia isiyovutia, hivyo ni muhimu sana na kuna "**wadondoa alama"** ambao wanaweza kupata jina halisi:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Binaries zenye kufungwa

* Angalia entropy kubwa
* Angalia strings (kama hakuna string inayoeleweka, imefungwa)
* Packer wa UPX kwa MacOS huzalisha sehemu inayoitwa "\_\_XHDR"

## Uchambuzi wa Kudumu

{% hint style="warning" %}
Tafadhali kumbuka kwamba ili kudebugi binaries, **SIP inahitaji kuzimwa** (`csrutil disable` au `csrutil enable --without debug`) au nakala binaries kwenye folda ya muda na **ondoa saini** na `codesign --remove-signature <njia-ya-binary>` au ruhusu uchambuzi wa binary (unaweza kutumia [script hii](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Tafadhali kumbuka kwamba ili **kuweza kufuatilia binaries za mfumo**, (kama vile `cloudconfigurationd`) kwenye macOS, **SIP lazima izimwe** (kuondoa saini pekee haitafanya kazi).
{% endhint %}

### APIs

macOS ina APIs zenye kuvutia zinazotoa taarifa kuhusu michakato:

* `proc_info`: Hii ni moja kuu inayotoa taarifa nyingi kuhusu kila mchakato. Unahitaji kuwa na ruhusa ya mizizi kupata taarifa za michakato mingine lakini hauitaji ruhusa maalum au mach ports.
* `libsysmon.dylib`: Inaruhusu kupata taarifa kuhusu michakato kupitia kazi zilizofunuliwa za XPC, hata hivyo, ni muhimu kuwa na ruhusa ya `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ni mbinu inayotumika kukamata hali ya michakato, ikiwa ni pamoja na mstari wa wito wa nyuzi zote zinazoendesha. Hii ni muhimu hasa kwa kudebugi, uchambuzi wa utendaji, na kuelewa tabia ya mfumo wakati fulani. Kwenye iOS na macOS, stackshotting inaweza kufanywa kwa kutumia zana na njia kadhaa kama vile zana **`sample`** na **`spindump`**.

### Sysdiagnose

Zana hii (`/usr/bini/ysdiagnose`) kimsingi inakusanya taarifa nyingi kutoka kwenye kompyuta yako ikitekeleza amri nyingi tofauti kama vile `ps`, `zprint`...

Inapaswa kutekelezwa kama **mizizi** na daemon `/usr/libexec/sysdiagnosed` ina ruhusa za kuvutia sana kama vile `com.apple.system-task-ports` na `get-task-allow`.

Plist yake iko katika `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` ambayo inatangaza MachServices 3:

* `com.apple.sysdiagnose.CacheDelete`: Inafuta nyaraka za zamani kwenye /var/rmp
* `com.apple.sysdiagnose.kernel.ipc`: Bandari maalum 23 (kernel)
* `com.apple.sysdiagnose.service.xpc`: Kiolesura cha mode ya mtumiaji kupitia darasa la `Libsysdiagnose` Obj-C. Vigezo vitatu vinaweza kupitishwa kwenye dict (`compress`, `display`, `run`)

### Unified Logs

MacOS inazalisha magogo mengi ambayo yanaweza kuwa na manufaa sana wakati wa kukimbia programu jaribio kuelewa **inachofanya**.

Zaidi ya hayo, kuna baadhi ya magogo ambayo yatakuwa na lebo `<private>` kuficha baadhi ya taarifa **za mtumiaji** au **kompyuta**. Hata hivyo, inawezekana **kufunga cheti kufichua taarifa hizi**. Fuata maelezo kutoka [**hapa**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Kifungu cha Kushoto

Kwenye kifungu cha kushoto cha hopper inawezekana kuona alama (**Labels**) za binary, orodha ya taratibu na kazi (**Proc**) na strings (**Str**). Hizi siyo strings zote lakini zile zilizofafanuliwa katika sehemu kadhaa za faili ya Mac-O (kama vile _cstring au_ `objc_methname`).

#### Kifungu cha Kati

Kwenye kifungu cha kati unaweza kuona **msimbo uliopanguliwa**. Na unaweza kuona kama **panguliwa**, kama **grafu**, kama **kupasuliwa** na kama **binary** kwa kubofya kwenye ishara husika:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Kwa kubofya kulia kwenye kitu cha msimbo unaweza kuona **marejeo kwa/na kutoka kwa kitu hicho** au hata kubadilisha jina lake (hii haitafanyi kazi kwenye pseudocode iliyopasuliwa):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Zaidi ya hayo, kwenye **kati chini unaweza kuandika amri za python**.

#### Kifungu cha Kulia

Kwenye kifungu cha kulia unaweza kuona taarifa za kuvutia kama **historia ya urambazaji** (ili ujue jinsi ulivyofika kwenye hali ya sasa), **grafu ya wito** ambapo unaweza kuona **kazi zote zinazopiga simu kazi hii** na kazi zote ambazo **kazi hii inapiga simu**, na taarifa za **variables za eneo**.

### dtrace

Inaruhusu watumiaji kupata ufikivu kwenye programu kwa kiwango cha **chini sana** na hutoa njia kwa watumiaji kufuatilia **programu** na hata kubadilisha mtiririko wao wa utekelezaji. Dtrace hutumia **probes** ambazo zinawekwa kote kwenye kernel na ziko kwenye maeneo kama mwanzo na mwisho wa wito wa mfumo.

DTrace hutumia kazi ya **`dtrace_probe_create`** kuunda kipimo kwa kila wito wa mfumo. Vipimo hivi vinaweza kufyatuliwa kwenye **ingia na toka kwa kila wito wa mfumo**. Mwingiliano na DTrace hufanyika kupitia /dev/dtrace ambayo inapatikana kwa mtumiaji wa mizizi pekee.

{% hint style="success" %}
Ili kuwezesha Dtrace bila kuzima kabisa ulinzi wa SIP unaweza kutekeleza kwenye hali ya kupona: `csrutil enable --without dtrace`

Unaweza pia **kudtrace** au **kudtruss** binaries ambazo **umekusanya**.
{% endhint %}

Vipimo vilivyopo vya dtrace vinaweza kupatikana na:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Jina la kichunguzi linajumuisha sehemu nne: mtoa huduma, moduli, kazi, na jina (`fbt:mach_kernel:ptrace:entry`). Ikiwa haujataja sehemu fulani ya jina, Dtrace itatumia sehemu hiyo kama kichujio.

Ili kusanidi DTrace kuchochea vichunguzi na kueleza ni hatua gani za kuchukua wanapochomwa, tutahitaji kutumia lugha ya D.

Maelezo zaidi na mifano zaidi inaweza kupatikana katika [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Mifano

Chapa `man -k dtrace` ili kuorodhesha **skrini za DTrace zilizopo**. Mfano: `sudo dtruss -n binary`

* Katika mstari
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* skript
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

Ni kituo cha kufuatilia msingi. Miezi iliyodhibitishwa inaweza kupatikana katika **`/usr/share/misc/trace.codes`**.

Vyombo kama vile `latency`, `sc_usage`, `fs_usage` na `trace` hutumia hii ndani.

Kuongeza na `kdebug` `sysctl` hutumiwa juu ya `kern.kdebug` jina la nafasi na MIBs za kutumia zinaweza kupatikana katika `sys/sysctl.h` zikiwa na kazi zilizoanzishwa katika `bsd/kern/kdebug.c`.

Kuwasiliana na kdebug na mteja wa desturi kawaida hatua hizi:

* Ondoa mipangilio iliyopo na KERN\_KDSETREMOVE
* Weka mfuatilio na KERN\_KDSETBUF na KERN\_KDSETUP
* Tumia KERN\_KDGETBUF kupata idadi ya vipengele vya kawaida
* Pata mteja wako mwenyewe kutoka kwa mfuatilio na KERN\_KDPINDEX
* Wezesha ufuatiliaji na KERN\_KDENABLE
* Soma kifaa kwa kuita KERN\_KDREADTR
* Kulinganisha kila mchakato na mchakato wake piga simu KERN\_KDTHRMAP.

Ili kupata habari hii inawezekana kutumia zana ya Apple **`trace`** au zana ya desturi [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Tafadhali kumbuka kuwa Kdebug inapatikana kwa mteja 1 kwa wakati mmoja.** Kwa hivyo zana moja tu yenye nguvu ya k-debug inaweza kutekelezwa wakati huo huo.

### ktrace

`ktrace_*` APIs hutoka kwa `libktrace.dylib` ambayo hufunga zile za `Kdebug`. Kisha, mteja anaweza tu kupiga simu `ktrace_session_create` na `ktrace_events_[single/class]` kuweka maingiliano kwenye nambari maalum na kisha anza na `ktrace_start`.

Unaweza kutumia hata **SIP ikiwa imewashwa**

Unaweza kutumia kama wateja zana ya matumizi `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Au `tailspin`.

### kperf

Hii hutumika kufanya uchambuzi wa kiwango cha kernel na imejengwa kwa kutumia simu za `Kdebug`.

Kimsingi, kipimo cha jumla `kernel_debug_active` huchunguzwa na ikisetiwa huita `kperf_kdebug_handler` na simu ya `Kdebug` na anwani ya fremu ya kernel inayopiga simu. Ikiwa simu ya `Kdebug` inalingana na moja iliyochaguliwa, inapata "vitendo" vilivyowekwa kama ramani (angalia `osfmk/kperf/action.h` kwa chaguo).

Kperf ina pia jedwali la sysctl MIB: (kama mzizi) `sysctl kperf`. Nambari hizi zinaweza kupatikana katika `osfmk/kperf/kperfbsd.c`.

Zaidi ya hayo, sehemu ya Kperfs inapatikana katika `kpc`, ambayo hutoa habari kuhusu vigezo vya utendaji wa mashine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ni chombo chenye manufaa sana kuchunguza vitendo vinavyohusiana na mchakato ambavyo mchakato unafanya (kwa mfano, kufuatilia mchakato mpya ambao mchakato unazalisha).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ni chombo cha kuchapisha mahusiano kati ya michakato.\
Unahitaji kufuatilia mac yako na amri kama **`sudo eslogger fork exec rename create > cap.json`** (terminal inayoanzisha hii inahitaji FDA). Kisha unaweza kupakia json katika chombo hiki kuona mahusiano yote:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) inaruhusu kufuatilia matukio ya faili (kama vile uundaji, marekebisho, na kufutwa) ikitoa habari ya kina kuhusu matukio hayo.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ni chombo cha GUI kinachofanana na watumiaji wa Windows wanaweza kufahamu kutoka kwa _Procmon_ ya Microsoft Sysinternal. Chombo hiki kuruhusu kuanza na kuacha kurekodi aina mbalimbali za matukio, kuruhusu kuchuja matukio haya kwa makundi kama vile faili, mchakato, mtandao, n.k., na hutoa utendaji wa kuhifadhi matukio yaliyorekodiwa kwa muundo wa json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ni sehemu ya zana za Developer za Xcode - hutumika kwa kufuatilia utendaji wa programu, kutambua uvujaji wa kumbukumbu na kufuatilia shughuli za mfumo wa faili.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Inaruhusu kufuata vitendo vilivyofanywa na michakato:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### Mchunguzi wa Kazi

[**Mchunguzi wa Kazi**](https://objective-see.com/products/taskexplorer.html) ni muhimu kuona **maktaba** zinazotumiwa na faili, **faili** inazotumia, na **muunganisho wa mtandao**.\
Pia huchunguza michakato ya faili dhidi ya **virustotal** na kuonyesha habari kuhusu faili hiyo.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Katika [**chapisho hili la blogi**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) unaweza kupata mfano jinsi ya **kudebugi daemon inayotumia** **`PT_DENY_ATTACH`** kuzuia uchunguzi hata kama SIP ilikuwa imelemazwa.

### lldb

**lldb** ni chombo cha **msingi** kwa **kudebugi** faili za **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Unaweza kuweka intel flavour unapotumia lldb kwa kuunda faili iitwayo **`.lldbinit`** katika folda yako ya nyumbani na mstari ufuatao:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Ndani ya lldb, dumpisha mchakato kwa kutumia `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Amri</strong></td><td><strong>Maelezo</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Kuanza utekelezaji, ambao utaendelea bila kikomo mpaka kivinjari kikome au mchakato ukome.</td></tr><tr><td><strong>continue (c)</strong></td><td>Kuendelea na utekelezaji wa mchakato uliopo kwenye uchunguzi.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Kutekeleza maagizo ijayo. Amri hii itaruka wito wa kazi.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Kutekeleza maagizo ijayo. Tofauti na amri ya nexti, amri hii itaingia kwenye wito wa kazi.</td></tr><tr><td><strong>finish (f)</strong></td><td>Kutekeleza maagizo mengine kwenye kazi ya sasa ("frame") kurudi na kusimamisha.</td></tr><tr><td><strong>control + c</strong></td><td>Kusitisha utekelezaji. Ikiwa mchakato umekuwa ukitekelezwa (r) au kuendelea (c), hii itasababisha mchakato kusimama ...popote ulipo kwenye utekelezaji.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Wito wowote wa kazi unaoitwa main</p><p>b &#x3C;binname>`main #Kazi kuu ya bin</p><p>b set -n main --shlib &#x3C;lib_name> #Kazi kuu ya bin iliyotajwa</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Orodha ya vituo vya kuvunja</p><p>br e/dis &#x3C;num> #Wezesha/lemaza kituo cha kuvunja</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Pata msaada wa amri ya kituo cha kuvunja</p><p>help memory write #Pata msaada wa kuandika kwenye kumbukumbu</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama mnyororo ulio na mwisho wa null.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama maagizo ya mkusanyiko.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama baiti.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Hii itachapisha kitu kinachotajwa na paramu</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Tafadhali kumbuka kuwa APIs au njia nyingi za Objective-C za Apple hurudisha vitu, na hivyo inapaswa kuonyeshwa kupitia amri ya "print object" (po). Ikiwa po haizalishi matokeo yanayofaa tumia <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>kumbukumbu soma 0x000....<br>kumbukumbu soma $x0+0xf2a<br>kumbukumbu andika 0x100600000 -s 4 0x41414141 #Andika AAAA kwenye anwani hiyo<br>kumbukumbu andika -f s $rip+0x11f+7 "AAAA" #Andika AAAA kwenye anwani</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas kazi ya sasa</p><p>dis -n &#x3C;funcname> #Disas kazi</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disas kazi<br>dis -c 6 #Disas mistari 6<br>dis -c 0x100003764 -e 0x100003768 # Kutoka anwani moja hadi nyingine<br>dis -p -c 4 # Anza kwenye anwani ya sasa ya kuchambua</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Angalia safu ya 3 katika x1 reg</td></tr></tbody></table>

{% hint style="info" %}
Unapoitisha **`objc_sendMsg`** function, **rsi** register inashikilia **jina la njia** kama mnyororo ulio na mwisho wa null ("C"). Ili kuchapisha jina kupitia lldb fanya:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Uchambuzi wa Kuzuia-Dinamiki

#### Uchunguzi wa VM

* Amri **`sysctl hw.model`** inarudisha "Mac" wakati **mwenyeji ni MacOS** lakini kitu tofauti wakati ni VM.
* Kwa kucheza na thamani za **`hw.logicalcpu`** na **`hw.physicalcpu`** baadhi ya programu hasidi jaribu kugundua ikiwa ni VM.
* Baadhi ya programu hasidi pia zinaweza **kugundua** ikiwa mashine ni ya **VMware** kulingana na anwani ya MAC (00:50:56).
* Pia inawezekana kugundua ikiwa mchakato unachunguzwa na msimbo rahisi kama huu:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //mchakato unachunguzwa }`
* Inaweza pia kuita wito wa mfumo wa **`ptrace`** na bendera ya **`PT_DENY_ATTACH`**. Hii **inazuia** kivinjari kutua na kufuatilia.
* Unaweza kuangalia ikiwa **`sysctl`** au **`ptrace`** kazi inaingizwa (lakini programu hasidi inaweza kuipakia kwa njia ya dinamiki)
* Kama ilivyobainishwa katika andishi hili, “[Kushinda Mbinu za Kuzuia-Uchunguzi: toleo za macOS za ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Ujumbe Mchakato # ulitoka na **hali = 45 (0x0000002d)** kawaida ni ishara wazi kwamba lengo la uchunguzi linatumia **PT\_DENY\_ATTACH**_”
## Kuhifadhi Core

Core dumps huundwa ikiwa:

- `kern.coredump` sysctl imewekwa kama 1 (kwa chaguo-msingi)
- Ikiwa mchakato haukuwa suid/sgid au `kern.sugid_coredump` ni 1 (kwa chaguo-msingi ni 0)
- Kikomo cha `AS_CORE` kuruhusu operesheni. Inawezekana kuzuia uundaji wa core dumps kwa kuita `ulimit -c 0` na kuziruhusu tena kwa `ulimit -c unlimited`.

Katika kesi hizo, core dumps huundwa kulingana na `kern.corefile` sysctl na kuhifadhiwa kawaida katika `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **anauchambua michakato inayopasuka na kuokoa ripoti ya kupasuka kwa diski**. Ripoti ya kupasuka ina habari ambayo inaweza **kusaidia mwandishi wa programu kutambua** sababu ya kupasuka.\
Kwa maombi na michakato mingine **inayoendeshwa katika muktadha wa uzinduzi wa mtumiaji mmoja**, ReportCrash inaendeshwa kama LaunchAgent na kuokoa ripoti za kupasuka kwenye `~/Library/Logs/DiagnosticReports/` ya mtumiaji\
Kwa daemons, michakato mingine **inayoendeshwa katika muktadha wa uzinduzi wa mfumo** na michakato mingine yenye mamlaka, ReportCrash inaendeshwa kama LaunchDaemon na kuokoa ripoti za kupasuka katika `/Library/Logs/DiagnosticReports` ya mfumo

Ikiwa una wasiwasi kuhusu ripoti za kupasuka **kutumwa kwa Apple** unaweza kuzizima. Vinginevyo, ripoti za kupasuka zinaweza kuwa na manufaa **kutambua jinsi server ilivyopasuka**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Kulala

Wakati wa kufanya fuzzing kwenye MacOS ni muhimu kuhakikisha Mac haipati usingizi:

* systemsetup -setsleep Never
* pmset, System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Kukatisha SSH

Ikiwa unafanya fuzzing kupitia uhusiano wa SSH ni muhimu kuhakikisha kikao hakitakwenda siku nzima. Kwa hivyo badilisha faili ya sshd\_config na:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Wasindikaji wa Ndani

**Angalia ukurasa ufuatao** ili kujua jinsi unavyoweza kugundua ni programu ipi inayohusika na **kushughulikia mpango au itifaki iliyotajwa:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Kuhesabu Michakato ya Mtandao

Hii ni ya kuvutia kugundua michakato inayosimamia data ya mtandao:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Au tumia `netstat` au `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Inafanya kazi kwa zana za CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Inafanya kazi "inavyopaswa" na zana za GUI za macOS. Tafadhali kumbuka kuwa baadhi ya programu za macOS zinahitaji mahitaji maalum kama majina ya faili ya kipekee, ugani sahihi, kusoma faili kutoka kwa sanduku (`~/Library/Containers/com.apple.Safari/Data`)...

Baadhi ya mifano:
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Maelezo Zaidi ya Fuzzing kwenye MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Marejeo

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za kuiba taarifa**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
