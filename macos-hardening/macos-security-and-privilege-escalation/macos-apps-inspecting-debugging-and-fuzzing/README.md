# Programu za macOS - Kuchunguza, kurekebisha na Kufanya Fuzzing

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Uchambuzi Statisa

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

Zana hii inaweza kutumika kama **badala** ya **codesign**, **otool**, na **objdump**, na inatoa huduma chache za ziada. [**Pakua hapa**](http://www.newosxbook.com/tools/jtool.html) au usakinishe kwa kutumia `brew`.
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
**`Codesign`** inapatikana kwenye **macOS** wakati **`ldid`** inapatikana kwenye **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ni chombo kinachofaa kuchunguza faili za **.pkg** (wakala) na kuona kilichomo ndani kabla ya kuiweka.\
Wakala hawa wana skripti za bash za `preinstall` na `postinstall` ambazo waundaji wa programu hasidi kawaida hutumia kuweka **programu hasidi**.

### hdiutil

Chombo hiki kinaruhusu kufunga picha za diski za Apple (**.dmg**) ili kuzichunguza kabla ya kuzitumia:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Itakuwa imewekwa katika `/Volumes`

### Objective-C

#### Metadata

{% hint style="danger" %}
Tafadhali kumbuka kuwa programu zilizoandikwa kwa Objective-C **huhifadhi** maelezo yao ya darasa **wakati** **zinafanywa** **kuwa** [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Maelezo haya ya darasa **yanajumuisha** jina na aina ya:
{% endhint %}

* Darasa
* Njia za darasa
* Variables za kesi ya darasa

Unaweza kupata habari hii kwa kutumia [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Tafadhali kumbuka kuwa majina haya yanaweza kufichwa ili kufanya kurejesha kwa binary kuwa ngumu zaidi.

#### Kuita kazi

Wakati kazi inaitwa kwenye binary ambayo inatumia objective-C, badala ya kuita kazi hiyo, code iliyokompiliwa itaita **`objc_msgSend`**. Ambayo itaita kazi ya mwisho:

![](<../../../.gitbook/assets/image (560).png>)

Paramu ambazo kazi hii inatarajia ni:

* Paramu ya kwanza (**self**) ni "kiashiria kinachoelekeza kwa **kifungu cha darasa ambacho kinapaswa kupokea ujumbe**". Au kwa maneno rahisi, ni kitu ambacho njia inaitwa juu yake. Ikiwa njia ni njia ya darasa, hii itakuwa kifungu cha kitu cha darasa (kwa ujumla), wakati kwa njia ya kifungu, self itaelekeza kwa kifungu kilichotengenezwa cha darasa kama kitu.
* Paramu ya pili, (**op**), ni "chaguo la njia ambayo inashughulikia ujumbe". Tena, kwa maneno rahisi, hii ni tu **jina la njia**.
* Paramu zilizobaki ni **thamani zozote zinazohitajika na njia** (op).

| **Hoja**          | **Jisajili**                                                    | **(kwa) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **Hoja ya 1**     | **rdi**                                                         | **self: kitu ambacho njia inaitwa juu yake**           |
| **Hoja ya 2**     | **rsi**                                                         | **op: jina la njia**                                   |
| **Hoja ya 3**     | **rdx**                                                         | **hoja ya 1 kwa njia**                                 |
| **Hoja ya 4**     | **rcx**                                                         | **hoja ya 2 kwa njia**                                 |
| **Hoja ya 5**     | **r8**                                                          | **hoja ya 3 kwa njia**                                 |
| **Hoja ya 6**     | **r9**                                                          | **hoja ya 4 kwa njia**                                 |
| **Hoja ya 7+**    | <p><strong>rsp+</strong><br><strong>(kwenye stack)</strong></p> | **hoja ya 5+ kwa njia**                                |

### Swift

Kwa binary za Swift, kwa kuwa kuna utangamano wa Objective-C, mara nyingi unaweza kuchambua maelezo kwa kutumia [class-dump](https://github.com/nygard/class-dump/) lakini sio kila wakati.

Kwa kutumia amri za **`jtool -l`** au **`otool -l`**, inawezekana kupata sehemu kadhaa ambazo zinaanza na kipimo cha **`__swift5`**:
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
Unaweza kupata habari zaidi kuhusu [**habari zilizohifadhiwa katika sehemu hizi katika chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Zaidi ya hayo, **faili za Swift zinaweza kuwa na alama** (kwa mfano maktaba zinahitaji kuhifadhi alama ili kuita kazi zake). **Alama kwa kawaida zina habari kuhusu jina la kazi** na sifa kwa njia isiyovutia, hivyo ni muhimu sana na kuna "**demanglers"** ambazo zinaweza kupata jina halisi:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Programu zilizopakiwa

* Angalia kiwango cha entropy
* Angalia herufi (kama hakuna herufi inayoeleweka, inaweza kuwa imepakwa)
* Packer ya UPX kwa MacOS inazalisha sehemu inayoitwa "\_\_XHDR"

## Uchambuzi wa Kudumu

{% hint style="warning" %}
Tafadhali kumbuka kuwa ili kuchunguza programu zilizopakiwa, **SIP inahitaji kuwa imezimwa** (`csrutil disable` au `csrutil enable --without debug`) au nakala programu zipelekwe kwenye folda ya muda na **saini iondolewe** kwa kutumia `codesign --remove-signature <njia-ya-programu>` au ruhusu uchunguzi wa programu (unaweza kutumia [script hii](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Tafadhali kumbuka kuwa ili **kuchunguza programu za mfumo**, (kama vile `cloudconfigurationd`) kwenye macOS, **SIP lazima iwe imezimwa** (kuondoa saini pekee haitafanya kazi).
{% endhint %}

### Kumbukumbu Zilizounganishwa

MacOS inazalisha kumbukumbu nyingi ambazo zinaweza kuwa na manufaa sana wakati wa kukimbia programu na kujaribu kuelewa **inachofanya**.

Zaidi ya hayo, kuna kumbukumbu ambazo zitakuwa na lebo `<private>` ili **kuficha** baadhi ya habari **zinazoweza kutambulika** za mtumiaji au kompyuta. Hata hivyo, ni **inawezekana kufunga cheti** ili kufichua habari hizi. Fuata maelezo kutoka [**hapa**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Kifungu cha Kushoto

Kwenye kifungu cha kushoto cha hopper, ni muhimu kuona alama (**Lebo**) za programu, orodha ya taratibu na kazi (**Proc**) na herufi (**Str**). Hizi sio herufi zote lakini ni zile zilizofafanuliwa katika sehemu kadhaa za faili ya Mac-O (kama vile _cstring au_ `objc_methname`).

#### Kifungu cha Kati

Kwenye kifungu cha kati unaweza kuona **msimbo uliopanguliwa**. Na unaweza kuona kama **msimbo safi**, kama **grafu**, kama **kimeundwa** na kama **binari** kwa kubofya kwenye ishara husika:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Kwa kubofya kulia kwenye kifungu cha msimbo, unaweza kuona **marejeleo kwa/na kutoka kwa kifungu hicho** au hata kubadilisha jina lake (hii haifanyi kazi katika msimbo wa pseudocode ulioundwa):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Zaidi ya hayo, kwenye **kifungu cha kati chini unaweza kuandika amri za python**.

#### Kifungu cha Kulia

Kwenye kifungu cha kulia unaweza kuona habari muhimu kama **historia ya urambazaji** (ili ujue jinsi ulivyofika kwenye hali ya sasa), **grafu ya wito** ambapo unaweza kuona **kazi zote zinazowaita kazi hii** na kazi zote ambazo **kazi hii inawaita**, na habari za **majaribio ya ndani**.

### dtrace

Inaruhusu watumiaji kupata ufikiaji wa programu kwa kiwango cha **chini sana** na inatoa njia kwa watumiaji kufuatilia **programu** na hata kubadilisha mtiririko wao wa utekelezaji. Dtrace hutumia **probes** ambazo zimewekwa kote katika kernel na ziko katika maeneo kama mwanzo na mwisho wa wito wa mfumo.

DTrace hutumia kazi ya **`dtrace_probe_create`** kuunda kipimo kwa kila wito wa mfumo. Vipimo hivi vinaweza kufanywa katika **kipengele cha kuingia na kutoka kwa kila wito wa mfumo**. Mwingiliano na DTrace hufanyika kupitia /dev/dtrace ambayo inapatikana tu kwa mtumiaji wa mizizi.

{% hint style="success" %}
Ili kuwezesha Dtrace bila kuzima kabisa ulinzi wa SIP, unaweza kutekeleza kwenye hali ya kupona: `csrutil enable --without dtrace`

Unaweza pia kuchunguza programu za **`dtrace`** au **`dtruss`** ambazo **umekusanya**.
{% endhint %}

Vipimo vilivyopo vya dtrace vinaweza kupatikana kwa kutumia:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Jina la kuchunguza linajumuisha sehemu nne: mtoa huduma, moduli, kazi, na jina (`fbt:mach_kernel:ptrace:entry`). Ikiwa haujataja sehemu fulani ya jina, Dtrace itatumia sehemu hiyo kama kichujio.

Ili kusanidi DTrace kuamsha vichujio na kuelezea vitendo gani vifanyike wakati vinapochomwa, tutahitaji kutumia lugha ya D.

Maelezo zaidi na mifano zaidi yanaweza kupatikana katika [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Mifano

Changanya `man -k dtrace` ili kuorodhesha **scripti za DTrace zinazopatikana**. Mfano: `sudo dtruss -n binary`

* Katika mstari
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
# Maelezo

Hii ni hati ya bash ambayo inaweza kutumika kwa uchambuzi wa haraka wa faili za maandishi. Inachukua faili ya maandishi kama parameter na kisha inachambua faili hiyo kwa mistari ya maandishi ambayo ina maneno yaliyopewa.

## Matumizi

Unaweza kutumia hati hii kwa kufuata hatua hizi:

1. Pakua hati ya bash na uhifadhi kwenye folda yako ya kazi.
2. Fungua terminal na nenda kwenye folda ambapo hati ya bash imehifadhiwa.
3. Chapa amri ifuatayo kwenye terminal: `bash script.sh <jina_la_faili> <neno_la_kutafuta>`

    - `<jina_la_faili>`: Jina la faili ya maandishi unayotaka kuchambua.
    - `<neno_la_kutafuta>`: Neno ambalo unataka kuchunguza kwenye faili ya maandishi.

4. Baada ya kuchapisha amri hiyo, hati ya bash itachambua faili ya maandishi na itatoa matokeo ya mistari ambayo ina neno la kutafuta.

## Mfano

Ili kuelewa vizuri jinsi ya kutumia hati hii, hapa kuna mfano:

Chukulia una faili ya maandishi inayoitwa `majaribio.txt` ambayo ina mistari kadhaa ya maandishi. Unataka kuchunguza ikiwa kuna mistari ambayo ina neno "hakiki" ndani yake.

1. Pakua hati ya bash na uhifadhi kwenye folda yako ya kazi.
2. Fungua terminal na nenda kwenye folda ambapo hati ya bash imehifadhiwa.
3. Chapa amri ifuatayo kwenye terminal: `bash script.sh majaribio.txt hakiki`

Baada ya kuchapisha amri hiyo, hati ya bash itachambua faili ya maandishi `majaribio.txt` na itatoa matokeo ya mistari ambayo ina neno "hakiki".
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

dtruss is a command-line tool available on macOS that allows you to trace and inspect system calls made by an application. It can be used for debugging and analyzing the behavior of macOS applications.

To use dtruss, you need to run it with the target application as an argument. It will then display a list of system calls made by the application, along with their arguments and return values. This can be helpful in understanding how an application interacts with the operating system and identifying any potential security vulnerabilities or privilege escalation opportunities.

Here's an example of how to use dtruss:

```
$ dtruss /path/to/application
```

This will start tracing the system calls made by the specified application. You can then analyze the output to gain insights into its behavior.

It's important to note that dtruss requires root privileges to trace system calls made by other processes. Therefore, you may need to run it with sudo or as the root user.

Overall, dtruss is a powerful tool for inspecting and debugging macOS applications. By analyzing the system calls made by an application, you can gain a deeper understanding of its inner workings and potentially uncover security vulnerabilities or privilege escalation paths.
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Unaweza kutumia hii hata na **SIP imewezeshwa**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ni zana muhimu sana ya kuchunguza vitendo vinavyohusiana na mchakato ambavyo mchakato unatekeleza (kwa mfano, kufuatilia mchakato gani mpya mchakato unazalisha).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ni zana inayochapisha uhusiano kati ya michakato.\
Unahitaji kuchunguza mac yako na amri kama **`sudo eslogger fork exec rename create > cap.json`** (terminal inayozindua hii inahitaji FDA). Kisha unaweza kupakia json katika zana hii kuona uhusiano wote:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) inaruhusu kufuatilia matukio ya faili (kama vile uundaji, marekebisho, na kufuta) kwa kutoa habari za kina kuhusu matukio hayo.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ni zana ya GUI ambayo inaonekana na hisia ambazo watumiaji wa Windows wanaweza kuzijua kutoka kwa _Procmon_ ya Microsoft Sysinternal. Zana hii inaruhusu kuanza na kuacha kurekodi aina mbalimbali za matukio, inaruhusu kuchuja matukio haya kwa makundi kama faili, mchakato, mtandao, nk., na inatoa uwezo wa kuhifadhi matukio yaliyorekodiwa katika muundo wa json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ni sehemu ya zana za Maendeleo ya Xcode - hutumiwa kwa kufuatilia utendaji wa programu, kutambua uvujaji wa kumbukumbu, na kufuatilia shughuli za mfumo wa faili.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Inaruhusu kufuatilia vitendo vilivyotekelezwa na michakato:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ni muhimu kuona **maktaba** zinazotumiwa na faili ya binary, **faili** inayotumiwa na **muunganisho wa mtandao**. Pia inachunguza michakato ya binary dhidi ya **virustotal** na kuonyesha habari kuhusu binary hiyo.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Katika [**chapisho hili la blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) unaweza kupata mfano juu ya jinsi ya **kudebugi daemon inayofanya kazi** ambayo ilikuwa inatumia **`PT_DENY_ATTACH`** kuzuia kudebugi hata kama SIP ilikuwa imelemazwa.

### lldb

**lldb** ni chombo cha **kawaida** kwa ajili ya **kudebugi** faili za binary za **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Unaweza kuweka intel flavour unapotumia lldb kwa kuunda faili inayoitwa **`.lldbinit`** katika folda yako ya nyumbani na mstari ufuatao:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Ndani ya lldb, dumpisha mchakato na `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Amri</strong></td><td><strong>Maelezo</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Kuanza utekelezaji, ambao utaendelea bila kikomo hadi kizuizi kikubwa kisipigwe au mchakato ukome.</td></tr><tr><td><strong>continue (c)</strong></td><td>Kuendelea na utekelezaji wa mchakato uliopimwa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Tekeleza maagizo inayofuata. Amri hii itaruka wito wa kazi.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Tekeleza maagizo inayofuata. Kinyume na amri ya nexti, amri hii itaingia kwenye wito wa kazi.</td></tr><tr><td><strong>finish (f)</strong></td><td>Tekeleza maagizo yaliyobaki katika kazi ya sasa ("frame") na kusimamisha.</td></tr><tr><td><strong>control + c</strong></td><td>Sitisha utekelezaji. Ikiwa mchakato umekimbia (r) au kuendelea (c), hii itasababisha mchakato kusimama ...popote inapotekelezwa kwa sasa.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Wito wowote wa kazi unaitwa main</p><p>b &#x3C;binname>`main #Wito wa kazi kuu ya bin</p><p>b set -n main --shlib &#x3C;lib_name> #Wito wa kazi kuu ya bin iliyotajwa</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Orodha ya kizuizi</p><p>br e/dis &#x3C;num> #Wezesha/lemaza kizuizi</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Pata msaada wa amri ya kizuizi</p><p>help memory write #Pata msaada wa kuandika kwenye kumbukumbu</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">muundo</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama herufi zilizomalizika na sifuri.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama maagizo ya mkutano.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama herufi.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Hii itaonyesha kitu kinachohusishwa na paramu</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Taarifa kwamba API nyingi za Objective-C za Apple au njia zinarudisha vitu, na kwa hivyo zinapaswa kuonyeshwa kupitia amri ya "print object" (po). Ikiwa po haizalishi matokeo yanayofaa tumia <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Andika AAAA kwenye anwani hiyo<br>memory write -f s $rip+0x11f+7 "AAAA" #Andika AAAA kwenye anwani</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas kazi ya sasa</p><p>dis -n &#x3C;funcname> #Disas kazi</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disas kazi<br>dis -c 6 #Disas mistari 6<br>dis -c 0x100003764 -e 0x100003768 # Kutoka anwani moja hadi nyingine<br>dis -p -c 4 # Anza kwenye anwani ya sasa ya kufasiri</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Angalia safu ya 3 katika x1 reg</td></tr></tbody></table>

{% hint style="info" %}
Wakati wa kuita **`objc_sendMsg`** function, usajili wa **rsi** unashikilia **jina la njia** kama herufi zilizomalizika na sifuri ("C"). Ili kuonyesha jina kupitia lldb fanya:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Uchambuzi wa Kuzuia-Dinamiki

#### Ugunduzi wa VM

* Amri ya **`sysctl hw.model`** inarudi "Mac" wakati **mwenyeji ni MacOS** lakini kitu tofauti wakati ni VM.
* Kwa kucheza na thamani za **`hw.logicalcpu`** na **`hw.physicalcpu`** baadhi ya programu hasidi jaribu kugundua ikiwa ni VM.
* Baadhi ya programu hasidi pia zinaweza **kugundua** ikiwa mashine ni ya VMware kulingana na anwani ya MAC (00:50:56).
* Pia inawezekana kugundua ikiwa mchakato unafanyiwa uchunguzi na nambari rahisi kama hii:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //mchakato unafanyiwa uchunguzi }`
* Inaweza pia kuita wito wa mfumo wa **`ptrace`** na bendera ya **`PT_DENY_ATTACH`**. Hii **inazuia** mchunguzi kushikamana na kufuatilia.
* Unaweza kuangalia ikiwa **`sysctl`** au **`ptrace`** kazi inaingizwa (lakini programu hasidi inaweza kuiongeza kwa kudumu)
* Kama ilivyobainishwa katika nakala hii, “[Kushinda Mbinu za Kuzuia-Uchunguzi: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
"_Ujumbe Mchakato # ulitoka na **hali = 45 (0x0000002d)** kawaida ni ishara ya wazi kwamba lengo la uchunguzi linatumia **PT\_DENY\_ATTACH**_"
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **huchambua michakato inayopata ajali na kuokoa ripoti ya ajali kwenye diski**. Ripoti ya ajali ina habari ambazo zinaweza **kusaidia msanidi programu kugundua** sababu ya ajali.\
Kwa maombi na michakato mingine **inayofanya kazi katika muktadha wa uzinduzi wa mtumiaji mmoja**, ReportCrash inafanya kazi kama LaunchAgent na kuokoa ripoti za ajali kwenye `~/Library/Logs/DiagnosticReports/` ya mtumiaji.\
Kwa daemons, michakato mingine **inayofanya kazi katika muktadha wa uzinduzi wa mfumo** na michakato mingine yenye mamlaka, ReportCrash inafanya kazi kama LaunchDaemon na kuokoa ripoti za ajali kwenye `/Library/Logs/DiagnosticReports` ya mfumo.

Ikiwa una wasiwasi juu ya ripoti za ajali **zikitumwa kwa Apple**, unaweza kuzizima. Ikiwa sivyo, ripoti za ajali zinaweza kuwa na manufaa katika **kugundua jinsi seva ilivyoanguka**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Kulala

Wakati wa kufanya fuzzing kwenye MacOS, ni muhimu kuhakikisha kuwa Mac haipati usingizi:

* systemsetup -setsleep Kamwe
* pmset, Mapendeleo ya Mfumo
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Kukatisha Mawasiliano ya SSH

Ikiwa unafanya fuzzing kupitia kikao cha SSH, ni muhimu kuhakikisha kuwa kikao hakitakatika. Kwa hivyo, badilisha faili ya sshd\_config na:

* TCPKeepAlive Ndiyo
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Wachunguzi wa Ndani

**Angalia ukurasa ufuatao** ili kujua jinsi unavyoweza kugundua ni programu gani inayohusika na **kushughulikia mpango au itifaki iliyotajwa:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Kuhesabu Mchakato wa Mtandao

Hii ni muhimu kupata mchakato ambao unashughulikia data ya mtandao:
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

Inafanya kazi na zana za GUI za macOS. Tafadhali kumbuka kuwa baadhi ya programu za macOS zinahitaji mahitaji maalum kama majina ya faili ya kipekee, ugani sahihi, na kusoma faili kutoka kwenye sanduku la mchanga (`~/Library/Containers/com.apple.Safari/Data`)...

Baadhi ya mifano:

{% code overflow="wrap" %}
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

### Maelezo Zaidi Kuhusu Fuzzing kwenye MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Marejeo

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
