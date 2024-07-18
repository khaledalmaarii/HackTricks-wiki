# macOS-toepassings - Inspeksie, foutopsporing en Fuzzing

{% hint style="success" %}
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steelmalware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekening-oorneem te bekamp en lospryse-aanvalle as gevolg van inligtingsteelmalware te voorkom.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

***

## Statische Analise

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
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
```bash
nm -m ./tccd # List of symbols
```
### jtool2 & Disarm

Jy kan [**disarm hier aflaai**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Jy kan [**jtool2 hier aflaai**](http://www.newosxbook.com/tools/jtool.html) of dit installeer met `brew`.
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
{% hint style="danger" %}
**jtool is verouderd ten gunste van disarm**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`** kan gevind word in **macOS** terwyl **`ldid`** gevind kan word in **iOS**
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
### VerdagtePakket

[**VerdagtePakket**](https://mothersruin.com/software/SuspiciousPackage/get.html) is 'n nuttige hulpmiddel om **.pkg** lêers (installateurs) te inspekteer en te sien wat binne-in is voordat dit geïnstalleer word. Hierdie installateurs het `preinstall` en `postinstall` bash-skripte wat malware-skrywers gewoonlik misbruik om die malware te **volhard**.

### hdiutil

Hierdie hulpmiddel maak dit moontlik om Apple skyfafbeeldings (**.dmg**) lêers te **mount** om hulle te inspekteer voordat enigiets uitgevoer word:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Dit sal in `/Volumes` aangeheg word

### Gepakte bineêre lêers

* Kontroleer vir hoë entropie
* Kontroleer die strings (is daar byna geen verstaanbare string nie, gepak)
* Die UPX-pakker vir MacOS genereer 'n afdeling genaamd "\_\_XHDR"

## Statische Objective-C analise

### Metadata

{% hint style="danger" %}
Let daarop dat programme geskryf in Objective-C hul klasverklarings behou wanneer dit gekompileer word na [Mach-O bineêre lêers](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Sulke klasverklarings sluit die naam en tipe van in:
{% endhint %}

* Die gedefinieerde koppelvlakke
* Die koppelvlakmetodes
* Die koppelvlak-instansie veranderlikes
* Die gedefinieerde protokolle

Let daarop dat hierdie name geobfuskeer kan word om die omkeer van die bineêre lêer moeiliker te maak.

### Funksie-oproep

Wanneer 'n funksie in 'n bineêre lêer wat Objective-C gebruik, geroep word, sal die gekompileerde kode in plaas daarvan daardie funksie roep, **`objc_msgSend`** roep. Dit sal die finale funksie roep:

![](<../../../.gitbook/assets/image (305).png>)

Die parameters wat hierdie funksie verwag is:

* Die eerste parameter (**self**) is " 'n aanwyser wat wys na die **instansie van die klas wat die boodskap moet ontvang** ". Of meer eenvoudig gestel, dit is die objek waarop die metode opgeroep word. As die metode 'n klasmetode is, sal dit 'n instansie van die klasobjek wees (as geheel), terwyl vir 'n instansiemetode sal self wys na 'n geïnstantieerde instansie van die klas as 'n objek.
* Die tweede parameter, (**op**), is "die selektor van die metode wat die boodskap hanteer". Weereens, meer eenvoudig gestel, dit is net die **naam van die metode**.
* Die oorblywende parameters is enige **waardes wat deur die metode benodig word** (op).

Sien hoe om hierdie inligting maklik te kry met `lldb` in ARM64 op hierdie bladsy:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argument**      | **Register**                                                    | **(vir) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ste argument** | **rdi**                                                         | **self: objek waarop die metode opgeroep word**       |
| **2de argument**  | **rsi**                                                         | **op: naam van die metode**                           |
| **3de argument**  | **rdx**                                                         | **1ste argument vir die metode**                      |
| **4de argument**  | **rcx**                                                         | **2de argument vir die metode**                      |
| **5de argument**  | **r8**                                                          | **3de argument vir die metode**                      |
| **6de argument**  | **r9**                                                          | **4de argument vir die metode**                      |
| **7de+ argument** | <p><strong>rsp+</strong><br><strong>(op die stok)</strong></p> | **5de+ argument vir die metode**                     |

### Stort ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) is 'n instrument om Objective-C bineêre lêers te klas-dump. Die github spesifiseer dylibs maar dit werk ook met uitvoerbare lêers.
```bash
./dynadump dump /path/to/bin
```
Ten tyde van die skryf van hierdie stuk is **tans die een wat die beste werk**.

#### Gewone gereedskap
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) is die oorspronklike gereedskap om verklarings vir die klasse, kategorieë en protokolle in ObjetiveC geformateerde kode te genereer.

Dit is oud en nie onderhou nie, so dit sal waarskynlik nie behoorlik werk nie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) is 'n moderne en kruisplatform Objective-C klasse dump. Vergeleke met bestaande gereedskappe, kan iCDump onafhanklik van die Apple-ekosisteem hardloop en dit bloot Python-bindings.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statische Swift-analise

Met Swift-binêre lêers, aangesien daar Objective-C-verenigbaarheid is, kan jy soms verklarings onttrek deur [class-dump](https://github.com/nygard/class-dump/) te gebruik, maar nie altyd nie.

Met die **`jtool -l`** of **`otool -l`** opdragreëls is dit moontlik om verskeie seksies te vind wat met die **`__swift5`** voorvoegsel begin:
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
Jy kan meer inligting oor die **inligting wat in hierdie afdeling gestoor word in hierdie blogpos** vind.

Verder, **Swift-binêre lêers mag simbole hê** (byvoorbeeld biblioteke moet simbole stoor sodat sy funksies geroep kan word). Die **simbole het gewoonlik die inligting oor die funksienaam** en attr op 'n lelike manier, so hulle is baie nuttig en daar is "**demanglers"** wat die oorspronklike naam kan kry:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamiese Analise

{% hint style="warning" %}
Let daarop dat ten einde bineêre lêers te ontleed, **moet SIP gedeaktiveer wees** (`csrutil disable` of `csrutil enable --without debug`) of kopieer die bineêre lêers na 'n tydelike vouer en **verwyder die handtekening** met `codesign --remove-signature <binede-pad>` of staan die ontleed van die bineêre lêer toe (jy kan [hierdie skripsie](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) gebruik)
{% endhint %}

{% hint style="warning" %}
Let daarop dat ten einde **sisteem bineêre lêers** (soos `cloudconfigurationd`) op macOS te **instrumenteer**, **moet SIP gedeaktiveer wees** (net die handtekening verwyder sal nie werk nie).
{% endhint %}

### API's

macOS stel 'n paar interessante API's bloot wat inligting oor die prosesse gee:

* `proc_info`: Dit is die belangrikste een wat baie inligting oor elke proses gee. Jy moet 'n beheerder wees om ander prosesse se inligting te kry, maar jy het nie spesiale toestemmings of mach-poorte nodig nie.
* `libsysmon.dylib`: Dit maak dit moontlik om inligting oor prosesse te kry via XPC blootgestelde funksies, maar dit is nodig om die toestemming `com.apple.sysmond.client` te hê.

### Stackshot & microstackshots

**Stackshotting** is 'n tegniek wat gebruik word om die toestand van die prosesse vas te lê, insluitend die oproepstapel van alle lopende drade. Dit is veral nuttig vir ontleed, prestasie-analise, en om die gedrag van die stelsel op 'n spesifieke tydstip te verstaan. Op iOS en macOS kan stackshotting uitgevoer word met verskeie gereedskap en metodes soos die gereedskap **`sample`** en **`spindump`**.

### Sysdiagnose

Hierdie gereedskap (`/usr/bini/ysdiagnose`) versamel basies baie inligting van jou rekenaar deur tientalle verskillende bevele uit te voer soos `ps`, `zprint`...

Dit moet as **beheerder** uitgevoer word en die daemon `/usr/libexec/sysdiagnosed` het baie interessante toestemmings soos `com.apple.system-task-ports` en `get-task-allow`.

Die plist daarvan is geleë in `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` wat 3 MachServices verklaar:

* `com.apple.sysdiagnose.CacheDelete`: Verwyder ou argiewe in /var/rmp
* `com.apple.sysdiagnose.kernel.ipc`: Spesiale poort 23 (kernel)
* `com.apple.sysdiagnose.service.xpc`: Gebruikermodus koppelvlak deur `Libsysdiagnose` Obj-C klas. Drie argumente in 'n dict kan deurgegee word (`compress`, `display`, `run`)

### Eenvormige Logboeke

MacOS genereer baie logboeke wat baie nuttig kan wees wanneer 'n toepassing uitgevoer word om te probeer verstaan **wat dit doen**.

Daar is ook logboeke wat die tag `<private>` sal bevat om sekere **gebruiker** of **rekenaar** **identifiseerbare** inligting te **versteek**. Dit is egter moontlik om 'n sertifikaat te **installeer om hierdie inligting bekend te maak**. Volg die verduidelikings van [**hier**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Linker paneel

In die linker paneel van hopper is dit moontlik om die simbole (**Etikette**) van die bineêre lêer, die lys van prosedures en funksies (**Proc**) en die strings (**Str**) te sien. Dit is nie al die strings nie, maar diegene wat in verskeie dele van die Mac-O lêer gedefinieer is (soos _cstring of_ `objc_methname`).

#### Middelste paneel

In die middelste paneel kan jy die **ontleedde kode** sien. En jy kan dit sien as **rof** ontleed, as **grafiek**, as **ontleed** en as **binede** deur op die betrokke ikoon te klik:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Deur regs te klik op 'n kode objek kan jy **verwysings na/van daardie objek** sien of selfs sy naam verander (dit werk nie in ontledde pseudokode nie):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Verder kan jy in die **middel onder python bevele skryf**.

#### Regter paneel

In die regter paneel kan jy interessante inligting sien soos die **navigasiegeskiedenis** (sodat jy weet hoe jy by die huidige situasie uitgekom het), die **oproepgrafiek** waar jy al die **funksies kan sien wat hierdie funksie aanroep** en al die funksies wat **hierdie funksie aanroep**, en **plaaslike veranderlikes** inligting.

### dtrace

Dit gee gebruikers toegang tot toepassings op 'n uiters **lae vlak** en bied 'n manier vir gebruikers om **programme te volg** en selfs hul uitvoervloei te verander. Dtrace gebruik **sondes** wat **deur die hele kernel geplaas is** en is op plekke soos die begin en einde van stelseloproepe.

DTrace gebruik die **`dtrace_probe_create`** funksie om 'n sonde vir elke stelseloproep te skep. Hierdie sonde kan in die **ingangs- en uitgangspunt van elke stelseloproep** afgevuur word. Die interaksie met DTrace vind plaas deur /dev/dtrace wat slegs beskikbaar is vir die rootgebruiker.

{% hint style="success" %}
Om Dtrace te aktiveer sonder om SIP-beskerming heeltemal te deaktiveer, kan jy in herstelmodus uitvoer: `csrutil enable --without dtrace`

Jy kan ook **`dtrace`** of **`dtruss`** bineêre lêers wat **jy saamgestel het**, gebruik.
{% endhint %}

Die beskikbare sonde van dtrace kan verkry word met:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Die sondenaam bestaan uit vier dele: die verskaffer, module, funksie, en naam (`fbt:mach_kernel:ptrace:entry`). As jy nie 'n deel van die naam spesifiseer nie, sal Dtrace daardie deel as 'n jokerteken toepas.

Om DTrace te konfigureer om sondes te aktiveer en om te spesifiseer watter aksies uitgevoer moet word wanneer hulle afgaan, sal ons die D-taal moet gebruik.

'n Meer gedetailleerde verduideliking en meer voorbeelde kan gevind word op [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Voorbeelde

Voer `man -k dtrace` uit om die **DTrace-skripte wat beskikbaar is** te lys. Voorbeeld: `sudo dtruss -n binary`

* In lyn
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* skrips
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

Dit is 'n kernel naspeurfasiliteit. Die gedokumenteerde kodes kan gevind word in **`/usr/share/misc/trace.codes`**.

Gereedskap soos `latency`, `sc_usage`, `fs_usage` en `trace` gebruik dit intern.

Om met `kdebug` te kommunikeer, word `sysctl` oor die `kern.kdebug`-naamruimte gebruik en die MIB's wat gebruik moet word, kan gevind word in `sys/sysctl.h` met die funksies wat geïmplementeer is in `bsd/kern/kdebug.c`.

Om met kdebug te kommunikeer met 'n aangepaste klient, is hierdie gewoonlik die stappe:

* Verwyder bestaande instellings met KERN\_KDSETREMOVE
* Stel naspeuring in met KERN\_KDSETBUF en KERN\_KDSETUP
* Gebruik KERN\_KDGETBUF om die aantal bufferinskrywings te kry
* Kry die eie klient uit die naspeuring met KERN\_KDPINDEX
* Skakel naspeuring in met KERN\_KDENABLE
* Lees die buffer deur KERN\_KDREADTR te roep
* Om elke draad met sy proses te koppel, roep KERN\_KDTHRMAP aan.

Om hierdie inligting te verkry, is dit moontlik om die Apple-gereedskap **`trace`** of die aangepaste gereedskap [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** te gebruik.**

**Let daarop dat Kdebug slegs beskikbaar is vir 1 kliënt op 'n slag.** Slegs een k-debug aangedrewe gereedskap kan dus gelyktydig uitgevoer word.

### ktrace

Die `ktrace_*` API's kom van `libktrace.dylib` wat dié van `Kdebug` omvou. Dan kan 'n klient net `ktrace_session_create` en `ktrace_events_[single/class]` noem om terugroependes op spesifieke kodes in te stel en dit dan met `ktrace_start` te begin.

Jy kan hierdie selfs met **SIP geaktiveer** gebruik.

Jy kan as kliënte die nutsprogram `ktrace` gebruik:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Of `tailspin`.

### kperf

Dit word gebruik om 'n kernvlakprofiel te maak en dit is gebou met behulp van `Kdebug` oproepe.

Basies word die globale veranderlike `kernel_debug_active` nagegaan en as dit ingestel is, roep dit `kperf_kdebug_handler` aan met die `Kdebug` kode en adres van die kernraamoproep. As die `Kdebug` kode een gekies is, kry dit die "aksies" wat gekonfigureer is as 'n bitkaart (kyk na `osfmk/kperf/action.h` vir die opsies).

Kperf het ook 'n sysctl MIB-tabel: (as root) `sysctl kperf`. Hierdie kodes kan gevind word in `osfmk/kperf/kperfbsd.c`.

Verder bly 'n subset van Kperfs funksionaliteit in `kpc`, wat inligting oor masjienprestasiemeters verskaf.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is 'n baie nuttige instrument om die prosesverwante aksies wat 'n proses uitvoer, te monitor (byvoorbeeld, monitor watter nuwe prosesse 'n proses skep).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) is 'n instrument wat die verhoudings tussen prosesse afdruk.\
Jy moet jou Mac monitor met 'n bevel soos **`sudo eslogger fork exec rename create > cap.json`** (die terminaal wat dit lanceer, vereis FDA). En dan kan jy die json in hierdie instrument laai om al die verhoudings te sien:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) maak dit moontlik om lêergebeure (soos skepping, wysigings en verwyderings) te monitor en bied gedetailleerde inligting oor sulke gebeure.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) is 'n GUI-instrument met die uiterlike wat Windows-gebruikers mag ken van Microsoft Sysinternal se _Procmon_. Hierdie instrument maak dit moontlik om die opname van verskeie tipes gebeure te begin en te stop, maak dit moontlik om hierdie gebeure te filter volgens kategorieë soos lêer, proses, netwerk, ens., en bied die funksionaliteit om die opgeneemde gebeure in 'n json-formaat te stoor.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) is deel van Xcode se Ontwikkelaarshulpmiddels – gebruik vir die monitor van programprestasie, identifisering van geheuelekke en opsporing van lêersisteemaktiwiteit.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Maak dit moontlik om aksies wat deur prosesse uitgevoer word, te volg:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### Taakontleder

[**Taakontleder**](https://objective-see.com/products/taskexplorer.html) is nuttig om die **biblioteke** wat deur 'n binêre lêer gebruik word, die **lêers** wat dit gebruik en die **netwerk**-verbindings te sien.\
Dit kontroleer ook die binêre prosesse teen **virustotal** en toon inligting oor die binêre lêer.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

In [**hierdie blogpos**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) kan jy 'n voorbeeld vind oor hoe om 'n lopende duiwel te **debug** wat **`PT_DENY_ATTACH`** gebruik om te voorkom dat dit gedebug word selfs as SIP uitgeschakel is.

### lldb

**lldb** is die de **facto gereedskap** vir **macOS** binêre **debugging**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Jy kan die intel geur instel wanneer jy lldb gebruik deur 'n lêer genaamd **`.lldbinit`** in jou tuisgids te skep met die volgende lyn:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Binne lldb, dump 'n proses met `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Opdrag</strong></td><td><strong>Beskrywing</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Begin uitvoering, wat ononderbroke sal voortgaan totdat 'n breekpunt getref word of die proses eindig.</td></tr><tr><td><strong>continue (c)</strong></td><td>Laat die uitvoering van die gedebugde proses voortgaan.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Voer die volgende instruksie uit. Hierdie opdrag sal oorspring oor funksie-oproepe.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Voer die volgende instruksie uit. Anders as die nexti-opdrag, sal hierdie opdrag in funksie-oproepe stap.</td></tr><tr><td><strong>finish (f)</strong></td><td>Voer die res van die instruksies in die huidige funksie ("raam") uit en hou op.</td></tr><tr><td><strong>control + c</strong></td><td>Onderbreek uitvoering. As die proses uitgevoer (r) of voortgesit (c) is, sal dit veroorsaak dat die proses halthou waar dit tans uitgevoer word.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Enige funksie genoem main</p><p>b &#x3C;binnaam>`main #Hoof funksie van die bin</p><p>b set -n main --shlib &#x3C;lib_naam> #Hoof funksie van die aangeduide bin</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Breekpunt lys</p><p>br e/dis &#x3C;nommer> #Aktiveer/Deaktiveer breekpunt</p><p>breakpoint delete &#x3C;nommer></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Kry hulp van breekpunt-opdrag</p><p>help memory write #Kry hulp om in die geheue te skryf</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">formaat</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/geheue adres></strong></td><td>Vertoon die geheue as 'n nul-geëindigde string.</td></tr><tr><td><strong>x/i &#x3C;reg/geheue adres></strong></td><td>Vertoon die geheue as samestellingsinstruksie.</td></tr><tr><td><strong>x/b &#x3C;reg/geheue adres></strong></td><td>Vertoon die geheue as byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Dit sal die voorwerp wat deur die parameter verwys word, druk</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Merk op dat die meeste van Apple se Objective-C API's of metodes voorwerpe teruggee, en dus vertoon moet word via die "druk voorwerp" (po) opdrag. As po nie 'n betekenisvolle uitset lewer nie, gebruik <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Skryf AAAA in daardie adres<br>memory write -f s $rip+0x11f+7 "AAAA" #Skryf AAAA in die adres</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Ontas huidige funksie</p><p>dis -n &#x3C;funksienaam> #Ontas funksie</p><p>dis -n &#x3C;funksienaam> -b &#x3C;basenaam> #Ontas funksie<br>dis -c 6 #Ontas 6 lyne<br>dis -c 0x100003764 -e 0x100003768 # Van een adres tot die ander<br>dis -p -c 4 # Begin in die huidige adres met ontas</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Kontroleer 'n reeks van 3 komponente in x1 reg</td></tr></tbody></table>

{% hint style="info" %}
Wanneer die **`objc_sendMsg`**-funksie geroep word, hou die **rsi** register die **naam van die metode** as 'n nul-geëindigde ("C") string. Om die naam via lldb af te druk:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dinamiese Analise

#### VM opsporing

* Die opdrag **`sysctl hw.model`** gee "Mac" terug wanneer die **gasheer 'n MacOS** is, maar iets anders wanneer dit 'n VM is.
* Deur te speel met die waardes van **`hw.logicalcpu`** en **`hw.physicalcpu`** probeer sommige kwaadwillige sagteware om te bepaal of dit 'n VM is.
* Sommige kwaadwillige sagteware kan ook **vasstel** of die masjien **VMware**-gebaseer is op grond van die MAC-adres (00:50:56).
* Dit is ook moontlik om te vind of 'n proses gedebugeer word met 'n eenvoudige kode soos:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proses wat gedebugeer word }`
* Dit kan ook die **`ptrace`**-sisteemaanroep aanroep met die **`PT_DENY_ATTACH`**-vlag. Dit **voorkom** dat 'n deb**u**gger kan aanheg en naspeur.
* Jy kan nagaan of die **`sysctl`** of **`ptrace`**-funksie **ingevoer** word (maar die kwaadwillige sagteware kan dit dinamies invoer)
* Soos opgemerk in hierdie uiteensetting, “[Anti-Debug Tegnieke Oorwin: macOS ptrace variasies](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Die boodskap Proses # het geëindig met **status = 45 (0x0000002d)** is gewoonlik 'n duidelike teken dat die doel van die debuut **PT\_DENY\_ATTACH** gebruik_”
## Kernafval

Kernafval word geskep as:

- `kern.coredump` sysctl is ingestel op 1 (standaard)
- As die proses nie suid/sgid was nie of `kern.sugid_coredump` is 1 (standaard is 0)
- Die `AS_CORE` limiet die operasie toelaat. Dit is moontlik om kernafval skepping te onderdruk deur `ulimit -c 0` te roep en hulle weer in te skakel met `ulimit -c unlimited`.

In daardie gevalle word die kernafval gegenereer volgens `kern.corefile` sysctl en gewoonlik gestoor in `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiseer afbreekprosesse en stoor 'n afbreekverslag op die skyf**. 'n Afbreekverslag bevat inligting wat 'n ontwikkelaar kan help om die oorsaak van 'n afbreek te diagnoseer.\
Vir aansoeke en ander prosesse wat **in die per-gebruiker launchd konteks loop**, hardloop ReportCrash as 'n LaunchAgent en stoor afbreekverslae in die gebruiker se `~/Library/Logs/DiagnosticReports/`\
Vir daemons, ander prosesse wat **in die stelsel launchd konteks loop** en ander bevoorregte prosesse, hardloop ReportCrash as 'n LaunchDaemon en stoor afbreekverslae in die stelsel se `/Library/Logs/DiagnosticReports`

As jy bekommerd is oor afbreekverslae **wat aan Apple gestuur word** kan jy hulle deaktiveer. Indien nie, kan afbreekverslae nuttig wees om **uit te vind hoe 'n bediener afgebreek het**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Slaap

Tydens die fuzzing in 'n MacOS is dit belangrik om die Mac nie te laat slaap nie:

* systemsetup -setsleep Never
* pmset, Sisteemvoorkeure
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Ontkoppel

As jy fuzzing doen via 'n SSH-verbinding is dit belangrik om seker te maak dat die sessie nie gaan verstryk nie. Verander dus die sshd\_config-lêer met:

* TCPKeepAlive Ja
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interne Handlers

**Kyk na die volgende bladsy** om uit te vind hoe jy kan bepaal watter toepassing verantwoordelik is vir **die hanteer van die gespesifiseerde skema of protokol:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerating Netwerkprosesse

Dit is interessant om prosesse te vind wat netwerkdata bestuur:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Of gebruik `netstat` of `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Werk vir CLI-gereedskap

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Dit "**werk net"** met macOS GUI-gereedskap. Let op dat sommige macOS-toepassings spesifieke vereistes het soos unieke lêernaam, die regte uitbreiding, moet die lêers lees vanuit die sandboks (`~/Library/Containers/com.apple.Safari/Data`)...

Sommige voorbeelde:

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

### Meer Fuzzing MacOS Inligting

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Verwysings

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **diefstal malware** gekompromitteer is.

Hul primêre doel van WhiteIntel is om rekening-oorneemings en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteel-malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
