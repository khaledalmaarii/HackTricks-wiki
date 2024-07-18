# macOS Aplikacije - Inspekcija, debugovanje i Faziranje

{% hint style="success" %}
Naučite i vežbajte AWS Hakovanje: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-web**-om koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu podataka**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb stranicu i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Statistička Analiza

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
{% код препун="wrap" %}
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

Možete [**preuzeti disarm odavde**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Možete [**preuzeti jtool2 ovde**](http://www.newosxbook.com/tools/jtool.html) ili ga instalirati pomoću `brew`.
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
**jtool je zastareo u korist disarm-a**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`** se može pronaći u **macOS-u**, dok se **`ldid`** može pronaći u **iOS-u**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koristan za inspekciju **.pkg** fajlova (instalatera) i videti šta se nalazi unutra pre instaliranja.\
Ovi instalateri imaju `preinstall` i `postinstall` bash skripte koje zlonamerni autori obično zloupotrebljavaju da bi **upornost** **zlonamernog softvera**.

### hdiutil

Ovaj alat omogućava da se **montiraju** Apple disk slike (**.dmg**) fajlovi radi inspekcije pre pokretanja bilo čega:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Biće montiran u `/Volumes`

### Pakovani binarni fajlovi

* Provera visoke entropije
* Provera stringova (da li postoji skoro nijedan razumljiv string, pakovan)
* UPX paket za MacOS generiše sekciju nazvanu "\_\_XHDR"

## Statička analiza Objective-C

### Metapodaci

{% hint style="danger" %}
Imajte na umu da programi napisani u Objective-C **zadržavaju** svoje deklaracije klasa **kada** **se kompajliraju** u [Mach-O binarne fajlove](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **uključuju** ime i tip:
{% endhint %}

* Definisane interfejse
* Metode interfejsa
* Instance varijable interfejsa
* Definisane protokole

Imajte na umu da ova imena mogu biti zamućena kako bi se otežalo reverzno inženjerstvo binarnog fajla.

### Pozivanje funkcija

Kada se funkcija poziva u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto pozivanja te funkcije, pozvaće **`objc_msgSend`**. Što će pozvati konačnu funkciju:

![](<../../../.gitbook/assets/image (305).png>)

Parametri koje ova funkcija očekuje su:

* Prvi parametar (**self**) je "pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**". Jednostavnije rečeno, to je objekat na koji se poziva metoda. Ako je metoda klasna metoda, ovo će biti instanca objekta klase (u celini), dok će za instancu metodu, self će pokazivati na instanciranu instancu klase kao objekat.
* Drugi parametar, (**op**), je "selektor metode koja obrađuje poruku". Ponovo, jednostavnije rečeno, ovo je samo **ime metode**.
* Preostali parametri su bilo **vrednosti koje su potrebne metodi** (op).

Pogledajte kako **lako dobiti ove informacije sa `lldb` u ARM64** na ovoj stranici:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argument**      | **Registar**                                                    | **(za) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**  | **rdi**                                                         | **self: objekat na koji se poziva metoda** |
| **2. argument**  | **rsi**                                                         | **op: ime metode**                             |
| **3. argument**  | **rdx**                                                         | **1. argument metode**                         |
| **4. argument**  | **rcx**                                                         | **2. argument metode**                         |
| **5. argument**  | **r8**                                                          | **3. argument metode**                         |
| **6. argument**  | **r9**                                                          | **4. argument metode**                         |
| **7. i više argumenata** | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p> | **5. i više argumenata metode**                        |

### Dumpovanje ObjectiveC metapodataka

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) je alat za klasno-dumpovanje Objective-C binarnih fajlova. GitHub specifikuje dylibs ali ovo takođe funkcioniše sa izvršnim fajlovima.
```bash
./dynadump dump /path/to/bin
```
U trenutku pisanja, ovo je **trenutno ono što najbolje funkcioniše**.

#### Redovni alati
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) je originalni alat koji generiše deklaracije za klase, kategorije i protokole u formatiranom ObjectiveC kodu.

Star je i nije održavan, pa verovatno neće pravilno raditi.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) je moderan i višepatformski Objective-C class dump. U poređenju sa postojećim alatima, iCDump može raditi nezavisno od Apple ekosistema i izlaže Python veze.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statička analiza Swift-a

Sa Swift binarnim fajlovima, s obzirom da postoji kompatibilnost sa Objective-C-om, ponekad možete izvući deklaracije koristeći [class-dump](https://github.com/nygard/class-dump/), ali ne uvek.

Pomoću komandi **`jtool -l`** ili **`otool -l`** moguće je pronaći nekoliko sekcija koje počinju sa prefiksom **`__swift5`**:
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
Možete pronaći dodatne informacije o [**informacijama koje su smeštene u ovim sekcijama u ovom blog postu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Štaviše, **Swift binarni fajlovi mogu imati simbole** (na primer, biblioteke moraju čuvati simbole kako bi se njenim funkcijama moglo pristupiti). **Simboli obično sadrže informacije o imenu funkcije** i atributima na neuredan način, pa su veoma korisni, i postoje "**demangleri"** koji mogu dobiti originalno ime:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamička analiza

{% hint style="warning" %}
Imajte na umu da bi za debagovanje binarnih fajlova, **SIP treba da bude onemogućen** (`csrutil disable` ili `csrutil enable --without debug`) ili da kopirate binarne fajlove u privremenu fasciklu i **uklonite potpis** pomoću `codesign --remove-signature <putanja-do-binarnog-fajla>` ili dozvolite debagovanje binarnog fajla (možete koristiti [ovaj skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Imajte na umu da bi za **instrumentaciju sistemskih binarnih fajlova** (kao što je `cloudconfigurationd`) na macOS-u, **SIP mora biti onemogućen** (samo uklanjanje potpisa neće raditi).
{% endhint %}

### API-ji

macOS izlaže neke zanimljive API-jeve koji pružaju informacije o procesima:

* `proc_info`: Ovo je glavni API koji pruža mnogo informacija o svakom procesu. Potrebno je da budete root da biste dobili informacije o drugim procesima, ali vam nisu potrebna posebna ovlašćenja ili mach portovi.
* `libsysmon.dylib`: Omogućava dobijanje informacija o procesima putem XPC izloženih funkcija, međutim, potrebno je imati ovlašćenje `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** je tehnika koja se koristi za snimanje stanja procesa, uključujući stek pozive svih pokrenutih niti. Ovo je posebno korisno za debagovanje, analizu performansi i razumevanje ponašanja sistema u određenom trenutku. Na iOS-u i macOS-u, stackshotting se može izvršiti korišćenjem nekoliko alata i metoda poput alata **`sample`** i **`spindump`**.

### Sysdiagnose

Ovaj alat (`/usr/bini/ysdiagnose`) uglavnom prikuplja mnogo informacija sa vašeg računara izvršavajući desetine različitih komandi poput `ps`, `zprint`...

Mora se pokrenuti kao **root** i daemon `/usr/libexec/sysdiagnosed` ima veoma zanimljiva ovlašćenja poput `com.apple.system-task-ports` i `get-task-allow`.

Njegov plist se nalazi u `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` koji deklariše 3 MachServices:

* `com.apple.sysdiagnose.CacheDelete`: Briše stare arhive u /var/rmp
* `com.apple.sysdiagnose.kernel.ipc`: Poseban port 23 (kernel)
* `com.apple.sysdiagnose.service.xpc`: Korisnički interfejs putem `Libsysdiagnose` Obj-C klase. Mogu se proslediti tri argumenta u obliku rečnika (`compress`, `display`, `run`)

### Unified Logs

macOS generiše mnogo logova koji mogu biti veoma korisni prilikom pokretanja aplikacije pokušavajući da razumete **šta radi**.

Osim toga, postoje neki logovi koji će sadržati oznaku `<private>` da bi **sakrili** neke **identifikacione** informacije **korisnika** ili **računara**. Međutim, moguće je **instalirati sertifikat da biste otkrili ove informacije**. Pratite objašnjenja sa [**ovde**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Leva tabla

Na levoj tabli hoppera mogu se videti simboli (**Oznake**) binarnog fajla, lista procedura i funkcija (**Proc**) i stringovi (**Str**). Ovo nisu svi stringovi već oni definisani u nekoliko delova Mac-O fajla (kao što su _cstring ili_ `objc_methname`).

#### Srednja tabla

Na srednjoj tabli možete videti **disejblirani kod**. I možete ga videti kao **sirovi** disasembl, kao **graf**, kao **dekompilirani** i kao **binarni** klikom na odgovarajuću ikonu:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Desnim klikom na objekat koda možete videti **reference ka/od tog objekta** ili čak promeniti njegovo ime (ovo ne funkcioniše u dekompiliranom pseudokodu):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Osim toga, u **sredini dole možete pisati Python komande**.

#### Desna tabla

Na desnoj tabli možete videti zanimljive informacije poput **istorije navigacije** (da znate kako ste stigli do trenutne situacije), **pozivnog grafa** gde možete videti sve **funkcije koje pozivaju ovu funkciju** i sve funkcije koje **ova funkcija poziva**, i informacije o **lokalnim varijablama**.

### dtrace

Omogućava korisnicima pristup aplikacijama na izuzetno **niskom nivou** i pruža način korisnicima da **prate** **programe** i čak promene njihov tok izvršavanja. Dtrace koristi **sonde** koje su **postavljene širom jezgra** i nalaze se na lokacijama poput početka i kraja sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje sonde za svaki sistemski poziv. Ove sonde mogu biti aktivirane na **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace-om se vrši preko /dev/dtrace koji je dostupan samo root korisniku.

{% hint style="success" %}
Da biste omogućili Dtrace bez potpune onemogućenosti SIP zaštite, možete izvršiti u režimu oporavka: `csrutil enable --without dtrace`

Takođe možete **`dtrace`** ili **`dtruss`** binarne fajlove koje **ste kompajlirali**.
{% endhint %}

Dostupne sonde dtrace-a mogu se dobiti sa:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Ime sonde se sastoji od četiri dela: provajdera, modula, funkcije i imena (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo imena, Dtrace će taj deo primeniti kao zamenski znak.

Da biste konfigurisali DTrace da aktivira sonde i specificira koje akcije treba izvršiti kada se aktiviraju, moraćemo koristiti D jezik.

Detaljnije objašnjenje i više primera možete pronaći na [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Primeri

Pokrenite `man -k dtrace` da biste videli **dostupne DTrace skripte**. Primer: `sudo dtruss -n binary`

* U liniji
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* skripta
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

To je mogućnost praćenja jezgra. Dokumentovani kodovi mogu se pronaći u **`/usr/share/misc/trace.codes`**.

Alati poput `latency`, `sc_usage`, `fs_usage` i `trace` ga koriste interno.

Za interakciju sa `kdebug`-om se koristi `sysctl` preko `kern.kdebug` prostora imena, a MIB-ovi koji se koriste mogu se pronaći u `sys/sysctl.h` imajući funkcije implementirane u `bsd/kern/kdebug.c`.

Da biste komunicirali sa kdebug-om pomoću prilagođenog klijenta, obično se koriste sledeći koraci:

* Uklonite postojeće postavke sa KERN\_KDSETREMOVE
* Postavite trag sa KERN\_KDSETBUF i KERN\_KDSETUP
* Koristite KERN\_KDGETBUF da biste dobili broj unosa u baferu
* Izvucite sopstvenog klijenta iz traga sa KERN\_KDPINDEX
* Omogućite praćenje sa KERN\_KDENABLE
* Pročitajte bafer pozivajući KERN\_KDREADTR
* Da biste uparili svaku nit sa njenim procesom, pozovite KERN\_KDTHRMAP.

Da biste dobili ove informacije, moguće je koristiti Apple alat **`trace`** ili prilagođeni alat [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Imajte na umu da je Kdebug dostupan samo za 1 korisnika u isto vreme.** Tako da samo jedan alat sa k-debug mogućnostima može biti pokrenut u isto vreme.

### ktrace

API-ji `ktrace_*` dolaze iz `libktrace.dylib` koji obuhvataju one iz `Kdebug`. Zatim, klijent može jednostavno pozvati `ktrace_session_create` i `ktrace_events_[single/class]` da postavi povratne pozive na specifične kodove, a zatim ga pokrenuti sa `ktrace_start`.

Možete koristiti ovaj čak i kada je **SIP aktiviran**

Možete koristiti kao klijente korisnu alatku `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ili `tailspin`.

### kperf

Ovo se koristi za profilisanje na nivou jezgra i izgrađeno je koristeći `Kdebug` pozive.

U osnovi, globalna promenljiva `kernel_debug_active` se proverava i postavlja poziva `kperf_kdebug_handler` sa `Kdebug` kodom i adresom jezgra koji poziva. Ako se `Kdebug` kod poklapa sa odabranim, dobijaju se "akcije" konfigurisane kao bitmape (proverite `osfmk/kperf/action.h` za opcije).

Kperf takođe ima sysctl MIB tabelu: (kao root) `sysctl kperf`. Ovaj kod se može pronaći u `osfmk/kperf/kperfbsd.c`.

Osim toga, podskup funkcionalnosti Kperf-a se nalazi u `kpc`, koji pruža informacije o brojačima performansi mašine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru radnji povezanih sa procesima koje proces obavlja (na primer, praćenje novih procesa koje proces kreira).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji prikazuje odnose između procesa.\
Potrebno je pratiti vaš Mac pomoću komande poput **`sudo eslogger fork exec rename create > cap.json`** (terminal koji pokreće ovo zahteva FDA). Zatim možete učitati json u ovaj alat da biste videli sve odnose:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) omogućava praćenje događaja sa datotekama (kao što su kreiranje, izmene i brisanje) pružajući detaljne informacije o takvim događajima.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat sa izgledom koji korisnici Windows-a mogu prepoznati iz Microsoft Sysinternal’s _Procmon_. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih tipova događaja, omogućava filtriranje ovih događaja po kategorijama kao što su datoteka, proces, mreža, itd., i pruža funkcionalnost za čuvanje snimljenih događaja u json formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) su deo Xcode-ovih Developer alata - koriste se za praćenje performansi aplikacija, identifikaciju curenja memorije i praćenje aktivnosti sistema datoteka.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Omogućava praćenje radnji koje obavljaju procesi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan alat za pregled **biblioteka** koje koristi binarni fajl, **datoteke** koje koristi i **mrežne** veze.\
Takođe proverava binarne procese na **virustotalu** i prikazuje informacije o binarnom fajlu.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako **debugovati pokrenuti daemon** koji koristi **`PT_DENY_ATTACH`** kako bi sprečio debugovanje čak i ako je SIP onemogućen.

### lldb

**lldb** je glavni alat za **debugovanje** binarnih fajlova na **macOS**-u.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Možete postaviti Intel ukus prilikom korišćenja lldb-a kreiranjem datoteke nazvane **`.lldbinit`** u vašem matičnom folderu sa sledećom linijom:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Unutar lldb-a, izvršite dump procesa sa `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komanda</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Pokretanje izvršenja, koje će se nastaviti dok se ne naiđe na prekidnu tačku ili dok se proces ne završi.</td></tr><tr><td><strong>continue (c)</strong></td><td>Nastavak izvršenja debugiranog procesa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda će preskočiti pozive funkcija.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od nexti komande, ova komanda će ući u pozive funkcija.</td></tr><tr><td><strong>finish (f)</strong></td><td>Izvršava preostale instrukcije u trenutnoj funkciji ("frame") i zaustavlja se.</td></tr><tr><td><strong>control + c</strong></td><td>Pauzira izvršenje. Ako je proces pokrenut (r) ili nastavljen (c), ovo će uzrokovati zaustavljanje procesa ...gde god se trenutno izvršava.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Bilo koja funkcija nazvana main</p><p>b &#x3C;ime_binarne_datoteke>`main #Glavna funkcija binarne datoteke</p><p>b set -n main --shlib &#x3C;ime_biblioteke> #Glavna funkcija naznačene binarne datoteke</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista prekida</p><p>br e/dis &#x3C;br> #Omogući/Onemogući prekid</p><p>breakpoint delete &#x3C;br></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Dobijanje pomoći za komandu prekida</p><p>help memory write #Dobijanje pomoći za pisanje u memoriju</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/adresa_memorije></strong></td><td>Prikazuje memoriju kao string završen nulom.</td></tr><tr><td><strong>x/i &#x3C;reg/adresa_memorije></strong></td><td>Prikazuje memoriju kao asemblersku instrukciju.</td></tr><tr><td><strong>x/b &#x3C;reg/adresa_memorije></strong></td><td>Prikazuje memoriju kao bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Ovo će ispisati objekat na koji se parametar odnosi</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Imajte na umu da većina Apple-ovih Objective-C API-ja ili metoda vraća objekte, i stoga bi trebalo da se prikažu putem "print object" (po) komande. Ako po ne proizvodi smislene rezultate, koristite <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Upisuje AAAA na tu adresu<br>memory write -f s $rip+0x11f+7 "AAAA" #Upisuje AAAA na adresu</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disasembleruje trenutnu funkciju</p><p>dis -n &#x3C;ime_funkcije> #Disasembleruje funkciju</p><p>dis -n &#x3C;ime_funkcije> -b &#x3C;ime_datoteke> #Disasembleruje funkciju<br>dis -c 6 #Disasembleruje 6 linija<br>dis -c 0x100003764 -e 0x100003768 # Od jedne adrese do druge<br>dis -p -c 4 # Počinje sa trenutnom adresom disasemblerovanja</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Proverava niz od 3 komponente u x1 registru</td></tr></tbody></table>

{% hint style="info" %}
Prilikom pozivanja funkcije **`objc_sendMsg`**, registar **rsi** sadrži **ime metode** kao string završen nulom ("C"). Da biste ispisali ime putem lldb-a, uradite sledeće:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dinamička Analiza

#### Detekcija virtuelne mašine

* Komanda **`sysctl hw.model`** vraća "Mac" kada je **domaćin MacOS**, ali nešto drugo kada je virtuelna mašina.
* Igranje sa vrednostima **`hw.logicalcpu`** i **`hw.physicalcpu`** neki malveri pokušavaju da detektuju da li je u pitanju virtuelna mašina.
* Neki malveri takođe mogu **detektovati** da li je mašina zasnovana na **VMware**-u na osnovu MAC adrese (00:50:56).
* Moguće je otkriti da li se proces **debuguje** jednostavnim kodom poput:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces se debuguje }`
* Takođe se može pozvati sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Ovo **sprečava** deb**a**ger da se poveže i prati.
* Možete proveriti da li se funkcija **`sysctl`** ili **`ptrace`** **uvozi** (ali malver bi mogao da je dinamički uveze)
* Kao što je navedeno u ovom tekstu, “[Pobeda nad tehnikama protiv-debugovanja: macOS ptrace varijante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Poruka Proces # je izašao sa **statusom = 45 (0x0000002d)** obično je znak da je cilj debugovanja koristi **PT\_DENY\_ATTACH**_”
## Core Dumps

Core dumps are created if:

* `kern.coredump` sysctl is set to 1 (podrazumevano)
* If the process wasn't suid/sgid or `kern.sugid_coredump` is 1 (podrazumevano je 0)
* The `AS_CORE` limit allows the operation. It's possible to suppress code dumps creation by calling `ulimit -c 0` and re-enable them with `ulimit -c unlimited`.

In those cases the core dumps is generated according to `kern.corefile` sysctl and stored usually in `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o rušenju na disku**. Izveštaj o rušenju sadrži informacije koje mogu **pomoći programeru da dijagnostikuje** uzrok rušenja.\
Za aplikacije i druge procese **koji se izvršavaju u kontekstu pokretanja po korisniku**, ReportCrash se izvršava kao LaunchAgent i čuva izveštaje o rušenju u `~/Library/Logs/DiagnosticReports/` korisnika\
Za demone, druge procese **koji se izvršavaju u kontekstu pokretanja po sistemu** i druge privilegovane procese, ReportCrash se izvršava kao LaunchDaemon i čuva izveštaje o rušenju u `/Library/Logs/DiagnosticReports` sistema

Ako vas brine što se izveštaji o rušenju **šalju Apple-u**, možete ih onemogućiti. U suprotnom, izveštaji o rušenju mogu biti korisni za **određivanje načina na koji je server pao**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Spavanje

Prilikom faziiranja u MacOS-u važno je sprečiti Mac da spava:

* systemsetup -setsleep Nikada
* pmset, System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Prekid

Ako faziirate putem SSH veze važno je osigurati da sesija neće isteći. Promenite sshd\_config datoteku sa:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interni rukovaoci

**Proverite sledeću stranicu** da biste saznali kako možete pronaći koja aplikacija je odgovorna za **obradu određene šeme ili protokola:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumeracija mrežnih procesa

Ovo je interesantno za pronalaženje procesa koji upravljaju mrežnim podacima:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Ili koristite `netstat` ili `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzeri

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Radi za CLI alate

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

On "**samo radi"** sa macOS GUI alatima. Imajte na umu da neki macOS aplikacije imaju specifične zahteve kao što su jedinstvena imena datoteka, ispravna ekstenzija, potreba za čitanjem datoteka iz peska (`~/Library/Containers/com.apple.Safari/Data`)...

Primeri:

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

### Više informacija o Fuzzing-u na MacOS-u

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Reference

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokrenut na **dark web-u** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji kradu informacije**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji kradu informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
