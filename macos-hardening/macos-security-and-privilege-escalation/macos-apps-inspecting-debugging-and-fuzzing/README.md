# macOS Aplikacije - Inspekcija, debugovanje i Faziranje

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera koji krade podatke**.

Primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb stranicu i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## Statistička Analiza

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

Ovaj alat može se koristiti kao **zamena** za **codesign**, **otool** i **objdump**, i pruža nekoliko dodatnih funkcija. [**Preuzmite ga ovde**](http://www.newosxbook.com/tools/jtool.html) ili ga instalirajte pomoću `brew`.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koji je koristan za inspekciju **.pkg** fajlova (instalatera) i da vidite šta se nalazi unutra pre instalacije.\
Ovi instalateri imaju `preinstall` i `postinstall` bash skripte koje autori obično zloupotrebljavaju da **upornost** **malvera**.

### hdiutil

Ovaj alat omogućava montiranje Apple disk slika (**.dmg**) fajlova radi inspekcije pre pokretanja:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Biće montiran u `/Volumes`

### Objective-C

#### Metapodaci

{% hint style="danger" %}
Imajte na umu da programi napisani u Objective-C **zadržavaju** svoje deklaracije klasa **kada** **se kompajliraju** u [Mach-O binarne datoteke](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **uključuju** ime i tip:
{% endhint %}

* Klasu
* Metode klase
* Instance varijable klase

Ove informacije možete dobiti koristeći [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Pozivanje funkcija

Kada se funkcija pozove u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto pozivanja te funkcije, pozvaće **`objc_msgSend`**. Što će pozvati konačnu funkciju:

![](<../../../.gitbook/assets/image (302).png>)

Parametri koje ova funkcija očekuje su:

- Prvi parametar (**self**) je "pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**". Jednostavnije rečeno, to je objekat na koji se metod poziva. Ako je metod klasni metod, ovo će biti instanca objekta klase (u celini), dok će za instancu metoda, self pokazivati na instanciranu instancu klase kao objekat.
- Drugi parametar, (**op**), je "selektor metoda koji obrađuje poruku". Ponovo, jednostavnije rečeno, ovo je samo **ime metoda**.
- Preostali parametri su bilo **vrednosti koje su potrebne metodu** (op).

Pogledajte kako **lako dobiti ove informacije sa `lldb` u ARM64** na ovoj stranici:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argument**      | **Registar**                                                   | **(za) objc\_msgSend**                                |
| ----------------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| **1. argument**  | **rdi**                                                        | **self: objekat na koji se metod poziva**            |
| **2. argument**  | **rsi**                                                        | **op: ime metoda**                                   |
| **3. argument**  | **rdx**                                                        | **1. argument metoda**                               |
| **4. argument**  | **rcx**                                                        | **2. argument metoda**                               |
| **5. argument**  | **r8**                                                         | **3. argument metoda**                               |
| **6. argument**  | **r9**                                                         | **4. argument metoda**                               |
| **7.+ argument** | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p> | **5.+ argument metoda**                              |

### Swift

Sa Swift binarnim fajlovima, budući da postoji kompatibilnost sa Objective-C, ponekad možete izvući deklaracije koristeći [class-dump](https://github.com/nygard/class-dump/) ali ne uvek.

Pomoću komandne linije **`jtool -l`** ili **`otool -l`** moguće je pronaći nekoliko sekcija koje počinju sa prefiksom **`__swift5`**:
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
Mo𝛂ете пронаћи додатне информације о [**информацијама сачуваним у овим одељцима у овом блог посту**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Осим тога, **Swift бинарни фајлови могу имати симболе** (на пример, библиотеке морају чувати симболе како би њихове функциј биле позване). **Симболи обично садрже информације о имену функције** и атрибутима на ружан начин, па су врло корисни и постоје "**деманглери"** који могу добити оригинално име:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Pakovani binarnih fajlova

* Provera visoke entropije
* Provera stringova (da li postoji skoro nijedan razumljiv string, pakovan)
* UPX paket za MacOS generiše seeveru nazvanu "\_\_XHDR"

## Dinamička analiza

{% hint style="warning" %}
Imajte na umu da bi za debagovanje binarnih fajlova, **SIP treba da bude onemogućen** (`csrutil disable` ili `csrutil enable --without debug`) ili da kopirate binarne fajlove u privremenu fasciklu i **uklonite potpis** sa `codesign --remove-signature <putanja-do-binarnog-fajla>` ili dozvolite debagovanje binarnog fajla (možete koristiti [ovaj skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Imajte na umu da bi za **instrumentiranje sistemskih binarnih fajlova** (kao što je `cloudconfigurationd`) na macOS-u, **SIP mora biti onemogućen** (samo uklanjanje potpisa neće raditi).
{% endhint %}

### Unified Logs

MacOS generiše mnogo logova koji mogu biti veoma korisni prilikom pokretanja aplikacije pokušavajući da razumete **šta radi**.

Osim toga, postoje neki logovi koji će sadržati oznaku `<private>` da bi **sakrili** neke **korisničke** ili **računarske** **identifikacione** informacije. Međutim, moguće je **instalirati sertifikat da biste otkrili ove informacije**. Pratite objašnjenja sa [**ovde**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Leva tabla

Na levoj tabli hoppera moguće je videti simbole (**Oznake**) binarnog fajla, listu procedura i funkcija (**Proc**) i stringove (**Str**). To nisu svi stringovi već oni definisani u nekoliko delova Mac-O fajla (kao što su _cstring ili `objc_methname`).

#### Srednja tabla

Na srednjoj tabli možete videti **dizasemblovani kod**. I možete ga videti kao **sirov** disasembl, kao **graf**, kao **dekompiliran** i kao **binarni** klikom na odgovarajuću ikonu:

<figure><img src="../../../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

Desnim klikom na objekat koda možete videti **reference ka/od tog objekta** ili čak promeniti njegovo ime (ovo ne radi u dekompiliranom pseudokodu):

<figure><img src="../../../.gitbook/assets/image (1114).png" alt=""><figcaption></figcaption></figure>

Osim toga, u **sredini dole možete pisati python komande**.

#### Desna tabla

Na desnoj tabli možete videti zanimljive informacije kao što su **istorija navigacije** (da znate kako ste stigli do trenutne situacije), **pozivni grafikon** gde možete videti sve **funkcije koje pozivaju ovu funkciju** i sve funkcije koje **ova funkcija poziva**, i informacije o **lokalnim varijablama**.

### dtrace

Omogućava korisnicima pristup aplikacijama na izuzetno **niskom nivou** i pruža način korisnicima da **prate** **programe** i čak promene njihov tok izvršavanja. Dtrace koristi **sonde** koje su **postavljene širom jezgra** i nalaze se na lokacijama poput početka i kraja sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje sonde za svaki sistemski poziv. Ove sonde mogu biti aktivirane na **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace-om se odvija preko /dev/dtrace koji je dostupan samo root korisniku.

{% hint style="success" %}
Da biste omogućili Dtrace bez potpune onemogućenosti SIP zaštite, možete izvrš _na režim za oporavak: `__csrutil enable --without dtrace`

Takođe možete **`dtrace`** ili **`dtruss`** binarne fajlove **koje ste kompajlirali**.
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
Ime sonde se sastoji od četiri dela: pružalac, modul, funkcija i ime (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo imena, Dtrace će primeniti taj deo kao zamenski simbol.

Da biste konfigurisali DTrace da aktivira sonde i specificira koje akcije izvršiti kada se aktiviraju, moraćemo koristiti D jezik.

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
### ktrace

Možete koristiti ovu čak i kada je **SIP aktiviran**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru akcija povezanih sa procesima koje proces obavlja (na primer, praćenje novih procesa koje proces kreira).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji prikazuje odnose između procesa.\
Potrebno je pratiti vaš Mac pomoću komande poput **`sudo eslogger fork exec rename create > cap.json`** (terminal koji pokreće ovo zahteva FDA). Zatim možete učitati json datoteku u ovaj alat da biste videli sve odnose:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor** Panopto](https://objective-see.com/products/utilities.html#FileMonitor) omogućava praćenje događaja sa datotekama (kao što su kreiranje, izmene i brisanje), pružajući detaljne informacije o tim događajima.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat sa izgledom koji korisnici Windowsa mogu prepoznati iz Microsoft Sysinternal-ovog _Procmon_. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih tipova događaja, omogućava filtriranje ovih događaja po kategorijama kao što su datoteka, proces, mreža, itd., i pruža funkcionalnost za čuvanje snimljenih događaja u json formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) su deo Xcode-ovih Developer alata - koriste 

![](<../../../.gitbook/assets/image (1135).png>)

### fs\_usage

Omogućava praćenje akcija koje obavljaju procesi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan alat za pregled **biblioteka** koje koristi binarni fajl, **datoteke** koje koristi i **mrežne** veze.\
Takođe proverava binarne procese protiv **virustotala** i prikazuje informacije o binarnom fajlu.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako **debugovati pokrenuti daemon** koji koristi **`PT_DENY_ATTACH`** kako bi sprečio debugovanje čak i ako je SIP onemogućen.

### lldb

**lldb** je glavni alat za **debugovanje** binarnih fajlova na **macOS** platformi.
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

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komanda</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Pokretanje izvršenja, koje će se nastaviti dok se ne naiđe na prekidnu tačku ili dok se proces ne završi.</td></tr><tr><td><strong>continue (c)</strong></td><td>Nastavak izvršenja debugiranog procesa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda će preskočiti pozive funkcija.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od komande nexti, ova komanda će ući u pozive funkcija.</td></tr><tr><td><strong>finish (f)</strong></td><td>Izvršava preostale instrukcije u trenutnoj funkciji ("frame") i zaustavlja se.</td></tr><tr><td><strong>control + c</strong></td><td>Pauzira izvršenje. Ako je proces pokrenut (r) ili nastavljen (c), ovo će uzrokovati zaustavljanje procesa ...gde god se trenutno izvršava.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Bilo koja funkcija nazvana main</p><p>b &#x3C;ime_binarnog_fajla>`main #Glavna funkcija binarnog fajla</p><p>b set -n main --shlib &#x3C;ime_biblioteke> #Glavna funkcija naznačenog binarnog fajla</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista prekida</p><p>br e/dis &#x3C;br> #Omogući/Onemogući prekid</p><p>breakpoint delete &#x3C;br></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Dobijanje pomoći za komandu prekida</p><p>help memory write #Dobijanje pomoći za pisanje u memoriju</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/adresa_memorije></strong></td><td>Prikazuje memoriju kao string završen nulom.</td></tr><tr><td><strong>x/i &#x3C;reg/adresa_memorije></strong></td><td>Prikazuje memoriju kao asemblersku instrukciju.</td></tr><tr><td><strong>x/b &#x3C;reg/adresa_memorije></strong></td><td>Prikazuje memoriju kao bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Ovo će ispisati objekat na koji se parametar odnosi</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Imajte na umu da većina Apple-ovih Objective-C API-ja ili metoda vraća objekte, i stoga bi trebalo da se prikažu putem "print object" (po) komande. Ako po ne proizvodi smislene rezultate, koristite <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Upisuje AAAA na tu adresu<br>memory write -f s $rip+0x11f+7 "AAAA" #Upisuje AAAA na adresu</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disasembliranje trenutne funkcije</p><p>dis -n &#x3C;ime_funkcije> #Disasembliranje funkcije</p><p>dis -n &#x3C;ime_funkcije> -b &#x3C;ime_binarnog_fajla> #Disasembliranje funkcije<br>dis -c 6 #Disasembliranje 6 linija<br>dis -c 0x100003764 -e 0x100003768 # Od jedne adrese do druge<br>dis -p -c 4 # Početak disasembliranja na trenutnoj adresi</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Provera niza od 3 komponente u registru x1</td></tr></tbody></table>

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
* Neki malveri takođe mogu **detektovati** da li je mašina **bazirana na VMware-u** na osnovu MAC adrese (00:50:56).
* Moguće je proveriti da li se **proces debuguje** jednostavnim kodom kao što je:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces se debuguje }`
* Takođe se može pozvati sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Ovo **sprečava** deb**a**ger da se poveže i prati.
* Možete proveriti da li se funkcija **`sysctl`** ili **`ptrace`** **uvozi** (ali malver bi mogao da je dinamički uveze)
* Kao što je navedeno u ovom tekstu, “[Pobeda nad tehnikama protiv-debugiranja: macOS ptrace varijante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Poruka Proces # je završen sa **statusom = 45 (0x0000002d)** obično je znak da je cilj debugiranja koristi **PT\_DENY\_ATTACH**_”
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o rušenju na disku**. Izveštaj o rušenju sadrži informacije koje mogu **pomoći programeru da dijagnostikuje** uzrok rušenja.\
Za aplikacije i druge procese **koji se izvršavaju u kontekstu pokretanja po korisniku**, ReportCrash se izvršava kao LaunchAgent i čuva izveštaje o rušenju u `~/Library/Logs/DiagnosticReports/` korisnika.\
Za demone, druge procese **koji se izvršavaju u kontekstu pokretanja po sistemu** i druge privilegovane procese, ReportCrash se izvršava kao LaunchDaemon i čuva izveštaje o rušenju u `/Library/Logs/DiagnosticReports` sistema.

Ako vas brine slanje izveštaja o rušenju **Apple-u**, možete ih onemogućiti. U suprotnom, izveštaji o rušenju mogu biti korisni za **određivanje načina na koji je server pao**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Spavanje

Prilikom faziiranja u MacOS-u važno je sprečiti Mac da zaspi:

* systemsetup -setsleep Nikada
* pmset, System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Prekid

Ako faziirate putem SSH veze, važno je osigurati da sesija neće isteći. Promenite sshd\_config datoteku sa:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interni rukovaoci

**Proverite sledeću stranicu** da biste saznali kako možete pronaći koja je aplikacija odgovorna za **obradu određene šeme ili protokola:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumeracija mrežnih procesa
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

Radi sa CLI alatima

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Radi sa macOS GUI alatima. Napomena: neki macOS aplikacije imaju specifične zahteve kao što su jedinstvena imena fajlova, ispravna ekstenzija, potreba za čitanjem fajlova iz peska (`~/Library/Containers/com.apple.Safari/Data`)...

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

### Više informacija o Fuzzingu na MacOS-u

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

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-webom** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu informacija**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
