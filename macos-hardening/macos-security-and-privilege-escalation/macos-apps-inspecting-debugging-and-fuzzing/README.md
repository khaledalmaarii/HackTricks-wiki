# macOS Aplikacije - Inspekcija, debagovanje i Faziranje

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Statička Analiza

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

Ovaj alat se može koristiti kao **zamena** za **codesign**, **otool** i **objdump**, i pruža nekoliko dodatnih funkcija. [**Preuzmite ga ovde**](http://www.newosxbook.com/tools/jtool.html) ili ga instalirajte pomoću `brew` komande.
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
**`Codesign`** se može pronaći u **macOS-u**, dok se **`ldid`** može pronaći u **iOS-u**.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koji je koristan za inspekciju **.pkg** fajlova (instalera) i pregled sadržaja pre nego što se instalira.\
Ovi instalateri imaju `preinstall` i `postinstall` bash skripte koje autori malvera obično zloupotrebljavaju kako bi **trajno** **instalirali** **malver**.

### hdiutil

Ovaj alat omogućava **montiranje** Apple disk slika (**.dmg**) fajlova kako bi se pregledali pre pokretanja bilo čega:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Biće montirano u `/Volumes`

### Objective-C

#### Metapodaci

{% hint style="danger" %}
Imajte na umu da programi napisani u Objective-C **zadržavaju** svoje deklaracije klasa **kada** **kompiliraju** u [Mach-O binarne datoteke](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **uključuju** ime i tip:
{% endhint %}

* Klasa
* Metode klase
* Instancne varijable klase

Ove informacije možete dobiti koristeći [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Pozivanje funkcija

Kada se funkcija poziva u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto pozivanja te funkcije, poziva **`objc_msgSend`**. Ova funkcija zatim poziva konačnu funkciju:

![](<../../../.gitbook/assets/image (560).png>)

Parametri koje ova funkcija očekuje su:

* Prvi parametar (**self**) je "pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**". Jednostavnije rečeno, to je objekat nad kojim se poziva metoda. Ako je metoda klasna metoda, ovo će biti instanca objekta klase (u celini), dok će za instancnu metodu, self pokazivati na instanciranu instancu klase kao objekat.
* Drugi parametar (**op**) je "selektor metode koja obrađuje poruku". Ponovo, jednostavnije rečeno, ovo je samo **ime metode**.
* Preostali parametri su bilo **koje vrednosti koje su potrebne metodi** (op).

| **Argument**      | **Registar**                                                    | **(za) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**   | **rdi**                                                         | **self: objekat nad kojim se poziva metoda**          |
| **2. argument**   | **rsi**                                                         | **op: ime metode**                                    |
| **3. argument**   | **rdx**                                                         | **1. argument metode**                                |
| **4. argument**   | **rcx**                                                         | **2. argument metode**                                |
| **5. argument**   | **r8**                                                          | **3. argument metode**                                |
| **6. argument**   | **r9**                                                          | **4. argument metode**                                |
| **7.+ argument**  | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p>     | **5.+ argument metode**                               |

### Swift

Sa Swift binarnim fajlovima, s obzirom da postoji kompatibilnost sa Objective-C, ponekad možete izvući deklaracije koristeći [class-dump](https://github.com/nygard/class-dump/), ali ne uvek.

Pomoću komandne linije **`jtool -l`** ili **`otool -l`** moguće je pronaći nekoliko sekcija koje počinju sa prefiksom **`__swift5`**.
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
Možete pronaći dodatne informacije o **informacijama koje se čuvaju u ovim sekcijama u ovom blog postu**.

Osim toga, **Swift binarni fajlovi mogu imati simbole** (na primer, biblioteke moraju čuvati simbole kako bi se funkcije mogle pozvati). **Simboli obično sadrže informacije o imenu funkcije** i atributima na ružan način, pa su vrlo korisni i postoje "**demangleri**" koji mogu dobiti originalno ime:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Pakovani binarnih fajlova

* Proverite visoku entropiju
* Proverite stringove (ako nema razumljivih stringova, pakovan je)
* UPX paket za MacOS generise sekciju nazvanu "\_\_XHDR"

## Dinamicka analiza

{% hint style="warning" %}
Napomena da bi se debagovale binarne datoteke, **SIP mora biti onemogucen** (`csrutil disable` ili `csrutil enable --without debug`) ili kopirati binarne datoteke u privremeni folder i **ukloniti potpis** sa `codesign --remove-signature <putanja-do-binarnog-fajla>` ili dozvoliti debagovanje binarnog fajla (mozete koristiti [ovaj skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Napomena da bi se **instrumentirale sistemski binarni fajlovi** (kao sto je `cloudconfigurationd`) na macOS-u, **SIP mora biti onemogucen** (samo uklanjanje potpisa nece raditi).
{% endhint %}

### Unified Logs

MacOS generise mnogo logova koji mogu biti veoma korisni prilikom pokretanja aplikacije i pokusaja razumevanja **sta radi**.

Osim toga, postoje neki logovi koji ce sadrzati oznaku `<private>` da bi **sakrili** neke **identifikacione informacije** korisnika ili racunara. Medjutim, moguce je **instalirati sertifikat da bi se ove informacije otkrile**. Pratite objasnjenja sa [**ovde**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Leva tabla

U levoj tabli hoppera mogu se videti simboli (**Oznake**) binarnog fajla, lista procedura i funkcija (**Proc**) i stringovi (**Str**). To nisu svi stringovi, vec oni definisani u nekoliko delova Mac-O fajla (kao sto su _cstring ili `objc_methname`).

#### Srednja tabla

U srednjoj tabli mozete videti **rasclanjenu kod**. I mozete ga videti kao **sirovi** disasembl, kao **graf**, kao **dekompajlirani** i kao **binarni** klikom na odgovarajucu ikonu:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Desnim klikom na kodni objekat mozete videti **reference ka/tom objektu** ili cak promeniti njegovo ime (ovo ne radi u dekompajliranom pseudokodu):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Osim toga, u **sredini dole mozete pisati python komande**.

#### Desna tabla

U desnoj tabli mozete videti interesantne informacije kao sto su **istorija navigacije** (tako da znate kako ste dosli do trenutne situacije), **graf poziva** gde mozete videti sve **funkcije koje pozivaju ovu funkciju** i sve funkcije koje **ova funkcija poziva**, i informacije o **lokalnim varijablama**.

### dtrace

Omogucava korisnicima pristup aplikacijama na izuzetno **niskom nivou** i pruza nacin korisnicima da **prate** **programe** i cak promene njihov tok izvrsavanja. Dtrace koristi **probe** koje su **postavljene u celom kernelu** i nalaze se na mestima kao sto su pocetak i kraj sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje sonde za svaki sistemski poziv. Ove sonde mogu biti aktivirane na **ulaznoj i izlaznoj tacki svakog sistemskog poziva**. Interakcija sa DTrace se odvija preko /dev/dtrace koji je dostupan samo root korisniku.

{% hint style="success" %}
Da biste omogucili Dtrace bez potpune onemogucenosti SIP zastite, mozete izvrsiti na recovery modu: `csrutil enable --without dtrace`

Takodje mozete koristiti **`dtrace`** ili **`dtruss`** binarne fajlove koje **ste kompajlirali**.
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
Ime sonde se sastoji od četiri dela: pružalac, modul, funkcija i ime (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo imena, Dtrace će ga primeniti kao džoker.

Da biste konfigurisali DTrace da aktivira sonde i da odredite koje radnje treba izvršiti kada se aktiviraju, moraćemo koristiti D jezik.

Detaljnije objašnjenje i više primera možete pronaći na [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Primeri

Pokrenite `man -k dtrace` da biste videli **dostupne DTrace skripte**. Primer: `sudo dtruss -n binary`

* Na liniji
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
# Inspekcija, debagovanje i faziiranje macOS aplikacija

Ovaj direktorijum sadrži informacije i tehnike koje se odnose na inspekciju, debagovanje i faziiranje macOS aplikacija.

## Inspekcija aplikacija

### Osnovne informacije o aplikaciji

Da biste dobili osnovne informacije o macOS aplikaciji, možete koristiti sledeće alate:

- `codesign`: Koristi se za proveru digitalnog potpisa aplikacije.
- `otool`: Omogućava pregled informacija o objektima u izvršnom fajlu aplikacije.
- `spctl`: Koristi se za proveru potpisa aplikacije i njenog porekla.

### Analiza aplikacije

Za detaljniju analizu macOS aplikacija, možete koristiti sledeće alate:

- `class-dump`: Omogućava izdvajanje deklaracija klasa iz izvršnog fajla aplikacije.
- `Hopper Disassembler`: Napredni disasembler koji vam omogućava da analizirate izvršni fajl aplikacije.
- `IDA Pro`: Profesionalni disasembler i debager koji vam omogućava da analizirate izvršni fajl aplikacije.

## Debagovanje aplikacija

Da biste debagovali macOS aplikaciju, možete koristiti sledeće alate:

- `lldb`: Debager koji je ugrađen u Xcode i omogućava vam da debagovali izvršni fajl aplikacije.
- `gdb`: Univerzalni debager koji može biti korišćen za debagovanje izvršnih fajlova aplikacija.

## Faziiranje aplikacija

Faziiranje aplikacija je proces testiranja aplikacija na greške i ranjivosti. Za faziiranje macOS aplikacija, možete koristiti sledeće alate:

- `AFL`: Fuzzer koji koristi tehnike generisanja mutacija za pronalaženje grešaka u aplikacijama.
- `honggfuzz`: Efikasan fuzzer koji koristi tehnike generisanja mutacija i heuristike za pronalaženje grešaka u aplikacijama.

## Dodatni resursi

Ovde možete pronaći dodatne resurse i informacije o inspekciji, debagovanju i faziiranju macOS aplikacija:

- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide): Vodič koji pruža informacije o bezbednosti i privatnosti na macOS platformi.
- [Awesome Mac Security](https://github.com/drduh/awesome-mac-security): Lista resursa i alata za macOS bezbednost.
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

`dtruss` je alatka koja se koristi za inspekciju i debagovanje aplikacija na macOS operativnom sistemu. Ova alatka pruža mogućnost praćenja sistema poziva (system calls) koje aplikacija izvršava tokom svog izvršavanja.

Korišćenje `dtruss` alatke omogućava vam da pratite i analizirate interakciju između aplikacije i operativnog sistema. Možete videti koje sistemske pozive aplikacija koristi, kao i argumente koje šalje tim pozivima. Ovo može biti korisno za pronalaženje grešaka, otkrivanje sigurnosnih propusta ili razumevanje kako aplikacija funkcioniše.

Da biste koristili `dtruss`, jednostavno pokrenite komandu `dtruss` sa putanjom do izvršne datoteke aplikacije koju želite da pratite. Alatka će zatim prikazati sve sistemske pozive koje aplikacija izvršava, zajedno sa njihovim argumentima i povratnim vrednostima.

Na primer, možete pokrenuti sledeću komandu da biste pratili sistemske pozive aplikacije `myapp`:

```
dtruss /putanja/do/myapp
```

Ovo će prikazati sve sistemske pozive koje `myapp` izvršava tokom svog izvršavanja. Možete koristiti ove informacije za analizu i debagovanje aplikacije, kao i za pronalaženje potencijalnih sigurnosnih propusta.

Važno je napomenuti da `dtruss` zahteva privilegije root korisnika kako bi pratio sistemske pozive drugih aplikacija. Takođe, budite oprezni prilikom korišćenja ove alatke, jer nepravilna upotreba može dovesti do nestabilnosti sistema ili ometanja normalnog rada aplikacija.
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Možete koristiti ovu metodu čak i kada je **SIP aktiviran**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru akcija koje proces izvršava (na primer, praćenje novih procesa koje proces kreira).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji prikazuje odnose između procesa.\
Treba da pratite vaš Mac pomoću komande kao što je **`sudo eslogger fork exec rename create > cap.json`** (terminal koji pokreće ovu komandu zahteva FDA). Zatim možete učitati json datoteku u ovaj alat da biste videli sve odnose:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) omogućava praćenje događaja vezanih za datoteke (kao što su kreiranje, izmene i brisanje), pružajući detaljne informacije o tim događajima.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat koji korisnicima Windows-a može biti poznat po izgledu i osećaju Microsoft Sysinternal's _Procmon_. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih vrsta događaja, filtriranje tih događaja po kategorijama kao što su datoteka, proces, mreža itd., i pruža funkcionalnost za čuvanje snimljenih događaja u json formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) su deo Xcode-ovih razvojnih alata - koriste se za praćenje performansi aplikacija, identifikaciju curenja memorije i praćenje aktivnosti na fajl sistemu.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Omogućava praćenje akcija koje procesi izvršavaju:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan alat za pregledanje **biblioteka** koje koristi binarna datoteka, **datoteke** koje koristi i **mrežne** veze koje uspostavlja.\
Takođe proverava binarne procese na **virustotalu** i prikazuje informacije o binarnoj datoteci.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako **debugovati pokrenuti daemon** koji koristi **`PT_DENY_ATTACH`** da bi sprečio debugovanje čak i ako je SIP onemogućen.

### lldb

**lldb** je de **facto alat** za **debugovanje** binarnih datoteka na macOS-u.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Možete postaviti Intel stil kada koristite lldb tako što ćete kreirati datoteku nazvanu **`.lldbinit`** u vašem matičnom folderu sa sledećom linijom:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Unutar lldb-a, izvršite dump procesa pomoću `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komanda</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Pokretanje izvršavanja, koje će se nastaviti dok se ne naiđe na prekidnu tačku ili dok se proces ne završi.</td></tr><tr><td><strong>continue (c)</strong></td><td>Nastavak izvršavanja procesa u debug modu.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda će preskočiti pozive funkcija.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od komande nexti, ova komanda će ući u pozive funkcija.</td></tr><tr><td><strong>finish (f)</strong></td><td>Izvršava preostale instrukcije u trenutnoj funkciji ("okviru") i zaustavlja se.</td></tr><tr><td><strong>control + c</strong></td><td>Pauzira izvršavanje. Ako je proces pokrenut (r) ili nastavljen (c), ovo će uzrokovati zaustavljanje procesa ... gde god se trenutno izvršava.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Bilo koja funkcija koja se zove main</p><p>b &#x3C;ime_binarnog_fajla>`main #Main funkcija binarnog fajla</p><p>b set -n main --shlib &#x3C;ime_biblioteke> #Main funkcija određenog binarnog fajla</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista prekidnih tačaka</p><p>br e/dis &#x3C;broj> #Omogući/Onemogući prekidnu tačku</p><p>breakpoint delete &#x3C;broj></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Dobijanje pomoći za komandu breakpoint</p><p>help memory write #Dobijanje pomoći za pisanje u memoriju</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;adresa_registra/memorije></strong></td><td>Prikazuje memoriju kao string sa nulama na kraju.</td></tr><tr><td><strong>x/i &#x3C;adresa_registra/memorije></strong></td><td>Prikazuje memoriju kao asemblersku instrukciju.</td></tr><tr><td><strong>x/b &#x3C;adresa_registra/memorije></strong></td><td>Prikazuje memoriju kao bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Ovo će ispisati objekat na koji se parametar odnosi</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Napomena: Većina Apple-ovih Objective-C API-ja ili metoda vraća objekte i treba ih prikazati putem "print object" (po) komande. Ako po ne daje smislene rezultate, koristite <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Upisuje AAAA na tu adresu<br>memory write -f s $rip+0x11f+7 "AAAA" #Upisuje AAAA na tu adresu</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disasembler trenutne funkcije</p><p>dis -n &#x3C;ime_funkcije> #Disasembler funkcije</p><p>dis -n &#x3C;ime_funkcije> -b &#x3C;ime_binarnog_fajla> #Disasembler funkcije<br>dis -c 6 #Disasembler 6 linija<br>dis -c 0x100003764 -e 0x100003768 #Od jedne adrese do druge<br>dis -p -c 4 #Počinje od trenutne adrese disasemblera</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #Proverava niz od 3 komponente u registru x1</td></tr></tbody></table>

{% hint style="info" %}
Prilikom pozivanja funkcije **`objc_sendMsg`**, registar **rsi** sadrži **ime metode** kao string završen sa nulom ("C"). Da biste ispisali ime putem lldb-a, uradite sledeće:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dinamička Analiza

#### Detekcija virtuelne mašine

* Komanda **`sysctl hw.model`** vraća "Mac" kada je **host MacOS**, ali nešto drugo kada je virtuelna mašina.
* Igrajući se sa vrednostima **`hw.logicalcpu`** i **`hw.physicalcpu`**, neki malveri pokušavaju da otkriju da li je u pitanju virtuelna mašina.
* Neki malveri takođe mogu **detektovati** da li je mašina **bazirana na VMware-u** na osnovu MAC adrese (00:50:56).
* Takođe je moguće utvrditi da li se proces **debuguje** pomoću jednostavnog koda kao što je:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces se debuguje }`
* Može se takođe pozvati sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Ovo **onemogućava** debageru da se poveže i prati.
* Možete proveriti da li se funkcija **`sysctl`** ili **`ptrace`** **uvozi** (ali malver bi mogao da je uveze dinamički)
* Kao što je navedeno u ovom članku, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Poruka Process # exited with **status = 45 (0x0000002d)** obično je jasan znak da je cilj debugovanja koristio **PT\_DENY\_ATTACH**_”
## Fuzziranje

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o rušenju na disku**. Izveštaj o rušenju sadrži informacije koje mogu **pomoći programeru da dijagnostikuje** uzrok rušenja.\
Za aplikacije i druge procese **koji se izvršavaju u kontekstu pokretača specifičnog za korisnika**, ReportCrash se pokreće kao LaunchAgent i čuva izveštaje o rušenju u direktorijumu `~/Library/Logs/DiagnosticReports/` korisnika.\
Za demone, druge procese **koji se izvršavaju u kontekstu sistema pokretača** i druge privilegovane procese, ReportCrash se pokreće kao LaunchDaemon i čuva izveštaje o rušenju u direktorijumu `/Library/Logs/DiagnosticReports` sistema.

Ako vas brine slanje izveštaja o rušenju **Apple-u**, možete ih onemogućiti. U suprotnom, izveštaji o rušenju mogu biti korisni za **utvrđivanje načina na koji je server pao**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Spavanje

Prilikom izvođenja fuziranja na MacOS-u važno je sprečiti Mac da zaspi:

* systemsetup -setsleep Never
* pmset, System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Prekid SSH veze

Ako izvodite fuziranje putem SSH veze, važno je osigurati da se sesija ne prekida. Promenite sshd\_config datoteku na sledeći način:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interni rukovaoci

**Pogledajte sledeću stranicu** da biste saznali kako možete pronaći koja aplikacija je odgovorna za **obradu određene šeme ili protokola:**

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

Radi sa macOS GUI alatima. Napomena: neki macOS aplikacije imaju specifične zahteve kao što su jedinstvena imena fajlova, odgovarajuća ekstenzija, potreba za čitanjem fajlova iz sandbox-a (`~/Library/Containers/com.apple.Safari/Data`)...

Primeri:
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

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
