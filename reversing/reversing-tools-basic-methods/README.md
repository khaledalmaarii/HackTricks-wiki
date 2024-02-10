# Alati za obrtanje i osnovne metode

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Alati za obrtanje bazirani na ImGui-u

Softver:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm dekompajler / Wat kompajler

Online:

* Koristite [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) za **dekompajliranje** iz wasm (binarnog) u wat (čisti tekst)
* Koristite [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) za **kompajliranje** iz wat u wasm
* Takođe možete pokušati koristiti [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) za dekompajliranje

Softver:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net dekompajler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek je dekompajler koji **dekompajlira i pregleda više formata**, uključujući **biblioteke** (.dll), **Windows metadata fajlove** (.winmd) i **izvršne fajlove** (.exe). Nakon dekompajliranja, skup može biti sačuvan kao Visual Studio projekat (.csproj).

Prednost ovde je da ako izgubljeni izvorni kod zahteva obnovu iz starije skupine, ova akcija može uštedeti vreme. Osim toga, dotPeek pruža praktičnu navigaciju kroz dekompajlirani kod, čineći ga jednim od savršenih alata za **Xamarin analizu algoritama**.&#x20;

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Sa sveobuhvatnim modelom dodataka i API-jem koji proširuje alat prema vašim tačnim potrebama, .NET reflector štedi vreme i pojednostavljuje razvoj. Hajde da pogledamo mnoštvo usluga za obrtanje inženjeringa koje ovaj alat pruža:

* Pruža uvid u to kako podaci prolaze kroz biblioteku ili komponentu
* Pruža uvid u implementaciju i upotrebu .NET jezika i okvira
* Pronalazi neodokumentovanu i neeksponiranu funkcionalnost kako bi se više iskoristili API-ji i tehnologije koje se koriste.
* Pronalazi zavisnosti i različite skupove
* Pronalazi tačnu lokaciju grešaka u vašem kodu, komponentama trećih strana i bibliotekama.&#x20;
* Debajluje izvor svog .NET koda sa kojim radite.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Možete ga imati na bilo kojem operativnom sistemu (možete ga instalirati direktno iz VSCode-a, nije potrebno preuzimanje sa gita. Kliknite na **Extensions** i **search ILSpy**).\
Ako vam je potrebno **dekompajliranje**, **izmena** i **ponovno kompajliranje** možete koristiti: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Right Click -> Modify Method** da biste promenili nešto unutar funkcije).\
Takođe možete probati [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### DNSpy Logging

Da biste omogućili **DNSpy da beleži neke informacije u fajl**, možete koristiti ove .Net linije:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugiranje

Da biste debagovali kod koristeći DNSpy, morate:

Prvo, promenite **Atribute skupa instrukcija** koji se odnose na **debugiranje**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Do: 

# Osnovne metode i alati za obrtanje inženjeringa

Ovde ćete pronaći osnovne metode i alate za obrtanje inženjeringa. Obrtanje inženjering je proces analiziranja softvera kako biste razumeli njegovu strukturu, funkcionalnost i način rada. Ova tehnika je često korišćena u svetu hakovanja kako bi se istražile ranjivosti i pronašle sigurnosne rupe.

## Metode obrtanja inženjeringa

### Statička analiza

Statička analiza je proces pregledanja izvornog koda ili izvršnog fajla bez njegovog izvršavanja. Ova metoda se koristi za pronalaženje ranjivosti, identifikaciju funkcija i analizu strukture programa. Alati koji se koriste za statičku analizu uključuju:

- Disassembleri: Alati koji prevode mašinski kod u ljudski čitljiv oblik.
- Decompileri: Alati koji prevode izvršni fajl u izvorni kod.
- Debuggeri: Alati koji omogućavaju analizu izvršavanja programa korak po korak.

### Dinamička analiza

Dinamička analiza je proces analize softvera tokom njegovog izvršavanja. Ova metoda se koristi za praćenje ponašanja programa, identifikaciju ranjivosti i pronalaženje sigurnosnih propusta. Alati koji se koriste za dinamičku analizu uključuju:

- Fuzzeri: Alati koji generišu nasumične ili ciljane ulaze kako bi testirali softver na neočekivane reakcije.
- Snifferi: Alati koji prate i analiziraju mrežni saobraćaj.
- Instrumentacija: Tehnika koja omogućava ubacivanje koda u program radi praćenja njegovog izvršavanja.

## Alati za obrtanje inženjeringa

### IDA Pro

IDA Pro je jedan od najpopularnijih alata za obrtanje inženjeringa. Ovaj alat omogućava analizu izvornog koda, dekompilaciju, praćenje izvršavanja programa i mnoge druge funkcionalnosti. IDA Pro je dostupan za Windows, Linux i macOS.

### Ghidra

Ghidra je besplatan alat za obrtanje inženjeringa koji je razvio Nacionalni centar za kibernetičku bezbednost (NSA). Ovaj alat omogućava analizu izvornog koda, dekompilaciju, praćenje izvršavanja programa i mnoge druge funkcionalnosti. Ghidra je dostupan za Windows, Linux i macOS.

### Radare2

Radare2 je open-source alat za obrtanje inženjeringa koji podržava analizu izvornog koda, dekompilaciju, praćenje izvršavanja programa i mnoge druge funkcionalnosti. Radare2 je dostupan za Windows, Linux i macOS.

### OllyDbg

OllyDbg je popularan alat za dinamičku analizu softvera. Ovaj alat omogućava praćenje izvršavanja programa korak po korak, analizu registara i memorije, kao i pronalaženje ranjivosti. OllyDbg je dostupan samo za Windows.

### WinDbg

WinDbg je alat za debagovanje koji je razvio Microsoft. Ovaj alat se često koristi za analizu izvršavanja programa, praćenje grešaka i pronalaženje ranjivosti. WinDbg je dostupan samo za Windows.

## Zaključak

Obrtanje inženjeringa je važna tehnika u svetu hakovanja koja omogućava analizu softvera i pronalaženje sigurnosnih propusta. Korišćenje odgovarajućih metoda i alata može vam pomoći da efikasno izvršite obrtanje inženjeringa i identifikujete ranjivosti.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
I kliknite na **compile**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Zatim sačuvajte novi fajl na _**File >> Save module...**_:

![](<../../.gitbook/assets/image (279).png>)

Ovo je neophodno jer ako to ne uradite, tokom **runtime**-a će biti primenjene neke **optimizacije** na kodu i moguće je da prilikom debagiranja **break-point neće biti dostignut** ili da neki **promenljivi ne postoje**.

Zatim, ako se vaša .Net aplikacija **izvršava** putem **IIS**-a, možete je **restartovati** sa:
```
iisreset /noforce
```
Zatim, da biste započeli sa debagovanjem, trebali biste zatvoriti sve otvorene datoteke i unutar **Debug kartice** odabrati **Attach to Process...**:

![](<../../.gitbook/assets/image (280).png>)

Zatim odaberite **w3wp.exe** da biste se povezali sa **IIS serverom** i kliknite na **attach**:

![](<../../.gitbook/assets/image (281).png>)

Sada kada debagiramo proces, vrijeme je da ga zaustavimo i učitamo sve module. Prvo kliknite na _Debug >> Break All_, a zatim kliknite na _**Debug >> Windows >> Modules**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Kliknite na bilo koji modul na **Modules** i odaberite **Open All Modules**:

![](<../../.gitbook/assets/image (284).png>)

Desnim klikom na bilo koji modul u **Assembly Explorer** i kliknite na **Sort Assemblies**:

![](<../../.gitbook/assets/image (285).png>)

## Java dekompajler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debagiranje DLL-ova

### Korišćenje IDA

* **Učitajte rundll32** (64-bitni u C:\Windows\System32\rundll32.exe i 32-bitni u C:\Windows\SysWOW64\rundll32.exe)
* Odaberite **Windbg** debager
* Odaberite "**Suspend on library load/unload**"

![](<../../.gitbook/assets/image (135).png>)

* Konfigurišite **parametre** izvršenja postavljajući **putanju do DLL-a** i funkciju koju želite pozvati:

![](<../../.gitbook/assets/image (136).png>)

Zatim, kada započnete debagiranje, **izvršenje će biti zaustavljeno kada se svaki DLL učita**, a zatim, kada rundll32 učita vaš DLL, izvršenje će biti zaustavljeno.

Ali, kako možete pristupiti kodu DLL-a koji je učitan? Koristeći ovu metodu, ne znam kako.

### Korišćenje x64dbg/x32dbg

* **Učitajte rundll32** (64-bitni u C:\Windows\System32\rundll32.exe i 32-bitni u C:\Windows\SysWOW64\rundll32.exe)
* **Promijenite Command Line** ( _File --> Change Command Line_ ) i postavite putanju do DLL-a i funkciju koju želite pozvati, na primjer: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Promijenite _Options --> Settings_ i odaberite "**DLL Entry**".
* Zatim **pokrenite izvršenje**, debager će se zaustaviti na svakom dll main, u nekom trenutku ćete **zaustaviti u dll Entry svog dll-a**. Odavde samo tražite tačke na kojima želite postaviti prekid.

Primijetite da kada je izvršenje zaustavljeno iz bilo kojeg razloga u win64dbg, možete vidjeti **u kojem se kodu nalazite** gledajući u **vrhu prozora win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Zatim, gledajući ovo možete vidjeti kada je izvršenje zaustavljeno u dll-u koji želite debagirati.

## GUI aplikacije / Video igre

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje važnih vrijednosti koje su spremljene u memoriji pokrenute igre i njihovo mijenjanje. Više informacija na:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shell kodovi

### Debagiranje shell koda pomoću blobrunner-a

[**Blobrunner**](https://github.com/OALabs/BlobRunner) će **alocirati** shell kod unutar prostora memorije, **pokazati** vam **adresu memorije** na kojoj je shell kod alociran i **zaustaviti** izvršenje.\
Zatim, trebate **povezati debager** (Ida ili x64dbg) sa procesom i postaviti **prekidnu tačku na označenoj adresi memorije** i **nastaviti** izvršenje. Na taj način ćete debagirati shell kod.

Stranica izdanja na github-u sadrži zipove koji sadrže kompilirane verzije: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Možete pronaći malo izmijenjenu verziju Blobrunner-a na sljedećem linku. Da biste je kompajlirali, samo **kreirajte C/C++ projekat u Visual Studio Code-u, kopirajte i zalijepite kod i izgradite ga**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debagiranje shell koda pomoću jmp2it-a

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)je vrlo sličan blobrunner-u. On će **alocirati** shell kod unutar prostora memorije i pokrenuti **beskonačnu petlju**. Zatim trebate **povezati debager** sa procesom, **pokrenuti, sačekati 2-5 sekundi i pritisnuti stop** i naći ćete se unutar **beskonačne petlje**. Skočite na sljedeću instrukciju beskonačne petlje jer će to biti poziv shell kodu, i na kraju ćete se naći u izvršavanju shell koda.

![](<../../.gitbook/assets/image (397).png>)

Možete preuzeti kompiliranu verziju [jmp2it sa stranice izdanja](https://github.com/adamkramer/jmp2it/releases/).

### Debagiranje shell koda pomoću Cutter-a

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) je grafički korisnički interfejs za radare. Pomoću Cutter-a možete emulirati shell kod i dinamički ga pregledati.

Imajte na umu da Cutter vam omogućava "Otvori datoteku" i "Otvori shell kod". U mom slučaju, kada sam otvorio shell kod kao datoteku, dekompajlirao ga je ispravno, ali kada sam ga otvorio kao shell kod, nije:

![](<../../.gitbook/assets/image (400).png>)

Da biste započeli emulaciju na mjestu na kojem želite, postavite prekidnu tačku tamo i izgleda da će Cutter automatski pokrenuti emulaciju od tamo:

![](<../../.gitbook/assets/image (399).png>)

Možete vidjeti stek na primjer unutar heksadecimalnog prikaza:

![](<../../.gitbook/assets/image (402).png>)

### Deobfuskacija shell koda i dobijanje izvršenih funkcija

Trebali biste isprobati [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
On će vam reći koje funkcije shell kod koristi i da li se shell kod **dekodira** u memoriji.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg takođe ima grafički pokretač gde možete odabrati opcije koje želite i izvršiti shellcode

![](<../../.gitbook/assets/image (398).png>)

Opcija **Create Dump** će izbaciti konačni shellcode ako se bilo kakva promena izvrši dinamički u memoriji (korisno za preuzimanje dekodiranog shellcode-a). **Start offset** može biti koristan da započnete shellcode na određenom offsetu. Opcija **Debug Shell** je korisna za debugiranje shellcode-a koristeći scDbg terminal (međutim, smatram da su sve prethodno objašnjene opcije bolje za ovu svrhu jer ćete moći koristiti Ida ili x64dbg).

### Disassembling pomoću CyberChefa

Otpremite svoju datoteku shellcode-a kao ulaz i koristite sledeći recept za dekompilaciju: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ovaj obfuscator **menja sve instrukcije za `mov`** (da, zaista kul). Takođe koristi prekide da promeni tok izvršavanja. Za više informacija o tome kako radi:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Ako imate sreće, [demovfuscator](https://github.com/kirschju/demovfuscator) će deobfuskirati binarnu datoteku. Ima nekoliko zavisnosti.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [instalirajte keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ako igrate **CTF, ovaj trik za pronalaženje zastave** može biti vrlo koristan: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje prijetnji, pronalazi probleme u cijelom vašem tehnološkom sklopu, od API-ja do web aplikacija i cloud sustava. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Da biste pronašli **ulaznu točku**, pretražite funkcije pomoću `::main` kao u:

![](<../../.gitbook/assets/image (612).png>)

U ovom slučaju, binarni je nazvan authenticator, pa je prilično očigledno da je ovo zanimljiva glavna funkcija.\
Imajući **ime** **funkcija** koje se pozivaju, pretražite ih na **Internetu** kako biste saznali o njihovim **ulazima** i **izlazima**.

## **Delphi**

Za Delphi kompilirane binarne datoteke možete koristiti [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ako morate obrnuti Delphi binarnu datoteku, predlažem vam da koristite IDA dodatak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Samo pritisnite **ATL+f7** (uvoz python dodatka u IDA) i odaberite python dodatak.

Ovaj dodatak će izvršiti binarnu datoteku i dinamički riješiti imena funkcija na početku ispitivanja. Nakon pokretanja ispitivanja ponovno pritisnite gumb Start (zeleni ili f9) i prekidna točka će se aktivirati na početku stvarnog koda.

Također je vrlo zanimljivo jer ako pritisnete gumb u grafičkoj aplikaciji, debugger će se zaustaviti u funkciji koju izvršava taj gumb.

## Golang

Ako morate obrnuti Golang binarnu datoteku, predlažem vam da koristite IDA dodatak [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Samo pritisnite **ATL+f7** (uvoz python dodatka u IDA) i odaberite python dodatak.

To će riješiti imena funkcija.

## Kompajlirani Python

Na ovoj stranici možete saznati kako dobiti python kod iz ELF/EXE python kompilirane binarne datoteke:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Ako dobijete **binarnu** datoteku GBA igre, možete koristiti različite alate za **emulaciju** i **debugiranje**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Preuzmite verziju za debugiranje_) - Sadrži debugger s sučeljem
* [**mgba** ](https://mgba.io)- Sadrži CLI debugger
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra dodatak
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra dodatak

U [**no$gba**](https://problemkaputt.de/gba.htm), u _**Options --> Emulation Setup --> Controls**_\*\* \*\* možete vidjeti kako pritisnuti tipke Game Boy Advance-a

![](<../../.gitbook/assets/image (578).png>)

Kada se pritisne, svaki **ključ ima vrijednost** koja ga identificira:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Dakle, u ovakvim programima, interesantan deo će biti **kako program obrađuje korisnički unos**. Na adresi **0x4000130** nalazi se često korišćena funkcija: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Na prethodnoj slici možete videti da se funkcija poziva iz **FUN\_080015a8** (adrese: _0x080015fa_ i _0x080017ac_).

U toj funkciji, nakon nekih inicijalnih operacija (bez ikakvog značaja):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Pronađen je ovaj kod:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Poslednji if proverava da li je **`uVar4`** u **poslednjim ključevima** i da nije trenutni ključ, što se naziva otpuštanje dugmeta (trenutni ključ je smešten u **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
U prethodnom kodu možete videti da upoređujemo **uVar1** (mesto gde se nalazi **vrednost pritisnutog dugmeta**) sa nekim vrednostima:

* Prvo se upoređuje sa **vrednošću 4** (**SELECT** dugme): U izazovu ovo dugme briše ekran.
* Zatim se upoređuje sa **vrednošću 8** (**START** dugme): U izazovu se proverava da li je kod validan za dobijanje zastave.
* U ovom slučaju se varijabla **`DAT_030000d8`** upoređuje sa 0xf3 i ako je vrednost ista, izvršava se određeni kod.
* U svim ostalim slučajevima se proverava neka promenljiva (`DAT_030000d4`). To je promenljiva jer se dodaje 1 odmah nakon unosa koda.\
Ako je manje od 8, radi se nešto što uključuje **dodavanje** vrednosti u \*\*`DAT_030000d8` \*\* (u osnovi se dodaju vrednosti pritisnutih tastera u ovu promenljivu sve dok je brojač manji od 8).

Dakle, u ovom izazovu, znajući vrednosti dugmića, trebalo je **pritisnuti kombinaciju sa dužinom manjom od 8 tako da je rezultujuće sabiranje jednako 0xf3**.

**Reference za ovaj tutorijal:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kursevi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i sistemima u oblaku. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
