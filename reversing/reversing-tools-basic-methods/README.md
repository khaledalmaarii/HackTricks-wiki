# Omkeerhulpmiddels & Basiese Metodes

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Probeer Hard Security Group**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## ImGui-gebaseerde Omkeerhulpmiddels

Sagteware:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat-kompilator

Aanlyn:

* Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om te **decompileer** vanaf wasm (binêr) na wat (teks)
* Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om te **kompileer** vanaf wat na wasm
* Jy kan ook probeer om [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) te decompileer

Sagteware:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n decompiler wat **decompileer en ondersoek meervoudige formate**, insluitend **biblioteke** (.dll), **Windows metadatabestande** (.winmd), en **uitvoerbare lêers** (.exe). Nadat dit ontleed is, kan 'n samestelling gestoor word as 'n Visual Studio-projek (.csproj).

Die verdienste hier is dat as 'n verlore bronkode herstel moet word vanaf 'n ouer samestelling, kan hierdie aksie tyd bespaar. Verder bied dotPeek handige navigasie deur die ontleedde kode, wat dit een van die perfekte hulpmiddels maak vir **Xamarin-algoritmeanalise.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende invoegmodel en 'n API wat die hulpmiddel uitbrei om by jou presiese behoeftes te pas, bespaar .NET Reflector tyd en vereenvoudig ontwikkeling. Kom ons kyk na die oorvloed van omgekeerde ingenieursdienste wat hierdie hulpmiddel bied:

* Gee insig in hoe die data vloei deur 'n biblioteek of komponent
* Gee insig in die implementering en gebruik van .NET-tale en -raamwerke
* Vind ongedokumenteerde en onblootgestelde funksionaliteit om meer uit die gebruikte API's en tegnologieë te kry.
* Vind afhanklikhede en verskillende samestellings
* Spoor die presiese ligging van foute in jou kode, derdeparty-komponente en biblioteke af.
* Foutopsporing in die bron van al die .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit hê op enige bedryfstelsel (jy kan dit direk vanaf VSCode installeer, geen nodigheid om die git af te laai nie. Klik op **Uitbreidings** en **soek ILSpy**).\
As jy moet **decompileer**, **verander** en **weer kompileer** kan jy [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) gebruik of 'n aktief onderhoude vurk daarvan, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Regsklik -> Wysig Metode** om iets binne 'n funksie te verander).

### DNSpy Logging

Om **DNSpy 'n paar inligting in 'n lêer te laat log**, kan jy hierdie snipper:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Foutopsporing

Om kode te foutopspoor met DNSpy moet jy:

Eerstens, verander die **Monteerkenmerke** wat verband hou met **foutopsporing**:

![](<../../.gitbook/assets/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Na:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
En klik op **kompilasie**:

![](<../../.gitbook/assets/image (314) (1).png>)

Berg dan die nuwe lêer op via _**Lêer >> Berg module op...**_:

![](<../../.gitbook/assets/image (602).png>)

Dit is noodsaaklik omdat as jy dit nie doen nie, sal verskeie **optimaliserings** tydens **uitvoering** op die kode toegepas word en dit moontlik wees dat terwyl jy 'n **onderbreekpunt** aan die **debugging** is nooit bereik word of sommige **veranderlikes** nie bestaan nie.

Dan, as jou .NET-toepassing deur **IIS** uitgevoer word, kan jy dit **herlaai** met:
```
iisreset /noforce
```
Dan, om te begin met foutopsporing moet jy al die geopende lêers sluit en binne die **Foutopsporing**-tabblad **Heg aan Proses...** kies:

![](<../../.gitbook/assets/image (318).png>)

Kies dan **w3wp.exe** om aan die **IIS-bediener** te heg en klik **heg aan**:

![](<../../.gitbook/assets/image (113).png>)

Nou dat ons die proses foutopspoor, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Foutopsporing >> Breek Alles_ en dan klik op _**Foutopsporing >> Vensters >> Modules**_:

![](<../../.gitbook/assets/image (132).png>)

![](<../../.gitbook/assets/image (834).png>)

Klik op enige module op **Modules** en kies **Maak Alle Modules Oop**:

![](<../../.gitbook/assets/image (922).png>)

Regsklik op enige module in **Monteerder Verkenner** en klik **Sorteer Versamelings**:

![](<../../.gitbook/assets/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Foutopsporing DLL's

### Met behulp van IDA

* **Laai rundll32** (64-bits in C:\Windows\System32\rundll32.exe en 32-bits in C:\Windows\SysWOW64\rundll32.exe)
* Kies **Windbg** foutopspoorger
* Kies "**Stel op skorsing by biblioteek laai/ontlaai**"

![](<../../.gitbook/assets/image (868).png>)

* Stel die **parameters** van die uitvoering in deur die **pad na die DLL** en die funksie wat jy wil roep in te stel:

![](<../../.gitbook/assets/image (704).png>)

Dan, wanneer jy begin met foutopsporing, sal die uitvoering gestop word wanneer elke DLL gelaai word, dan, wanneer rundll32 jou DLL laai, sal die uitvoering gestop word.

Maar, hoe kan jy by die kode van die DLL wat gelaai is, kom? Met behulp van hierdie metode, weet ek nie hoe nie.

### Met behulp van x64dbg/x32dbg

* **Laai rundll32** (64-bits in C:\Windows\System32\rundll32.exe en 32-bits in C:\Windows\SysWOW64\rundll32.exe)
* **Verander die Opdraglyn** ( _Lêer --> Verander Opdraglyn_ ) en stel die pad van die dll en die funksie wat jy wil roep in, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\gedeel\Cyberkamp\rev2\\\14.ridii\_2.dll",DLLMain
* Verander _Opsies --> Instellings_ en kies "**DLL Inskrywing**".
* Begin dan met die uitvoering, die foutopspoorger sal by elke dll-hoof stop, op 'n stadium sal jy **stop in die dll Inskrywing van jou dll**. Van daar af, soek net na die punte waar jy 'n breekpunt wil plaas.

Let daarop dat wanneer die uitvoering gestop word om enige rede in win64dbg, kan jy sien **in watter kode jy is** deur na die **bo van die win64dbg-venster** te kyk:

![](<../../.gitbook/assets/image (842).png>)

Dan, deur na hierdie te kyk, kan jy sien wanneer die uitvoering in die dll wat jy wil foutopspoor, gestop is.

## GUI-toepassings / Videospelletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende spel gestoor word en om hulle te verander. Meer inligting in:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is 'n voorsteinde/omgekeerde ingenieurswese hulpmiddel vir die GNU Project Foutopspoorger (GDB), wat op speletjies fokus. Dit kan egter vir enige omgekeerde-ingenieurswese verwante dinge gebruik word

[**Decompiler Explorer**](https://dogbolt.org/) is 'n web voorsteinde vir 'n aantal decompilers. Hierdie webdiens laat jou toe om die uitset van verskillende decompilers op klein uitvoerbare lêers te vergelyk.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellkodes

### Foutopsporing van 'n shellkode met blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) sal die **shellkode** binne 'n geheue-ruimte toewys, sal jou die **geheue-adres** aandui waar die shellkode toegewys is en sal die uitvoering **stop**.\
Dan moet jy 'n foutopspoorger (Ida of x64dbg) aan die proses heg en 'n **breekpunt by die aangeduide geheue-adres** plaas en die uitvoering **hervat**. Op hierdie manier sal jy die shellkode foutopspoor.

Die github-bladsy met vrystellings bevat zip-lêers wat die saamgestelde vrystellings bevat: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan 'n effens gewysigde weergawe van Blobrunner vind by die volgende skakel. Om dit saam te stel, **skep net 'n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Foutopsporing van 'n shellkode met jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is baie soortgelyk aan blobrunner. Dit sal die **shellkode** binne 'n geheue-ruimte toewys en 'n **ewige lus** begin. Jy moet dan die foutopspoorger aan die proses heg, **begin speel wag 2-5 sekondes en druk stop** en jy sal jouself binne die **ewige lus** vind. Spring na die volgende instruksie van die ewige lus aangesien dit 'n oproep na die shellkode sal wees, en uiteindelik sal jy vind dat jy die shellkode uitvoer.

![](<../../.gitbook/assets/image (509).png>)

Jy kan 'n saamgestelde weergawe van [jmp2it binne die vrystellingsbladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Foutopsporing van 'n shellkode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met cutter kan jy die shellkode emuleer en dit dinamies inspekteer.

Let daarop dat Cutter jou toelaat om "Lêer Oop te Maak" en "Shellkode Oop te Maak". In my geval toe ek die shellkode as 'n lêer oopgemaak het, het dit dit korrek ontleed, maar toe ek dit as 'n shellkode oopgemaak het, het dit nie:

![](<../../.gitbook/assets/image (562).png>)

Om die emulasie te begin op die plek waar jy wil, stel 'n bp daar en blykbaar sal cutter outomaties die emulasie van daar begin:

![](<../../.gitbook/assets/image (589).png>)

![](<../../.gitbook/assets/image (387).png>)

Jy kan die stok byvoorbeeld binne 'n heksdump sien:

![](<../../.gitbook/assets/image (186).png>)

### Ontsleuteling van shellkode en verkryging van uitgevoerde funksies

Jy moet **scdbg** probeer ([http://sandsprite.com/blogs/index.php?uid=7\&pid=152](http://sandsprite.com/blogs/index.php?uid=7\&pid=152)).\
Dit sal vir jou sê watter funksies die shellkode gebruik en of die shellkode homself in geheue ontsluit.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg het ook 'n grafiese aanvraer waar jy die opsies wat jy wil kies en die shellcode kan uitvoer

![](<../../.gitbook/assets/image (258).png>)

Die **Skep Dump** opsie sal die finale shellcode dump as enige verandering aan die shellcode dinamies in die geheue gedoen word (nuttig om die gedekodeerde shellcode af te laai). Die **begin offset** kan nuttig wees om die shellcode te begin by 'n spesifieke offset. Die **Debug Shell** opsie is nuttig om die shellcode te debug deur die scDbg-terminal te gebruik (ek vind egter enige van die opsies wat voorheen verduidelik is beter vir hierdie aangeleentheid aangesien jy Ida of x64dbg kan gebruik).

### Ontskeur deur CyberChef te gebruik

Laai jou shellcode-lêer as insette en gebruik die volgende resep om dit te dekomponeer: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie ontwrigter **verander al die instruksies vir `mov`**(ja, regtig cool). Dit gebruik ook onderbrekings om uitvoervloeie te verander. Vir meer inligting oor hoe dit werk:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

As jy gelukkig is, sal [demovfuscator](https://github.com/kirschju/demovfuscator) die binêre lêer ontskeur. Dit het verskeie afhanklikhede
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy 'n **CTF speel, kan hierdie omweg om die vlag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Om die **inskrywpunt** te vind, soek vir die funksies deur `::main` soos in:

![](<../../.gitbook/assets/image (1080).png>)

In hierdie geval is die binêre lêer genoem authenticator, so dit is redelik duidelik dat dit die interessante hooffunksie is.\
Met die **naam** van die **funksies** wat opgeroep word, soek vir hulle op die **Internet** om meer oor hul **inskrywings** en **uitsette** te leer.

## **Delphi**

Vir Delphi saamgestelde binêre lêers kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik

As jy 'n Delphi binêre lêer moet omkeer, sal ek voorstel dat jy die IDA-inprop [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik

Druk net **ATL+f7** (import python inprop in IDA) en kies die python inprop.

Hierdie inprop sal die binêre lêer uitvoer en funksienames dinamies aan die begin van die foutopsporing oplos. Nadat die foutopsporing begin het, druk weer op die Begin-knoppie (die groen een of f9) en 'n breekpunt sal tref aan die begin van die werklike kode.

Dit is ook baie interessant omdat as jy 'n knoppie in die grafiese aansoek druk, sal die foutopspoorprogram in die funksie stop wat deur daardie knoppie uitgevoer word.

## Golang

As jy 'n Golang binêre lêer moet omkeer, sal ek voorstel dat jy die IDA-inprop [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik

Druk net **ATL+f7** (import python inprop in IDA) en kies die python inprop.

Dit sal die name van die funksies oplos.

## Saamgestelde Python

Op hierdie bladsy kan jy vind hoe om die python-kode uit 'n ELF/EXE python-saamgestelde binêre lêer te kry:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

As jy die **binêre** van 'n GBA-speletjie kry, kan jy verskillende gereedskap gebruik om dit te **emuleer** en **foutopsporing**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die foutopsporingsweergawe af_) - Bevat 'n foutopspoorprogram met 'n koppelvlak
* [**mgba** ](https://mgba.io)- Bevat 'n CLI-foutopspoorprogram
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_\*\* \*\* kan jy sien hoe om die Game Boy Advance **knoppies** te druk

![](<../../.gitbook/assets/image (581).png>)

Wanneer dit gedruk word, het elke **sleutel 'n waarde** om dit te identifiseer:
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
So, in hierdie soort program, sal die interessante deel wees **hoe die program die gebruiker se insette hanteer**. In die adres **0x4000130** sal jy die algemeen gevonde funksie vind: **KEYINPUT**.

![](<../../.gitbook/assets/image (447).png>)

In die vorige beeld kan jy sien dat die funksie geroep word vanaf **FUN\_080015a8** (adresse: _0x080015fa_ en _0x080017ac_).

In daardie funksie, na 'n paar inisialiseringsoperasies (sonder enige belang):
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
Dit is gevind hierdie kode:
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
Die laaste if kontroleer of **`uVar4`** in die **laaste Sleutels** is en nie die huidige sleutel is nie, ook genoem om 'n knoppie los te laat (die huidige sleutel word gestoor in **`uVar1`**).
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
In die vorige kode kan jy sien dat ons **uVar1** (die plek waar die **waarde van die gedrukte knoppie** is) vergelyk met sekere waardes:

- Eerstens, dit word vergelyk met die **waarde 4** (**SELECT** knoppie): In die uitdaging maak hierdie knoppie die skerm skoon
- Dan word dit vergelyk met die **waarde 8** (**START** knoppie): In die uitdaging word hierdie knoppie gebruik om te kyk of die kode geldig is om die vlag te kry.
- In hierdie geval word die var **`DAT_030000d8`** vergelyk met 0xf3 en as die waarde dieselfde is, word sekere kode uitgevoer.
- In enige ander gevalle word daar na 'n kont (`DAT_030000d4`) gekyk. Dit is 'n kont omdat dit 1 byvoeg net nadat die kode ingegaan is.\
As dit minder as 8 is, word iets gedoen wat die byvoeging van waardes aan **`DAT_030000d8`** behels (basies word die waardes van die gedrukte knoppies by hierdie veranderlike gevoeg solank die kont minder as 8 is).

Dus, in hierdie uitdaging, deur die waardes van die knoppies te ken, moes jy **'n kombinasie indruk met 'n lengte kleiner as 8 waarvan die resulterende byvoeging 0xf3 is.**

**Verwysing vir hierdie handleiding:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kursusse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binêre deobfuscation)

**Try Hard Security Group**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
