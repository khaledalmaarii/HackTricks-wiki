# Reversing Tools & Basiese Metodes

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## ImGui-gebaseerde omkeerhulpmiddels

Sagteware:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm-ontleder / Wat-kompilator

Aanlyn:

* Gebruik [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) om van wasm (binêre) na wat (duidelike teks) te **ontleed**
* Gebruik [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) om van wat na wasm te **kompileer**
* Jy kan ook probeer om [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) te gebruik om te ontleed

Sagteware:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net-ontleder

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is 'n ontleder wat **ontleed en ondersoek doen na verskeie formate**, insluitend **biblioteke** (.dll), **Windows-metadata-lêers** (.winmd) en **uitvoerbare lêers** (.exe). Nadat dit ontleed is, kan 'n samestelling as 'n Visual Studio-projek (.csproj) gestoor word.

Die voordeel hiervan is dat as 'n verlore bronkode herstel moet word uit 'n ouerwetse samestelling, kan hierdie aksie tyd bespaar. Verder bied dotPeek handige navigasie deur die ontleedde kode, wat dit een van die perfekte hulpmiddels maak vir **Xamarin-algoritmeanalise.**&#x20;

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Met 'n omvattende byvoegingsmodel en 'n API wat die hulpmiddel uitbrei om aan jou presiese behoeftes te voldoen, bespaar .NET reflector tyd en vereenvoudig ontwikkeling. Kom ons kyk na die oorvloed van omgekeerde ingenieursdienste wat hierdie hulpmiddel bied:

* Gee insig in hoe die data vloei deur 'n biblioteek of komponent
* Gee insig in die implementering en gebruik van .NET-tale en raamwerke
* Vind ongedokumenteerde en onblootgestelde funksionaliteit om meer uit die gebruikte API's en tegnologieë te haal.
* Vind afhanklikhede en verskillende samestellings
* Spoor die presiese ligging van foute in jou kode, derdeparty-komponente en biblioteke op.&#x20;
* Doen foutopsporing in die bron van alle .NET-kode waarmee jy werk.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Jy kan dit hê op enige bedryfstelsel (jy kan dit direk vanaf VSCode installeer, geen nodig om die git af te laai nie. Klik op **Extensions** en **search ILSpy**).\
As jy moet **ontleed**, **verander** en **weer saamstel**, kan jy gebruik maak van: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Right Click -> Modify Method** om iets binne 'n funksie te verander).\
Jy kan ook [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/) probeer.

### DNSpy Logging

Om **DNSpy om sekere inligting in 'n lêer te log**, kan jy hierdie .Net-lyne gebruik:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debuur

Om kode te debuut met behulp van DNSpy, moet jy die volgende doen:

Eerstens, verander die **Monteerkenmerke** wat verband hou met **debuut**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Aan:

# Reverse Engineering Tools - Basiese Metodes

Hierdie gids bevat 'n oorsig van basiese metodes en gereedskap wat gebruik word vir omgekeerde ingenieurswese. Hierdie metodes en gereedskap kan jou help om die werking van sagteware en hardeware te ontleed en te verstaan.

## Inhoudsopgawe

- [Wat is omgekeerde ingenieurswese?](#wat-is-omgekeerde-ingenieurswese)
- [Basiese metodes vir omgekeerde ingenieurswese](#basiese-metodes-vir-omgekeerde-ingenieurswese)
- [Gereedskap vir omgekeerde ingenieurswese](#gereedskap-vir-omgekeerde-ingenieurswese)
- [Aanbevole bronne](#aanbevole-bronne)

## Wat is omgekeerde ingenieurswese?

Omgekeerde ingenieurswese is die proses om 'n produk, sagteware of hardeware te ontled en te verstaan om die interne werking daarvan te bepaal. Dit behels die ontleed van binêre kode, ontleding van algoritmes en die identifisering van funksies en datastrukture binne die program.

## Basiese metodes vir omgekeerde ingenieurswese

Hier is 'n paar basiese metodes wat gebruik word vir omgekeerde ingenieurswese:

- **Stap-vir-stap ontleding**: Hierdie metode behels die stapsgewyse ontleding van die program deur die kode te ontleed en die funksies en datastrukture te identifiseer.
- **Statiese ontleding**: Hierdie metode behels die ontleding van die program sonder om dit uit te voer. Dit kan gedoen word deur die bronkode te bestudeer, die program te ontleed met behulp van gereedskap soos disassemblers en dekompilers, en die program te analiseer vir kwesbaarhede en beveiligingslekke.
- **Dinamiese ontleding**: Hierdie metode behels die uitvoering van die program in 'n geïsoleerde omgewing en die monitering van die program se gedrag. Dit kan gedoen word deur die program te hardloop in 'n virtuele masjien of 'n debugger te gebruik om die program te ontleed terwyl dit uitgevoer word.
- **Ontleding van netwerkverkeer**: Hierdie metode behels die ontleding van die netwerkverkeer tussen 'n toepassing en die bedieners waarmee dit kommunikeer. Dit kan gedoen word deur die netwerkverkeer te onderskep en te analiseer om inligting soos protokolle, versleuteling en data-uitruiling te verkry.

## Gereedskap vir omgekeerde ingenieurswese

Hier is 'n paar gereedskap wat gebruik kan word vir omgekeerde ingenieurswese:

- **Disassemblers**: Hierdie gereedskap ontleed die masjienkode van 'n program en vertaal dit na leesbare instruksies.
- **Dekompilers**: Hierdie gereedskap ontleed die uitvoerbare kode van 'n program en vertaal dit na bronkode.
- **Debugger**: Hierdie gereedskap maak dit moontlik om 'n program te ontleed terwyl dit uitgevoer word deur die program stap vir stap te deurloop en die waardes van veranderlikes en geheue-adresse te ondersoek.
- **Ontleders vir netwerkverkeer**: Hierdie gereedskap maak dit moontlik om die netwerkverkeer tussen 'n toepassing en die bedieners te ontleed en te analiseer.

## Aanbevole bronne

Hier is 'n paar aanbevole bronne vir verdere studie oor omgekeerde ingenieurswese:

- [Reverse Engineering for Beginners](https://beginners.re/RE4B-EN.pdf)
- [Practical Reverse Engineering](https://www.amazon.com/Practical-Reverse-Engineering-Reversing-Obfuscation/dp/1118787315)
- [Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/)
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
En klik op **kompilasie**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Stoor dan die nuwe lêer op _**Lêer >> Stoor module...**_:

![](<../../.gitbook/assets/image (279).png>)

Dit is nodig omdat as jy dit nie doen nie, sal verskeie **optimalisering** op die kode by **uitvoering** toegepas word en dit moontlik wees dat 'n **breekpunt nooit getref word** of sommige **veranderlikes nie bestaan nie**.

Dan, as jou .Net-toepassing deur **IIS** uitgevoer word, kan jy dit **herlaai** met:
```
iisreset /noforce
```
Daarna, om te begin met debuggen, moet jy alle geopende lêers sluit en binne die **Debug Tab** kies **Attach to Process...**:

![](<../../.gitbook/assets/image (280).png>)

Kies dan **w3wp.exe** om aan die **IIS-bediener** te heg en klik op **attach**:

![](<../../.gitbook/assets/image (281).png>)

Nou dat ons die proses aan die debuggen is, is dit tyd om dit te stop en al die modules te laai. Klik eers op _Debug >> Break All_ en dan klik op _**Debug >> Windows >> Modules**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Klik enige module op **Modules** en kies **Open All Modules**:

![](<../../.gitbook/assets/image (284).png>)

Regskliek enige module in **Assembly Explorer** en kies **Sort Assemblies**:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Met behulp van IDA

* **Laai rundll32** (64-bits in C:\Windows\System32\rundll32.exe en 32-bits in C:\Windows\SysWOW64\rundll32.exe)
* Kies **Windbg** debugger
* Kies "**Suspend on library load/unload**"

![](<../../.gitbook/assets/image (135).png>)

* Stel die **parameters** van die uitvoering in deur die **pad na die DLL** en die funksie wat jy wil oproep, in te voer:

![](<../../.gitbook/assets/image (136).png>)

Dan, wanneer jy begin met debuggen, sal die uitvoering gestop word wanneer elke DLL gelaai word. Wanneer rundll32 jou DLL laai, sal die uitvoering gestop word.

Maar, hoe kan jy by die kode van die DLL kom wat gelaai is? Met hierdie metode weet ek nie hoe nie.

### Met behulp van x64dbg/x32dbg

* **Laai rundll32** (64-bits in C:\Windows\System32\rundll32.exe en 32-bits in C:\Windows\SysWOW64\rundll32.exe)
* **Verander die opdraglyn** ( _File --> Change Command Line_ ) en stel die pad van die dll en die funksie wat jy wil oproep, byvoorbeeld: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Verander _Options --> Settings_ en kies "**DLL Entry**".
* Begin dan met die uitvoering, die debugger sal by elke dll hoof stop, op 'n punt sal jy stop in die dll Entry van jou dll. Van daar af, soek net na die punte waar jy 'n breekpunt wil plaas.

Let daarop dat wanneer die uitvoering om enige rede in win64dbg gestop word, kan jy sien **in watter kode jy is** deur na die **bo-kant van die win64dbg-venster** te kyk:

![](<../../.gitbook/assets/image (137).png>)

Dan kan jy sien wanneer die uitvoering gestop is in die dll wat jy wil debug.

## GUI-programme / Videospelletjies

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende spel gestoor word en om hulle te verander. Meer inligting in:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellkodes

### Debugging van 'n shellkode met blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) sal die **shellkode** toewys binne 'n geheue-ruimte, sal jou die **geheue-adres** waar die shellkode toegewys is, aandui en die uitvoering **stop**.\
Dan moet jy 'n debugger (Ida of x64dbg) aan die proses heg en 'n breekpunt by die aangeduide geheue-adres plaas en die uitvoering hervat. Op hierdie manier sal jy die shellkode debug.

Die github-bladsy met vrylatings bevat zip-lêers wat die saamgestelde vrylatings bevat: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Jy kan 'n effens gewysigde weergawe van Blobrunner in die volgende skakel vind. Om dit saam te stel, skep net 'n C/C++-projek in Visual Studio Code, kopieer en plak die kode en bou dit.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debugging van 'n shellkode met jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is baie soortgelyk aan blobrunner. Dit sal die **shellkode** toewys binne 'n geheue-ruimte en 'n **ewige lus** begin. Jy moet dan die debugger aan die proses heg, begin speel, 2-5 sekondes wag en stop druk, en jy sal jouself binne die **ewige lus** bevind. Spring na die volgende instruksie van die ewige lus, want dit sal 'n oproep na die shellkode wees, en uiteindelik sal jy die shellkode uitvoer.

![](<../../.gitbook/assets/image (397).png>)

Jy kan 'n saamgestelde weergawe van [jmp2it binne die vrylatingsbladsy aflaai](https://github.com/adamkramer/jmp2it/releases/).

### Debugging van shellkode met Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is die GUI van radare. Met cutter kan jy die shellkode emuleer en dit dinamies ondersoek.

Let daarop dat Cutter jou toelaat om "Open File" en "Open Shellcode" te doen. In my geval, toe ek die shellkode as 'n lêer oopgemaak het, het dit dit korrek ontleed, maar toe ek dit as 'n shellkode oopgemaak het, het dit nie:

![](<../../.gitbook/assets/image (400).png>)

Om die emulasie te begin op die plek waar jy wil, stel 'n bp daar en blykbaar sal cutter outomaties die emulasie daar begin:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Jy kan byvoorbeeld die stapel sien binne 'n heksdump:

![](<../../.gitbook/assets/image (402).png>)

### Ontmaskering van shellkode en verkryging van uitgevoerde funksies

Jy moet [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152) probeer.\
Dit sal jou dinge vertel soos **watter funksies** die shellkode gebruik en of die shellkode self in die geheue ontsluit word.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg tel ook 'n grafiese launcher waar jy die opsies kan kies wat jy wil en die shellcode kan uitvoer.

![](<../../.gitbook/assets/image (398).png>)

Die **Create Dump** opsie sal die finale shellcode dump as daar enige verandering aan die shellcode dinamies in die geheue gedoen word (nuttig om die gedekodeerde shellcode af te laai). Die **start offset** kan nuttig wees om die shellcode te begin by 'n spesifieke offset. Die **Debug Shell** opsie is nuttig om die shellcode te debug met behulp van die scDbg-terminal (ek vind egter enige van die opsies wat voorheen verduidelik is beter vir hierdie doel, omdat jy Ida of x64dbg kan gebruik).

### Disassembling met behulp van CyberChef

Laai jou shellcode-lêer as insette op en gebruik die volgende resep om dit te dekomponeer: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Hierdie obfuscator **verander alle instruksies vir `mov`** (ja, regtig cool). Dit gebruik ook onderbrekings om uitvoervloeie te verander. Vir meer inligting oor hoe dit werk:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

As jy gelukkig is, sal [demovfuscator](https://github.com/kirschju/demovfuscator) die binêre kode ontsluier. Dit het verskeie afhanklikhede.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
En [installeer keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

As jy 'n **CTF speel, kan hierdie omweg om die vlag te vind** baie nuttig wees: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Om die **inskakelpunt** te vind, soek die funksies deur `::main` soos in:

![](<../../.gitbook/assets/image (612).png>)

In hierdie geval is die binêre lêernaam authenticator, so dit is redelik duidelik dat dit die interessante hooffunksie is.\
Met die **naam** van die **funksies** wat aangeroep word, soek na hulle op die **Internet** om meer te leer oor hul **inskrywings** en **uitsette**.

## **Delphi**

Vir Delphi gekompileerde binêre lêers kan jy [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) gebruik

As jy 'n Delphi binêre lêer moet omkeer, sal ek voorstel dat jy die IDA-inprop [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) gebruik

Druk net **ATL+f7** (voer Python-inprop in IDA in) en kies die Python-inprop.

Hierdie inprop sal die binêre lêer uitvoer en funksienames dinamies oplos aan die begin van die foutopsporing. Druk na die begin van die foutopsporing weer die Begin-knoppie (die groen een of f9) en 'n breekpunt sal tref aan die begin van die regte kode.

Dit is ook baie interessant omdat as jy 'n knoppie in die grafiese toepassing druk, sal die foutopspoorprogram in die funksie stop wat deur daardie knoppie uitgevoer word.

## Golang

As jy 'n Golang binêre lêer moet omkeer, sal ek voorstel dat jy die IDA-inprop [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) gebruik

Druk net **ATL+f7** (voer Python-inprop in IDA in) en kies die Python-inprop.

Dit sal die name van die funksies oplos.

## Gekompileerde Python

Op hierdie bladsy kan jy vind hoe om die Python-kode uit 'n ELF/EXE Python-gekompileerde binêre lêer te kry:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

As jy die **binêre lêer** van 'n GBA-spel kry, kan jy verskillende hulpmiddels gebruik om dit te **emuleer** en **foutopsporing** daarop uit te voer:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Laai die foutopsporingsweergawe af_) - Bevat 'n foutopspoorprogram met 'n koppelvlak
* [**mgba** ](https://mgba.io)- Bevat 'n CLI-foutopspoorprogram
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-inprop
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-inprop

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_\*\* \*\* kan jy sien hoe om die Game Boy Advance **knoppies** te druk

![](<../../.gitbook/assets/image (578).png>)

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
So, in hierdie tipe programme, sal die interessante deel wees **hoe die program die gebruiker se insette hanteer**. In die adres **0x4000130** sal jy die algemeen gevonde funksie vind: **KEYINPUT.**

![](<../../.gitbook/assets/image (579).png>)

In die vorige prentjie kan jy sien dat die funksie geroep word vanaf **FUN\_080015a8** (adres: _0x080015fa_ en _0x080017ac_).

In daardie funksie, na 'n paar inisialisasie-operasies (sonder enige belangrikheid):
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
Dit is die kode wat gevind is:
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
Die laaste if-stelling kontroleer of `uVar4` in die laaste sleutels is en nie die huidige sleutel nie, wat ook genoem word om 'n knoppie los te laat (die huidige sleutel word gestoor in `uVar1`).
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

* Eerstens word dit vergelyk met die **waarde 4** (**SELECT**-knoppie): In die uitdaging vee hierdie knoppie die skerm skoon.
* Daarna word dit vergelyk met die **waarde 8** (**START**-knoppie): In die uitdaging word hierdie knoppie gebruik om te kyk of die kode geldig is om die vlag te kry.
* In hierdie geval word die var **`DAT_030000d8`** vergelyk met 0xf3 en as die waarde dieselfde is, word sekere kode uitgevoer.
* In enige ander gevalle word daar gekyk na 'n kont (`DAT_030000d4`). Dit is 'n kont omdat dit 1 byvoeg net nadat die kode ingegaan is.\
As dit minder as 8 is, word iets wat die byvoeging van waardes by \*\*`DAT_030000d8` \*\* behels, gedoen (basies word die waardes van die gedrukte sleutels in hierdie veranderlike bygevoeg solank die kont minder as 8 is).

Dus moes jy in hierdie uitdaging, met kennis van die waardes van die knoppies, **'n kombinasie indruk met 'n lengte kleiner as 8 sodat die resulterende byvoeging 0xf3 is.**

**Verwysing vir hierdie handleiding:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kursusse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binêre deobfuscation)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
