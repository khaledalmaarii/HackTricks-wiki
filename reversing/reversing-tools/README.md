{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

# Wasm Decompilering en Wat Kompilering Gids

In die wêreld van **WebAssembly**, is gereedskap vir **decompilering** en **kompilering** noodsaaklik vir ontwikkelaars. Hierdie gids stel 'n paar aanlyn hulpbronne en sagteware voor vir die hantering van **Wasm (WebAssembly binêre)** en **Wat (WebAssembly teks)** lêers.

## Aanlyn Gereedskap

- Om **decompile** Wasm na Wat, is die gereedskap beskikbaar by [Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) handig.
- Vir **kompilering** van Wat terug na Wasm, dien [Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) die doel.
- 'n Ander decompilering opsie kan gevind word by [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Sagteware Oplossings

- Vir 'n meer robuuste oplossing, bied [JEB deur PNF Software](https://www.pnfsoftware.com/jeb/demo) uitgebreide funksies.
- Die oopbron projek [wasmdec](https://github.com/wwwg/wasmdec) is ook beskikbaar vir decompilering take.

# .Net Decompilering Hulpbronne

Decompilering van .Net assemblies kan gedoen word met gereedskap soos:

- [ILSpy](https://github.com/icsharpcode/ILSpy), wat ook 'n [plugin vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) bied, wat kruis-platform gebruik moontlik maak.
- Vir take wat **decompilering**, **wysiging**, en **herkompilering** behels, word [dnSpy](https://github.com/0xd4d/dnSpy/releases) hoogs aanbeveel. **Regsklik** op 'n metode en kies **Wysig Metode** stel kode veranderinge in staat.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) is 'n ander alternatief vir decompilering van .Net assemblies.

## Verbetering van Foutopsporing en Logging met DNSpy

### DNSpy Logging
Om inligting na 'n lêer te log met DNSpy, sluit die volgende .Net kode-snippet in:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Wagwoord: " + password + "\n");
%%%

### DNSpy Foutopsporing
Vir effektiewe foutopsporing met DNSpy, word 'n reeks stappe aanbeveel om **Assembly eienskappe** vir foutopsporing aan te pas, wat verseker dat optimalisering wat foutopsporing kan hindern, gedeaktiveer is. Hierdie proses sluit die verandering van die `DebuggableAttribute` instellings in, herkompilering van die assembly, en die stoor van die veranderinge.

Boonop, om 'n .Net toepassing wat deur **IIS** gedraai word te foutopspoor, herbegin `iisreset /noforce` IIS. Om DNSpy aan die IIS proses te heg vir foutopsporing, gee die gids aan om die **w3wp.exe** proses binne DNSpy te kies en die foutopsporing sessie te begin.

Vir 'n omvattende oorsig van gelaaide modules tydens foutopsporing, word dit aanbeveel om die **Modules** venster in DNSpy te benader, gevolg deur die opening van alle modules en die sortering van assemblies vir makliker navigasie en foutopsporing.

Hierdie gids sluit die essensie van WebAssembly en .Net decompilering in, wat 'n pad bied vir ontwikkelaars om hierdie take met gemak te navigeer.

## **Java Decompiler**
Om Java bytecode te decompile, kan hierdie gereedskap baie nuttig wees:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Foutopsporing DLLs**
### Gebruik IDA
- **Rundll32** word gelaai vanaf spesifieke paaie vir 64-bit en 32-bit weergawes.
- **Windbg** word gekies as die foutopsporing gereedskap met die opsie om op biblioteek laai/ontlaai te pauzeer geaktiveer.
- Uitvoeringsparameters sluit die DLL pad en funksienaam in. Hierdie opstelling stop uitvoering by elke DLL se laai.

### Gebruik x64dbg/x32dbg
- Soortgelyk aan IDA, word **rundll32** gelaai met opdraglyn wysigings om die DLL en funksie te spesifiseer.
- Instellings word aangepas om op DLL toegang te breek, wat die instelling van breekpunte by die gewenste DLL toegangspunt moontlik maak.

### Beelde
- Uitvoering stop punte en konfigurasies word deur middel van skermskote geïllustreer.

## **ARM & MIPS**
- Vir emulasie, is [arm_now](https://github.com/nongiach/arm_now) 'n nuttige hulpbron.

## **Shellcodes**
### Foutopsporing Tegnieke
- **Blobrunner** en **jmp2it** is gereedskap vir die toewysing van shellcodes in geheue en die foutopsporing daarvan met Ida of x64dbg.
- Blobrunner [vrygawes](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [gecompileerde weergawe](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** bied GUI-gebaseerde shellcode emulasie en inspeksie, wat verskille in shellcode hantering as 'n lêer teenoor direkte shellcode uitlig.

### Deobfuscation en Analise
- **scdbg** bied insigte in shellcode funksies en deobfuscation vermoëns.
%%%bash
scdbg.exe -f shellcode # Basiese inligting
scdbg.exe -f shellcode -r # Analise verslag
scdbg.exe -f shellcode -i -r # Interaktiewe hake
scdbg.exe -f shellcode -d # Dump gedecodeerde shellcode
scdbg.exe -f shellcode /findsc # Vind begin offset
scdbg.exe -f shellcode /foff 0x0000004D # Voer uit vanaf offset
%%%

- **CyberChef** vir die disassemblage van shellcode: [CyberChef resep](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- 'n obfuscator wat alle instruksies met `mov` vervang.
- Nuttige hulpbronne sluit 'n [YouTube verduideliking](https://www.youtube.com/watch?v=2VF_wPkiBJY) en [PDF skyfies](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf) in.
- **demovfuscator** mag movfuscator se obfuscation omkeer, wat afhanklikhede soos `libcapstone-dev` en `libz3-dev` vereis, en die installering van [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Vir Delphi binêre, word [IDR](https://github.com/crypto2011/IDR) aanbeveel.


# Kursusse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binêre deobfuscation\)



{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
