<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>

# Wasm Decompilasie en Wat Kompilasie Gids

In die wêreld van **WebAssembly** is gereedskap vir **decompilasie** en **kompilasie** noodsaaklik vir ontwikkelaars. Hierdie gids stel 'n paar aanlynbronne en sagteware bekend vir die hanteer van **Wasm (WebAssembly binêre)** en **Wat (WebAssembly-teks)** lêers.

## Aanlyn Gereedskap

- Vir die **decompilasie** van Wasm na Wat, is die gereedskap beskikbaar by [Wabt se wasm2wat-demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) handig.
- Vir die **kompilasie** van Wat terug na Wasm, dien [Wabt se wat2wasm-demo](https://webassembly.github.io/wabt/demo/wat2wasm/) die doel.
- 'n Ander decompilasie-opsie kan gevind word by [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Sagteware-Opsies

- Vir 'n meer robuuste oplossing, bied [JEB deur PNF Software](https://www.pnfsoftware.com/jeb/demo) uitgebreide funksies.
- Die oopbronprojek [wasmdec](https://github.com/wwwg/wasmdec) is ook beskikbaar vir decompilasietake.

# .Net Decompilasie Hulpbronne

Decompilasie van .Net-samestellings kan gedoen word met gereedskap soos:

- [ILSpy](https://github.com/icsharpcode/ILSpy), wat ook 'n [inprop vir Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) bied, wat kruisplatformgebruik moontlik maak.
- Vir take wat **decompilasie**, **modifikasie** en **rekompilasie** behels, word [dnSpy](https://github.com/0xd4d/dnSpy/releases) sterk aanbeveel. Deur met die regterknoppie op 'n metode te klik en **Modify Method** te kies, kan kodeveranderinge aangebring word.
- [JetBrains se dotPeek](https://www.jetbrains.com/es-es/decompiler/) is 'n ander alternatief vir die decompilasie van .Net-samestellings.

## Verbetering van Debugging en Logging met DNSpy

### DNSpy Logging
Om inligting na 'n lêer te log met behulp van DNSpy, sluit die volgende .Net-kodefragment in:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy Debugging
Vir effektiewe debugging met DNSpy, word 'n reeks stappe aanbeveel om **Assembly-eienskappe** vir debugging aan te pas, om te verseker dat optimalisering wat debugging kan belemmer, gedeaktiveer word. Hierdie proses sluit in die verandering van die `DebuggableAttribute`-instellings, die rekompilering van die samestelling en die stoor van die veranderinge.

Verder, om 'n .Net-toepassing wat deur **IIS** uitgevoer word te debug, herlaai IIS deur `iisreset /noforce` uit te voer. Om DNSpy aan die IIS-proses te heg vir debugging, bied die gids instruksies om die **w3wp.exe**-proses binne DNSpy te kies en die debugging-sessie te begin.

Vir 'n omvattende siening van gelaai modules tydens debugging, word dit aanbeveel om die **Modules**-venster in DNSpy te gebruik, gevolg deur die oopmaak van alle modules en die sortering van samestellings vir makliker navigasie en debugging.

Hierdie gids omvat die essensie van WebAssembly- en .Net-decompilasie en bied 'n pad vir ontwikkelaars om hierdie take met gemak te hanteer.

## **Java Decompiler**
Om Java-bytekode te dekompilasie, kan hierdie gereedskap baie nuttig wees:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLLs Debugging**
### Met behulp van IDA
- **Rundll32** word gelaai vanaf spesifieke paaie vir 64-bis en 32-bis weergawes.
- **Windbg** word as die debugger gekies met die opsie om op die laai/ontlaai van biblioteke te staak.
- Uitvoeringsparameters sluit die DLL-pad en funksienaam in. Hierdie opset stel die uitvoering elke keer dat 'n DLL gelaai word, stop.

### Met behulp van x64dbg/x32dbg
- Soortgelyk aan IDA, word **rundll32** gelaai met opdraglynveranderings om die DLL en funksie te spesifiseer.
- Instellings word aangepas om te breek by DLL-ingang, wat die instelling van breekpunte by die gewenste DLL-ingangspunt moontlik maak.

### Beelde
- Uitvoeringsstoppe en -konfigurasies word geïllustreer deur skermkiekies.

## **ARM & MIPS**
- Vir emulasie is [arm_now](https://github.com/nongiach/arm_now) 'n nuttige hulpbron.

## **Shellkodes**
### Debugging Tegnieke
- **Blobrunner** en **jmp2it** is gereedskap vir die toewysing van shellkodes in geheue en die debugging daarvan met Ida of x64dbg.
- Blobrunner [vrylatings](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [gekompileerde weergawe](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** bied GUI-gebaseerde shellkode-emulasie en -ondersoek, wat verskille in die hantering van shellkodes as 'n lêer teenoor direkte shellkode beklemtoon.

### Deobfuscation en Analise
- **scdbg** bied insig in shellkode-funksies en deobfuscation-vermoëns.
%%%bash
scdbg.exe -f shellcode # Basiese inligting
scdbg.exe -f shellcode -r # Analiserapport
scdbg.exe -f shellcode -i -r # Interaktiewe hakies
scdbg.exe -f shellcode -d # Gedekodeerde shellkode dump
scdbg.exe -f shellcode /findsc # Vind beginoffset
scdbg.exe -f shellcode /foff 0x0000004D # Voer uit vanaf offset
%%%

- **CyberChef** vir die disassembling van shellkodes: [CyberChef-resep](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- 'n Obfuskator wat alle instruksies met `mov` vervang.
- Nuttige hulpbronne sluit 'n [YouTube-verduideliking](https://www.youtube.com/watch?v=2VF_wPkiBJY) en [PDF-slides](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf) in.
- **demovfuscator** kan movfuscator se obfuskasie omkeer, met afhanklikhede soos `libcapstone-dev` en `libz3-dev`, en die installering van [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).
## **Delphi**
- Vir Delphi binêre lêers word [IDR](https://github.com/crypto2011/IDR) aanbeveel.


# Kursusse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binêre deobfuscation\)



<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
