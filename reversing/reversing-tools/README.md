<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

# Vodič za dekompilaciju Wasm-a i kompilaciju Wat-a

U svetu **WebAssembly-a**, alati za **dekompilaciju** i **kompilaciju** su neophodni za programere. Ovaj vodič predstavlja neke online resurse i softver za rukovanje **Wasm (WebAssembly binarnim)** i **Wat (WebAssembly tekstualnim)** fajlovima.

## Online alati

- Za **dekompilaciju** Wasm-a u Wat, koristan je alat dostupan na [Wabt-ovom wasm2wat demo-u](https://webassembly.github.io/wabt/demo/wasm2wat/index.html).
- Za **kompilaciju** Wat-a nazad u Wasm, [Wabt-ov wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) služi svrsi.
- Druga opcija za dekompilaciju može se pronaći na [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Softverska rešenja

- Za robustnije rešenje, [JEB od PNF Software](https://www.pnfsoftware.com/jeb/demo) nudi obimne funkcionalnosti.
- Open-source projekat [wasmdec](https://github.com/wwwg/wasmdec) takođe je dostupan za zadatke dekompilacije.

# Resursi za dekompilaciju .Net-a

Dekompilacija .Net skupova može se postići pomoću alata kao što su:

- [ILSpy](https://github.com/icsharpcode/ILSpy), koji takođe nudi [dodatak za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), omogućavajući upotrebu na više platformi.
- Za zadatke koji uključuju **dekompilaciju**, **modifikaciju** i **rekompilaciju**, visoko se preporučuje [dnSpy](https://github.com/0xd4d/dnSpy/releases). **Desnim klikom** na metod i izborom **Modify Method** omogućava se izmena koda.
- [JetBrains-ov dotPeek](https://www.jetbrains.com/es-es/decompiler/) je još jedna alternativa za dekompilaciju .Net skupova.

## Unapređivanje debagovanja i logovanja sa DNSpy

### DNSpy logovanje
Da biste logovali informacije u fajl pomoću DNSpy-a, uključite sledeći .Net kod:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy debagovanje
Za efikasno debagovanje sa DNSpy, preporučuje se niz koraka za podešavanje **Assembly atributa** za debagovanje, obezbeđujući da su onemogućene optimizacije koje mogu ometati debagovanje. Ovaj proces uključuje promenu podešavanja `DebuggableAttribute`, rekomplikaciju skupa i čuvanje promena.

Osim toga, da biste debagovali .Net aplikaciju pokrenutu putem **IIS-a**, izvršavanje `iisreset /noforce` restartuje IIS. Da biste povezali DNSpy sa IIS procesom za debagovanje, vodič daje instrukcije za odabir **w3wp.exe** procesa unutar DNSpy-a i pokretanje debagovanja.

Za sveobuhvatan prikaz učitanih modula tokom debagovanja, preporučuje se pristupanje prozoru **Modules** u DNSpy-u, zatim otvaranje svih modula i sortiranje skupova radi lakšeg navigiranja i debagovanja.

Ovaj vodič obuhvata suštinu dekompilacije WebAssembly-a i .Net-a, nudeći putokaz programerima za lakše rukovanje ovim zadacima.

## **Java dekompajler**
Za dekompajliranje Java bajtkoda, ovi alati mogu biti veoma korisni:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debagovanje DLL fajlova**
### Korišćenje IDA-e
- **Rundll32** se učitava sa specifičnih putanja za 64-bitne i 32-bitne verzije.
- **Windbg** se bira kao debager sa omogućenom opcijom za zaustavljanje pri učitavanju/isključivanju biblioteke.
- Parametri izvršavanja uključuju putanju DLL fajla i ime funkcije. Ova konfiguracija zaustavlja izvršavanje pri svakom učitavanju DLL-a.

### Korišćenje x64dbg/x32dbg
- Slično kao i kod IDA-e, **rundll32** se učitava sa modifikacijama komandne linije koje specificiraju DLL i funkciju.
- Podešavanja se prilagođavaju da bi se prekinulo izvršavanje pri ulasku u DLL, omogućavajući postavljanje prekida na željenoj tački ulaska u DLL.

### Slike
- Tačke zaustavljanja izvršavanja i konfiguracije ilustrovane su putem snimaka ekrana.

## **ARM i MIPS**
- Za emulaciju, [arm_now](https://github.com/nongiach/arm_now) je koristan resurs.

## **Shell kodovi**
### Tehnike debagovanja
- **Blobrunner** i **jmp2it** su alati za alokaciju shell kodova u memoriji i debagovanje istih pomoću Ida ili x64dbg.
- Blobrunner [izdanja](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [kompilirana verzija](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** nudi GUI baziranu emulaciju i inspekciju shell kodova, ističući razlike u rukovanju shell kodovima kao fajlom naspram direktnog shell koda.

### Deobfuskacija i analiza
- **scdbg** pruža uvid u funkcije shell koda i mogućnosti deobfuskacije.
%%%bash
scdbg.exe -f shellcode # Osnovne informacije
scdbg.exe -f shellcode -r # Izveštaj analize
scdbg.exe -f shellcode -i -r # Interaktivni hookovi
scdbg.exe -f shellcode -d # Dump dekodiranog shell koda
scdbg.exe -f shellcode /findsc # Pronalaženje početnog offseta
scdbg.exe -f shellcode /foff 0x0000004D # Izvršavanje od offseta
%%%

- **CyberChef** za rastavljanje shell koda: [CyberChef recept](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Obfuskator koji zamenjuje sve instrukcije sa `mov`.
- Korisni resursi uključuju [YouTube objašnjenje](https://www.youtube.com/watch?v=2VF_wPkiBJY) i
## **Delphi**
- Za Delphi binarne datoteke preporučuje se korišćenje [IDR](https://github.com/crypto2011/IDR).


# Kursevi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Deobfuskacija binarnih datoteka\)



<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju oglašenu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
