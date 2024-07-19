{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

# Vodič za dekompilaciju Wasm i kompilaciju Wat

U oblasti **WebAssembly**, alati za **dekompilaciju** i **kompilaciju** su neophodni za programere. Ovaj vodič uvodi neke online resurse i softver za rukovanje **Wasm (WebAssembly binarni)** i **Wat (WebAssembly tekst)** datotekama.

## Online alati

- Da biste **dekompilovali** Wasm u Wat, alat dostupan na [Wabt-ovom wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) je koristan.
- Za **kompilaciju** Wat nazad u Wasm, [Wabt-ov wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) služi toj svrsi.
- Druga opcija za dekompilaciju može se naći na [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Softverska rešenja

- Za robusnije rešenje, [JEB od PNF Software](https://www.pnfsoftware.com/jeb/demo) nudi opsežne funkcije.
- Open-source projekat [wasmdec](https://github.com/wwwg/wasmdec) je takođe dostupan za zadatke dekompilacije.

# Resursi za dekompilaciju .Net

Dekompilacija .Net biblioteka može se ostvariti pomoću alata kao što su:

- [ILSpy](https://github.com/icsharpcode/ILSpy), koji takođe nudi [plugin za Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), omogućavajući korišćenje na više platformi.
- Za zadatke koji uključuju **dekompilaciju**, **modifikaciju** i **rekonstrukciju**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) se toplo preporučuje. **Desni klik** na metodu i izbor **Modify Method** omogućava promene u kodu.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) je još jedna alternativa za dekompilaciju .Net biblioteka.

## Unapređenje debagovanja i logovanja sa DNSpy

### DNSpy logovanje
Da biste logovali informacije u datoteku koristeći DNSpy, uključite sledeći .Net kod:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Lozinka: " + password + "\n");
%%%

### DNSpy debagovanje
Za efikasno debagovanje sa DNSpy, preporučuje se niz koraka za podešavanje **atributa Assembly** za debagovanje, osiguravajući da su optimizacije koje bi mogle ometati debagovanje onemogućene. Ovaj proces uključuje promenu `DebuggableAttribute` podešavanja, rekonstrukciju biblioteke i čuvanje promena.

Pored toga, da biste debagovali .Net aplikaciju koju pokreće **IIS**, izvršavanje `iisreset /noforce` ponovo pokreće IIS. Da biste priključili DNSpy na IIS proces za debagovanje, vodič objašnjava kako da izaberete **w3wp.exe** proces unutar DNSpy i započnete sesiju debagovanja.

Za sveobuhvatan pregled učitanih modula tokom debagovanja, preporučuje se pristup **Modules** prozoru u DNSpy, nakon čega se otvaraju svi moduli i sortiraju biblioteke radi lakše navigacije i debagovanja.

Ovaj vodič obuhvata suštinu WebAssembly i .Net dekompilacije, nudeći put za programere da lako navigiraju ovim zadacima.

## **Java dekompilator**
Za dekompilaciju Java bajtkoda, ovi alati mogu biti veoma korisni:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debagovanje DLL-ova**
### Korišćenje IDA
- **Rundll32** se učitava iz specifičnih putanja za 64-bitne i 32-bitne verzije.
- **Windbg** se bira kao debager sa opcijom da se pauzira prilikom učitavanja/izlaska biblioteke.
- Parametri izvršenja uključuju putanju DLL-a i naziv funkcije. Ova postavka zaustavlja izvršenje prilikom svakog učitavanja DLL-a.

### Korišćenje x64dbg/x32dbg
- Slično IDA, **rundll32** se učitava sa izmenama komandne linije kako bi se odredili DLL i funkcija.
- Podešavanja se prilagođavaju da se prekine na ulazu DLL-a, omogućavajući postavljanje tačke prekida na željenoj tački ulaza DLL-a.

### Slike
- Tačke zaustavljanja izvršenja i konfiguracije su ilustrovane kroz snimke ekrana.

## **ARM & MIPS**
- Za emulaciju, [arm_now](https://github.com/nongiach/arm_now) je koristan resurs.

## **Shellcodes**
### Tehnike debagovanja
- **Blobrunner** i **jmp2it** su alati za alokaciju shellcode-a u memoriji i debagovanje sa Idom ili x64dbg.
- Blobrunner [izdanja](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [kompilovana verzija](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** nudi GUI baziranu emulaciju shellcode-a i inspekciju, ističući razlike u rukovanju shellcode-om kao datotekom naspram direktnog shellcode-a.

### Deobfuskacija i analiza
- **scdbg** pruža uvide u funkcije shellcode-a i mogućnosti deobfuskacije.
%%%bash
scdbg.exe -f shellcode # Osnovne informacije
scdbg.exe -f shellcode -r # Izveštaj o analizi
scdbg.exe -f shellcode -i -r # Interaktivne petlje
scdbg.exe -f shellcode -d # Dump-ovanje dekodiranog shellcode-a
scdbg.exe -f shellcode /findsc # Pronađi start offset
scdbg.exe -f shellcode /foff 0x0000004D # Izvrši od offset-a
%%%

- **CyberChef** za disasembleranje shellcode-a: [CyberChef recept](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Obfuskator koji zamenjuje sve instrukcije sa `mov`.
- Korisni resursi uključuju [YouTube objašnjenje](https://www.youtube.com/watch?v=2VF_wPkiBJY) i [PDF prezentacije](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** može da obrne obfuskaciju movfuscatora, zahtevajući zavisnosti kao što su `libcapstone-dev` i `libz3-dev`, i instaliranje [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Za Delphi binarne datoteke, [IDR](https://github.com/crypto2011/IDR) se preporučuje.


# Kursevi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binarna deobfuskacija\)



{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
