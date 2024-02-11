<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

# Mwongozo wa Kudekompili na Kompili Wasm na Wat

Katika ulimwengu wa **WebAssembly**, zana za **kudekompili** na **kukompili** ni muhimu kwa watengenezaji. Mwongozo huu unawasilisha rasilimali za mtandaoni na programu kwa kushughulikia faili za **Wasm (WebAssembly binary)** na **Wat (WebAssembly text)**.

## Zana za Mtandaoni

- Kwa kudekompili Wasm kuwa Wat, zana inayopatikana kwenye [demonstri ya wasm2wat ya Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) inakuja kwa manufaa.
- Kwa kukompili Wat kurudi Wasm, [demonstri ya wat2wasm ya Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) inatumika.
- Chaguo lingine la kudekompili linaweza kupatikana kwenye [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Suluhisho za Programu

- Kwa suluhisho imara zaidi, [JEB na PNF Software](https://www.pnfsoftware.com/jeb/demo) inatoa huduma nyingi.
- Mradi wa chanzo wazi [wasmdec](https://github.com/wwwg/wasmdec) pia inapatikana kwa kazi za kudekompili.

# Rasilimali za Kudekompili .Net

Kudekompili vifungu vya .Net inaweza kufanywa kwa kutumia zana kama:

- [ILSpy](https://github.com/icsharpcode/ILSpy), ambayo pia inatoa [programu-jalizi kwa Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), kuruhusu matumizi kwenye majukwaa tofauti.
- Kwa kazi zinazohusisha **kudekompili**, **kubadilisha**, na **kukompili**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) inapendekezwa sana. **Bonyeza-kulia** kwenye njia na uchague **Badilisha Njia** kuruhusu mabadiliko ya nambari.
- [dotPeek ya JetBrains](https://www.jetbrains.com/es-es/decompiler/) ni chaguo lingine kwa kudekompili vifungu vya .Net.

## Kuboresha Uchunguzi na Kuingiza Kumbukumbu na DNSpy

### Kuingiza Kumbukumbu na DNSpy
Kuongeza habari kwenye faili kwa kutumia DNSpy, jumuisha kificho cha .Net kifuatacho:

%%%cpp
kutumia System.IO;
njia = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(njia, "Nenosiri: " + nenosiri + "\n");
%%%

### Uchunguzi na DNSpy
Kwa uchunguzi wenye ufanisi na DNSpy, hatua za mfululizo zinapendekezwa kurekebisha **sifa za Kusanyiko** kwa uchunguzi, kuhakikisha kuwa uboreshaji ambao unaweza kuzuia uchunguzi unalemazwa. Mchakato huu ni pamoja na kubadilisha mipangilio ya `DebuggableAttribute`, kukompili kusanyiko, na kuhifadhi mabadiliko.

Zaidi ya hayo, kwa kuchunguza programu ya .Net inayotekelezwa na **IIS**, kutekeleza `iisreset /noforce` kunasababisha IIS kuanza tena. Kuambatisha DNSpy kwenye mchakato wa IIS kwa uchunguzi, mwongozo unafundisha kuchagua mchakato wa **w3wp.exe** ndani ya DNSpy na kuanza kikao cha uchunguzi.

Kwa mtazamo kamili wa moduli zilizopakia wakati wa uchunguzi, ufikiaji wa dirisha la **Moduli** katika DNSpy unapendekezwa, ikifuatiwa na kufungua moduli zote na kusorti kusanyiko kwa urahisi wa urambazaji na uchunguzi.

Mwongozo huu unajumuisha kiini cha kudekompili WebAssembly na .Net, kutoa njia kwa watengenezaji kupitia kazi hizi kwa urahisi.

## **Kudekompili Java**
Kudekompili bytecode ya Java, zana hizi zinaweza kuwa na manufaa sana:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Uchunguzi wa DLLs**
### Kutumia IDA
- **Rundll32** inapakia kutoka njia maalum kwa toleo la 64-bit na 32-bit.
- **Windbg** inachaguliwa kama kichunguzi na chaguo la kusimamisha wakati wa kupakia/kupakua maktaba limezimwa.
- Vigezo vya utekelezaji ni pamoja na njia ya DLL na jina la kazi. Usanidi huu unasimamisha utekelezaji kwa kila upakiaji wa DLL.

### Kutumia x64dbg/x32dbg
- Kama IDA, **rundll32** inapakia na marekebisho ya mstari wa amri kwa kufafanua DLL na kazi.
- Mipangilio inabadilishwa kuvunja kwenye kuingia kwa DLL, kuruhusu kuweka alama ya kuvunja kwenye hatua ya kuingia ya DLL inayotakiwa.

### Picha
- Maeneo ya kusimamisha utekelezaji na usanidi unaonyeshwa kupitia viwambo vya skrini.

## **ARM & MIPS**
- Kwa uigaji, [arm_now](https://github.com/nongiach/arm_now) ni rasilimali yenye manufaa.

## **Shellcodes**
### Mbinu za Uchunguzi
- **Blobrunner** na **jmp2it** ni zana za kugawa shellcodes kwenye kumbukumbu na kuzichunguza na Ida au x64dbg.
- Blobrunner [toleo](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [toleo lililokompiliwa](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** inatoa uigaji na ukaguzi wa shellcode kwa kutumia GUI, ikionyesha tofauti katika kushughulikia shellcode kama faili dhidi ya shellcode moja kwa moja.

### Kufuta na Uchambuzi
- **scdbg** inatoa ufahamu juu ya kazi za shellcode na uwezo wa kufuta.
%%%bash
scdbg.exe -f shellcode # Habari ya msingi
scdbg.exe -f shellcode -r # Ripoti ya uchambuzi
scdbg.exe -f shellcode -i -r # Kuingiza kwa kushirikiana
scdbg.exe -f shellcode -d # Kudondosha shellcode iliyofuta
scdbg.exe -f shellcode /findsc # Tafuta kuanzia offset
scdbg.exe -f shellcode /foff 0x0000004D # Tekeleza kutoka kwa offset
%%%

- **CyberChef
## **Delphi**
- Kwa binaries za Delphi, [IDR](https://github.com/crypto2011/IDR) inapendekezwa.


# Kozi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Ufichuaji wa binary\)



<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
