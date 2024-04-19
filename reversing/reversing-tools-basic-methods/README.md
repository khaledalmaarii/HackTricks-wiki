# Zana za Kugeuza & Mbinu za Msingi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kikundi cha Usalama cha Try Hard**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Zana za Kugeuza Zilizotegemea ImGui

Programu:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Msambazaji wa Wasm / Msambazaji wa Wat

Mtandaoni:

* Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kwa **kugeuza** kutoka kwa wasm (binary) hadi wat (maandishi wazi)
* Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kwa **kusambaza** kutoka kwa wat hadi wasm
* unaweza pia jaribu kutumia [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kwa kugeuza

Programu:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Msambazaji wa .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni msambazaji ambao **hugawanya na kuchunguza muundo wa multiple**, ikiwa ni pamoja na **maktaba** (.dll), **faili za metadata za Windows** (.winmd), na **programu za kutekelezwa** (.exe). Mara baada ya kugawanywa, mkusanyiko unaweza kuokolewa kama mradi wa Visual Studio (.csproj).

Faida hapa ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwa mkusanyiko wa zamani, hatua hii inaweza kuokoa muda. Zaidi, dotPeek hutoa urambazaji wa manufaa kote kwenye msimbo uliogawanywa, ikifanya iwe moja ya zana kamili kwa **uchambuzi wa algorithm wa Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kwa mfano wa kuongeza wa kina na API ambayo inapanua zana ili kufaa mahitaji yako halisi, .NET reflector hupunguza muda na kufanya maendeleo kuwa rahisi. Hebu tuangalie huduma nyingi za uhandisi wa nyuma ambazo zana hii hutoa:

* Hutoa ufahamu jinsi data inavyopita kupitia maktaba au sehemu
* Hutoa ufahamu wa utekelezaji na matumizi ya lugha na fremu za .NET
* Hupata utendaji usioelezwa na usiofunuliwa ili kupata zaidi kutoka kwa APIs na teknolojia zilizotumiwa.
* Hupata tegemezi na makusanyo tofauti
* Inagundua mahali sahihi ya makosa katika msimbo wako, vipengele vya watu wengine, na maktaba.
* Hufanya uchunguzi kwenye chanzo cha msimbo wote wa .NET unaoendelea kufanya kazi nao.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy programu-jalizi kwa Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuwa nayo kwenye OS yoyote (unaweza kuisakinisha moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bonyeza **Extensions** na **tafuta ILSpy**).\
Ikiwa unahitaji **kugeuza**, **kurekebisha** na **kusambaza** tena unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au tawi linalosimamiwa kwa sasa, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Bonyeza Kulia -> Badilisha Mbinu** kubadilisha kitu ndani ya kazi).

### Uchakataji wa DNSpy

Ili kufanya **DNSpy iweke rekodi fulani katika faili**, unaweza kutumia kificho hiki:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Kurekebisha DNSpy

Ili kurekebisha nambari kwa kutumia DNSpy unahitaji:

Kwanza, badilisha **sifa za Mkusanyiko** zinazohusiana na **urekebishaji**:

![](<../../.gitbook/assets/image (970).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
//////////////////////////////////////////////////////////////////////////A//A//A////////////////////////////
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Na bonyeza **compile**:

![](<../../.gitbook/assets/image (314) (1).png>)

Kisha hifadhi faili mpya kupitia _**File >> Save module...**_:

![](<../../.gitbook/assets/image (599).png>)

Hii ni muhimu kwa sababu ikiwa hutafanya hivyo, wakati wa **runtime** maboresho kadhaa yatafanywa kwenye nambari na inaweza kuwa kwamba wakati wa kutatua hitilafu **break-point is never hit** au baadhi ya **variables hazipo**.

Kisha, ikiwa programu yako ya .NET inaendeshwa na **IIS** unaweza ku**restart** kwa:
```
iisreset /noforce
```
Kisha, ili kuanza kurekebisha hitilafu unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Kichupo cha Kurekebisha** chagua **Ambatanisha kwa Mchakato...**:

![](<../../.gitbook/assets/image (315).png>)

Kisha chagua **w3wp.exe** kuambatisha kwenye **seva ya IIS** na bonyeza **ambatanisha**:

![](<../../.gitbook/assets/image (110).png>)

Sasa tukiwa tunarekebisha mchakato, ni wakati wa kuusimamisha na kupakia moduli zote. Kwanza bonyeza _Kurekebisha >> Simamisha Yote_ kisha bonyeza _**Kurekebisha >> Windows >> Moduli**_:

![](<../../.gitbook/assets/image (129).png>)

![](<../../.gitbook/assets/image (831).png>)

Bonyeza moduli yoyote kwenye **Moduli** na chagua **Fungua Moduli Zote**:

![](<../../.gitbook/assets/image (919).png>)

Bonyeza kulia moduli yoyote kwenye **Mtafuta wa Mkusanyiko** na bonyeza **Panga Mkusanyiko**:

![](<../../.gitbook/assets/image (336).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Kurekebisha DLLs

### Kutumia IDA

* **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
* Chagua kurekebisha **Windbg**
* Chagua "**Sitishe wakati wa kupakia/kusitisha maktaba**"

![](<../../.gitbook/assets/image (865).png>)

* Sanidi **parameta** za utekelezaji ukiweka **njia ya DLL** na kazi unayotaka kuita:

![](<../../.gitbook/assets/image (701).png>)

Kisha, unapoanza kurekebisha **utekelezaji utasimamishwa kila DLL inapopakiwa**, basi, wakati rundll32 inapopakia DLL yako utekelezaji utasimamishwa.

Lakini, unawezaje kufikia namna ya kificho cha DLL iliyopakiwa? Kutumia njia hii, sijui jinsi.

### Kutumia x64dbg/x32dbg

* **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
* **Badilisha Mstari wa Amri** ( _Faili --> Badilisha Mstari wa Amri_ ) na weka njia ya dll na kazi unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Badilisha _Chaguo --> Vipimo_ na chagua "**Kuingia kwa DLL**".
* Kisha **anza utekelezaji**, mchakato wa kurekebisha utasimama kila dll kuu, kwa wakati fulani utasimama kwenye kuingia kwa dll yako. Kutoka hapo, tafuta tu sehemu ambapo unataka kuweka kiungo cha kusitisha.

Tambua kwamba unapokuwa umesimamishwa kwa sababu yoyote katika win64dbg unaweza kuona **kificho unachotazama** juu ya dirisha la win64dbg:

![](<../../.gitbook/assets/image (839).png>)

Kisha, ukitazama hii unaweza kuona wakati utekelezaji uliposimamishwa kwenye dll unayotaka kurekebisha.

## Programu za GUI / Michezo ya Video

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa ndani ya kumbukumbu ya mchezo unaoendeshwa na kuzibadilisha. Taarifa zaidi katika:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) ni zana ya mbele/urekebishaji wa nyuma kwa GNU Project Debugger (GDB), iliyolenga michezo. Walakini, inaweza kutumika kwa mambo yoyote yanayohusiana na urekebishaji wa nyuma

[**Decompiler Explorer**](https://dogbolt.org/) ni mbele ya wavuti kwa idadi ya wadecompiler. Huduma hii ya wavuti inakuwezesha kulinganisha matokeo ya wadecompiler tofauti kwenye programu ndogo za kutekelezwa.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Kurekebisha shellcode na blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) ita **tenga** **shellcode** ndani ya nafasi ya kumbukumbu, itaku **onyesha** anwani ya **kumbukumbu** ambapo shellcode ilipangiwa na itasimamisha utekelezaji.\
Kisha, unahitaji **kuambatanisha kurekebisha** (Ida au x64dbg) kwa mchakato na weka **kiungo cha kusitisha kwenye anwani ya kumbukumbu iliyotajwa** na **endelea** utekelezaji. Kwa njia hii utakuwa unarekebisha shellcode.

Ukurasa wa kutolewa kwenye github una zip zinazoleta kutolewa kwa kuhaririwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililobadilishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kulipakua tu **unda mradi wa C/C++ katika Visual Studio Code, nakili na ubandike kificho na ujenge**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Kurekebisha shellcode na jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ni sawa sana na blobrunner. Ita **tenga** **shellcode** ndani ya nafasi ya kumbukumbu, na anza **mzunguko wa milele**. Kisha unahitaji **kuambatanisha kurekebisha** kwa mchakato, **cheza anza subiri sekunde 2-5 na bonyeza simama** na utajikuta ndani ya **mzunguko wa milele**. Ruka kwenye maagizo ijayo ya mzunguko wa milele kwani itakuwa wito kwa shellcode, na mwishowe utajikuta unatekeleza shellcode.

Unaweza kupakua toleo lililokompiliwa la [jmp2it kwenye ukurasa wa kutolewa](https://github.com/adamkramer/jmp2it/releases/).

### Kurekebisha shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kutumia cutter unaweza kuiga shellcode na kuichunguza kwa njia ya kudumu.

Tambua kwamba Cutter inakuruhusu "Fungua Faili" na "Fungua Shellcode". Kwa upande wangu nilipoifungua shellcode kama faili ilikuwa imehaririwa kwa usahihi, lakini nilipoifungua kama shellcode haikuwa hivyo:

![](<../../.gitbook/assets/image (559).png>)

Ili kuanza uigaji katika mahali unapotaka, weka bp hapo na kwa kwato cutter itaanza moja kwa moja uigaji kutoka hapo:

![](<../../.gitbook/assets/image (586).png>)

![](<../../.gitbook/assets/image (384).png>)

Unaweza kuona rundo kwa mfano ndani ya kumbukumbu ya hex:

![](<../../.gitbook/assets/image (183).png>)

### Kufuta shellcode na kupata kazi zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Itakwambia mambo kama **ni kazi zipi** shellcode inatumia na ikiwa shellcode inajichimbua yenyewe kwenye kumbukumbu.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia ina launcher ya kielelezo ambapo unaweza kuchagua chaguo unalotaka na kutekeleza shellcode

![](<../../.gitbook/assets/image (255).png>)

Chaguo la **Unda Dump** litadump shellcode ya mwisho ikiwa kuna mabadiliko yoyote yanayofanywa kwa shellcode kwa njia ya kumbukumbu (inayoweza kutumiwa kupakua shellcode iliyofanywa). **Kianzio cha kuanza** kinaweza kuwa muhimu kuanza shellcode kwenye kianzio maalum. Chaguo la **Kianzio cha Kufuatilia** ni muhimu kufuatilia shellcode kwa kutumia terminal ya scDbg (hata hivyo, ninaona chaguo lolote lililoelezwa hapo awali ni bora kwa suala hili kwani utaweza kutumia Ida au x64dbg).

### Kufasiri kwa Kutumia CyberChef

Pakia faili yako ya shellcode kama kuingiza na tumia mapishi yafuatayo kudecompile: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator huyu **hubadilisha maagizo yote kwa `mov`** (ndio, kweli ni nzuri sana). Pia hutumia kuvuruga kubadilisha mifumo ya utekelezaji. Kwa maelezo zaidi kuhusu jinsi inavyofanya kazi:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Ikiwa una bahati [demovfuscator](https://github.com/kirschju/demovfuscator) itaondoa ufusaji wa binary. Ina mahitaji kadhaa
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, njia hii ya kupata bendera** inaweza kuwa na manufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **sehemu ya kuingia**, tafuta kazi kwa `::main` kama hivi:

![](<../../.gitbook/assets/image (1077).png>)

Katika kesi hii binary ilikuwa inaitwa authenticator, hivyo ni wazi kuwa hii ndio kazi kuu inayovutia.\
Ukiwa na **jina** la **kazi** zinazoitwa, tafuta kuhusu hizo **mtandaoni** ili kujifunza kuhusu **vipimo** vyao na **matokeo**.

## **Delphi**

Kwa binaries zilizokompiliwa kwa Delphi unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kubadilisha binary ya Delphi ningependekeza utumie programu-jalizi ya IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **ATL+f7** (ingiza programu-jalizi ya python kwenye IDA) na chagua programu-jalizi ya python.

Programu-jalizi hii itatekeleza binary na kutatua majina ya kazi kwa njia ya moja kwa moja mwanzoni mwa uchunguzi. Baada ya kuanza uchunguzi bonyeza tena kitufe cha Kuanza (kijani au f9) na kuvunja itagonga mwanzoni mwa msimbo halisi.

Pia ni ya kuvutia sana kwa sababu ikiwa bonyeza kitufe katika programu ya kielelezo cha picha, mchunguzi utasimama kwenye kazi inayotekelezwa na kitufe hicho.

## Golang

Ikiwa unahitaji kubadilisha binary ya Golang ningependekeza utumie programu-jalizi ya IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **ATL+f7** (ingiza programu-jalizi ya python kwenye IDA) na chagua programu-jalizi ya python.

Hii itatatua majina ya kazi.

## Python Iliyokompiliwa

Kwenye ukurasa huu unaweza kupata jinsi ya kupata msimbo wa python kutoka kwa binary iliyokompiliwa ya ELF/EXE python:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Ikiwa unapata **binary** ya mchezo wa GBA unaweza kutumia zana tofauti kwa **kuiga** na **kutatua hitilafu**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la kurekebisha hitilafu_) - Ina mchunguzi na kiolesura
* [**mgba** ](https://mgba.io)- Ina mchunguzi wa CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Programu-jalizi ya Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Programu-jalizi ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), katika _**Chaguo --> Usanidi wa Kuiga --> Vidhibiti**_\*\* \*\* unaweza kuona jinsi ya kubonyeza vitufe vya Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Vinapobonyezwa, kila **kitufe kina thamani** ya kuwatambua:
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
Kwa hivyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia matokeo ya mtumiaji**. Katika anwani **0x4000130** utapata kazi inayopatikana kawaida: **KEYINPUT**.

![](<../../.gitbook/assets/image (444).png>)

Katika picha iliyopita unaweza kuona kwamba kazi hiyo inaitwa kutoka **FUN\_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika kazi hiyo, baada ya operesheni za awali (bila umuhimu wowote):
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
//File/Code/ / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / // / / / / / / / / / / / / / / / / reconstruction/ / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / /
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
Ikiwa **`uVar4`** iko kwenye **funguo za mwisho** na sio funguo ya sasa, hii inaitwa kuachilia kitufe (funguo ya sasa imehifadhiwa katika **`uVar1`**).
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
/Il/ /file/ /delle/ /immagini/ /è/ /stato/ /cambiato/ /in/ /questo/ /modo/./ /Il/ /file/ /è/ /stato/ /modificato/./ /Lo/ /stesso/ /file/ /è/ /stato/ /cambiato/./ /Lo/ /stesso Fame/ è/ stato/ cambiato/ in/ questo/ modo/./ /Lo/ /stesso/ /file/ /è/ /stato/ /modificato/./ /e/ // // // // / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / / /
