# Zana za Kugeuza & Mbinu za Msingi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kikundi cha Usalama cha Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Zana za Kugeuza Zilizotegemea ImGui

Programu:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Msaidizi wa Kugeuza Wasm / Kompilisha Wat

Mtandaoni:

* Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kwa **kugeuza** kutoka wasm (binary) hadi wat (maandishi wazi)
* Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kwa **kukompilisha** kutoka wat hadi wasm
* unaweza pia kujaribu kutumia [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kwa kugeuza

Programu:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Msaidizi wa Kugeuza .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni msaidizi wa kugeuza ambao **hufanya kugeuza na kuchunguza muundo mbalimbali**, ikiwa ni pamoja na **maktaba** (.dll), **faili za metadata za Windows** (.winmd), na **programu za kutekelezwa** (.exe). Mara baada ya kugeuzwa, mkusanyiko unaweza kuokolewa kama mradi wa Visual Studio (.csproj).

Faida hapa ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwa mkusanyiko wa zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji wa manufaa kote kwenye msimbo uliogeuzwa, ikifanya kuwa moja ya zana kamili kwa **uchambuzi wa algorithm za Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kwa mfano wa kuongeza kina na API ambayo inapanua zana ili kufaa mahitaji yako halisi, .NET reflector hupunguza muda na kufanya maendeleo kuwa rahisi. Hebu tuangalie huduma nyingi za uhandisi wa kurudi ambazo zana hii hutoa:

* Hutoa ufahamu jinsi data inavyopita kupitia maktaba au sehemu
* Hutoa ufahamu wa utekelezaji na matumizi ya lugha na fremu za .NET
* Hupata utendaji usioelezwa na usiofunuliwa ili kupata zaidi kutoka kwa APIs na teknolojia zilizotumiwa.
* Hupata tegemezi na makusanyo tofauti
* Inagundua mahali sahihi ya makosa katika msimbo wako, vipengele vya mtu wa tatu, na maktaba.
* Hufanya uchunguzi wa kina wa chanzo cha msimbo wote wa .NET unaoendelea.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin kwa Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuwa nayo kwenye OS yoyote (unaweza kuweka moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bonyeza **Extensions** na **tafuta ILSpy**).\
Ikiwa unahitaji **kugeuza**, **kurekebisha** na **kukompilisha** tena unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au tawi linalosimamiwa kikamilifu la hiyo, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Bonyeza Kulia -> Badilisha Mbinu** kubadilisha kitu ndani ya kazi).

### Uchakataji wa DNSpy

Ili kufanya **DNSpy iwekeze baadhi ya habari kwenye faili**, unaweza kutumia kificho hiki:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Kurekebisha DNSpy

Ili kurekebisha nambari kwa kutumia DNSpy unahitaji:

Kwanza, badilisha **Vipengele vya Mkusanyiko** vinavyohusiana na **urekebishaji**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Kwa:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Na bonyeza **compile**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Kisha hifadhi faili mpya kupitia _**File >> Save module...**_:

![](<../../.gitbook/assets/image (279).png>)

Hii ni muhimu kwa sababu ikiwa hutafanya hivyo, wakati wa **runtime** maboresho kadhaa yatafanywa kwenye nambari na inaweza kuwa kwamba wakati wa kutatua hitilafu **break-point is never hit** au baadhi ya **variables don't exist**.

Kisha, ikiwa programu yako ya .NET inaendeshwa na **IIS** unaweza ku**restart** kwa:
```
iisreset /noforce
```
Kisha, ili kuanza kudebugi unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Tab ya Kudebugi** chagua **Ambatanisha kwa Mchakato...**:

![](<../../.gitbook/assets/image (280).png>)

Kisha chagua **w3wp.exe** kuambatisha kwenye **seva ya IIS** na bonyeza **ambatanisha**:

![](<../../.gitbook/assets/image (281).png>)

Sasa tukiwa tunadebugi mchakato, ni wakati wa kuusimamisha na kupakia moduli zote. Kwanza bonyeza _Kudebugi >> Simamisha Yote_ kisha bonyeza _**Kudebugi >> Windows >> Moduli**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Bonyeza moduli yoyote kwenye **Moduli** na chagua **Fungua Moduli Zote**:

![](<../../.gitbook/assets/image (284).png>)

Bonyeza kulia moduli yoyote kwenye **Mtafuta wa Moduli** na bonyeza **Panga Moduli**:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Kudebugi DLLs

### Kutumia IDA

* **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
* Chagua kudebugi ya **Windbg**
* Chagua "**Sitishe wakati wa kupakia/kusitisha maktaba**"

![](<../../.gitbook/assets/image (135).png>)

* Sanidi **parameta** za utekelezaji ukiweka **njia ya DLL** na kazi unayotaka kuita:

![](<../../.gitbook/assets/image (136).png>)

Kisha, unapoanza kudebugi **utekelezaji utasimamishwa kila DLL inapopakiwa**, basi, wakati rundll32 inapopakia DLL yako utekelezaji utasimamishwa.

Lakini, unawezaje kufikia namna ya kificho cha DLL iliyopakiwa? Kutumia njia hii, sijui jinsi.

### Kutumia x64dbg/x32dbg

* **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
* **Badilisha Mstari wa Amri** ( _Faili --> Badilisha Mstari wa Amri_ ) na weka njia ya dll na kazi unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Badilisha _Chaguo --> Vipimo_ na chagua "**Kuingia kwa DLL**".
* Kisha **anza utekelezaji**, kudebugi itasimama kwa kila kuingia kwa dll, kwa wakati fulani utasimama kwenye kuingia kwa dll ya dll yako. Kutoka hapo, tafuta tu sehemu unayotaka kuweka kiungo cha kusimamisha.

Tambua kwamba unapokuwa umesimamishwa kwa sababu yoyote katika win64dbg unaweza kuona **kificho unachotazama** juu ya dirisha la win64dbg:

![](<../../.gitbook/assets/image (137).png>)

Kisha, ukitazama hii unaweza kuona wakati utekelezaji uliposimamishwa kwenye dll unayotaka kudebugi.

## Programu za GUI / Michezo ya Video

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa ndani ya kumbukumbu ya mchezo unaoendeshwa na kuzibadilisha. Taarifa zaidi katika:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Kudebugi shellcode na blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) ita **tenga** **shellcode** ndani ya nafasi ya kumbukumbu, itaku **onyesha** anwani ya **kumbukumbu** ambapo shellcode ilipangiwa na itasimamisha utekelezaji.\
Kisha, unahitaji **kuambatanisha kudebugi** (Ida au x64dbg) kwa mchakato na weka **kiungo cha kusimamisha kwenye anwani ya kumbukumbu iliyopendekezwa** na **rejesha** utekelezaji. Hivi ndivyo utakavyokuwa unadebugi shellcode.

Ukurasa wa kutolewa kwenye github una zip zinazojumuisha kutolewa kwa kisasa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililobadilishwa kidogo la Blobrunner kwenye kiungo kifuatacho. Ili kuikusanya tu **unda mradi wa C/C++ katika Visual Studio Code, nakili na ubandike kificho na uijenge**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Kudebugi shellcode na jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ni sawa sana na blobrunner. Ita **tenga** **shellcode** ndani ya nafasi ya kumbukumbu, na anza **mzunguko wa milele**. Kisha unahitaji **kuambatanisha kudebugi** kwa mchakato, **anza, subiri sekunde 2-5 na bonyeza kusimamisha** na utajikuta ndani ya **mzunguko wa milele**. Ruka kwenye maagizo ijayo ya mzunguko wa milele kwani itakuwa wito kwa shellcode, na hatimaye utajikuta unatekeleza shellcode.

![](<../../.gitbook/assets/image (397).png>)

Unaweza kupakua toleo lililokusanywa la [jmp2it kwenye ukurasa wa kutolewa](https://github.com/adamkramer/jmp2it/releases/).

### Kudebugi shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kutumia cutter unaweza kuiga shellcode na kuichunguza kwa njia ya kudumu.

Tambua kwamba Cutter inakuruhusu "Fungua Faili" na "Fungua Shellcode". Kwa upande wangu nilipoifungua shellcode kama faili ilikuwa imefanyiwa decompile kwa usahihi, lakini nilipoifungua kama shellcode haikuwa hivyo:

![](<../../.gitbook/assets/image (400).png>)

Ili kuanza uigaji katika mahali unapotaka, weka bp hapo na kwa mujibu wa cutter itaanza moja kwa moja uigaji kutoka hapo:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Unaweza kuona stakiti kwa mfano ndani ya kumbukumbu ya hex:

![](<../../.gitbook/assets/image (402).png>)

### Kufuta Obfuscating shellcode na kupata kazi zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Itakwambia mambo kama **kazi zipi** shellcode inatumia na ikiwa shellcode inajichakaza yenyewe kwenye kumbukumbu.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia inaendelea na mtumiaji wa picha ambapo unaweza kuchagua chaguo unazotaka na kutekeleza shellcode

![](<../../.gitbook/assets/image (398).png>)

Chaguo la **Unda Dump** litadump shellcode ya mwisho ikiwa kuna mabadiliko yoyote yanayofanywa kwa shellcode kwa njia ya kumbukumbu (inayoweza kutumika kupakua shellcode iliyofanywa). **Offset ya kuanza** inaweza kuwa muhimu kuanza shellcode kwenye offset maalum. Chaguo la **Kuweka Kitanzi** ni muhimu kwa kudebug shellcode kwa kutumia terminal ya scDbg (hata hivyo, ninaona chaguo lolote lililoelezwa hapo awali ni bora kwa suala hili kwani utaweza kutumia Ida au x64dbg).

### Kufasiri kwa Kutumia CyberChef

Pakia faili yako ya shellcode kama kuingiza na tumia mapishi yafuatayo kuidisassemble: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator huyu **hubadilisha maagizo yote kwa `mov`**(ndio, kweli ni mzuri sana). Pia hutumia kuvuruga kubadilisha mifumo ya utekelezaji. Kwa maelezo zaidi kuhusu jinsi inavyofanya kazi:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Ikiwa una bahati [demovfuscator](https://github.com/kirschju/demovfuscator) itaondoa ufusaji wa binary. Ina tegemezi kadhaa
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, njia hii ya kupata bendera** inaweza kuwa na manufaa sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **sehemu ya kuingia**, tafuta kazi kwa `::main` kama hivi:

![](<../../.gitbook/assets/image (612).png>)

Katika kesi hii binary ilikuwa inaitwa authenticator, hivyo ni wazi kuwa hii ni kazi kuu inayovutia.\
Ukiwa na **jina** la **kazi** zinazoitwa, tafuta kuhusu **vifaa** vyao na **matokeo** kwenye **Intaneti**.

## **Delphi**

Kwa binaries zilizokompiliwa kwa Delphi unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kubadilisha nyuma binary ya Delphi ningependekeza utumie programu-jalizi ya IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza **ATL+f7** (ingiza programu-jalizi ya python kwenye IDA) na chagua programu-jalizi ya python.

Programu-jalizi hii itatekeleza binary na kutatua majina ya kazi kwa njia ya moja kwa moja mwanzoni mwa uchunguzi. Baada ya kuanza uchunguzi bonyeza tena kitufe cha Kuanza (kijani au f9) na kuvunja itagonga mwanzoni mwa msimbo halisi.

Pia ni ya kuvutia sana kwa sababu ikiwa bonyeza kitufe katika programu ya kielelezo cha picha, mchunguzi utasimama kwenye kazi inayotekelezwa na kitufe hicho.

## Golang

Ikiwa unahitaji kubadilisha nyuma binary ya Golang ningependekeza utumie programu-jalizi ya IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza **ATL+f7** (ingiza programu-jalizi ya python kwenye IDA) na chagua programu-jalizi ya python.

Hii itatatua majina ya kazi.

## Python iliyokompiliwa

Kwenye ukurasa huu unaweza kupata jinsi ya kupata msimbo wa python kutoka kwa binary iliyokompiliwa ya ELF/EXE python:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Ikiwa unapata **binary** ya mchezo wa GBA unaweza kutumia zana tofauti kwa **kuiga** na **kudebugi**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la kudebugi_) - Ina kudebugi na kiolesura
* [**mgba** ](https://mgba.io)- Ina kudebugi ya CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Programu-jalizi ya Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Programu-jalizi ya Ghidra

Kwenye [**no$gba**](https://problemkaputt.de/gba.htm), katika _**Chaguo --> Usanidi wa Kuiga --> Vidhibiti**_\*\* \*\* unaweza kuona jinsi ya kubonyeza vitufe vya Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Vinapobonyezwa, kila **kitufe kina thamani** ya kukiwakilisha:
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

![](<../../.gitbook/assets/image (579).png>)

Katika picha iliyotangulia unaweza kuona kuwa kazi hiyo inaitwa kutoka **FUN\_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

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
Imepatikana msimbo huu:
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
Ikiwa **`uVar4`** iko kwenye **Keys za mwisho** na sio katika ufunguo wa sasa, hii inaitwa kuachilia kitufe (ufunguo wa sasa umehifadhiwa katika **`uVar1`**).
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
Katika msimbo uliopita unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **thamani ya kitufe kilichobonyezwa** iko) na baadhi ya thamani:

* Kwanza, inalinganishwa na **thamani 4** (kitufe cha **SELECT**): Katika changamoto hii kitufe hiki husafisha skrini
* Kisha, inalinganishwa na **thamani 8** (kitufe cha **START**): Katika changamoto hii inachunguza ikiwa msimbo ni halali kupata bendera.
* Katika kesi hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani ni sawa msimbo fulani unatekelezwa.
* Katika kesi nyingine yoyote, baadhi ya cont (`DAT_030000d4`) inachunguzwa. Ni cont kwa sababu inaongeza 1 mara tu baada ya kuingia katika msimbo.\
Ikiwa ni chini ya 8 kitu kinachohusisha **kuongeza** thamani kwa \*\*`DAT_030000d8` \*\* kinachofanywa (kimsingi inaongeza thamani za vitufe vilivyobonyezwa katika hii variable muda mrefu kama cont iko chini ya 8).

Hivyo, katika changamoto hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu mdogo kuliko 8 ambao matokeo ya kuongeza ni 0xf3.**

**Kumbukumbu kwa mafunzo haya:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kozi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Ufumbuzi wa binary)

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
