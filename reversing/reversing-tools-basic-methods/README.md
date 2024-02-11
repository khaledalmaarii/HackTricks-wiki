# Zana za Kugeuza na Mbinu za Msingi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaowajali zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Zana za Kugeuza kwa Kutumia ImGui

Programu:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Kugeuza Wasm / Kompila Wat

Mkondoni:

* Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kugeuza kutoka wasm (binary) hadi wat (maandishi wazi)
* Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kugeuza kutoka wat hadi wasm
* unaweza pia kujaribu kutumia [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kugeuza

Programu:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Kugeuza .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni kigeuzi ambacho **kinageuza na kuchunguza muundo mbalimbali**, ikiwa ni pamoja na **maktaba** (.dll), **faili za metadata za Windows** (.winmd), na **utekelezaji** (.exe). Mara baada ya kugeuzwa, mkusanyiko unaweza kuokolewa kama mradi wa Visual Studio (.csproj).

Faida hapa ni kwamba ikiwa msimbo wa chanzo uliopotea unahitaji kurejeshwa kutoka kwa mkusanyiko wa zamani, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji rahisi kote kwenye msimbo uliogeuzwa, hivyo kuifanya kuwa moja ya zana kamili kwa **uchambuzi wa algorithm za Xamarin.**&#x20;

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Na mfano kamili wa kuongeza na API inayotanua zana ili kukidhi mahitaji yako halisi, .NET reflector hupunguza muda na kusaidia maendeleo. Hebu tuangalie huduma nyingi za uhandisi wa nyuma ambazo zana hii hutoa:

* Hutoa ufahamu juu ya jinsi data inavyosafiri kupitia maktaba au sehemu
* Hutoa ufahamu juu ya utekelezaji na matumizi ya lugha na fremu za .NET
* Hupata utendaji usioelezewa na usiofunuliwa ili kupata zaidi kutoka kwa APIs na teknolojia zinazotumiwa.
* Hupata tegemezi na makusanyo tofauti
* Inapatia eneo sahihi la makosa katika msimbo wako, sehemu za tatu, na maktaba.&#x20;
* Inafuatilia chanzo cha msimbo wote wa .NET unavyofanya kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Programu-jalizi ya ILSpy kwa Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuwa nayo kwenye mfumo wowote (unaweza kuweka moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bonyeza **Extensions** na **tafuta ILSpy**).\
Ikiwa unahitaji **kugeuza**, **kubadilisha** na **kugeuza tena** unaweza kutumia: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Bonyeza Kulia -> Badilisha Njia** kubadilisha kitu ndani ya kazi).\
Unaweza pia kujaribu [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### Kuingiza Kumbukumbu ya DNSpy

Ili kufanya **DNSpy iweke kumbukumbu baadhi ya habari kwenye faili**, unaweza kutumia mistari hii ya .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Uchunguzi wa DNSpy

Ili kuchunguza kificho kwa kutumia DNSpy unahitaji:

Kwanza, badilisha **sifa za Kusanyiko** zinazohusiana na **uchunguzi**:

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

Kisha hifadhi faili mpya kwenye _**File >> Save module...**_:

![](<../../.gitbook/assets/image (279).png>)

Hii ni muhimu kwa sababu ikiwa hautafanya hivyo, wakati wa **runtime** maboresho kadhaa yatafanywa kwenye nambari na inaweza kuwa iwezekanavyo kwamba wakati wa kudebugiwa **break-point haitafikiwa kamwe** au baadhi ya **variables hazipo**.

Kisha, ikiwa programu yako ya .Net inaendeshwa na **IIS** unaweza kuirejesha kwa kubonyeza:
```
iisreset /noforce
```
Kisha, ili kuanza kurekebisha makosa, unapaswa kufunga faili zote zilizofunguliwa na ndani ya **Kichupo cha Kurekebisha** chagua **Weka kwenye Mchakato...**:

![](<../../.gitbook/assets/image (280).png>)

Kisha chagua **w3wp.exe** ili kuunganisha kwenye **seva ya IIS** na bonyeza **unganisha**:

![](<../../.gitbook/assets/image (281).png>)

Sasa tukiwa tunarekebisha mchakato, ni wakati wa kuusimamisha na kupakia moduli zote. Kwanza bonyeza _Kurekebisha >> Simama Yote_ na kisha bonyeza _**Kurekebisha >> Windows >> Moduli**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Bonyeza moduli yoyote kwenye **Moduli** na chagua **Fungua Moduli Zote**:

![](<../../.gitbook/assets/image (284).png>)

Bonyeza kulia kwenye moduli yoyote katika **Mtafuta wa Makusanyo** na bonyeza **Panga Makusanyo**:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Kurekebisha DLLs

### Kutumia IDA

* **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
* Chagua kurekebisha **Windbg**
* Chagua "**Suspend on library load/unload**"

![](<../../.gitbook/assets/image (135).png>)

* Sanidi **parameta** za utekelezaji kwa kuweka **njia ya DLL** na kazi unayotaka kuita:

![](<../../.gitbook/assets/image (136).png>)

Kisha, unapoanza kurekebisha **utekelezaji utasimamishwa wakati kila DLL inapakia**, kisha, wakati rundll32 inapakia DLL yako, utekelezaji utasimamishwa.

Lakini, jinsi gani unaweza kufikia nambari ya DLL iliyopakiwa? Kwa kutumia njia hii, sijui jinsi.

### Kutumia x64dbg/x32dbg

* **Pakia rundll32** (64bits katika C:\Windows\System32\rundll32.exe na 32 bits katika C:\Windows\SysWOW64\rundll32.exe)
* **Badilisha Mstari wa Amri** ( _Faili --> Badilisha Mstari wa Amri_ ) na weka njia ya dll na kazi unayotaka kuita, kwa mfano: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Badilisha _Chaguo --> Mipangilio_ na chagua "**DLL Entry**".
* Kisha **anza utekelezaji**, kurekebisha itasimama kwa kila dll kuu, wakati fulani utasimama kwenye Kuingia kwa dll yako. Kutoka hapo, tafuta tu sehemu ambapo unataka kuweka alama ya kusimamisha.

Tambua kuwa wakati utekelezaji unaposimamishwa kwa sababu yoyote katika win64dbg unaweza kuona **katika nambari gani uko** ukitazama **juu ya dirisha la win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Kisha, ukitazama hii unaweza kuona wakati utekelezaji ulisimamishwa kwenye dll unayotaka kurekebisha.

## Programu za GUI / Michezo ya Video

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa ndani ya kumbukumbu ya mchezo unaotumika na kuzibadilisha. Habari zaidi katika:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Kurekebisha shellcode na blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) ita **tenga** shellcode ndani ya nafasi ya kumbukumbu, itakuonyesha **anwani ya kumbukumbu** ambapo shellcode ilipangiwa na itasimamisha utekelezaji.\
Kisha, unahitaji **kuunganisha kurekebisha** (Ida au x64dbg) kwenye mchakato na kuweka **alama ya kusimamisha kwenye anwani ya kumbukumbu iliyotajwa** na **kuendelea** utekelezaji. Kwa njia hii utakuwa unarekebisha shellcode.

Ukurasa wa kutolewa wa github una vifurushi vilivyopakuliwa: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Unaweza kupata toleo lililobadilishwa kidogo la Blobrunner kwenye kiunga kifuatacho. Ili kuipachika tu **unda mradi wa C/C++ katika Visual Studio Code, nakili na ubandike nambari na ijenge**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Kurekebisha shellcode na jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ni sawa sana na blobrunner. Ita **tenga** shellcode ndani ya nafasi ya kumbukumbu, na anza **mzunguko wa milele**. Kisha unahitaji **kuunganisha kurekebisha** kwenye mchakato, **cheza anza subiri sekunde 2-5 na bonyeza simama** na utakuta uko ndani ya **mzunguko wa milele**. Ruka kwa maagizo inayofuata ya mzunguko wa milele kwani itakuwa wito kwa shellcode, na hatimaye utakuta unatekeleza shellcode.

![](<../../.gitbook/assets/image (397).png>)

Unaweza kupakua toleo lililopakuliwa la [jmp2it kwenye ukurasa wa kutolewa](https://github.com/adamkramer/jmp2it/releases/).

### Kurekebisha shellcode kwa kutumia Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ni GUI ya radare. Kwa kutumia cutter unaweza kuiga shellcode na kuichunguza kwa njia ya kudumu.

Tambua kuwa Cutter inakuwezesha "Fungua Faili" na "Fungua Shellcode". Katika kesi yangu wakati nilipofungua shellcode kama faili ilikuwa imefichuliwa kwa usahihi, lakini wakati nilipofungua kama shellcode haikuwa:

![](<../../.gitbook/assets/image (400).png>)

Ili kuanza uigaji katika mahali unapotaka, weka alama hapo na inaonekana cutter itaanza uigaji kiotomatiki kutoka hapo:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Unaweza kuona steki kwa mfano ndani ya kumbukumbu ya hex:

![](<../../.gitbook/assets/image (402).png>)

### Kufuta shellcode na kupata kazi zilizotekelezwa

Unapaswa kujaribu [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Itakuambia mambo kama **kazi zipi** shellcode inatumia na ikiwa shellcode inajitafsiri yenyewe kwenye kumbukumbu.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia ina kipengele cha kuzindua kwa picha ambapo unaweza kuchagua chaguo unayotaka na kutekeleza shellcode

![](<../../.gitbook/assets/image (398).png>)

Chaguo la **Tengeneza Dump** litatengeneza dump ya shellcode ya mwisho ikiwa kuna mabadiliko yoyote yanayofanywa kwa shellcode kwa njia ya kumbukumbu (inatumika kupakua shellcode iliyohifadhiwa). **Kianzia cha kuanza** kinaweza kuwa na manufaa kuanza shellcode kwenye kianzia maalum. Chaguo la **Kagua Shell** ni muhimu kwa kuchunguza shellcode kwa kutumia terminal ya scDbg (hata hivyo, ninaona chaguo zingine zilizoelezwa hapo awali kuwa bora kwa suala hili kwani utaweza kutumia Ida au x64dbg).

### Kuchambua kwa kutumia CyberChef

Pakia faili yako ya shellcode kama kipengele cha kuingiza na tumia mapokezi yafuatayo kudekompili: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Obfuscator huyu **hubadilisha maagizo yote ya `mov`** (ndiyo, ni nzuri sana). Pia hutumia kuvuruga kutekeleza mzunguko. Kwa maelezo zaidi kuhusu jinsi inavyofanya kazi:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Ikiwa una bahati, [demovfuscator](https://github.com/kirschju/demovfuscator) itaweza kufuta ufusaji wa faili. Ina tegemezi kadhaa.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, njia hii ya kupata bendera** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitolea, inapata masuala katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Ili kupata **sehemu ya kuingia**, tafuta kazi kwa kutumia `::main` kama hivi:

![](<../../.gitbook/assets/image (612).png>)

Katika kesi hii, faili ya binary ilikuwa inaitwa authenticator, kwa hivyo ni wazi kabisa kuwa hii ndio kazi kuu inayovutia.\
Ukiwa na **jina** la **kazi** zinazoitwa, tafuta kuhusu **vipengele vyao** na **matokeo** kwenye **mtandao**.

## **Delphi**

Kwa faili za binary zilizopangwa kwa Delphi, unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ikiwa unahitaji kubadilisha faili ya binary ya Delphi, ningekushauri utumie programu-jalizi ya IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza tu **ATL+f7** (ingiza programu-jalizi ya python katika IDA) na chagua programu-jalizi ya python.

Programu-jalizi hii itatekeleza faili ya binary na kutatua majina ya kazi kwa njia ya kudumu mwanzoni mwa uchunguzi. Baada ya kuanza uchunguzi, bonyeza tena kitufe cha Kuanza (kijani au f9) na kizuizi kitagonga mwanzoni mwa namna halisi ya kificho.

Pia ni ya kuvutia sana kwa sababu ikiwa bonyeza kitufe katika programu ya picha, kizuizi kitasimama katika kazi inayotekelezwa na kitufe hicho.

## Golang

Ikiwa unahitaji kubadilisha faili ya binary ya Golang, ningekushauri utumie programu-jalizi ya IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza tu **ATL+f7** (ingiza programu-jalizi ya python katika IDA) na chagua programu-jalizi ya python.

Hii itatatua majina ya kazi.

## Python Iliyopangwa

Katika ukurasa huu unaweza kupata jinsi ya kupata nambari ya python kutoka kwa faili ya binary iliyopangwa kwa ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Ikiwa unapata **binary** ya mchezo wa GBA, unaweza kutumia zana tofauti kwa **kuiga** na **kuchunguza**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Pakua toleo la kudhibiti_) - Ina kizuizi na kiolesura
* [**mgba** ](https://mgba.io)- Ina kizuizi cha CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Programu-jalizi ya Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Programu-jalizi ya Ghidra

Katika [**no$gba**](https://problemkaputt.de/gba.htm), katika _**Options --> Emulation Setup --> Controls**_\*\* \*\* unaweza kuona jinsi ya kubonyeza **vitufe** vya Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Unapobonyeza, kila **funguo lina thamani** ya kuitambulisha:
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
Kwa hivyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia kuingia kwa mtumiaji**. Katika anwani **0x4000130** utapata kazi inayopatikana kawaida: **KEYINPUT.**

![](<../../.gitbook/assets/image (579).png>)

Katika picha iliyotangulia, unaweza kuona kuwa kazi inaitwa kutoka **FUN\_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika kazi hiyo, baada ya shughuli za kuanzisha (bila umuhimu wowote):
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
Imepatikana nambari hii:
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
If-ya mwisho inachunguza **`uVar4`** iko kwenye **funguo za mwisho** na sio funguo ya sasa, inayoitwa pia kuacha kushikilia kitufe (funguo ya sasa imehifadhiwa katika **`uVar1`**).
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

* Kwanza, inalinganishwa na **thamani 4** (**kitufe cha SELECT**): Katika changamoto hii kitufe hiki kinasafisha skrini
* Kisha, inalinganishwa na **thamani 8** (**kitufe cha START**): Katika changamoto hii inathibitisha ikiwa msimbo ni sahihi ili kupata bendera.
* Katika kesi hii, var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani ni sawa, msimbo fulani unatekelezwa.
* Katika kesi zingine, inachunguzwa cont (`DAT_030000d4`). Ni cont kwa sababu inaongeza 1 mara tu baada ya kuingia kwenye msimbo.\
Ikiwa ni chini ya 8, kitu kinachohusiana na **kuongeza** thamani kwa \*\*`DAT_030000d8` \*\* kinafanyika (kimsingi inaongeza thamani za vitufe vilivyobonyezwa kwenye kipekee hiki kama muda mrefu kama cont ni chini ya 8).

Kwa hivyo, katika changamoto hii, kwa kujua thamani za vitufe, ulihitaji **kubonyeza mchanganyiko wenye urefu mdogo kuliko 8 ambao matokeo ya kuongeza ni 0xf3.**

**Marejeleo kwa mafunzo haya:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kozi

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Ufichuaji wa binary)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaowajali zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia zingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
