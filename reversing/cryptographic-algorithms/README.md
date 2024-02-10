# Algoritmi crittografici/compressione

## Algoritmi crittografici/compressione

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Identificazione degli algoritmi

Se ti trovi in un codice **che utilizza shift a destra e sinistra, xor e diverse operazioni aritmetiche**, è molto probabile che si tratti dell'implementazione di un **algoritmo crittografico**. Qui verranno mostrati alcuni modi per **identificare l'algoritmo utilizzato senza dover invertire ogni passaggio**.

### Funzioni API

**CryptDeriveKey**

Se viene utilizzata questa funzione, è possibile trovare quale **algoritmo viene utilizzato** controllando il valore del secondo parametro:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Controlla qui la tabella degli algoritmi possibili e dei loro valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e decomprime un determinato buffer di dati.

**CryptAcquireContext**

Da [documentazione](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): La funzione **CryptAcquireContext** viene utilizzata per acquisire un handle a un particolare contenitore di chiavi all'interno di un particolare provider di servizi crittografici (CSP). **Questo handle restituito viene utilizzato nelle chiamate alle funzioni CryptoAPI** che utilizzano il CSP selezionato.

**CryptCreateHash**

Inizia l'hashing di un flusso di dati. Se viene utilizzata questa funzione, è possibile trovare quale **algoritmo viene utilizzato** controllando il valore del secondo parametro:

![](<../../.gitbook/assets/image (376).png>)

\
Controlla qui la tabella degli algoritmi possibili e dei loro valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Costanti di codice

A volte è molto facile identificare un algoritmo grazie al fatto che deve utilizzare un valore speciale e unico.

![](<../../.gitbook/assets/image (370).png>)

Se cerchi la prima costante su Google, otterrai questo risultato:

![](<../../.gitbook/assets/image (371).png>)

Pertanto, puoi assumere che la funzione decompilata sia un **calcolatore sha256**.\
Puoi cercare qualsiasi altra costante e otterrai (probabilmente) lo stesso risultato.

### informazioni sui dati

Se il codice non ha alcuna costante significativa, potrebbe essere **caricamento di informazioni dalla sezione .data**.\
Puoi accedere a quei dati, **raggruppare il primo dword** e cercarlo su Google come abbiamo fatto nella sezione precedente:

![](<../../.gitbook/assets/image (372).png>)

In questo caso, se cerchi **0xA56363C6** puoi scoprire che è correlato alle **tabelle dell'algoritmo AES**.

## RC4 **(Crittografia simmetrica)**

### Caratteristiche

È composto da 3 parti principali:

* **Fase di inizializzazione/**: Crea una **tabella di valori da 0x00 a 0xFF** (256 byte in totale, 0x100). Questa tabella è comunemente chiamata **Substitution Box** (o SBox).
* **Fase di scrambling**: Attraverserà **la tabella** creata in precedenza (ciclo di 0x100 iterazioni, ancora) modificando ogni valore con byte **semi-random**. Per creare questi byte semi-random, viene utilizzata la **chiave RC4**. Le chiavi RC4 possono essere **lunghe da 1 a 256 byte**, anche se di solito si consiglia di utilizzare una lunghezza superiore a 5 byte. Comunemente, le chiavi RC4 sono lunghe 16 byte.
* **Fase di XOR**: Infine, il testo in chiaro o il testo cifrato viene **XORato con i valori creati in precedenza**. La funzione per crittografare e decrittografare è la stessa. A tal fine, verrà eseguito un **ciclo attraverso i 256 byte creati** tante volte quanto necessario. Questo di solito viene riconosciuto in un codice decompilato con un **%256 (mod 256)**.

{% hint style="info" %}
**Per identificare un RC4 in un codice di disassemblaggio/decompilato, puoi controllare 2 cicli di dimensione 0x100 (con l'uso di una chiave) e quindi un XOR dei dati di input con i 256 valori creati in precedenza nei 2 cicli probabilmente usando un %256 (mod 256)**
{% endhint %}

### **Fase di inizializzazione/Substitution Box:** (Nota il numero 256 utilizzato come contatore e come viene scritto uno 0 in ogni posizione dei 256 caratteri)

![](<../../.gitbook/assets/image (377).png>)

### **Fase di scrambling:**

![](<../../.gitbook/assets/image (378).png>)

### **Fase di XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Crittografia simmetrica)**

### **Caratteristiche**

* Utilizzo di **tabelle di sostituzione e tabelle di ricerca**
* È possibile **distinguere AES grazie all'uso di valori specifici delle tabelle di ricerca** (costanti). _Nota che la **costante** può essere **memorizzata** nel binario **o creata**_ _**dinamicamente**._
* La **chiave di crittografia** deve essere **divisibile** per **16** (di solito 32B) e di solito viene utilizzato un **IV** di 16B.

### Costanti SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Crittografia simmetrica)**

### Caratteristiche

* È raro trovare malware che lo utilizza, ma ci sono esempi (Ursnif)
* Semplice determinare se un algoritmo è Serpent o meno in base alla sua lunghezza (funzione estremamente lunga)

### Identificazione

Nell'immagine seguente, nota come viene utilizzata la costante **0x9E3779B9** (nota che questa costante viene utilizzata anche da altri algoritmi crittografici come **TEA** - Tiny Encryption Algorithm).\
Nota anche la **dimensione del ciclo** (**132**) e il **numero di operazioni XOR** nelle istruzioni di **disassemblaggio** e nell'**esempio di codice**:

![](<../../.gitbook/assets/image (381).png>)

Come accennato in precedenza, questo codice può essere visualizzato all'interno di qualsiasi decompiler come una **funzione molto lunga** poiché non ci sono **salti** al suo interno. Il codice decompilato può apparire come segue:

![](<../../.gitbook/assets/image (382).png>)

Pertanto, è possibile identificare questo algoritmo controllando il **numero magico** e gli **XOR iniziali**, osservando una **funzione molto lunga** e **confrontando** alcune **istruzioni** della lunga funzione **con un'implementazione** (come lo shift a sinistra di
## RSA **(Crittografia Asimmetrica)**

### Caratteristiche

* Più complesso rispetto agli algoritmi simmetrici
* Non ci sono costanti! (le implementazioni personalizzate sono difficili da determinare)
* KANAL (un analizzatore crittografico) non fornisce suggerimenti su RSA in quanto si basa su costanti.

### Identificazione tramite confronti

![](<../../.gitbook/assets/image (383).png>)

* Nella riga 11 (sinistra) c'è `+7) >> 3`, che è lo stesso della riga 35 (destra): `+7) / 8`
* La riga 12 (sinistra) controlla se `modulus_len < 0x040` e nella riga 36 (destra) controlla se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Caratteristiche

* 3 funzioni: Init, Update, Final
* Funzioni di inizializzazione simili

### Identificazione

**Init**

Puoi identificarli entrambi controllando le costanti. Nota che sha\_init ha una costante che MD5 non ha:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Nota l'uso di più costanti

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Più piccolo ed efficiente in quanto la sua funzione è trovare cambiamenti accidentali nei dati
* Utilizza tabelle di ricerca (quindi puoi identificare le costanti)

### Identificazione

Controlla le **costanti delle tabelle di ricerca**:

![](<../../.gitbook/assets/image (387).png>)

Un algoritmo di hash CRC assomiglia a:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compressione)

### Caratteristiche

* Costanti non riconoscibili
* Puoi provare a scrivere l'algoritmo in Python e cercare cose simili online

### Identificazione

Il grafico è piuttosto grande:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Controlla **3 confronti per riconoscerlo**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
