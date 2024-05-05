# Algoritmi crittografici/Compressione

## Algoritmi crittografici/Compressione

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Identificazione degli Algoritmi

Se ti trovi in un codice **che utilizza shift a destra e sinistra, xor e diverse operazioni aritmetiche** è molto probabile che si tratti dell'implementazione di un **algoritmo crittografico**. Qui verranno mostrati alcuni modi per **identificare l'algoritmo utilizzato senza dover invertire ogni passaggio**.

### Funzioni API

**CryptDeriveKey**

Se viene utilizzata questa funzione, puoi trovare quale **algoritmo viene utilizzato** controllando il valore del secondo parametro:

![](<../../.gitbook/assets/image (156).png>)

Controlla qui la tabella degli algoritmi possibili e dei loro valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e decomprime un dato buffer di dati.

**CryptAcquireContext**

Da [documentazione](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): La funzione **CryptAcquireContext** viene utilizzata per acquisire un handle a un particolare contenitore di chiavi all'interno di un particolare provider di servizi crittografici (CSP). **Questo handle restituito viene utilizzato nelle chiamate alle funzioni CryptoAPI** che utilizzano il CSP selezionato.

**CryptCreateHash**

Inizia l'hashing di un flusso di dati. Se viene utilizzata questa funzione, puoi trovare quale **algoritmo viene utilizzato** controllando il valore del secondo parametro:

![](<../../.gitbook/assets/image (549).png>)

Controlla qui la tabella degli algoritmi possibili e dei loro valori assegnati: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Costanti di codice

A volte è davvero facile identificare un algoritmo grazie al fatto che deve utilizzare un valore speciale e unico.

![](<../../.gitbook/assets/image (833).png>)

Se cerchi la prima costante su Google, otterrai questo:

![](<../../.gitbook/assets/image (529).png>)

Pertanto, puoi assumere che la funzione decompilata sia un **calcolatore sha256**.\
Puoi cercare qualsiasi altra costante e otterrai (probabilmente) lo stesso risultato.

### informazioni sui dati

Se il codice non ha costanti significative, potrebbe essere **caricamento di informazioni dalla sezione .data**.\
Puoi accedere a quei dati, **raggruppare il primo dword** e cercarlo su Google come abbiamo fatto nella sezione precedente:

![](<../../.gitbook/assets/image (531).png>)

In questo caso, se cerchi **0xA56363C6** puoi scoprire che è correlato alle **tabelle dell'algoritmo AES**.

## RC4 **(Crittografia Simmetrica)**

### Caratteristiche

È composto da 3 parti principali:

* **Fase di inizializzazione/**: Crea una **tabella di valori da 0x00 a 0xFF** (256 byte in totale, 0x100). Questa tabella è comunemente chiamata **Substitution Box** (o SBox).
* **Fase di scrambling**: **Scorrerà la tabella** creata prima (ciclo di 0x100 iterazioni, di nuovo) modificando ogni valore con byte **semi-random**. Per creare questi byte semi-random, viene utilizzata la **chiave RC4**. Le **chiavi RC4** possono essere **lunghe da 1 a 256 byte**, ma di solito è consigliabile che siano superiori a 5 byte. Comunemente, le chiavi RC4 sono lunghe 16 byte.
* **Fase XOR**: Infine, il testo in chiaro o cifrato viene **XORato con i valori creati prima**. La funzione per crittografare e decrittografare è la stessa. Per questo, verrà eseguito un **ciclo attraverso i 256 byte creati** tante volte quante necessario. Questo è di solito riconosciuto in un codice decompilato con un **%256 (mod 256)**.

{% hint style="info" %}
**Per identificare un RC4 in un codice di disassemblaggio/decompilato, controlla la presenza di 2 cicli di dimensione 0x100 (con l'uso di una chiave) e poi un XOR dei dati di input con i 256 valori creati prima nei 2 cicli probabilmente usando un %256 (mod 256)**
{% endhint %}

### **Fase di inizializzazione/Substitution Box:** (Nota il numero 256 usato come contatore e come un 0 è scritto in ogni posizione dei 256 caratteri)

![](<../../.gitbook/assets/image (584).png>)

### **Fase di scrambling:**

![](<../../.gitbook/assets/image (835).png>)

### **Fase XOR:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (Crittografia Simmetrica)**

### **Caratteristiche**

* Uso di **scatole di sostituzione e tabelle di ricerca**
* È possibile **distinguere AES grazie all'uso di valori specifici delle tabelle di ricerca** (costanti). _Nota che la **costante** può essere **memorizzata** nel binario **o creata**_ _**dinamicamente**._
* La **chiave di crittografia** deve essere **divisibile** per **16** (di solito 32B) e di solito viene utilizzato un **IV** di 16B.

### Costanti SBox

![](<../../.gitbook/assets/image (208).png>)

## Serpent **(Crittografia Simmetrica)**

### Caratteristiche

* È raro trovare del malware che lo utilizza ma ci sono esempi (Ursnif)
* Semplice determinare se un algoritmo è Serpent o meno in base alla sua lunghezza (funzione estremamente lunga)

### Identificazione

Nell'immagine seguente nota come viene utilizzata la costante **0x9E3779B9** (nota che questa costante è utilizzata anche da altri algoritmi crittografici come **TEA** -Tiny Encryption Algorithm).\
Nota anche la **dimensione del ciclo** (**132**) e il **numero di operazioni XOR** nelle istruzioni di **disassemblaggio** e nell'esempio di **codice**:

![](<../../.gitbook/assets/image (547).png>)

Come è stato menzionato prima, questo codice può essere visualizzato all'interno di qualsiasi decompilatore come una **funzione molto lunga** poiché **non ci sono salti** al suo interno. Il codice decompilato può apparire come segue:

![](<../../.gitbook/assets/image (513).png>)

Pertanto, è possibile identificare questo algoritmo controllando il **numero magico** e gli **XOR iniziali**, vedendo una **funzione molto lunga** e **confrontando** alcune **istruzioni** della funzione lunga **con un'implementazione** (come lo shift a sinistra di 7 e la rotazione a sinistra di 22).
## RSA **(Crittografia Asimmetrica)**

### Caratteristiche

* Più complesso rispetto agli algoritmi simmetrici
* Non ci sono costanti! (difficile determinare implementazioni personalizzate)
* KANAL (un analizzatore crittografico) non fornisce suggerimenti su RSA in quanto si basa su costanti.

### Identificazione tramite confronti

![](<../../.gitbook/assets/image (1113).png>)

* Nella riga 11 (sinistra) c'è un `+7) >> 3` che è lo stesso della riga 35 (destra): `+7) / 8`
* La riga 12 (sinistra) controlla se `modulus_len < 0x040` e nella riga 36 (destra) controlla se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Caratteristiche

* 3 funzioni: Init, Update, Final
* Funzioni di inizializzazione simili

### Identificazione

**Init**

Puoi identificarli entrambi controllando le costanti. Nota che sha\_init ha 1 costante che MD5 non ha:

![](<../../.gitbook/assets/image (406).png>)

**Trasformazione MD5**

Nota l'uso di più costanti

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (hash)

* Più piccolo e più efficiente poiché la sua funzione è trovare cambiamenti accidentali nei dati
* Utilizza tabelle di ricerca (quindi puoi identificare costanti)

### Identificazione

Controlla le **costanti delle tabelle di ricerca**:

![](<../../.gitbook/assets/image (508).png>)

Un algoritmo di hash CRC appare come:

![](<../../.gitbook/assets/image (391).png>)

## APLib (Compressione)

### Caratteristiche

* Costanti non riconoscibili
* Puoi provare a scrivere l'algoritmo in python e cercare cose simili online

### Identificazione

Il grafico è piuttosto grande:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Controlla **3 confronti per riconoscerlo**:

![](<../../.gitbook/assets/image (430).png>)
