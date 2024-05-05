# Cheat Engine

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove sono salvati i valori importanti all'interno della memoria di un gioco in esecuzione e modificarli.\
Quando lo scarichi ed esegui, ti viene **presentato** un **tutorial** su come utilizzare lo strumento. Se vuoi imparare ad usare lo strumento, è altamente consigliato completarlo.

## Cosa stai cercando?

![](<../../.gitbook/assets/image (762).png>)

Questo strumento è molto utile per trovare **dove è memorizzato un valore** (di solito un numero) **nella memoria di un programma**.\
**Di solito i numeri** sono memorizzati in forma **4bytes**, ma potresti trovarli anche in formati **double** o **float**, o potresti voler cercare qualcosa **diverso da un numero**. Per questo motivo devi essere sicuro di **selezionare** ciò che desideri **cercare**:

![](<../../.gitbook/assets/image (324).png>)

Puoi anche indicare **diversi** tipi di **ricerche**:

![](<../../.gitbook/assets/image (311).png>)

Puoi anche spuntare la casella per **fermare il gioco durante la scansione della memoria**:

![](<../../.gitbook/assets/image (1052).png>)

### Scorciatoie

In _**Modifica --> Impostazioni --> Scorciatoie**_ puoi impostare diverse **scorciatoie** per scopi diversi come **fermare** il **gioco** (che è molto utile se in qualche momento desideri eseguire la scansione della memoria). Altre opzioni sono disponibili:

![](<../../.gitbook/assets/image (864).png>)

## Modificare il valore

Una volta che hai **trovato** dove si trova il **valore** che stai **cercando** (più dettagli nelle fasi successive) puoi **modificarlo** facendo doppio clic su di esso, quindi facendo doppio clic sul suo valore:

![](<../../.gitbook/assets/image (563).png>)

E infine **selezionando la spunta** per effettuare la modifica nella memoria:

![](<../../.gitbook/assets/image (385).png>)

La **modifica** alla **memoria** verrà immediatamente **applicata** (nota che finché il gioco non utilizza nuovamente questo valore, il valore **non verrà aggiornato nel gioco**).

## Ricerca del valore

Quindi, supponiamo che ci sia un valore importante (come la vita del tuo utente) che desideri migliorare, e stai cercando questo valore nella memoria)

### Attraverso una modifica conosciuta

Supponendo che stai cercando il valore 100, **esegui una scansione** cercando quel valore e trovi molte corrispondenze:

![](<../../.gitbook/assets/image (108).png>)

Quindi, fai qualcosa in modo che il **valore cambi**, e **fermi** il gioco e **esegui** una **scansione successiva**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine cercherà i **valori** che **sono passati da 100 al nuovo valore**. Congratulazioni, hai **trovato** l'**indirizzo** del valore che cercavi, ora puoi modificarlo.\
_Se hai ancora diversi valori, fai qualcosa per modificare nuovamente quel valore e esegui un'altra "scansione successiva" per filtrare gli indirizzi._

### Valore sconosciuto, modifica conosciuta

Nello scenario in cui **non conosci il valore** ma sai **come farlo cambiare** (e anche il valore del cambiamento) puoi cercare il tuo numero.

Quindi, inizia eseguendo una scansione di tipo "**Valore iniziale sconosciuto**":

![](<../../.gitbook/assets/image (890).png>)

Quindi, fai cambiare il valore, indica **come** il **valore è cambiato** (nel mio caso è stato diminuito di 1) e esegui una **scansione successiva**:

![](<../../.gitbook/assets/image (371).png>)

Ti verranno presentati **tutti i valori che sono stati modificati nel modo selezionato**:

![](<../../.gitbook/assets/image (569).png>)

Una volta trovato il tuo valore, puoi modificarlo.

Nota che ci sono **molte modifiche possibili** e puoi fare questi **passaggi quante volte vuoi** per filtrare i risultati:

![](<../../.gitbook/assets/image (574).png>)

### Indirizzo di memoria casuale - Trovare il codice

Fino ad ora abbiamo imparato come trovare un indirizzo che memorizza un valore, ma è molto probabile che in **esecuzioni diverse del gioco quell'indirizzo si trovi in posizioni diverse della memoria**. Scopriamo quindi come trovare sempre quell'indirizzo.

Utilizzando alcuni dei trucchi menzionati, trova l'indirizzo in cui il tuo gioco attuale sta memorizzando il valore importante. Quindi (fermando il gioco se lo desideri) fai un **clic destro** sull'**indirizzo** trovato e seleziona "**Scopri cosa accede a questo indirizzo**" o "**Scopri cosa scrive a questo indirizzo**":

![](<../../.gitbook/assets/image (1067).png>)

La **prima opzione** è utile per sapere quali **parti** del **codice** stanno **usando** questo **indirizzo** (cosa utile per altre cose come **sapere dove puoi modificare il codice** del gioco).\
La **seconda opzione** è più **specifica**, e sarà più utile in questo caso poiché siamo interessati a sapere **da dove viene scritto questo valore**.

Una volta selezionata una di queste opzioni, il **debugger** sarà **collegato** al programma e comparirà una nuova **finestra vuota**. Ora, **gioca** al **gioco** e **modifica** quel **valore** (senza riavviare il gioco). La **finestra** dovrebbe essere **riempita** con gli **indirizzi** che stanno **modificando** il **valore**:

![](<../../.gitbook/assets/image (91).png>)

Ora che hai trovato l'indirizzo che sta modificando il valore, puoi **modificare il codice a tuo piacimento** (Cheat Engine ti consente di modificarlo per NOPs molto rapidamente):

![](<../../.gitbook/assets/image (1057).png>)

Quindi, ora puoi modificarlo in modo che il codice non influenzi il tuo numero, o influenzi sempre in modo positivo.
### Indirizzo di memoria casuale - Trovare il puntatore

Seguendo i passaggi precedenti, trova dove si trova il valore di tuo interesse. Quindi, utilizzando "**Scopri cosa scrive a questo indirizzo**" scopri quale indirizzo scrive questo valore e fai doppio clic su di esso per ottenere la visualizzazione della disassemblazione:

![](<../../.gitbook/assets/image (1039).png>)

Successivamente, esegui una nuova scansione **cercando il valore esadecimale tra "\[]"** (il valore di $edx in questo caso):

![](<../../.gitbook/assets/image (994).png>)

(Se ne appaiono diversi, di solito è necessario scegliere il più piccolo)

Ora, abbiamo **trovato il puntatore che modificherà il valore di nostro interesse**.

Clicca su "**Aggiungi indirizzo manualmente**":

![](<../../.gitbook/assets/image (990).png>)

Ora, clicca sulla casella di controllo "Puntatore" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario, l'indirizzo trovato nell'immagine precedente era "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Nota come il primo "Indirizzo" venga automaticamente popolato dall'indirizzo del puntatore che hai inserito)

Clicca su OK e verrà creato un nuovo puntatore:

![](<../../.gitbook/assets/image (308).png>)

Ora, ogni volta che modifichi quel valore, stai **modificando il valore importante anche se l'indirizzo di memoria in cui si trova il valore è diverso**.

### Iniezione di codice

L'iniezione di codice è una tecnica in cui si inietta un pezzo di codice nel processo di destinazione e si reindirizza l'esecuzione del codice per passare attraverso il proprio codice scritto (come darti punti invece di sottrarli).

Quindi, immagina di aver trovato l'indirizzo che sottrae 1 alla vita del tuo giocatore:

![](<../../.gitbook/assets/image (203).png>)

Clicca su Mostra disassemblatore per ottenere il **codice disassemblato**.\
Quindi, premi **CTRL+a** per richiamare la finestra di auto-assemblaggio e seleziona _**Modello --> Iniezione di codice**_

![](<../../.gitbook/assets/image (902).png>)

Inserisci l'**indirizzo dell'istruzione che desideri modificare** (di solito viene autocompilato):

![](<../../.gitbook/assets/image (744).png>)

Verrà generato un modello:

![](<../../.gitbook/assets/image (944).png>)

Quindi, inserisci il tuo nuovo codice di assemblaggio nella sezione "**newmem**" e rimuovi il codice originale da "**originalcode**" se non vuoi che venga eseguito. In questo esempio, il codice iniettato aggiungerà 2 punti invece di sottrarre 1:

![](<../../.gitbook/assets/image (521).png>)

**Clicca su esegui e così via e il tuo codice dovrebbe essere iniettato nel programma cambiando il comportamento della funzionalità!**

## **Riferimenti**

* **Tutorial Cheat Engine, completalo per imparare come iniziare con Cheat Engine**
