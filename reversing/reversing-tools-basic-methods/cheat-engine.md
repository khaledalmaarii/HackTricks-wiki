<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove sono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli.\
Quando lo scarichi ed esegui, ti viene **presentato** un **tutorial** su come utilizzare lo strumento. Se vuoi imparare come utilizzare lo strumento, è altamente consigliato completarlo.

# Cosa stai cercando?

![](<../../.gitbook/assets/image (580).png>)

Questo strumento è molto utile per trovare **dove viene memorizzato un certo valore** (di solito un numero) **nella memoria** di un programma.\
**Di solito i numeri** sono memorizzati in formato **4 byte**, ma potresti trovarli anche in formati **double** o **float**, o potresti voler cercare qualcosa di **diverso da un numero**. Per questo motivo devi essere sicuro di **selezionare** ciò che vuoi **cercare**:

![](<../../.gitbook/assets/image (581).png>)

Puoi anche indicare **diversi** tipi di **ricerche**:

![](<../../.gitbook/assets/image (582).png>)

Puoi anche selezionare la casella per **fermare il gioco durante la scansione della memoria**:

![](<../../.gitbook/assets/image (584).png>)

## Tasti di scelta rapida

In _**Modifica --> Impostazioni --> Tasti di scelta rapida**_ puoi impostare diversi **tasti di scelta rapida** per diversi scopi, come **fermare** il **gioco** (cosa molto utile se in qualche momento vuoi analizzare la memoria). Altre opzioni sono disponibili:

![](<../../.gitbook/assets/image (583).png>)

# Modificare il valore

Una volta che hai **trovato** dove si trova il **valore** che stai **cercando** (più dettagli nelle fasi successive), puoi **modificarlo** facendo doppio clic su di esso, quindi facendo doppio clic sul suo valore:

![](<../../.gitbook/assets/image (585).png>)

E infine **selezionando la casella** per effettuare la modifica nella memoria:

![](<../../.gitbook/assets/image (586).png>)

La **modifica** alla **memoria** verrà immediatamente **applicata** (nota che finché il gioco non utilizza nuovamente questo valore, il valore **non verrà aggiornato nel gioco**).

# Ricerca del valore

Quindi, supponiamo che ci sia un valore importante (come la vita del tuo utente) che desideri migliorare e stai cercando questo valore nella memoria)

## Attraverso una modifica nota

Supponendo che tu stia cercando il valore 100, **esegui una scansione** cercando quel valore e trovi molte coincidenze:

![](<../../.gitbook/assets/image (587).png>)

Quindi, fai qualcosa in modo che il **valore cambi**, quindi **ferma** il gioco e **esegui** una **scansione successiva**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine cercherà i **valori** che **sono passati da 100 al nuovo valore**. Congratulazioni, hai **trovato** l'**indirizzo** del valore che cercavi, ora puoi modificarlo.\
_Se hai ancora diversi valori, fai qualcosa per modificare nuovamente quel valore e esegui un'altra "scansione successiva" per filtrare gli indirizzi._

## Valore sconosciuto, modifica nota

Nello scenario in cui **non conosci il valore** ma sai **come farlo cambiare** (e anche il valore del cambiamento) puoi cercare il tuo numero.

Quindi, inizia eseguendo una scansione di tipo "**Valore iniziale sconosciuto**":

![](<../../.gitbook/assets/image (589).png>)

Quindi, fai cambiare il valore, indica **come** il **valore** è **cambiato** (nel mio caso è diminuito di 1) e fai una **scansione successiva**:

![](<../../.gitbook/assets/image (590).png>)

Ti verranno presentati **tutti i valori che sono stati modificati nel modo selezionato**:

![](<../../.gitbook/assets/image (591).png>)

Una volta trovato il tuo valore, puoi modificarlo.

Nota che ci sono **molte possibili modifiche** e puoi eseguire questi **passaggi quante volte vuoi** per filtrare i risultati:

![](<../../.gitbook/assets/image (592).png>)

## Indirizzo di memoria casuale - Trovare il codice

Fino ad ora abbiamo imparato come trovare un indirizzo che memorizza un valore, ma è molto probabile che in **diverse esecuzioni del gioco quell'indirizzo si trovi in posizioni diverse della memoria**. Scopriamo quindi come trovare sempre quell'indirizzo.

Utilizzando alcuni dei trucchi menzionati, trova l'indirizzo in cui il tuo gioco corrente sta memorizzando il valore importante. Quindi (fermando il gioco se lo desideri) fai un **clic destro** sull'**indirizzo** trovato e seleziona "**Scopri cosa accede a questo indirizzo**" o "**Scopri cosa scrive a questo indirizzo**":

![](<../../.gitbook/assets/image (593).png>)

La **prima opzione** è utile per sapere quali **parti** del **codice** stanno **usando** questo **indirizzo** (cosa utile per altre cose come **sapere dove puoi modificare il codice** del gioco).\
La **seconda opzione** è più **specifica**, e sarà più utile in questo caso in quanto siamo interessati a sapere **da dove viene scritto questo valore**.

Una volta selezionata una di queste opzioni, il **debugger** sarà **collegato** al programma e verrà visualizzata una nuova **finestra vuota**. Ora, **gioca** al **gioco** e **modifica** quel **valore** (senza riavviare il gioco). La **finestra** dovrebbe essere **riempita** con gli **indirizzi** che stanno **modificando** il **valore**:

![](<../../.gitbook/assets/image (594).png>)

Ora che hai trovato l'indirizzo che sta modificando il valore, puoi **modificare il codice a tuo piacimento** (Cheat Engine ti consente di modificarlo rapidamente per NOPs):

![](<../../.gitbook/assets/image (595).png>)

Quindi, ora puoi modificarlo in modo che il codice non influisca sul tuo numero, o influisca sempre in modo positivo.
## Indirizzo di memoria casuale - Trovare il puntatore

Seguendo i passaggi precedenti, trova dove si trova il valore di tuo interesse. Quindi, utilizzando "**Scopri cosa scrive a questo indirizzo**", scopri quale indirizzo scrive questo valore e fai doppio clic su di esso per ottenere la visualizzazione dello smontaggio:

![](<../../.gitbook/assets/image (596).png>)

Successivamente, esegui una nuova scansione **cercando il valore esadecimale tra "\[]"** (il valore di $edx in questo caso):

![](<../../.gitbook/assets/image (597).png>)

(Se ne compaiono diversi, di solito è necessario scegliere quello con l'indirizzo più piccolo)\
Ora, abbiamo trovato il puntatore che modificherà il valore di nostro interesse.

Fai clic su "**Aggiungi indirizzo manualmente**":

![](<../../.gitbook/assets/image (598).png>)

Successivamente, seleziona la casella di controllo "Puntatore" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario, l'indirizzo trovato nell'immagine precedente era "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Osserva come il primo "Indirizzo" venga automaticamente popolato con l'indirizzo del puntatore che hai inserito)

Fai clic su OK e verrà creato un nuovo puntatore:

![](<../../.gitbook/assets/image (600).png>)

Ora, ogni volta che modifichi quel valore, stai **modificando il valore importante anche se l'indirizzo di memoria in cui si trova il valore è diverso.**

## Iniezione di codice

L'iniezione di codice è una tecnica in cui si inietta un pezzo di codice nel processo di destinazione e quindi si reindirizza l'esecuzione del codice per passare attraverso il proprio codice scritto (ad esempio, ottenendo punti invece di sottrarli).

Quindi, immagina di aver trovato l'indirizzo che sottrae 1 alla vita del tuo giocatore:

![](<../../.gitbook/assets/image (601).png>)

Fai clic su Mostra disassemblatore per ottenere il **codice scomposto**.\
Quindi, fai clic su **CTRL+a** per richiamare la finestra di Auto assemble e seleziona _**Template --> Iniezione di codice**_

![](<../../.gitbook/assets/image (602).png>)

Inserisci l'**indirizzo dell'istruzione che desideri modificare** (di solito viene compilato automaticamente):

![](<../../.gitbook/assets/image (603).png>)

Verrà generato un modello:

![](<../../.gitbook/assets/image (604).png>)

Quindi, inserisci il tuo nuovo codice di assembly nella sezione "**newmem**" e rimuovi il codice originale da "**originalcode**" se non vuoi che venga eseguito. In questo esempio, il codice iniettato aggiungerà 2 punti invece di sottrarre 1:

![](<../../.gitbook/assets/image (605).png>)

**Fai clic su Esegui e così via e il tuo codice dovrebbe essere iniettato nel programma, modificando il comportamento della funzionalità!**

# **Riferimenti**

* **Tutorial Cheat Engine, completalo per imparare come iniziare con Cheat Engine**



<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
