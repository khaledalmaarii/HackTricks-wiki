# RF Sub-GHz

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Porte del Garage

I telecomandi per le porte del garage di solito operano a frequenze comprese tra 300 e 190 MHz, con le frequenze più comuni che sono 300 MHz, 310 MHz, 315 MHz e 390 MHz. Questo intervallo di frequenza è comunemente utilizzato per i telecomandi delle porte del garage perché è meno affollato rispetto ad altre bande di frequenza ed è meno probabile che subisca interferenze da altri dispositivi.

## Porte dell'Auto

La maggior parte dei telecomandi per le auto opera a **315 MHz o 433 MHz**. Queste sono entrambe frequenze radio e vengono utilizzate in una varietà di applicazioni diverse. La differenza principale tra le due frequenze è che 433 MHz ha un raggio maggiore rispetto a 315 MHz. Ciò significa che 433 MHz è migliore per le applicazioni che richiedono un raggio maggiore, come l'apertura remota senza chiave.\
In Europa viene comunemente utilizzato il 433,92 MHz e negli Stati Uniti e in Giappone il 315 MHz.

## **Attacco di Forza Bruta**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Se invece di inviare ogni codice 5 volte (inviato in questo modo per assicurarsi che il ricevitore lo riceva) lo si invia solo una volta, il tempo si riduce a 6 minuti:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

e se si **rimuove il periodo di attesa di 2 ms** tra i segnali si può **ridurre il tempo a 3 minuti**.

Inoltre, utilizzando la Sequenza De Bruijn (un modo per ridurre il numero di bit necessari per inviare tutti i numeri binari potenziali per la forza bruta) questo **tempo si riduce a soli 8 secondi**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Un esempio di questo attacco è stato implementato in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Richiedere **un preambolo eviterà la sequenza De Bruijn** di ottimizzazione e **i codici rolling impediranno questo attacco** (supponendo che il codice sia abbastanza lungo da non essere forzato).

## Attacco Sub-GHz

Per attaccare questi segnali con Flipper Zero controlla:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protezione dei Codici Rolling

I telecomandi automatici per le porte del garage di solito utilizzano un telecomando wireless per aprire e chiudere la porta del garage. Il telecomando **invia un segnale radio (RF)** all'apriporta del garage, che attiva il motore per aprire o chiudere la porta.

È possibile per qualcuno utilizzare un dispositivo noto come un code grabber per intercettare il segnale RF e registrarlo per un uso successivo. Questo è noto come un **attacco di ripetizione**. Per prevenire questo tipo di attacco, molti moderni apriporta per garage utilizzano un metodo di crittografia più sicuro noto come un sistema di **codice rolling**.

Il **segnale RF viene tipicamente trasmesso utilizzando un codice rolling**, il che significa che il codice cambia ad ogni utilizzo. Questo rende **difficile** per qualcuno **intercettare** il segnale e **utilizzarlo** per ottenere **accesso non autorizzato** al garage.

In un sistema di codice rolling, il telecomando e l'apriporta del garage hanno un **algoritmo condiviso** che **genera un nuovo codice** ogni volta che il telecomando viene utilizzato. L'apriporta del garage risponderà solo al **codice corretto**, rendendo molto più difficile per qualcuno ottenere accesso non autorizzato al garage semplicemente catturando un codice.

### **Attacco Missing Link**

Fondamentalmente, si ascolta il pulsante e **si cattura il segnale mentre il telecomando è fuori portata** del dispositivo (ad esempio l'auto o il garage). Si passa quindi al dispositivo e **si utilizza il codice catturato per aprirlo**.

### Attacco di Jamming Full Link

Un attaccante potrebbe **interferire con il segnale vicino al veicolo o al ricevitore** in modo che il **ricevitore non possa effettivamente 'sentire' il codice**, e una volta che ciò accade è possibile **catturare e ripetere** semplicemente il codice quando si smette di interferire.

La vittima a un certo punto userà le **chiavi per chiudere l'auto**, ma quindi l'attacco avrà **registrato abbastanza codici di "chiudi porta"** che idealmente potrebbero essere rispediti per aprire la porta (potrebbe essere necessario un **cambio di frequenza** poiché ci sono auto che utilizzano gli stessi codici per aprire e chiudere ma ascoltano entrambi i comandi in frequenze diverse).

{% hint style="warning" %}
**Il Jamming funziona**, ma è evidente se la **persona che chiude l'auto semplicemente controlla le porte** per assicurarsi che siano chiuse noterà che l'auto è sbloccata. Inoltre, se fosse consapevole di tali attacchi potrebbe anche ascoltare il fatto che le porte non hanno emesso il suono di chiusura o che le **luci dell'auto** non hanno lampeggiato quando ha premuto il pulsante di 'chiusura'.
{% endhint %}

### **Attacco di Cattura del Codice (detto 'RollJam')**

Si tratta di una tecnica di Jamming più **furtiva**. L'attaccante interferirà con il segnale, quindi quando la vittima cerca di chiudere la porta non funzionerà, ma l'attaccante **registrerà questo codice**. Quindi, la vittima **proverà a chiudere l'auto nuovamente** premendo il pulsante e l'auto **registrerà questo secondo codice**.\
Immediatamente dopo questo l'**attaccante può inviare il primo codice** e l'**auto si chiuderà** (la vittima penserà che la seconda pressione l'abbia chiusa). Quindi, l'attaccante sarà in grado di **inviare il secondo codice rubato per aprire** l'auto (supponendo che un **codice di "chiudi auto" possa essere utilizzato anche per aprirla**). Potrebbe essere necessario un cambio di frequenza (poiché ci sono auto che utilizzano gli stessi codici per aprire e chiudere ma ascoltano entrambi i comandi in frequenze diverse).

L'attaccante può **interferire con il ricevitore dell'auto e non con il suo ricevitore** perché se il ricevitore dell'auto sta ascoltando ad esempio una banda larga di 1 MHz, l'attaccante non **interferirà** con la frequenza esatta utilizzata dal telecomando ma **una vicina in quello spettro** mentre il **ricevitore dell'attaccante ascolterà in un intervallo più piccolo** dove può ascoltare il segnale del telecomando **senza il segnale di interferenza**.

{% hint style="warning" %}
Altre implementazioni viste nelle specifiche mostrano che il **codice rolling è una parte** del codice totale inviato. Ad esempio, il codice inviato è una **chiave a 24 bit** dove i primi **12 sono il codice rolling**, i **secondi 8 sono il comando** (come blocco o sblocco) e gli ultimi 4 sono il **checksum**. I veicoli che implementano questo tipo sono naturalmente suscettibili poiché l'attaccante deve semplicemente sostituire il segmento del codice rolling per poter **usare qualsiasi codice rolling su entrambe le frequenze**.
{% endhint %}

{% hint style="danger" %}
Nota che se la vittima invia un terzo codice mentre l'attaccante sta inviando il primo, il primo e il secondo codice saranno invalidati.
{% endhint %}
### Attacco di Jamming per l'attivazione dell'allarme

Testando un sistema di codice rolling di terze parti installato su un'auto, **inviare lo stesso codice due volte** immediatamente **attivava l'allarme** e l'immobilizzatore fornendo un'opportunità unica di **denial of service**. Ironicamente il modo per **disattivare l'allarme** e l'immobilizzatore era **premere** il **telecomando**, fornendo all'attaccante la capacità di **eseguire continuamente un attacco DoS**. Oppure mescolare questo attacco con il **precedente per ottenere più codici** poiché la vittima vorrebbe fermare l'attacco il prima possibile.

## Riferimenti

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
