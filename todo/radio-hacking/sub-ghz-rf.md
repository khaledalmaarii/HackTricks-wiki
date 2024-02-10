# Sub-GHz RF

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Porte del garage

I telecomandi per le porte del garage di solito operano a frequenze comprese tra 300 e 190 MHz, con le frequenze più comuni di 300 MHz, 310 MHz, 315 MHz e 390 MHz. Questo intervallo di frequenza è comunemente utilizzato per i telecomandi delle porte del garage perché è meno affollato rispetto ad altre bande di frequenza ed è meno soggetto a interferenze da parte di altri dispositivi.

## Porte dell'auto

La maggior parte dei telecomandi per le chiavi delle auto opera a **315 MHz o 433 MHz**. Queste sono entrambe frequenze radio e vengono utilizzate in una varietà di applicazioni diverse. La differenza principale tra le due frequenze è che 433 MHz ha un raggio maggiore rispetto a 315 MHz. Ciò significa che 433 MHz è migliore per le applicazioni che richiedono un raggio maggiore, come l'apertura remota senza chiave.\
In Europa viene comunemente utilizzato il 433,92 MHz e negli Stati Uniti e in Giappone è il 315 MHz.

## **Attacco di forza bruta**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Se invece di inviare ogni codice 5 volte (inviato in questo modo per assicurarsi che il ricevitore lo riceva) lo invii solo una volta, il tempo si riduce a 6 minuti:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

e se **rimuovi il periodo di attesa di 2 ms** tra i segnali puoi **ridurre il tempo a 3 minuti**.

Inoltre, utilizzando la Sequenza di De Bruijn (un modo per ridurre il numero di bit necessari per inviare tutti i numeri binari potenziali per la forza bruta) questo **tempo si riduce a soli 8 secondi**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Un esempio di questo attacco è stato implementato in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Richiedere **un preambolo eviterà la sequenza di De Bruijn** e **i codici rotanti impediranno questo attacco** (supponendo che il codice sia sufficientemente lungo da non poter essere forzato).

## Attacco Sub-GHz

Per attaccare questi segnali con Flipper Zero controlla:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protezione dei codici rotanti

I telecomandi automatici per le porte del garage utilizzano di solito un telecomando wireless per aprire e chiudere la porta del garage. Il telecomando **invia un segnale a radiofrequenza (RF)** all'apriporta del garage, che attiva il motore per aprire o chiudere la porta.

È possibile che qualcuno utilizzi un dispositivo noto come code grabber per intercettare il segnale RF e registrarlo per un uso successivo. Questo è noto come un **attacco di ripetizione**. Per prevenire questo tipo di attacco, molti apriporta moderni utilizzano un metodo di crittografia più sicuro noto come sistema di **codice rotante**.

Il segnale RF viene trasmesso di solito utilizzando un codice rotante, il che significa che il codice cambia ad ogni utilizzo. Ciò rende **difficile** per qualcuno **intercettare** il segnale e **utilizzarlo** per ottenere **accesso non autorizzato** al garage.

In un sistema di codice rotante, il telecomando e l'apriporta del garage hanno un **algoritmo condiviso** che **genera un nuovo codice** ogni volta che il telecomando viene utilizzato. L'apriporta del garage risponderà solo al **codice corretto**, rendendo molto più difficile per qualcuno ottenere accesso non autorizzato al garage semplicemente catturando un codice.

### **Attacco Missing Link**

Fondamentalmente, si ascolta il pulsante e si **cattura il segnale mentre il telecomando è fuori portata** del dispositivo (ad esempio l'auto o il garage). Quindi ci si sposta verso il dispositivo e si **utilizza il codice catturato per aprirlo**.

### Attacco di interruzione del collegamento completo

Un attaccante potrebbe **interrompere il segnale vicino al veicolo o al ricevitore** in modo che il **ricevitore non possa effettivamente "sentire" il codice**, e una volta che ciò accade è possibile **catturare e riprodurre** semplicemente il codice quando si smette di interrompere.

La vittima a un certo punto userà le **chiavi per chiudere l'auto**, ma poi l'attacco avrà **registrato abbastanza codici di "chiusura porte"** che potrebbero essere rispediti per aprire la porta (potrebbe essere necessario un **cambio di frequenza** poiché ci sono auto che utilizzano gli stessi codici per aprire e chiudere ma ascoltano entrambi i comandi in frequenze diverse).

{% hint style="warning" %}
**L'interruzione funziona**, ma è evidente perché se la **persona che chiude l'auto semplicemente prova le porte** per assicurarsi che siano chiuse, noterà che l'auto non è bloccata. Inoltre, se fossero consapevoli di tali attacchi, potrebbero persino ascoltare il fatto che le porte non hanno emesso il suono di **blocco** o che le **luci** dell'auto non si sono accese quando hanno premuto il pulsante "blocca".
{% endhint %}

### **Attacco di cattura del codice (detto anche 'RollJam')**

Si tratta di una tecnica di interruzione più **furtiva**. L'attaccante interromperà il segnale, quindi quando la vittima cercherà di chiudere la porta, non funzionerà, ma l'attaccante **registrerà questo codice**. Quindi, la vittima **proverà a chiudere l'auto di nuovo** premendo il pulsante e l'auto **registrerà questo secondo codice**.\
Immediatamente dopo, l'**attaccante può inviare il primo codice** e l'**auto si bloccherà** (la vittima penserà che la seconda pressione l'abbia chiusa). Quindi, l'attaccante sarà in grado di **inviare il secondo codice rubato per aprire** l'auto (supponendo che un **codice di "chiusura auto" possa essere utilizzato anche per aprirla**). Potrebbe essere necessario un cambio di frequenza (poiché ci sono auto che utilizzano gli stessi codici per aprire e chiudere ma ascoltano entrambi i comandi in frequenze diverse).

L'attaccante può **interrompere il ricevitore dell'auto e non il suo ricevitore** perché se il ricevitore dell'auto sta ascoltando
### Attacco di interferenza all'allarme

Testando un sistema aftermarket a codice rotante installato su una macchina, **l'invio dello stesso codice due volte** immediatamente **attivava l'allarme** e l'immobilizzatore, offrendo un'opportunità unica di **denial of service**. Ironicamente, il modo per **disabilitare l'allarme** e l'immobilizzatore era **premere** il **telecomando**, fornendo all'attaccante la possibilità di **eseguire continuamente l'attacco DoS**. Oppure combinare questo attacco con il **precedente per ottenere più codici**, poiché la vittima vorrebbe interrompere l'attacco il prima possibile.

## Riferimenti

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
