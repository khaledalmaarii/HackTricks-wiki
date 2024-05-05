# Radio

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)è un analizzatore di segnali digitali gratuito per GNU/Linux e macOS, progettato per estrarre informazioni da segnali radio sconosciuti. Supporta una varietà di dispositivi SDR tramite SoapySDR e consente la demodulazione regolabile di segnali FSK, PSK e ASK, la decodifica video analogico, l'analisi di segnali a raffica e l'ascolto di canali vocali analogici (tutto in tempo reale).

### Configurazione di base

Dopo l'installazione ci sono alcune cose che potresti considerare di configurare.\
Nelle impostazioni (il secondo pulsante della scheda) puoi selezionare il **dispositivo SDR** o **selezionare un file** da leggere e quale frequenza sintonizzare e il tasso di campionamento (raccomandato fino a 2,56Msps se il tuo PC lo supporta)\\

![](<../../.gitbook/assets/image (245).png>)

Nel comportamento della GUI è consigliabile abilitare alcune cose se il tuo PC lo supporta:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
Se ti rendi conto che il tuo PC non sta catturando le cose, prova a disabilitare OpenGL e abbassare il tasso di campionamento.
{% endhint %}

### Utilizzi

* Solo per **catturare un po' di tempo di un segnale e analizzarlo** mantieni premuto il pulsante "Premi per catturare" per tutto il tempo necessario.

![](<../../.gitbook/assets/image (960).png>)

* Il **Sintonizzatore** di SigDigger aiuta a **catturare segnali migliori** (ma può anche degradarli). Idealmente inizia con 0 e continua a **aumentare fino a** trovare che il **rumore** introdotto è **maggiore** dell'**miglioramento del segnale** di cui hai bisogno).

![](<../../.gitbook/assets/image (1099).png>)

### Sincronizzazione con il canale radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincronizzati con il canale che vuoi ascoltare, configura l'opzione "Anteprima audio in banda base", configura la larghezza di banda per ottenere tutte le informazioni inviate e quindi imposta il Sintonizzatore al livello prima che il rumore inizi davvero ad aumentare:

![](<../../.gitbook/assets/image (585).png>)

## Trucchi interessanti

* Quando un dispositivo invia raffiche di informazioni, di solito la **prima parte sarà un preambolo** quindi **non** devi **preoccuparti** se **non trovi informazioni** lì **o se ci sono degli errori**.
* Nei frame di informazioni di solito dovresti **trovare diversi frame ben allineati tra loro**:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Dopo aver recuperato i bit potresti aver bisogno di elaborarli in qualche modo**. Ad esempio, nella codifica Manchester un up+down sarà un 1 o 0 e un down+up sarà l'altro. Quindi coppie di 1 e 0 (up e down) saranno un vero 1 o un vero 0.
* Anche se un segnale utilizza la codifica Manchester (è impossibile trovare più di due 0 o 1 di fila), potresti **trovare diversi 1 o 0 insieme nel preambolo**!

### Scoprire il tipo di modulazione con IQ

Ci sono 3 modi per memorizzare informazioni nei segnali: Modulando l'**ampiezza**, la **frequenza** o la **fase**.\
Se stai controllando un segnale ci sono modi diversi per cercare di capire cosa viene utilizzato per memorizzare le informazioni (trova più modi qui sotto) ma un buono è controllare il grafico IQ.

![](<../../.gitbook/assets/image (788).png>)

* **Rilevare AM**: Se nel grafico IQ appaiono ad esempio **2 cerchi** (probabilmente uno in 0 e l'altro in un'ampiezza diversa), potrebbe significare che si tratta di un segnale AM. Questo perché nel grafico IQ la distanza tra lo 0 e il cerchio è l'ampiezza del segnale, quindi è facile visualizzare diverse ampiezze utilizzate.
* **Rilevare PM**: Come nell'immagine precedente, se trovi piccoli cerchi non correlati tra loro probabilmente significa che viene utilizzata una modulazione di fase. Questo perché nel grafico IQ, l'angolo tra il punto e lo 0,0 è la fase del segnale, quindi ciò significa che vengono utilizzate 4 fasi diverse.
* Nota che se le informazioni sono nascoste nel fatto che una fase viene cambiata e non nella fase stessa, non vedrai chiaramente fasi diverse differenziate.
* **Rilevare FM**: L'IQ non ha un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare FM, dovresti **vedere essenzialmente solo un cerchio** in questo grafico.\
Inoltre, una frequenza diversa è "rappresentata" dal grafico IQ da un **accelerazione della velocità attraverso il cerchio** (quindi in SysDigger selezionando il segnale il grafico IQ viene popolato, se trovi un'accelerazione o un cambiamento di direzione nel cerchio creato potrebbe significare che si tratta di FM):

## Esempio AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Scoprire AM

#### Controllare l'involucro

Controllando le informazioni AM con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)e guardando solo l'**involucro** puoi vedere chiaramente diversi livelli di ampiezza. Il segnale utilizzato sta inviando impulsi con informazioni in AM, ecco come appare un impulso:

![](<../../.gitbook/assets/image (590).png>)

E così appare parte del simbolo con la forma d'onda:

![](<../../.gitbook/assets/image (734).png>)

#### Controllare l'istogramma

Puoi **selezionare l'intero segnale** dove si trovano le informazioni, selezionare la modalità **Ampiezza** e **Selezione** e fare clic su **Istogramma**. Puoi osservare che sono presenti solo 2 livelli chiari

![](<../../.gitbook/assets/image (264).png>)

Ad esempio, se selezioni la Frequenza invece dell'Ampiezza in questo segnale AM trovi solo 1 frequenza (non c'è modo che le informazioni modulate in frequenza stiano usando solo 1 frequenza).

![](<../../.gitbook/assets/image (732).png>)

Se trovi molte frequenze potenzialmente questo non sarà un FM, probabilmente la frequenza del segnale è stata solo modificata a causa del canale.
#### Con IQ

In questo esempio puoi vedere come ci sia un **grande cerchio** ma anche **molteplici punti al centro.**

![](<../../.gitbook/assets/image (222).png>)

### Ottenere il Tasso di Simbolo

#### Con un simbolo

Seleziona il simbolo più piccolo che puoi trovare (così sei sicuro che sia solo 1) e controlla la "Frequenza di selezione". In questo caso sarebbe 1.013kHz (quindi 1kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Con un gruppo di simboli

Puoi anche indicare il numero di simboli che stai per selezionare e SigDigger calcolerà la frequenza di 1 simbolo (probabilmente più simboli selezionati sono migliori). In questo scenario ho selezionato 10 simboli e la "Frequenza di selezione" è 1.004 Khz:

![](<../../.gitbook/assets/image (1008).png>)

### Ottenere i Bit

Avendo scoperto che si tratta di un segnale **modulato in AM** e conoscendo il **tasso di simbolo** (e sapendo che in questo caso qualcosa in alto significa 1 e qualcosa in basso significa 0), è molto facile **ottenere i bit** codificati nel segnale. Quindi, seleziona il segnale con le informazioni e configura il campionamento e la decisione e premi campione (controlla che sia selezionata l'**Amplitude**, il tasso di simbolo scoperto è configurato e il **Gadner clock recovery** è selezionato):

![](<../../.gitbook/assets/image (965).png>)

* **Sincronizza gli intervalli di selezione** significa che se hai precedentemente selezionato degli intervalli per trovare il tasso di simbolo, quel tasso di simbolo verrà utilizzato.
* **Manuale** significa che il tasso di simbolo indicato verrà utilizzato
* In **Selezione intervallo fisso** indichi il numero di intervalli che devono essere selezionati e calcola il tasso di simbolo da esso
* **Gadner clock recovery** è di solito la migliore opzione, ma è comunque necessario indicare un tasso di simbolo approssimativo.

Premendo campione appare questo:

![](<../../.gitbook/assets/image (644).png>)

Ora, per far capire a SigDigger **dove si trova il range** del livello che porta le informazioni, devi fare clic sul **livello inferiore** e mantenere premuto fino al livello più grande:

![](<../../.gitbook/assets/image (439).png>)

Se ci fossero ad esempio **4 diversi livelli di ampiezza**, avresti dovuto configurare i **Bit per simbolo a 2** e selezionare dal più piccolo al più grande.

Infine, **aumentando** lo **Zoom** e **cambiando la dimensione della riga** puoi vedere i bit (e puoi selezionarli tutti e copiarli per ottenere tutti i bit):

![](<../../.gitbook/assets/image (276).png>)

Se il segnale ha più di 1 bit per simbolo (ad esempio 2), SigDigger **non ha modo di sapere quale simbolo è** 00, 01, 10, 11, quindi utilizzerà diverse **scale di grigi** per rappresentare ciascuno (e se copi i bit utilizzerà **numeri da 0 a 3**, dovrai trattarli).

Inoltre, utilizza **codifiche** come **Manchester**, e **su+giù** possono essere **1 o 0** e un giù+su può essere un 1 o 0. In quei casi devi **trattare i su ottenuti (1) e i giù (0)** per sostituire le coppie di 01 o 10 come 0 o 1.

## Esempio FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Scoprire FM

#### Controllare le frequenze e la forma d'onda

Esempio di segnale che invia informazioni modulate in FM:

![](<../../.gitbook/assets/image (725).png>)

Nell'immagine precedente puoi osservare abbastanza chiaramente che vengono utilizzate **2 frequenze** ma se **osservi** la **forma d'onda** potresti **non essere in grado di identificare correttamente le 2 diverse frequenze**:

![](<../../.gitbook/assets/image (717).png>)

Questo perché catturo il segnale in entrambe le frequenze, quindi una è approssimativamente l'altra in negativo:

![](<../../.gitbook/assets/image (942).png>)

Se la frequenza sincronizzata è **più vicina a una frequenza che all'altra** puoi vedere facilmente le 2 diverse frequenze:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Controllare l'istogramma

Controllando l'istogramma di frequenza del segnale con informazioni puoi vedere facilmente 2 segnali diversi:

![](<../../.gitbook/assets/image (871).png>)

In questo caso, se controlli l'**istogramma dell'ampiezza** troverai **solo un'ampiezza**, quindi **non può essere AM** (se trovi molte ampiezze potrebbe essere perché il segnale ha perso potenza lungo il canale):

![](<../../.gitbook/assets/image (817).png>)

E questo sarebbe l'istogramma di fase (che rende molto chiaro che il segnale non è modulato in fase):

![](<../../.gitbook/assets/image (996).png>)

#### Con IQ

IQ non ha un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare FM, dovresti **vedere essenzialmente solo un cerchio** in questo grafico.\
Inoltre, una frequenza diversa è "rappresentata" dal grafico IQ con un **accelerazione della velocità attraverso il cerchio** (quindi in SysDigger selezionando il segnale il grafico IQ viene popolato, se trovi un'accelerazione o un cambio di direzione nel cerchio creato potrebbe significare che si tratta di FM):

![](<../../.gitbook/assets/image (81).png>)

### Ottenere il Tasso di Simbolo

Puoi utilizzare la **stessa tecnica usata nell'esempio AM** per ottenere il tasso di simbolo una volta trovate le frequenze che trasportano i simboli.

### Ottenere i Bit

Puoi utilizzare la **stessa tecnica usata nell'esempio AM** per ottenere i bit una volta che hai **trovato che il segnale è modulato in frequenza** e il **tasso di simbolo**.
