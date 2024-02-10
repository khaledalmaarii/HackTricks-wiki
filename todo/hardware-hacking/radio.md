# Radio

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub.**

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)è un analizzatore di segnali digitali gratuito per GNU/Linux e macOS, progettato per estrarre informazioni da segnali radio sconosciuti. Supporta una varietà di dispositivi SDR attraverso SoapySDR e consente la demodulazione regolabile di segnali FSK, PSK e ASK, la decodifica di video analogici, l'analisi di segnali intermittenti e l'ascolto di canali vocali analogici (tutto in tempo reale).

### Configurazione di base

Dopo l'installazione ci sono alcune cose che potresti considerare di configurare.\
Nelle impostazioni (il secondo pulsante della scheda) puoi selezionare il **dispositivo SDR** o **selezionare un file** da leggere e quale frequenza sintonizzare e il tasso di campionamento (consigliato fino a 2,56Msps se il tuo PC lo supporta)\\

![](<../../.gitbook/assets/image (655) (1).png>)

Nel comportamento dell'interfaccia grafica è consigliabile abilitare alcune cose se il tuo PC lo supporta:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Se ti rendi conto che il tuo PC non sta catturando cose, prova a disabilitare OpenGL e abbassare il tasso di campionamento.
{% endhint %}

### Utilizzi

* Solo per **catturare un po' di tempo di un segnale e analizzarlo**, mantieni premuto il pulsante "Push to capture" per tutto il tempo necessario.

![](<../../.gitbook/assets/image (631).png>)

* Il **Tuner** di SigDigger aiuta a **catturare segnali migliori** (ma può anche degradarli). Idealmente inizia con 0 e continua a **aumentarlo finché** trovi che il **rumore** introdotto è **maggiore** del **miglioramento del segnale** di cui hai bisogno).

![](<../../.gitbook/assets/image (658).png>)

### Sincronizzazione con il canale radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincronizzati con il canale che vuoi ascoltare, configura l'opzione "Baseband audio preview", configura la larghezza di banda per ottenere tutte le informazioni inviate e quindi imposta il Tuner al livello prima che il rumore inizi davvero ad aumentare:

![](<../../.gitbook/assets/image (389).png>)

## Trucchi interessanti

* Quando un dispositivo invia raffiche di informazioni, di solito la **prima parte sarà un preambolo** quindi **non** devi **preoccuparti** se **non trovi informazioni** lì **o se ci sono degli errori**.
* Nei frame di informazioni di solito dovresti **trovare diversi frame ben allineati tra loro**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Dopo aver recuperato i bit potresti aver bisogno di elaborarli in qualche modo**. Ad esempio, nella codifica Manchester un up+down sarà un 1 o 0 e un down+up sarà l'altro. Quindi coppie di 1 e 0 (up e down) saranno un vero 1 o un vero 0.
* Anche se un segnale utilizza la codifica Manchester (è impossibile trovare più di due 0 o 1 di seguito), potresti **trovare diversi 1 o 0 insieme nel preambolo**!

### Scoprire il tipo di modulazione con IQ

Ci sono 3 modi per memorizzare le informazioni nei segnali: Modulando l'**ampiezza**, la **frequenza** o la **fase**.\
Se stai controllando un segnale ci sono diversi modi per cercare di capire cosa viene utilizzato per memorizzare le informazioni (trova altri modi di seguito), ma uno buono è controllare il grafico IQ.

![](<../../.gitbook/assets/image (630).png>)

* **Rilevare l'AM**: Se nel grafico IQ appaiono ad esempio **2 cerchi** (probabilmente uno in 0 e l'altro in un'ampiezza diversa), potrebbe significare che si tratta di un segnale AM. Questo perché nel grafico IQ la distanza tra lo 0 e il cerchio è l'ampiezza del segnale, quindi è facile visualizzare diverse ampiezze utilizzate.
* **Rilevare il PM**: Come nell'immagine precedente, se trovi piccoli cerchi non correlati tra loro probabilmente significa che viene utilizzata una modulazione di fase. Questo perché nel grafico IQ, l'angolo tra il punto e lo 0,0 è la fase del segnale, quindi ciò significa che vengono utilizzate 4 fasi diverse.
* Nota che se le informazioni sono nascoste nel fatto che una fase viene cambiata e non nella fase stessa, non vedrai chiaramente fasi diverse differenziate.
* **Rilevare l'FM**: IQ non ha un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare l'FM, dovresti **vedere solo fondamentalmente un cerchio** in questo grafico.\
Inoltre, una frequenza diversa è "rappresentata" dal grafico IQ da un'**accelerazione di velocità lungo il cerchio** (quindi in SysDigger selezionando il segnale il grafico IQ viene popolato, se trovi un'accelerazione o un cambio di direzione nel cerchio creato potrebbe significare che si tratta di FM):

## Esempio di AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Scoprire l'AM

#### Controllare l'involucro

Controllando le informazioni AM con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)e guardando solo l'**involucro** puoi vedere diversi livelli di ampiezza chiari. Il segnale utilizzato invia impulsi con informazioni in AM, ecco come appare un impulso:

![](<../../.gitbook/assets/image (636).png>)

Ecco come appare parte del simbolo con la forma d'onda:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Controllare l'istogramma

Puoi **selezionare l'intero segnale** dove si trova l'informazione, selezionare la modalità **Ampiezza** e **Selezione** e fare clic su **Istogramma**. Puoi osservare che vengono trovati solo 2 livelli chiari

![](<../../.gitbook/assets/image (647) (1) (1).png>)

Ad esempio, se selezioni la Frequenza invece dell'Ampiezza in questo segnale AM trovi solo 1 frequenza (non è possibile che l'informazione modulata in frequenza utilizzi solo 1 frequenza).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

Se trovi molte frequenze, probabilmente questo non sarà un FM, probabilmente la frequenza del segnale è stata modificata a causa del canale.
#### Con IQ

In questo esempio puoi vedere come ci sia un **grande cerchio** ma anche **molteplici punti al centro**.

![](<../../.gitbook/assets/image (640).png>)

### Ottenere il Symbol Rate

#### Con un solo simbolo

Seleziona il simbolo più piccolo che puoi trovare (in modo da essere sicuro che sia solo 1) e controlla la "Frequenza di selezione". In questo caso sarebbe 1,013 kHz (quindi 1 kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Con un gruppo di simboli

Puoi anche indicare il numero di simboli che stai per selezionare e SigDigger calcolerà la frequenza di 1 simbolo (più simboli selezionati probabilmente è meglio). In questo scenario ho selezionato 10 simboli e la "Frequenza di selezione" è di 1,004 kHz:

![](<../../.gitbook/assets/image (635).png>)

### Ottenere i Bit

Avendo scoperto che si tratta di un segnale **modulato in AM** e conoscendo il **symbol rate** (e sapendo che in questo caso qualcosa in alto significa 1 e qualcosa in basso significa 0), è molto facile **ottenere i bit** codificati nel segnale. Quindi, seleziona il segnale con le informazioni, configura il campionamento e la decisione e premi "sample" (controlla che sia selezionata l'**Amplitude**, che sia configurato il **Symbol rate** scoperto e che sia selezionato il **Gardner clock recovery**):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals** significa che se hai precedentemente selezionato degli intervalli per trovare il symbol rate, quel symbol rate verrà utilizzato.
* **Manual** significa che verrà utilizzato il symbol rate indicato.
* In **Fixed interval selection** indichi il numero di intervalli che devono essere selezionati e calcola il symbol rate da essi.
* **Gardner clock recovery** è di solito la migliore opzione, ma è comunque necessario indicare un symbol rate approssimativo.

Premendo "sample" appare questo:

![](<../../.gitbook/assets/image (659).png>)

Ora, per far capire a SigDigger **dove si trova l'intervallo** che trasporta le informazioni, devi fare clic sul **livello inferiore** e mantenere premuto fino al livello più grande:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Se ci fossero ad esempio **4 diversi livelli di ampiezza**, avresti dovuto configurare i **Bits per symbol a 2** e selezionare dal più piccolo al più grande.

Infine, **aumentando** lo **Zoom** e **cambiando la dimensione della riga**, puoi vedere i bit (e puoi selezionarli tutti e copiarli per ottenere tutti i bit):

![](<../../.gitbook/assets/image (649) (1).png>)

Se il segnale ha più di 1 bit per simbolo (ad esempio 2), SigDigger **non può sapere quale simbolo è** 00, 01, 10, 11, quindi utilizzerà diverse **scale di grigi** per rappresentare ciascuno (e se copi i bit utilizzerà **numeri da 0 a 3**, dovrai trattarli).

Inoltre, utilizza **codifiche** come **Manchester**, e **up+down** può essere **1 o 0** e down+up può essere 1 o 0. In questi casi devi **trattare gli up ottenuti (1) e i down (0)** per sostituire le coppie di 01 o 10 come 0 o 1.

## Esempio FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Scoprire FM

#### Verifica delle frequenze e della forma d'onda

Esempio di segnale che invia informazioni modulate in FM:

![](<../../.gitbook/assets/image (661) (1).png>)

Nell'immagine precedente puoi osservare che vengono utilizzate **2 frequenze diverse**, ma se **osservi** la **forma d'onda** potresti **non essere in grado di identificare correttamente le 2 diverse frequenze**:

![](<../../.gitbook/assets/image (653).png>)

Questo perché ho catturato il segnale in entrambe le frequenze, quindi una è approssimativamente l'opposta dell'altra:

![](<../../.gitbook/assets/image (656).png>)

Se la frequenza sincronizzata è **più vicina a una frequenza che all'altra**, puoi facilmente vedere le 2 diverse frequenze:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Verifica dell'istogramma

Verificando l'istogramma di frequenza del segnale con informazioni, puoi facilmente vedere 2 segnali diversi:

![](<../../.gitbook/assets/image (657).png>)

In questo caso, se controlli l'**istogramma dell'ampiezza**, troverai **solo un'ampiezza**, quindi **non può essere AM** (se trovi molte ampiezze potrebbe essere perché il segnale ha perso potenza lungo il canale):

![](<../../.gitbook/assets/image (646).png>)

E questo sarebbe l'istogramma di fase (che rende molto chiaro che il segnale non è modulato in fase):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Con IQ

IQ non ha un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare FM, dovresti **vedere solo un cerchio** in questo grafico.\
Inoltre, una frequenza diversa è "rappresentata" dal grafico IQ con un **accelerazione di velocità lungo il cerchio** (quindi in SysDigger selezionando il segnale il grafico IQ viene popolato, se trovi un'accelerazione o un cambio di direzione nel cerchio creato potrebbe significare che si tratta di FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Ottenere il Symbol Rate

Puoi utilizzare la **stessa tecnica utilizzata nell'esempio AM** per ottenere il symbol rate una volta che hai trovato le frequenze che trasportano i simboli.

### Ottenere i Bit

Puoi utilizzare la **stessa tecnica utilizzata nell'esempio AM** per ottenere i bit una volta che hai **trovato che il segnale è modulato in frequenza** e il **symbol rate**.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
