# Infrarossi

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Come funzionano gli infrarossi <a href="#come-funziona-la-porta-infrarossi" id="come-funziona-la-porta-infrarossi"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d'onda degli infrarossi va da **0,7 a 1000 micron**. I telecomandi domestici utilizzano un segnale infrarosso per la trasmissione dei dati e operano nella gamma di lunghezze d'onda compresa tra 0,75 e 1,4 micron. Un microcontrollore nel telecomando fa lampeggiare un LED infrarosso con una frequenza specifica, trasformando il segnale digitale in un segnale infrarosso.

Per ricevere segnali infrarossi viene utilizzato un **fotorecettore**. Esso **converte la luce infrarossa in impulsi di tensione**, che sono già **segnali digitali**. Di solito, all'interno del ricevitore è presente un **filtro di luce scura**, che lascia passare solo la lunghezza d'onda desiderata e taglia il rumore.

### Varie tipologie di protocolli infrarossi <a href="#varie-tipologie-di-protocolli-infrarossi" id="varie-tipologie-di-protocolli-infrarossi"></a>

I protocolli infrarossi differiscono in 3 fattori:

* codifica dei bit
* struttura dei dati
* frequenza del carrier - spesso compresa tra 36 e 38 kHz

#### Modalità di codifica dei bit <a href="#modalità-di-codifica-dei-bit" id="modalità-di-codifica-dei-bit"></a>

**1. Codifica a distanza di impulsi**

I bit vengono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell'impulso stesso è costante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Codifica a larghezza di impulso**

I bit vengono codificati modulando la larghezza dell'impulso. La larghezza dello spazio dopo la raffica di impulsi è costante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codifica di fase**

È anche conosciuta come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra la raffica di impulsi e lo spazio. "Spazio a raffica di impulsi" indica la logica "0", "raffica di impulsi a spazio" indica la logica "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinazione delle precedenti e altre esotiche**

{% hint style="info" %}
Ci sono protocolli infrarossi che stanno cercando di diventare **universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Purtroppo, i più famosi **non significano i più comuni**. Nel mio ambiente, ho incontrato solo due telecomandi NEC e nessuno di tipo RC5.

I produttori amano utilizzare i loro protocolli infrarossi unici, anche all'interno della stessa gamma di dispositivi (ad esempio, TV-box). Pertanto, i telecomandi di diverse aziende e talvolta di diversi modelli della stessa azienda, non sono in grado di funzionare con altri dispositivi dello stesso tipo.
{% endhint %}

### Esplorazione di un segnale infrarosso

Il modo più affidabile per vedere come appare il segnale infrarosso del telecomando è utilizzare un oscilloscopio. Esso non demodula o inverte il segnale ricevuto, ma lo visualizza "così com'è". Questo è utile per il test e il debug. Mostrerò il segnale atteso sull'esempio del protocollo infrarosso NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Di solito, all'inizio di un pacchetto codificato c'è un preambolo. Questo permette al ricevitore di determinare il livello di guadagno e il background. Ci sono anche protocolli senza preambolo, ad esempio Sharp.

Successivamente vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica dei bit sono determinati dal protocollo specifico.

Il protocollo infrarosso **NEC** contiene un comando breve e un codice di ripetizione, che viene inviato mentre il pulsante viene premuto. Sia il comando che il codice di ripetizione hanno lo stesso preambolo all'inizio.

Il **comando NEC**, oltre al preambolo, è composto da un byte di indirizzo e un byte di numero di comando, tramite i quali il dispositivo capisce cosa deve essere eseguito. I byte di indirizzo e numero di comando sono duplicati con valori inversi, per verificare l'integrità della trasmissione. Alla fine del comando c'è un bit di stop aggiuntivo.

Il **codice di ripetizione** ha un "1" dopo il preambolo, che è un bit di stop.

Per la logica "0" e "1" NEC utilizza la codifica a distanza di impulsi: prima viene trasmessa una raffica di impulsi, dopo la quale c'è una pausa, la cui lunghezza determina il valore del bit.

### Condizionatori d'aria

A differenza degli altri telecomandi, **i condizionatori d'aria non trasmettono solo il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando viene premuto un pulsante per assicurarsi che la **macchina del condizionatore d'aria e il telecomando siano sincronizzati**.\
Ciò evita che una macchina impostata a 20ºC venga aumentata a 21ºC con un telecomando e poi, quando viene utilizzato un altro telecomando, che ha ancora la temperatura impostata a 20ºC, venga "aumentata" a 21ºC (e non a 22ºC pensando che sia a 21ºC).

### Attacchi

È possibile attaccare gli infrarossi con Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la
