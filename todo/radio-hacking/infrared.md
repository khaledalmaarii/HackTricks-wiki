# Infrarosso

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Come Funziona l'Infrarosso <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d'onda dell'infrarosso va da **0,7 a 1000 micron**. I telecomandi domestici utilizzano un segnale IR per la trasmissione dei dati e operano nell'intervallo di lunghezza d'onda di 0,75..1,4 micron. Un microcontrollore nel telecomando fa lampeggiare un LED infrarosso con una frequenza specifica, trasformando il segnale digitale in un segnale IR.

Per ricevere segnali IR viene utilizzato un **fotorecevitore**. Esso **converte la luce IR in impulsi di tensione**, che sono già **segnali digitali**. Di solito, c'è un **filtro di luce scura all'interno del ricevitore**, che lascia passare **solo la lunghezza d'onda desiderata** e taglia il rumore.

### Varie Protocolli IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

I protocolli IR differiscono in 3 fattori:

* codifica bit
* struttura dei dati
* frequenza del carrier — spesso nell'intervallo 36..38 kHz

#### Modi di codifica bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codifica Distanza Impulsi**

I bit sono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell'impulso stesso è costante.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codifica Larghezza Impulsi**

I bit sono codificati modulando la larghezza dell'impulso. La larghezza dello spazio dopo il burst dell'impulso è costante.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codifica di Fase**

È anche conosciuta come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra il burst dell'impulso e lo spazio. "Spazio al burst dell'impulso" indica logica "0", "burst dell'impulso allo spazio" indica logica "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinazione dei precedenti e altri esotici**

{% hint style="info" %}
Ci sono protocolli IR che stanno **cercando di diventare universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Purtroppo, i più famosi **non significano necessariamente i più comuni**. Nel mio ambiente, ho incontrato solo due telecomandi NEC e nessuno RC5.

I produttori amano utilizzare i propri protocolli IR unici, anche all'interno dello stesso range di dispositivi (ad esempio, TV-box). Pertanto, i telecomandi di diverse aziende e talvolta di diversi modelli della stessa azienda, non sono in grado di funzionare con altri dispositivi dello stesso tipo.
{% endhint %}

### Esplorare un Segnale IR

Il modo più affidabile per vedere come appare il segnale IR del telecomando è utilizzare un oscilloscopio. Esso non demodula o inverte il segnale ricevuto, lo visualizza semplicemente "così com'è". Questo è utile per il testing e il debug. Mostrerò il segnale atteso sull'esempio del protocollo IR NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Di solito, c'è un preambolo all'inizio di un pacchetto codificato. Questo permette al ricevitore di determinare il livello di guadagno e di sfondo. Ci sono anche protocolli senza preambolo, ad esempio, Sharp.

Poi vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica bit sono determinati dal protocollo specifico.

Il protocollo IR **NEC** contiene un comando breve e un codice di ripetizione, che viene inviato mentre il pulsante è premuto. Sia il comando che il codice di ripetizione hanno lo stesso preambolo all'inizio.

Il **comando NEC**, oltre al preambolo, è composto da un byte di indirizzo e un byte di numero di comando, con cui il dispositivo capisce cosa deve essere eseguito. I byte di indirizzo e di numero di comando sono duplicati con valori inversi, per controllare l'integrità della trasmissione. Alla fine del comando c'è un bit di stop aggiuntivo.

Il **codice di ripetizione** ha un "1" dopo il preambolo, che è un bit di stop.

Per la logica "0" e "1" NEC utilizza la Codifica Distanza Impulsi: prima viene trasmesso un burst di impulsi dopo il quale c'è una pausa, la cui lunghezza imposta il valore del bit.

### Condizionatori d'Aria

A differenza degli altri telecomandi, **i condizionatori d'aria non trasmettono solo il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando un pulsante viene premuto per assicurare che la **macchina condizionata e il telecomando siano sincronizzati**.\
Questo eviterà che una macchina impostata a 20ºC venga aumentata a 21ºC con un telecomando e poi, quando un altro telecomando, che ha ancora la temperatura a 20ºC, viene utilizzato per aumentare ulteriormente la temperatura, essa verrà "aumentata" a 21ºC (e non a 22ºC pensando di essere a 21ºC).

### Attacchi

È possibile attaccare l'Infrarosso con Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
