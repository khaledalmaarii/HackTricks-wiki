# Infrarossi

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

## Come funziona l'Infrarosso <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d'onda IR va da **0,7 a 1000 micron**. I telecomandi domestici utilizzano un segnale IR per la trasmissione dei dati e operano nella gamma di lunghezze d'onda di 0,75..1,4 micron. Un microcontrollore nel telecomando fa lampeggiare un LED infrarosso con una frequenza specifica, trasformando il segnale digitale in un segnale IR.

Per ricevere i segnali IR si utilizza un **fotorecettore**. Esso **converte la luce IR in impulsi di tensione**, che sono già **segnali digitali**. Di solito, c'è un **filtro di luce scura all'interno del ricevitore**, che lascia **passare solo la lunghezza d'onda desiderata** e taglia il rumore.

### Varietà di protocolli IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

I protocolli IR differiscono in 3 fattori:

* codifica dei bit
* struttura dei dati
* frequenza portante — spesso nella gamma 36..38 kHz

#### Modi di codifica dei bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codifica della distanza degli impulsi**

I bit sono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell'impulso stesso è costante.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codifica della larghezza degli impulsi**

I bit sono codificati mediante modulazione della larghezza dell'impulso. La larghezza dello spazio dopo l'esplosione dell'impulso è costante.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codifica di fase**

È anche conosciuta come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra l'esplosione dell'impulso e lo spazio. "Spazio a esplosione dell'impulso" denota logica "0", "esplosione dell'impulso a spazio" denota logica "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinazione dei precedenti e altre esotiche**

{% hint style="info" %}
Ci sono protocolli IR che **cercano di diventare universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Sfortunatamente, il più famoso **non significa il più comune**. Nel mio ambiente, ho incontrato solo due telecomandi NEC e nessun RC5.

I produttori amano utilizzare i propri protocolli IR unici, anche all'interno della stessa gamma di dispositivi (ad esempio, TV-box). Pertanto, i telecomandi di diverse aziende e a volte di diversi modelli della stessa azienda, non sono in grado di funzionare con altri dispositivi dello stesso tipo.
{% endhint %}

### Esplorare un segnale IR

Il modo più affidabile per vedere come appare il segnale IR del telecomando è utilizzare un oscilloscopio. Esso non demodula o inverte il segnale ricevuto, viene semplicemente visualizzato "così com'è". Questo è utile per testare e fare debug. Mostrerò il segnale atteso con l'esempio del protocollo IR NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Di solito, c'è un preambolo all'inizio di un pacchetto codificato. Questo consente al ricevitore di determinare il livello di guadagno e il background. Ci sono anche protocolli senza preambolo, ad esempio, Sharp.

Poi vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica dei bit sono determinati dal protocollo specifico.

Il **protocollo IR NEC** contiene un breve comando e un codice di ripetizione, che viene inviato mentre il pulsante è premuto. Sia il comando che il codice di ripetizione hanno lo stesso preambolo all'inizio.

Il **comando NEC**, oltre al preambolo, è composto da un byte di indirizzo e un byte di numero di comando, con cui il dispositivo comprende cosa deve essere eseguito. I byte di indirizzo e numero di comando sono duplicati con valori inversi, per controllare l'integrità della trasmissione. C'è un bit di stop aggiuntivo alla fine del comando.

Il **codice di ripetizione** ha un "1" dopo il preambolo, che è un bit di stop.

Per **logica "0" e "1"** NEC utilizza la Codifica della Distanza degli Impulsi: prima viene trasmessa un'esplosione di impulsi dopo la quale c'è una pausa, la cui lunghezza determina il valore del bit.

### Condizionatori d'aria

A differenza di altri telecomandi, **i condizionatori d'aria non trasmettono solo il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando un pulsante viene premuto per garantire che la **macchina del condizionatore e il telecomando siano sincronizzati**.\
Questo eviterà che una macchina impostata a 20ºC venga aumentata a 21ºC con un telecomando, e poi quando un altro telecomando, che ha ancora la temperatura a 20ºC, viene utilizzato per aumentare ulteriormente la temperatura, essa verrà "aumentata" a 21ºC (e non a 22ºC pensando che sia a 21ºC).

### Attacchi

Puoi attaccare l'Infrarosso con Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
