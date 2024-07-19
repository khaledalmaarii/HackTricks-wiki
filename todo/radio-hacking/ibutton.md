# iButton

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

## Intro

iButton è un nome generico per una chiave di identificazione elettronica racchiusa in un **contenitore metallico a forma di moneta**. È anche chiamata **Dallas Touch** Memory o memoria a contatto. Anche se spesso viene erroneamente chiamata chiave “magnetica”, non c'è **nulla di magnetico** in essa. Infatti, un **microchip** a tutti gli effetti che opera su un protocollo digitale è nascosto all'interno.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Cos'è l'iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Di solito, l'iButton implica la forma fisica della chiave e del lettore - una moneta rotonda con due contatti. Per il telaio che la circonda, ci sono molte variazioni, dal supporto in plastica più comune con un foro a anelli, pendenti, ecc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando la chiave raggiunge il lettore, i **contatti si toccano** e la chiave viene alimentata per **trasmettere** il suo ID. A volte la chiave **non viene letta** immediatamente perché il **PSD di contatto di un citofono è più grande** di quanto dovrebbe essere. Quindi i contorni esterni della chiave e del lettore non possono toccarsi. Se è questo il caso, dovrai premere la chiave su una delle pareti del lettore.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocollo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Le chiavi Dallas scambiano dati utilizzando il protocollo 1-wire. Con solo un contatto per il trasferimento dei dati (!!) in entrambe le direzioni, dal master allo slave e viceversa. Il protocollo 1-wire funziona secondo il modello Master-Slave. In questa topologia, il Master inizia sempre la comunicazione e lo Slave segue le sue istruzioni.

Quando la chiave (Slave) contatta il citofono (Master), il chip all'interno della chiave si accende, alimentato dal citofono, e la chiave viene inizializzata. Successivamente, il citofono richiede l'ID della chiave. Ora esamineremo questo processo in modo più dettagliato.

Flipper può funzionare sia in modalità Master che Slave. In modalità lettura della chiave, Flipper agisce come un lettore, cioè funziona come un Master. E in modalità emulazione della chiave, il flipper finge di essere una chiave, è in modalità Slave.

### Chiavi Dallas, Cyfral e Metakom

Per informazioni su come funzionano queste chiavi, controlla la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacchi

Gli iButton possono essere attaccati con Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
