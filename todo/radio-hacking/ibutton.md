# iButton

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Introduzione

iButton è un nome generico per una chiave di identificazione elettronica confezionata in un **contenitore metallico a forma di moneta**. È anche chiamata **Dallas Touch** Memory o memoria di contatto. Anche se spesso viene erroneamente definita come una chiave "magnetica", in realtà al suo interno **non c'è nulla di magnetico**. Infatti, al suo interno è nascosto un **microchip** completo che opera su un protocollo digitale.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Cos'è iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Di solito, iButton implica la forma fisica della chiave e del lettore - una moneta rotonda con due contatti. Per la cornice che lo circonda, ci sono molte variazioni dal comune supporto di plastica con un foro a anelli, ciondoli, ecc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando la chiave raggiunge il lettore, i **contatti si toccano** e la chiave viene alimentata per **trasmettere** il suo ID. A volte la chiave **non viene letta** immediatamente perché il **PSD di contatto di un citofono è più grande** di quanto dovrebbe essere. Quindi i contorni esterni della chiave e del lettore non possono toccarsi. In tal caso, dovrai premere la chiave su uno dei lati del lettore.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocollo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Le chiavi Dallas scambiano dati utilizzando il protocollo 1-wire. Con un solo contatto per il trasferimento dati (!!) in entrambe le direzioni, dal master allo slave e viceversa. Il protocollo 1-wire funziona secondo il modello Master-Slave. In questa topologia, il Master inizia sempre la comunicazione e lo Slave segue le sue istruzioni.

Quando la chiave (Slave) entra in contatto con il citofono (Master), il chip all'interno della chiave si accende, alimentato dal citofono, e la chiave viene inizializzata. Successivamente il citofono richiede l'ID della chiave. Successivamente, esamineremo questo processo in modo più dettagliato.

Flipper può funzionare sia in modalità Master che Slave. In modalità di lettura chiave, Flipper agisce come un lettore, cioè funziona come Master. E in modalità di emulazione chiave, il flipper finge di essere una chiave, è in modalità Slave.

### Chiavi Dallas, Cyfral & Metakom

Per informazioni su come funzionano queste chiavi, controlla la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacchi

Gli iButton possono essere attaccati con Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
