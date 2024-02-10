# iButton

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Introduzione

iButton è un nome generico per una chiave di identificazione elettronica confezionata in un **contenitore metallico a forma di moneta**. Viene anche chiamata **Dallas Touch** Memory o memoria di contatto. Nonostante venga spesso erroneamente definita come una chiave "magnetica", in realtà non contiene nulla di magnetico. Infatti, al suo interno è nascosto un microchip completo che funziona con un protocollo digitale.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Cos'è iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Di solito, iButton si riferisce alla forma fisica della chiave e del lettore - una moneta rotonda con due contatti. Per la cornice che lo circonda, ci sono molte variazioni, dalla custodia di plastica più comune con un foro agli anelli, ai pendenti, ecc.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Quando la chiave raggiunge il lettore, i **contatti si toccano** e la chiave viene alimentata per **trasmettere** il suo ID. A volte la chiave **non viene letta** immediatamente perché il **PSD di contatto di un citofono è più grande** di quanto dovrebbe essere. Quindi i contorni esterni della chiave e del lettore non possono toccarsi. In tal caso, dovrai premere la chiave su una delle pareti del lettore.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **Protocollo 1-Wire** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Le chiavi Dallas scambiano dati utilizzando il protocollo 1-wire. Con un solo contatto per il trasferimento dei dati (!!) in entrambe le direzioni, dal master allo slave e viceversa. Il protocollo 1-wire funziona secondo il modello Master-Slave. In questa topologia, il Master inizia sempre la comunicazione e lo Slave segue le sue istruzioni.

Quando la chiave (Slave) entra in contatto con il citofono (Master), il chip all'interno della chiave si accende, alimentato dal citofono, e la chiave viene inizializzata. Successivamente, il citofono richiede l'ID della chiave. Ora vedremo questo processo in modo più dettagliato.

Flipper può funzionare sia in modalità Master che Slave. In modalità lettura chiave, Flipper funge da lettore, cioè funziona come Master. E in modalità emulazione chiave, Flipper si finge una chiave, quindi è in modalità Slave.

### Chiavi Dallas, Cyfral e Metakom

Per informazioni su come funzionano queste chiavi, consulta la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacchi

Le chiavi iButton possono essere attaccate con Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
