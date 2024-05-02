# FZ - 125kHz RFID

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository github di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduzione

Per maggiori informazioni su come funzionano i tag a 125kHz, controlla:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Azioni

Per ulteriori informazioni su questi tipi di tag [**leggi questa introduzione**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lettura

Tenta di **leggere** le informazioni della scheda. Poi può **emularle**.

{% hint style="warning" %}
Nota che alcuni citofoni cercano di proteggersi dalla duplicazione delle chiavi inviando un comando di scrittura prima della lettura. Se la scrittura ha successo, quella scheda viene considerata falsa. Quando Flipper emula l'RFID non c'è modo per il lettore di distinguerlo da quello originale, quindi non si verificano tali problemi.
{% endhint %}

### Aggiungi Manualmente

Puoi creare **schede false in Flipper Zero indicando i dati** manualmente e poi emularle.

#### ID sulle schede

A volte, quando ottieni una scheda, troverai l'ID (o parte) scritto nella scheda visibile.

* **EM Marin**

Ad esempio in questa scheda EM-Marin nella scheda fisica è possibile **leggere gli ultimi 3 byte su 5 in chiaro**.\
Gli altri 2 possono essere forzati se non puoi leggerli dalla scheda.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

* **HID**

Lo stesso accade in questa scheda HID dove solo 2 su 3 byte possono essere trovati stampati nella scheda

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Emula/Scrivi

Dopo aver **copiato** una scheda o **inserito** manualmente l'ID è possibile **emularla** con Flipper Zero o **scriverla** in una scheda reale.

## Riferimenti

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai repository github di [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
