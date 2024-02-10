# FZ - 125kHz RFID

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduzione

Per ulteriori informazioni su come funzionano i tag a 125kHz, consulta:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Azioni

Per ulteriori informazioni su questi tipi di tag, [**leggi questa introduzione**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lettura

Tenta di **leggere** le informazioni della carta. Successivamente può **emularle**.

{% hint style="warning" %}
Nota che alcuni citofoni cercano di proteggersi dalla duplicazione delle chiavi inviando un comando di scrittura prima della lettura. Se la scrittura ha successo, quel tag viene considerato falso. Quando Flipper emula l'RFID, non c'è modo per il lettore di distinguerlo da quello originale, quindi non si verificano tali problemi.
{% endhint %}

### Aggiungi manualmente

Puoi creare **schede false in Flipper Zero indicando manualmente i dati** e poi emularle.

#### ID sulle schede

A volte, quando ottieni una scheda, troverai l'ID (o parte) scritto sulla scheda visibile.

* **EM Marin**

Ad esempio, in questa scheda EM-Marin sulla scheda fisica è possibile **leggere gli ultimi 3 byte su 5 in chiaro**.\
Gli altri 2 possono essere forzati se non puoi leggerli dalla scheda.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Lo stesso accade in questa scheda HID, dove solo 2 byte su 3 possono essere trovati stampati sulla scheda.

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Emula/Scrivi

Dopo aver **copiato** una scheda o aver **inserito** manualmente l'ID, è possibile **emularla** con Flipper Zero o **scrivere** i dati su una scheda reale.

## Riferimenti

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
