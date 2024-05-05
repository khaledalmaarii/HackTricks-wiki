# FZ - NFC

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduzione <a href="#id-9wrzi" id="id-9wrzi"></a>

Per informazioni su RFID e NFC, controlla la seguente pagina:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Schede NFC supportate <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Oltre alle schede NFC, Flipper Zero supporta **altro tipo di schede ad alta frequenza** come diverse schede **Mifare** Classic e Ultralight e **NTAG**.
{% endhint %}

Nuovi tipi di schede NFC verranno aggiunti all'elenco delle schede supportate. Flipper Zero supporta i seguenti **tipi di schede NFC A** (ISO 14443A):

* ﻿**Carte bancarie (EMV)** — leggi solo UID, SAK e ATQA senza salvare.
* ﻿**Schede sconosciute** — leggi (UID, SAK, ATQA) ed emula un UID.

Per le **schede NFC di tipo B, tipo F e tipo V**, Flipper Zero è in grado di leggere un UID senza salvarlo.

### Schede NFC di tipo A <a href="#uvusf" id="uvusf"></a>

#### Carta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero può solo leggere un UID, SAK, ATQA e dati memorizzati sulle carte bancarie **senza salvare**.

Schermata di lettura della carta bancariaPer le carte bancarie, Flipper Zero può solo leggere i dati **senza salvarli ed emularli**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Schede sconosciute <a href="#id-37eo8" id="id-37eo8"></a>

Quando Flipper Zero è **incapace di determinare il tipo di scheda NFC**, allora solo un **UID, SAK e ATQA** possono essere **letti e salvati**.

Schermata di lettura della scheda sconosciutaPer le schede NFC sconosciute, Flipper Zero può emulare solo un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Schede NFC di tipo B, F e V <a href="#wyg51" id="wyg51"></a>

Per le **schede NFC di tipo B, F e V**, Flipper Zero può solo **leggere e visualizzare un UID** senza salvarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Azioni

Per una introduzione su NFC [**leggi questa pagina**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lettura

Flipper Zero può **leggere le schede NFC**, tuttavia, **non comprende tutti i protocolli** basati su ISO 14443. Tuttavia, poiché **UID è un attributo a basso livello**, potresti trovarti in una situazione in cui **l'UID è già stato letto, ma il protocollo di trasferimento dati ad alto livello è ancora sconosciuto**. Puoi leggere, emulare e inserire manualmente l'UID utilizzando Flipper per i lettori primitivi che utilizzano l'UID per l'autorizzazione.

#### Lettura dell'UID VS Lettura dei Dati Interni <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, la lettura dei tag a 13,56 MHz può essere divisa in due parti:

* **Lettura a basso livello** — legge solo l'UID, SAK e ATQA. Flipper cerca di indovinare il protocollo ad alto livello basandosi su questi dati letti dalla scheda. Non puoi essere al 100% certo di questo, poiché è solo un'ipotesi basata su determinati fattori.
* **Lettura ad alto livello** — legge i dati dalla memoria della scheda utilizzando un protocollo ad alto livlo specifico. Questo significherebbe leggere i dati su un Mifare Ultralight, leggere i settori da un Mifare Classic o leggere gli attributi della scheda da PayPass/Apple Pay.

### Lettura Specifica

Nel caso in cui Flipper Zero non sia in grado di trovare il tipo di scheda dai dati a basso livello, in `Azioni Extra` puoi selezionare `Leggi Tipo di Scheda Specifico` e **indicare manualmente** **il tipo di scheda che desideri leggere**.

#### Carte Bancarie EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oltre a leggere semplicemente l'UID, puoi estrarre molti altri dati da una carta bancaria. È possibile **ottenere il numero completo della carta** (i 16 cifre sul fronte della carta), la **data di validità** e in alcuni casi persino il **nome del proprietario** insieme a un elenco delle **transazioni più recenti**.\
Tuttavia, **non puoi leggere il CVV in questo modo** (i 3 cifre sul retro della carta). Inoltre, **le carte bancarie sono protette dagli attacchi di replay**, quindi copiarle con Flipper e poi cercare di emularle per pagare qualcosa non funzionerà.
## Riferimenti

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
