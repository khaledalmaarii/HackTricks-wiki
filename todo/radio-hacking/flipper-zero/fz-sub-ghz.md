# FZ - Sub-GHz

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Introduzione <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero può **ricevere e trasmettere frequenze radio nell'intervallo da 300 a 928 MHz** con il suo modulo integrato, che può leggere, salvare ed emulare telecomandi. Questi telecomandi vengono utilizzati per interagire con cancelli, barriere, serrature radio, interruttori a distanza, campanelli wireless, luci intelligenti e altro ancora. Flipper Zero può aiutarti a capire se la tua sicurezza è compromessa.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ha un modulo sub-1 GHz integrato basato su un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) e un'antenna radio (il raggio massimo è di 50 metri). Sia il chip CC1101 che l'antenna sono progettati per operare a frequenze nei band 300-348 MHz, 387-464 MHz e 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Analizzatore di Frequenza

{% hint style="info" %}
Come trovare quale frequenza sta utilizzando il telecomando
{% endhint %}

Durante l'analisi, Flipper Zero sta scansionando la potenza dei segnali (RSSI) a tutte le frequenze disponibili nella configurazione delle frequenze. Flipper Zero visualizza la frequenza con il valore RSSI più alto, con una potenza del segnale superiore a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Per determinare la frequenza del telecomando, esegui le seguenti operazioni:

1. Posiziona il telecomando molto vicino a sinistra di Flipper Zero.
2. Vai al **Menu Principale** **→ Sub-GHz**.
3. Seleziona **Analizzatore di Frequenza**, quindi premi e tieni premuto il pulsante sul telecomando che desideri analizzare.
4. Controlla il valore della frequenza sullo schermo.

### Leggi

{% hint style="info" %}
Trova informazioni sulla frequenza utilizzata (anche un altro modo per trovare la frequenza utilizzata)
{% endhint %}

L'opzione **Leggi** **ascolta sulla frequenza configurata** nella modulazione indicata: 433,92 AM di default. Se **viene trovato qualcosa** durante la lettura, **vengono fornite informazioni** sullo schermo. Queste informazioni potrebbero essere utili per replicare il segnale in futuro.

Mentre Leggi è in uso, è possibile premere il **pulsante sinistro** e **configurarlo**.\
In questo momento ha **4 modulazioni** (AM270, AM650, FM328 e FM476), e **diverse frequenze rilevanti** memorizzate:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Puoi impostare **quella che ti interessa**, tuttavia, se non sei sicuro di quale frequenza potrebbe essere quella utilizzata dal telecomando che possiedi, **imposta Hopping su ON** (disattivato per impostazione predefinita), e premi il pulsante più volte fino a quando Flipper la cattura e ti fornisce le informazioni necessarie per impostare la frequenza.

{% hint style="danger" %}
Il passaggio tra le frequenze richiede del tempo, quindi i segnali trasmessi al momento del passaggio possono essere persi. Per una migliore ricezione del segnale, imposta una frequenza fissa determinata dall'Analizzatore di Frequenza.
{% endhint %}

### **Leggi Raw**

{% hint style="info" %}
Rubare (e ripetere) un segnale nella frequenza configurata
{% endhint %}

L'opzione **Leggi Raw** **registra i segnali** inviati nella frequenza di ascolto. Questo può essere utilizzato per **rubare** un segnale e **ripeterlo**.

Per impostazione predefinita, **Leggi Raw è anche a 433,92 in AM650**, ma se con l'opzione Leggi hai scoperto che il segnale che ti interessa è in una **diversa frequenza/modulazione, puoi modificarla** premendo sinistra (mentre sei all'interno dell'opzione Leggi Raw).

### Forza Bruta

Se conosci il protocollo utilizzato ad esempio dal garage, è possibile **generare tutti i codici e inviarli con Flipper Zero.** Questo è un esempio che supporta i tipi comuni di garage: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Aggiungi Manualmente

{% hint style="info" %}
Aggiungi segnali da un elenco configurato di protocolli
{% endhint %}

#### Elenco dei [protocolli supportati](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funziona con la maggior parte dei sistemi di codici statici) | 433,92 | Statico  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433,92 | Statico  |
| Nice Flo 24bit\_433                                             | 433,92 | Statico  |
| CAME 12bit\_433                                                 | 433,92 | Statico  |
| CAME 24bit\_433                                                 | 433,92 | Statico  |
| Linear\_300                                                     | 300,00 | Statico  |
| CAME TWEE                                                       | 433,92 | Statico  |
| Gate TX\_433                                                    | 433,92 | Statico  |
| DoorHan\_315                                                    | 315,00 | Dinamico |
| DoorHan\_433                                                    | 433,92 | Dinamico |
| LiftMaster\_315                                                 | 315,00 | Dinamico |
| LiftMaster\_390                                                 | 390,00 | Dinamico |
| Security+2.0\_310                                               | 310,00 | Dinamico |
| Security+2.0\_315                                               | 315,00 | Dinamico |
| Security+2.0\_390                                               | 390,00 | Dinamico |
### Fornitori supportati Sub-GHz

Controlla l'elenco su [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequenze supportate per regione

Controlla l'elenco su [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Ottieni i dBm delle frequenze salvate
{% endhint %}

## Riferimento

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
