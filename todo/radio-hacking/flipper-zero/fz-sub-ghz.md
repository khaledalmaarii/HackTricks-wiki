# FZ - Sub-GHz

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


## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero può **ricevere e trasmettere frequenze radio nella gamma di 300-928 MHz** con il suo modulo integrato, che può leggere, salvare ed emulare telecomandi. Questi controlli sono utilizzati per interagire con cancelli, barriere, serrature radio, interruttori a distanza, campanelli wireless, luci intelligenti e altro. Flipper Zero può aiutarti a scoprire se la tua sicurezza è compromessa.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ha un modulo sub-1 GHz integrato basato su un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) e un'antenna radio (la portata massima è di 50 metri). Sia il chip CC1101 che l'antenna sono progettati per operare a frequenze nelle bande 300-348 MHz, 387-464 MHz e 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Analizzatore di Frequenza

{% hint style="info" %}
Come trovare quale frequenza sta usando il telecomando
{% endhint %}

Quando si analizza, Flipper Zero sta scansionando la forza dei segnali (RSSI) a tutte le frequenze disponibili nella configurazione di frequenza. Flipper Zero visualizza la frequenza con il valore RSSI più alto, con una forza del segnale superiore a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Per determinare la frequenza del telecomando, procedi come segue:

1. Posiziona il telecomando molto vicino a sinistra di Flipper Zero.
2. Vai a **Menu Principale** **→ Sub-GHz**.
3. Seleziona **Analizzatore di Frequenza**, quindi premi e tieni premuto il pulsante sul telecomando che desideri analizzare.
4. Controlla il valore della frequenza sullo schermo.

### Leggi

{% hint style="info" %}
Trova informazioni sulla frequenza utilizzata (anche un altro modo per trovare quale frequenza è utilizzata)
{% endhint %}

L'opzione **Leggi** **ascolta sulla frequenza configurata** sulla modulazione indicata: 433.92 AM per impostazione predefinita. Se **viene trovato qualcosa** durante la lettura, **viene fornita un'informazione** sullo schermo. Queste informazioni potrebbero essere utilizzate per replicare il segnale in futuro.

Mentre Leggi è in uso, è possibile premere il **pulsante sinistro** e **configurarlo**.\
In questo momento ha **4 modulazioni** (AM270, AM650, FM328 e FM476), e **diverse frequenze rilevanti** memorizzate:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Puoi impostare **quella che ti interessa**, tuttavia, se **non sei sicuro di quale frequenza** potrebbe essere quella utilizzata dal telecomando che hai, **imposta Hopping su ON** (Off per impostazione predefinita), e premi il pulsante più volte fino a quando Flipper non la cattura e ti fornisce le informazioni necessarie per impostare la frequenza.

{% hint style="danger" %}
Passare tra le frequenze richiede del tempo, quindi i segnali trasmessi al momento del passaggio possono essere persi. Per una migliore ricezione del segnale, imposta una frequenza fissa determinata dall'Analizzatore di Frequenza.
{% endhint %}

### **Leggi Raw**

{% hint style="info" %}
Ruba (e ripeti) un segnale nella frequenza configurata
{% endhint %}

L'opzione **Leggi Raw** **registra i segnali** inviati nella frequenza di ascolto. Questo può essere utilizzato per **rubare** un segnale e **ripeterlo**.

Per impostazione predefinita, **Leggi Raw è anche a 433.92 in AM650**, ma se con l'opzione Leggi hai scoperto che il segnale che ti interessa è in una **frequenza/modulazione diversa, puoi anche modificarlo** premendo a sinistra (mentre sei all'interno dell'opzione Leggi Raw).

### Brute-Force

Se conosci il protocollo utilizzato ad esempio dal cancello del garage, è possibile **generare tutti i codici e inviarli con il Flipper Zero.** Questo è un esempio che supporta i tipi comuni di garage: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Aggiungi Manualmente

{% hint style="info" %}
Aggiungi segnali da un elenco configurato di protocolli
{% endhint %}

#### Elenco dei [protocolli supportati](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funziona con la maggior parte dei sistemi a codice statico) | 433.92 | Statico  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Statico  |
| Nice Flo 24bit\_433                                             | 433.92 | Statico  |
| CAME 12bit\_433                                                 | 433.92 | Statico  |
| CAME 24bit\_433                                                 | 433.92 | Statico  |
| Linear\_300                                                     | 300.00 | Statico  |
| CAME TWEE                                                       | 433.92 | Statico  |
| Gate TX\_433                                                    | 433.92 | Statico  |
| DoorHan\_315                                                    | 315.00 | Dinamico |
| DoorHan\_433                                                    | 433.92 | Dinamico |
| LiftMaster\_315                                                 | 315.00 | Dinamico |
| LiftMaster\_390                                                 | 390.00 | Dinamico |
| Security+2.0\_310                                               | 310.00 | Dinamico |
| Security+2.0\_315                                               | 315.00 | Dinamico |
| Security+2.0\_390                                               | 390.00 | Dinamico |

### Fornitori Sub-GHz supportati

Controlla l'elenco su [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequenze supportate per regione

Controlla l'elenco su [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Ottieni dBms delle frequenze salvate
{% endhint %}

## Riferimento

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

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
