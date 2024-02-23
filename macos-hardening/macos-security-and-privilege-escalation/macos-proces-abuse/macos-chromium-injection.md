# Iniezione di Chromium su macOS

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di Base

I browser basati su Chromium come Google Chrome, Microsoft Edge, Brave e altri. Questi browser sono costruiti sul progetto open-source di Chromium, il che significa che condividono una base comune e, quindi, hanno funzionalità e opzioni per sviluppatori simili.

#### Flag `--load-extension`

La flag `--load-extension` viene utilizzata quando si avvia un browser basato su Chromium da riga di comando o da script. Questa flag permette di **caricare automaticamente una o più estensioni** nel browser all'avvio.

#### Flag `--use-fake-ui-for-media-stream`

La flag `--use-fake-ui-for-media-stream` è un'altra opzione da riga di comando che può essere utilizzata per avviare browser basati su Chromium. Questa flag è progettata per **bypassare le normali richieste dell'utente che chiedono il permesso di accedere ai flussi multimediali dalla fotocamera e dal microfono**. Quando viene utilizzata questa flag, il browser concede automaticamente il permesso a qualsiasi sito web o applicazione che richiede l'accesso alla fotocamera o al microfono.

### Strumenti

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Esempio
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Trova più esempi nei link degli strumenti

## Riferimenti

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
