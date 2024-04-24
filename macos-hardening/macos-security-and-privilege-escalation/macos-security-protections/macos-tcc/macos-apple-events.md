# macOS Eventi Apple

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**Gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di Base

Gli **Eventi Apple** sono una funzionalità di macOS di Apple che consente alle applicazioni di comunicare tra loro. Fanno parte del **Gestore Eventi Apple**, che è un componente del sistema operativo macOS responsabile della gestione della comunicazione tra processi. Questo sistema consente a un'applicazione di inviare un messaggio a un'altra applicazione per richiedere che esegua una particolare operazione, come aprire un file, recuperare dati o eseguire un comando.

Il demone mina è `/System/Library/CoreServices/appleeventsd` che registra il servizio `com.apple.coreservices.appleevents`.

Ogni applicazione che può ricevere eventi controllerà con questo demone fornendo la sua Porta Mach degli Eventi Apple. E quando un'applicazione vuole inviare un evento ad esso, l'applicazione richiederà questa porta al demone.

Le applicazioni con sandbox richiedono privilegi come `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` per poter inviare eventi. Notare che i diritti come `com.apple.security.temporary-exception.apple-events` potrebbero limitare chi ha accesso ad inviare eventi che richiederanno diritti come `com.apple.private.appleevents`.

{% hint style="success" %}
È possibile utilizzare la variabile di ambiente **`AEDebugSends`** per registrare informazioni sul messaggio inviato:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e ai [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
