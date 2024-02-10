# Apple Scripts di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in formato PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Apple Scripts

È un linguaggio di scripting utilizzato per l'automazione di compiti **interagendo con processi remoti**. Rende piuttosto facile **chiedere ad altri processi di eseguire determinate azioni**. **Malware** potrebbe sfruttare queste funzionalità per abusare delle funzioni esportate da altri processi.\
Ad esempio, un malware potrebbe **iniettare codice JS arbitrario nelle pagine aperte del browser**. O **fare clic automaticamente** su alcune autorizzazioni richieste all'utente;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ecco alcuni esempi: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trova ulteriori informazioni sui malware che utilizzano gli AppleScripts [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Gli AppleScripts possono essere facilmente "**compilati**". Queste versioni possono essere facilmente "**decompilate**" con `osadecompile`.

Tuttavia, questi script possono anche essere **esportati come "sola lettura"** (tramite l'opzione "Esporta..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
E in questo caso il contenuto non può essere decompilato nemmeno con `osadecompile`.

Tuttavia, ci sono ancora alcuni strumenti che possono essere utilizzati per comprendere questo tipo di eseguibili, [**leggi questa ricerca per ulteriori informazioni**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Lo strumento [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) sarà molto utile per capire come funziona lo script.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
