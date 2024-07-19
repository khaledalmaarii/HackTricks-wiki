# macOS Apple Scripts

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Apple Scripts

È un linguaggio di scripting utilizzato per l'automazione dei compiti **interagendo con processi remoti**. Rende abbastanza facile **chiedere ad altri processi di eseguire alcune azioni**. **Il malware** può abusare di queste funzionalità per sfruttare le funzioni esportate da altri processi.\
Ad esempio, un malware potrebbe **iniettare codice JS arbitrario nelle pagine aperte del browser**. Oppure **cliccare automaticamente** su alcune autorizzazioni richieste all'utente;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ecco alcuni esempi: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trova ulteriori informazioni su malware che utilizza applescripts [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Gli script Apple possono essere facilmente "**compilati**". Queste versioni possono essere facilmente "**decompilate**" con `osadecompile`

Tuttavia, questi script possono anche essere **esportati come "Sola lettura"** (tramite l'opzione "Esporta..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e in questo caso il contenuto non può essere decompilato nemmeno con `osadecompile`

Tuttavia, ci sono ancora alcuni strumenti che possono essere utilizzati per comprendere questo tipo di eseguibili, [**leggi questa ricerca per maggiori informazioni**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Lo strumento [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) sarà molto utile per capire come funziona lo script.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
