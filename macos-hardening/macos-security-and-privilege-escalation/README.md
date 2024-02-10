# Sicurezza e Privilege Escalation su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

**Hacking Insights**\
Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking

**Notizie sull'hacking in tempo reale**\
Resta aggiornato con il mondo dell'hacking frenetico attraverso notizie e approfondimenti in tempo reale

**Ultime novità**\
Rimani informato sul lancio delle nuove bug bounty e sugli aggiornamenti cruciali delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **e inizia a collaborare con i migliori hacker oggi stesso!**

## Base di macOS

Se non sei familiare con macOS, dovresti iniziare a imparare le basi di macOS:

* File e permessi speciali di macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Utenti comuni di macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* AppleFS

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* L'architettura del kernel

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servizi e protocolli di rete comuni di macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS **Open Source**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Per scaricare un `tar.gz` cambia un URL come [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Nelle aziende i sistemi **macOS** sono molto probabilmente gestiti con un MDM. Pertanto, dal punto di vista di un attaccante, è interessante sapere **come funziona**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Ispezione, Debugging e Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protezioni di sicurezza di macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superficie di attacco

### Permessi dei file

Se un **processo in esecuzione come root scrive** un file che può essere controllato da un utente, l'utente potrebbe sfruttarlo per **aumentare i privilegi**.\
Ciò potrebbe verificarsi nelle seguenti situazioni:

* Il file utilizzato è stato già creato da un utente (di proprietà dell'utente)
* Il file utilizzato è scrivibile dall'utente a causa di un gruppo
* Il file utilizzato si trova all'interno di una directory di proprietà dell'utente (l'utente potrebbe creare il file)
* Il file utilizzato si trova all'interno di una directory di proprietà di root, ma l'utente ha accesso in scrittura su di essa a causa di un gruppo (l'utente potrebbe creare il file)

Essere in grado di **creare un file** che verrà **utilizzato da root**, consente a un utente di **sfruttarne il contenuto** o addirittura creare **symlink/hardlink** per puntarlo in un altro luogo.

Per questo tipo di vulnerabilità, non dimenticare di **verificare gli installer `.pkg` vulnerabili**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Estensione del file e gestori di app per URL scheme

Le app strane registrate dalle estensioni dei file potrebbero essere sfruttate e diverse applicazioni possono essere registrate per aprire protocolli specifici

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Privilege Escalation TCC / SIP di macOS

In macOS, le **applicazioni e i binari possono avere autorizzazioni** per accedere a cartelle o impostazioni che li rendono più privilegiati rispetto ad altri.

Pertanto, un attaccante che desidera compromettere con successo una macchina macOS dovrà **aumentare i suoi privilegi TCC** (o addirittura **bypassare SIP**, a seconda delle sue esigenze).

Questi privilegi vengono di solito concessi sotto forma di **entitlements** con cui l'applicazione è firmata, oppure l'applicazione potrebbe richiedere alcuni accessi e dopo che l'**utente li ha approvati** possono essere trovati nei **database TCC**. Un altro modo in cui un processo può ottenere questi privilegi è essere un **figlio di un processo** con quei **privilegi**, poiché di solito vengono **ereditati**.

Segui questi link per trovare diversi modi per [**aumentare i privilegi in TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), per [**bypassare TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) e come in passato è stato **bypassato SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Privilege Escalation tradizionale di macOS

Naturalmente, dal punto di vista di un team di red team, dovresti essere interessato anche ad aumentare i privilegi a root. Controlla il seguente post per alcuni suggerimenti:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Riferimenti

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug!

**Insight sull'hacking**\
Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking

**Notizie sull'hacking in tempo reale**\
Resta aggiornato con il mondo dell'hacking in rapido movimento attraverso notizie e approfondimenti in tempo reale

**Ultime notizie**\
Rimani informato con i nuovi bug bounty in lancio e gli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi stesso!

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
