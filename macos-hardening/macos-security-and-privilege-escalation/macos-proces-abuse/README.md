# Abuso dei processi su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Abuso dei processi su macOS

macOS, come qualsiasi altro sistema operativo, fornisce una varietà di metodi e meccanismi per **l'interazione, la comunicazione e la condivisione dei dati tra i processi**. Sebbene queste tecniche siano essenziali per il corretto funzionamento del sistema, possono anche essere sfruttate dagli attori minacciosi per **eseguire attività malevole**.

### Iniezione di librerie

L'iniezione di librerie è una tecnica in cui un attaccante **costringe un processo a caricare una libreria malevola**. Una volta iniettata, la libreria viene eseguita nel contesto del processo di destinazione, fornendo all'attaccante gli stessi permessi e accessi del processo.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hooking di funzioni

L'hooking di funzioni consiste nell'**intercettare le chiamate alle funzioni** o i messaggi all'interno del codice di un software. Attraverso l'hooking delle funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o addirittura ottenere il controllo del flusso di esecuzione.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Comunicazione tra processi

La comunicazione tra processi (IPC) si riferisce a diversi metodi con cui i processi separati **condividono e scambiano dati**. Sebbene l'IPC sia fondamentale per molte applicazioni legittime, può anche essere utilizzato impropriamente per eludere l'isolamento dei processi, divulgare informazioni sensibili o eseguire azioni non autorizzate.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Iniezione nelle applicazioni Electron

Le applicazioni Electron eseguite con specifiche variabili d'ambiente potrebbero essere vulnerabili all'iniezione di processi:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Dirty NIB

I file NIB **definiscono gli elementi dell'interfaccia utente (UI)** e le loro interazioni all'interno di un'applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** l'esecuzione di un'applicazione già eseguita se un file NIB viene modificato. Pertanto, potrebbero essere utilizzati per far eseguire programmi arbitrari:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Iniezione nelle applicazioni Java

È possibile sfruttare determinate capacità di Java (come la variabile d'ambiente **`_JAVA_OPTS`**) per far eseguire a un'applicazione Java **codice/comandi arbitrari**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Iniezione nelle applicazioni .Net

È possibile iniettare codice nelle applicazioni .Net **sfruttando la funzionalità di debug di .Net** (non protetta dalle protezioni di macOS come l'indurimento in esecuzione).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Iniezione in Perl

Verifica le diverse opzioni per far eseguire a uno script Perl codice arbitrario in:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Iniezione in Ruby

È anche possibile sfruttare le variabili d'ambiente di Ruby per far eseguire script arbitrari:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Iniezione in Python

Se la variabile d'ambiente **`PYTHONINSPECT`** è impostata, il processo Python passerà a una CLI Python una volta terminato. È anche possibile utilizzare **`PYTHONSTARTUP`** per indicare uno script Python da eseguire all'inizio di una sessione interattiva.\
Tuttavia, nota che lo script **`PYTHONSTARTUP`** non verrà eseguito quando **`PYTHONINSPECT`** crea la sessione interattiva.

Altre variabili d'ambiente come **`PYTHONPATH`** e **`PYTHONHOME`** potrebbero essere utili per far eseguire un comando Python codice arbitrario.

Tieni presente che gli eseguibili compilati con **`pyinstaller`** non utilizzeranno queste variabili d'ambiente anche se vengono eseguiti utilizzando un Python integrato.

{% hint style="danger" %}
In generale, non sono riuscito a trovare un modo per far eseguire a Python codice arbitrario sfruttando le variabili d'ambiente.\
Tuttavia, la maggior parte delle persone installa Python utilizzando **Homebrew**, che installerà Python in una posizione **scrivibile** per l'utente amministratore predefinito. Puoi dirottarlo con qualcosa del genere:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Anche **root** eseguirà questo codice quando si esegue python.
{% endhint %}

## Rilevamento

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) è un'applicazione open source che può **rilevare e bloccare le azioni di iniezione di processo**:

* Utilizzando **Variabili Ambientali**: Monitorerà la presenza di una qualsiasi delle seguenti variabili ambientali: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
* Utilizzando chiamate **`task_for_pid`**: Per trovare quando un processo vuole ottenere la **porta del task di un altro** che consente di iniettare codice nel processo.
* **Parametri delle app Electron**: Qualcuno può utilizzare gli argomenti della riga di comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** per avviare un'app Electron in modalità di debug e quindi iniettare codice in essa.
* Utilizzando **symlink** o **hardlink**: Tipicamente l'abuso più comune è quello di **posizionare un link con i privilegi dell'utente**, e **puntarlo a una posizione con privilegi superiori**. La rilevazione è molto semplice sia per gli hardlink che per i symlink. Se il processo che crea il link ha un **livello di privilegio diverso** rispetto al file di destinazione, creiamo un **avviso**. Purtroppo, nel caso dei symlink, il blocco non è possibile, poiché non abbiamo informazioni sulla destinazione del link prima della creazione. Questa è una limitazione del framework EndpointSecuriy di Apple.

### Chiamate effettuate da altri processi

In [**questo post del blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puoi trovare come è possibile utilizzare la funzione **`task_name_for_pid`** per ottenere informazioni su altri **processi che iniettano codice in un processo** e quindi ottenere informazioni su quell'altro processo.

Nota che per chiamare quella funzione devi essere **lo stesso uid** di quello che esegue il processo o **root** (e restituisce informazioni sul processo, non un modo per iniettare codice).

## Riferimenti

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
