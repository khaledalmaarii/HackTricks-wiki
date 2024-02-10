# Spazio dei nomi PID

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

Lo spazio dei nomi PID (Process IDentifier) è una funzionalità nel kernel Linux che fornisce l'isolamento dei processi abilitando un gruppo di processi ad avere il proprio set di PID univoci, separati dai PID in altri spazi dei nomi. Questo è particolarmente utile nella containerizzazione, dove l'isolamento dei processi è essenziale per la sicurezza e la gestione delle risorse.

Quando viene creato un nuovo spazio dei nomi PID, il primo processo in tale spazio dei nomi viene assegnato il PID 1. Questo processo diventa il processo "init" del nuovo spazio dei nomi ed è responsabile della gestione degli altri processi all'interno dello spazio dei nomi. Ogni processo successivo creato all'interno dello spazio dei nomi avrà un PID univoco all'interno di tale spazio dei nomi e questi PID saranno indipendenti dai PID in altri spazi dei nomi.

Dal punto di vista di un processo all'interno di uno spazio dei nomi PID, può vedere solo gli altri processi nello stesso spazio dei nomi. Non è consapevole dei processi in altri spazi dei nomi e non può interagire con essi utilizzando gli strumenti tradizionali di gestione dei processi (ad esempio, `kill`, `wait`, ecc.). Ciò fornisce un livello di isolamento che aiuta a prevenire l'interferenza tra i processi.

### Come funziona:

1. Quando viene creato un nuovo processo (ad esempio, utilizzando la chiamata di sistema `clone()`), il processo può essere assegnato a uno spazio dei nomi PID nuovo o esistente. **Se viene creato un nuovo spazio dei nomi, il processo diventa il processo "init" di tale spazio dei nomi**.
2. Il **kernel** mantiene una **mappatura tra i PID nel nuovo spazio dei nomi e i PID corrispondenti** nello spazio dei nomi padre (cioè lo spazio dei nomi da cui è stato creato il nuovo spazio dei nomi). Questa mappatura **consente al kernel di tradurre i PID quando necessario**, ad esempio quando si inviano segnali tra processi in spazi dei nomi diversi.
3. **I processi all'interno di uno spazio dei nomi PID possono vedere e interagire solo con gli altri processi nello stesso spazio dei nomi**. Non sono consapevoli dei processi in altri spazi dei nomi e i loro PID sono univoci all'interno del loro spazio dei nomi.
4. Quando viene **distrutto uno spazio dei nomi PID** (ad esempio, quando il processo "init" dello spazio dei nomi esce), **tutti i processi all'interno di tale spazio dei nomi vengono terminati**. Ciò garantisce che tutte le risorse associate allo spazio dei nomi vengano correttamente pulite.

## Laboratorio:

### Creare spazi dei nomi diversi

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Errore: bash: fork: impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi spazi dei nomi PID (Process ID). Di seguito sono riportati i dettagli chiave e la soluzione:

1. **Spiegazione del problema**:
- Il kernel Linux consente a un processo di creare nuovi spazi dei nomi utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo spazio dei nomi PID (chiamato "processo di unshare") non entra nel nuovo spazio dei nomi; solo i suoi processi figlio lo fanno.
- L'esecuzione di `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figlio si trovano nello spazio dei nomi PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo spazio dei nomi diventa PID 1. Quando questo processo esce, viene attivata la pulizia dello spazio dei nomi se non ci sono altri processi, poiché il PID 1 ha il ruolo speciale di adottare i processi orfani. Il kernel Linux disabiliterà quindi l'allocazione dei PID in tale spazio dei nomi.

2. **Conseguenza**:
- L'uscita del PID 1 in un nuovo spazio dei nomi porta alla pulizia del flag `PIDNS_HASH_ADDING`. Ciò comporta il fallimento della funzione `alloc_pid` nell'allocazione di un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` crei un nuovo processo dopo aver creato il nuovo spazio dei nomi PID.
- Eseguendo `%unshare -fp /bin/bash%`, si garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo spazio dei nomi. `/bin/bash` e i suoi processi figlio sono quindi contenuti in modo sicuro all'interno di questo nuovo spazio dei nomi, evitando l'uscita prematura del PID 1 e consentendo un'allocazione normale dei PID.

Assicurandosi che `unshare` venga eseguito con l'opzione `-f`, il nuovo spazio dei nomi PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi sottoprocessi di funzionare senza incontrare l'errore di allocazione della memoria.

</details>

Montando una nuova istanza del filesystem `/proc` se si utilizza il parametro `--mount-proc`, si garantisce che il nuovo spazio dei nomi di montaggio abbia una **visualizzazione accurata e isolata delle informazioni sui processi specifiche di tale spazio dei nomi**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Controlla in quale namespace si trova il tuo processo

To check which namespace your process is in, you can use the following command:

Per controllare in quale namespace si trova il tuo processo, puoi utilizzare il seguente comando:

```bash
cat /proc/$$/ns/pid
```

This will display the inode number of the PID namespace associated with your process.

Questo mostrerà il numero di inode dello spazio dei nomi PID associato al tuo processo.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Trova tutti i namespace PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Nota che l'utente root dal PID namespace iniziale (predefinito) può vedere tutti i processi, anche quelli nei nuovi PID namespaces, ecco perché possiamo vedere tutti i PID namespaces.

### Entra all'interno di un PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Quando entri all'interno di uno spazio dei processi (PID namespace) dal namespace predefinito, sarai comunque in grado di vedere tutti i processi. E il processo dal PID ns sarà in grado di vedere il nuovo bash nel PID ns.

Inoltre, puoi **entrare in un altro PID namespace solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/pid`)

## Riferimenti
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
