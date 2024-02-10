# Spazio dei nomi UTS

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

Uno spazio dei nomi UTS (UNIX Time-Sharing System) è una funzionalità del kernel Linux che fornisce l'**isolamento di due identificatori di sistema**: il **nome host** e il **dominio NIS** (Network Information Service). Questo isolamento consente a ciascuno spazio dei nomi UTS di avere il suo **nome host e dominio NIS indipendenti**, il che è particolarmente utile in scenari di containerizzazione in cui ogni contenitore dovrebbe apparire come un sistema separato con il proprio nome host.

### Come funziona:

1. Quando viene creato un nuovo spazio dei nomi UTS, inizia con una **copia del nome host e del dominio NIS dallo spazio dei nomi genitore**. Ciò significa che, alla creazione, il nuovo spazio dei nomi **condivide gli stessi identificatori del genitore**. Tuttavia, eventuali modifiche successive al nome host o al dominio NIS all'interno dello spazio dei nomi non influiranno su altri spazi dei nomi.
2. I processi all'interno di uno spazio dei nomi UTS **possono modificare il nome host e il dominio NIS** utilizzando le chiamate di sistema `sethostname()` e `setdomainname()`, rispettivamente. Queste modifiche sono locali allo spazio dei nomi e non influiscono su altri spazi dei nomi o sul sistema host.
3. I processi possono spostarsi tra gli spazi dei nomi utilizzando la chiamata di sistema `setns()` o creare nuovi spazi dei nomi utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWUTS`. Quando un processo si sposta in un nuovo spazio dei nomi o ne crea uno, inizierà a utilizzare il nome host e il dominio NIS associati a tale spazio dei nomi.

## Laboratorio:

### Creare spazi dei nomi diversi

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` utilizzando il parametro `--mount-proc`, si garantisce che il nuovo namespace di montaggio abbia una **visione accurata e isolata delle informazioni specifiche dei processi in quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). Di seguito sono riportati i dettagli chiave e la soluzione:

1. **Spiegazione del problema**:
- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (chiamato "unshare" process) non entra nel nuovo namespace; solo i suoi processi figlio lo fanno.
- L'esecuzione di `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figlio si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, viene avviata la pulizia del namespace se non ci sono altri processi, poiché il PID 1 ha il ruolo speciale di adottare i processi orfani. Il kernel Linux disabiliterà quindi l'allocazione di PID in quel namespace.

2. **Conseguenza**:
- L'uscita del PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Ciò comporta il fallimento della funzione `alloc_pid` nell'allocazione di un nuovo PID durante la creazione di un nuovo processo, generando l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` crei un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguendo `%unshare -fp /bin/bash%`, si garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figlio sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, evitando l'uscita prematura del PID 1 e consentendo un'allocazione normale dei PID.

Assicurandosi che `unshare` venga eseguito con l'opzione `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi sottoprocessi di funzionare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifica in quale namespace si trova il tuo processo

To check which namespace your process is in, you can use the following command:

Per verificare in quale namespace si trova il tuo processo, puoi utilizzare il seguente comando:

```bash
cat /proc/$$/ns/uts
```

This will display the inode number of the UTS namespace associated with your process.

Questo mostrerà il numero di inode dello spazio dei nomi UTS associato al tuo processo.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Trova tutti i namespace UTS

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Entra all'interno di uno spazio dei nomi UTS

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace senza un descrittore che punti ad esso (come `/proc/self/ns/uts`).

### Cambiare il nome host
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## Riferimenti
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>
