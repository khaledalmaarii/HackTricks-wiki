# Namespace di montaggio

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

Un namespace di montaggio è una funzionalità del kernel Linux che fornisce l'isolamento dei punti di montaggio del file system visibili da un gruppo di processi. Ogni namespace di montaggio ha il proprio insieme di punti di montaggio del file system e **le modifiche ai punti di montaggio in un namespace non influiscono sugli altri namespace**. Ciò significa che i processi in esecuzione in diversi namespace di montaggio possono avere diverse visualizzazioni della gerarchia del file system.

I namespace di montaggio sono particolarmente utili nella containerizzazione, in cui ogni container dovrebbe avere il proprio file system e configurazione, isolato dagli altri container e dal sistema host.

### Come funziona:

1. Quando viene creato un nuovo namespace di montaggio, viene inizializzato con una **copia dei punti di montaggio dal namespace padre**. Ciò significa che, alla creazione, il nuovo namespace condivide la stessa visualizzazione del file system del suo genitore. Tuttavia, le modifiche successive ai punti di montaggio all'interno del namespace non influiranno sul genitore o sugli altri namespace.
2. Quando un processo modifica un punto di montaggio all'interno del suo namespace, ad esempio montando o smontando un file system, la **modifica è locale a quel namespace** e non influisce sugli altri namespace. Ciò consente a ciascun namespace di avere la propria gerarchia indipendente del file system.
3. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()`, o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWNS`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare i punti di montaggio associati a quel namespace.
4. **I descrittori di file e gli inode sono condivisi tra i namespace**, il che significa che se un processo in un namespace ha un descrittore di file aperto che punta a un file, può **passare quel descrittore di file** a un processo in un altro namespace e **entrambi i processi accederanno allo stesso file**. Tuttavia, il percorso del file potrebbe non essere lo stesso in entrambi i namespace a causa delle differenze nei punti di montaggio.

## Laboratorio:

### Creare diversi namespace

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
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
cat /proc/$$/mountinfo | grep "ns"
```

This command will display the mount information for your process and filter the output to show only the lines containing "ns".

Questo comando visualizzerà le informazioni di montaggio per il tuo processo e filtrerà l'output mostrando solo le righe contenenti "ns".
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Trova tutti i namespace di montaggio

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Entra all'interno di uno spazio dei nomi di montaggio

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace senza un descrittore che punti ad esso (come `/proc/self/ns/mnt`).

Poiché i nuovi mount sono accessibili solo all'interno del namespace, è possibile che un namespace contenga informazioni sensibili che possono essere accessibili solo da esso.

### Monta qualcosa
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
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
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
