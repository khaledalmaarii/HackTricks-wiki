# Network Namespace

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

Un namespace di rete è una funzionalità del kernel Linux che fornisce l'isolamento dello stack di rete, consentendo a **ogni namespace di rete di avere la propria configurazione di rete indipendente**, interfacce, indirizzi IP, tabelle di routing e regole del firewall. Questo isolamento è utile in vari scenari, come la containerizzazione, in cui ogni container dovrebbe avere la propria configurazione di rete, indipendente dagli altri container e dal sistema host.

### Come funziona:

1. Quando viene creato un nuovo namespace di rete, parte con uno **stack di rete completamente isolato**, senza **interfacce di rete** tranne l'interfaccia di loopback (lo). Ciò significa che i processi in esecuzione nel nuovo namespace di rete non possono comunicare con processi in altri namespace o con il sistema host per impostazione predefinita.
2. Possono essere creati e spostati **interfacce di rete virtuali**, come coppie veth, tra i namespace di rete. Ciò consente di stabilire la connettività di rete tra i namespace o tra un namespace e il sistema host. Ad esempio, un'estremità di una coppia veth può essere posizionata nel namespace di rete di un container e l'altra estremità può essere collegata a un **bridge** o a un'altra interfaccia di rete nel namespace dell'host, fornendo connettività di rete al container.
3. Le interfacce di rete all'interno di un namespace possono avere i loro **propri indirizzi IP, tabelle di routing e regole del firewall**, indipendenti dagli altri namespace. Ciò consente ai processi in diversi namespace di rete di avere diverse configurazioni di rete e di operare come se fossero in esecuzione su sistemi di rete separati.
4. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()`, o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWNET`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare la configurazione di rete e le interfacce associate a quel namespace.

## Laboratorio:

### Creare diversi Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
# Run ifconfig or ip -a
```
### &#x20;Verifica in quale namespace si trova il tuo processo

To check which namespace your process is in, you can use the following command:

Per verificare in quale namespace si trova il tuo processo, puoi utilizzare il seguente comando:

```bash
$ ls -l /proc/<PID>/ns/net
```

Replace `<PID>` with the process ID of your target process. This command will display the symbolic link to the network namespace of the process.

Sostituisci `<PID>` con l'ID del processo di destinazione. Questo comando mostrerà il collegamento simbolico al namespace di rete del processo.

Alternatively, you can use the `readlink` command to get the full path of the network namespace:

In alternativa, puoi utilizzare il comando `readlink` per ottenere il percorso completo del namespace di rete:

```bash
$ readlink /proc/<PID>/ns/net
```

Again, replace `<PID>` with the process ID of your target process. This command will provide you with the full path of the network namespace.

Di nuovo, sostituisci `<PID>` con l'ID del processo di destinazione. Questo comando ti fornirà il percorso completo del namespace di rete.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Trova tutti i namespace di rete

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Entra all'interno di uno spazio dei nomi di rete

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/net`).

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
