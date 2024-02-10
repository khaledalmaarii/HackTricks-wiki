# User Namespace

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

Uno spazio dei nomi utente è una funzionalità del kernel Linux che **fornisce l'isolamento delle mappature degli ID utente e di gruppo**, consentendo a ogni spazio dei nomi utente di avere il **proprio set di ID utente e di gruppo**. Questo isolamento consente ai processi in esecuzione in spazi dei nomi utente diversi di **avere privilegi e proprietà diversi**, anche se condividono gli stessi ID utente e di gruppo numericamente.

Gli spazi dei nomi utente sono particolarmente utili nella containerizzazione, dove ogni contenitore dovrebbe avere il proprio set indipendente di ID utente e di gruppo, consentendo una migliore sicurezza e isolamento tra i contenitori e il sistema host.

### Come funziona:

1. Quando viene creato un nuovo spazio dei nomi utente, **parte con un set vuoto di mappature degli ID utente e di gruppo**. Ciò significa che qualsiasi processo in esecuzione nel nuovo spazio dei nomi utente **inizialmente non avrà privilegi al di fuori dello spazio dei nomi**.
2. Le mappature degli ID possono essere stabilite tra gli ID utente e di gruppo nello spazio dei nomi utente nuovo e quelli nello spazio dei nomi genitore (o host). Ciò **consente ai processi nel nuovo spazio dei nomi di avere privilegi e proprietà corrispondenti agli ID utente e di gruppo nello spazio dei nomi genitore**. Tuttavia, le mappature degli ID possono essere limitate a intervalli specifici e sottoinsiemi di ID, consentendo un controllo dettagliato sui privilegi concessi ai processi nel nuovo spazio dei nomi.
3. All'interno di uno spazio dei nomi utente, **i processi possono avere privilegi di root completi (UID 0) per le operazioni all'interno dello spazio dei nomi**, pur avendo ancora privilegi limitati al di fuori dello spazio dei nomi. Ciò consente ai **contenitori di eseguire operazioni con capacità simili a root all'interno del proprio spazio dei nomi senza avere privilegi di root completi sul sistema host**.
4. I processi possono spostarsi tra gli spazi dei nomi utilizzando la chiamata di sistema `setns()` o creare nuovi spazi dei nomi utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWUSER`. Quando un processo si sposta in un nuovo spazio dei nomi o ne crea uno, inizierà a utilizzare le mappature degli ID utente e di gruppo associate a tale spazio dei nomi.

## Laboratorio:

### Creare spazi dei nomi diversi

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` utilizzando il parametro `--mount-proc`, si garantisce che il nuovo namespace di montaggio abbia una **visione accurata e isolata delle informazioni specifiche dei processi in quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). Di seguito sono riportati i dettagli chiave e la soluzione:

1. **Spiegazione del problema**:
- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (chiamato "unshare" process) non entra nel nuovo namespace; solo i suoi processi figlio lo fanno.
- L'esecuzione di `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figlio si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo esce, viene attivata la pulizia del namespace se non ci sono altri processi, poiché il PID 1 ha il ruolo speciale di adottare i processi orfani. Il kernel Linux disabiliterà quindi l'allocazione di PID in quel namespace.

2. **Conseguenza**:
- L'uscita del PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Ciò comporta il fallimento della funzione `alloc_pid` nell'allocazione di un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` crei un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguendo `%unshare -fp /bin/bash%` si garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figlio sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, evitando l'uscita prematura del PID 1 e consentendo un'allocazione normale dei PID.

Assicurandosi che `unshare` venga eseguito con l'opzione `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi sottoprocessi di funzionare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Per utilizzare il namespace utente, il demone Docker deve essere avviato con **`--userns-remap=default`** (In Ubuntu 14.04, ciò può essere fatto modificando `/etc/default/docker` e quindi eseguendo `sudo service docker restart`)

### &#x20;Verifica in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
È possibile verificare la mappatura degli utenti dal container Docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
O dal computer host con:
```bash
cat /proc/<pid>/uid_map
```
### Trova tutti i namespace utente

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Entra all'interno di uno User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace senza un descrittore che punti ad esso (come `/proc/self/ns/user`).

### Creare un nuovo User namespace (con mappature)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Recupero delle capacità

Nel caso dei namespace utente, quando viene creato un nuovo namespace utente, il processo che entra nel namespace ottiene un insieme completo di capacità all'interno di tale namespace. Queste capacità consentono al processo di eseguire operazioni privilegiate come il montaggio di filesystem, la creazione di dispositivi o la modifica della proprietà dei file, ma solo nel contesto del proprio namespace utente.

Ad esempio, quando si dispone della capacità `CAP_SYS_ADMIN` all'interno di un namespace utente, è possibile eseguire operazioni che richiedono tipicamente questa capacità, come il montaggio di filesystem, ma solo nel contesto del proprio namespace utente. Le operazioni eseguite con questa capacità non influiscono sul sistema host o su altri namespace.

{% hint style="warning" %}
Pertanto, anche se ottenere un nuovo processo all'interno di un nuovo namespace utente **ripristina tutte le capacità** (CapEff: 000001ffffffffff), in realtà è possibile **utilizzare solo quelle relative al namespace** (ad esempio il montaggio), ma non tutte. Quindi, questo da solo non è sufficiente per evadere da un container Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
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
