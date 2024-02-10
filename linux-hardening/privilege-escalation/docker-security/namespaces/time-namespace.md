# Spazio dei tempi

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Informazioni di base

Lo spazio dei tempi in Linux consente di avere offset per namespace rispetto ai clock monotoni di sistema e di avvio. Viene comunemente utilizzato nei container Linux per modificare la data/ora all'interno di un container e regolare gli orologi dopo il ripristino da un checkpoint o snapshot.

## Laboratorio:

### Creare diversi spazi dei nomi

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
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
### Verifica in quale namespace si trova il tuo processo

Per determinare in quale namespace si trova il tuo processo, puoi utilizzare il seguente comando:

```bash
cat /proc/$$/ns/pid
```

Questo comando restituirà il percorso del file che rappresenta il namespace del tempo per il tuo processo.
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Trova tutti i namespace di tempo

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Entra all'interno di uno spazio dei tempi

{% endcode %}
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace senza un descrittore che punti ad esso (come `/proc/self/ns/net`).


## Riferimenti
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
* [https://www.phoronix.com/news/Linux-Time-Namespace-Coming](https://www.phoronix.com/news/Linux-Time-Namespace-Coming)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
