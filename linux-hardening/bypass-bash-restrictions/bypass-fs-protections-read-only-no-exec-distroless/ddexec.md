# DDexec / EverythingExec

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Contesto

In Linux, per eseguire un programma, deve esistere come file e deve essere accessibile in qualche modo attraverso la gerarchia del file system (questo è solo il funzionamento di `execve()`). Questo file può risiedere su disco o in RAM (tmpfs, memfd), ma è necessario un percorso del file. Questo ha reso molto facile controllare cosa viene eseguito su un sistema Linux, facilitando la rilevazione delle minacce e degli strumenti degli attaccanti o impedendo loro di eseguire qualsiasi cosa di loro (_ad esempio_ non consentendo agli utenti non privilegiati di posizionare file eseguibili ovunque).

Ma questa tecnica è qui per cambiare tutto questo. Se non puoi avviare il processo desiderato... **allora dirottane uno già esistente**.

Questa tecnica ti consente di **eludere le tecniche di protezione comuni come la modalità di sola lettura, noexec, whitelist dei nomi dei file, whitelist degli hash...**

## Dipendenze

Lo script finale dipende dai seguenti strumenti per funzionare, devono essere accessibili nel sistema che stai attaccando (di default li troverai ovunque):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## La tecnica

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Ciò può essere utilizzato per dirottare un processo già esistente e sostituirlo con un altro programma. Possiamo ottenere ciò utilizzando la chiamata di sistema `ptrace()` (che richiede di poter eseguire chiamate di sistema o di avere gdb disponibile nel sistema) o, in modo più interessante, scrivendo su `/proc/$pid/mem`.

Il file `/proc/$pid/mem` è una mappatura uno a uno dell'intero spazio degli indirizzi di un processo (ad esempio, da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Ciò significa che leggere o scrivere su questo file in un offset `x` è lo stesso che leggere o modificare i contenuti all'indirizzo virtuale `x`.

Ora, abbiamo quattro problemi di base da affrontare:

* In generale, solo l'utente root e il proprietario del programma possono modificarlo.
* ASLR.
* Se proviamo a leggere o scrivere su un indirizzo non mappato nello spazio degli indirizzi del programma, otterremo un errore di I/O.

Questi problemi hanno soluzioni che, sebbene non siano perfette, sono buone:

* La maggior parte degli interpreti di shell consente la creazione di descrittori di file che verranno poi ereditati dai processi figlio. Possiamo creare un descrittore di file che punta al file `mem` della shell con permessi di scrittura... quindi i processi figlio che utilizzano quel descrittore di file saranno in grado di modificare la memoria della shell.
* ASLR non è nemmeno un problema, possiamo controllare il file `maps` della shell o qualsiasi altro file del procfs per ottenere informazioni sullo spazio degli indirizzi del processo.
* Quindi dobbiamo eseguire `lseek()` sul file. Dalla shell questo non può essere fatto a meno di utilizzare il famigerato `dd`.

### In dettaglio

I passaggi sono relativamente facili e non richiedono alcuna competenza particolare per comprenderli:

* Analizza il binario che vogliamo eseguire e il loader per scoprire quali mappature necessitano. Quindi crea un "shell"code che eseguirà, in generale, gli stessi passaggi che il kernel esegue ad ogni chiamata a `execve()`:
* Crea le suddette mappature.
* Leggi i binari in esse.
* Imposta i permessi.
* Infine, inizializza lo stack con gli argomenti per il programma e posiziona il vettore ausiliario (necessario per il loader).
* Salta nel loader e lascia che faccia il resto (carica le librerie necessarie per il programma).
* Ottieni dal file `syscall` l'indirizzo a cui il processo tornerà dopo la chiamata di sistema che sta eseguendo.
* Sovrascrivi quel punto, che sarà eseguibile, con il nostro shellcode (attraverso `mem` possiamo modificare pagine non scrivibili).
* Passa il programma che vogliamo eseguire allo stdin del processo (verrà `letto()` da detto "shell"code).
* A questo punto spetta al loader caricare le librerie necessarie per il nostro programma e saltare in esso.

**Controlla lo strumento su** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Ci sono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito utilizzato per eseguire `lseek()` attraverso il file `mem` (che era l'unico scopo per cui veniva utilizzato `dd`). Tali alternative sono:
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER` è possibile cambiare il seeker utilizzato, ad esempio:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque utilizzarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blocca questo, EDRs.

## Riferimenti
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
