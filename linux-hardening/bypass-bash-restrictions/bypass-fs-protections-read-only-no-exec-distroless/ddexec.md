# DDexec / EverythingExec

{% hint style="success" %}
Impara e pratica l'Hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) nei repository di github.

</details>
{% endhint %}

## Contesto

In Linux, per eseguire un programma, deve esistere come file, deve essere accessibile in qualche modo attraverso la gerarchia del sistema di file (così funziona `execve()`). Questo file può risiedere su disco o in ram (tmpfs, memfd) ma hai bisogno di un percorso del file. Questo ha reso molto facile controllare cosa viene eseguito su un sistema Linux, facilita la rilevazione delle minacce e degli strumenti degli attaccanti o impedisce loro di provare ad eseguire qualcosa di loro (_ad es._ non consentendo agli utenti non privilegiati di posizionare file eseguibili ovunque).

Ma questa tecnica è qui per cambiare tutto questo. Se non puoi avviare il processo che desideri... **allora dirottane uno già esistente**.

Questa tecnica ti permette di **aggirare tecniche di protezione comuni come sola lettura, noexec, whitelist dei nomi dei file, whitelist degli hash...**

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

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Questo può essere utilizzato per dirottare un processo esistente e sostituirlo con un altro programma. Possiamo ottenere ciò utilizzando la chiamata di sistema `ptrace()` (che richiede di poter eseguire chiamate di sistema o di avere gdb disponibile sul sistema) oppure, in modo più interessante, scrivendo su `/proc/$pid/mem`.

Il file `/proc/$pid/mem` è un mapping uno a uno dell'intero spazio degli indirizzi di un processo (ad esempio da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Ciò significa che leggere o scrivere su questo file in un offset `x` è lo stesso che leggere o modificare i contenuti all'indirizzo virtuale `x`.

Ora, abbiamo quattro problemi di base da affrontare:

- In generale, solo root e il proprietario del programma del file possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere su un indirizzo non mappato nello spazio degli indirizzi del programma, otterremo un errore di I/O.

Questi problemi hanno soluzioni che, sebbene non siano perfette, sono buone:

- La maggior parte degli interpreti di shell permette la creazione di descrittori di file che saranno ereditati dai processi figlio. Possiamo creare un fd che punta al file `mem` della shell con permessi di scrittura... quindi i processi figlio che utilizzano quel fd saranno in grado di modificare la memoria della shell.
- ASLR non è nemmeno un problema, possiamo controllare il file `maps` della shell o qualsiasi altro file da procfs per ottenere informazioni sullo spazio degli indirizzi del processo.
- Quindi dobbiamo eseguire `lseek()` sul file. Dalla shell questo non può essere fatto a meno di utilizzare il famigerato `dd`.

### In dettaglio

I passaggi sono relativamente facili e non richiedono alcun tipo di competenza per comprenderli:

- Analizzare il binario che vogliamo eseguire e il loader per scoprire quali mapping necessitano. Poi creare un "shell"code che eseguirà, in linea di massima, gli stessi passaggi che il kernel fa ad ogni chiamata a `execve()`:
- Creare tali mapping.
- Leggere i binari al loro interno.
- Impostare i permessi.
- Infine inizializzare lo stack con gli argomenti per il programma e posizionare il vettore ausiliario (necessario dal loader).
- Saltare nel loader e lasciarlo fare il resto (caricare le librerie necessarie al programma).
- Ottenere dal file `syscall` l'indirizzo a cui il processo tornerà dopo la chiamata di sistema che sta eseguendo.
- Sovrascrivere quel posto, che sarà eseguibile, con il nostro shellcode (attraverso `mem` possiamo modificare pagine non scrivibili).
- Passare il programma che vogliamo eseguire allo stdin del processo (verrà `letto()` da detto "shell"code).
- A questo punto spetta al loader caricare le librerie necessarie per il nostro programma e saltarci dentro.

**Controlla lo strumento su** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Ci sono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito utilizzato per `lseek()` attraverso il file `mem` (che era l'unico scopo per cui si usava `dd`). Tali alternative sono:
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER` è possibile cambiare il seeker utilizzato, _ad es._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque utilizzarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blocca questo, EDR.

## Riferimenti
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
