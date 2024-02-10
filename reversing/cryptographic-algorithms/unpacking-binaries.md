<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** repository di [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>


# Identificazione di binari compressi

* **Mancanza di stringhe**: È comune trovare che i binari compressi non abbiano quasi nessuna stringa.
* Molte **stringhe inutilizzate**: Inoltre, quando un malware utilizza qualche tipo di pacchetto commerciale, è comune trovare molte stringhe senza riferimenti incrociati. Anche se queste stringhe esistono, ciò non significa che il binario non sia compresso.
* È anche possibile utilizzare alcuni strumenti per cercare di individuare quale pacchetto è stato utilizzato per comprimere un binario:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Raccomandazioni di base

* **Inizia** analizzando il binario compresso **dal basso in IDA e risali**. Gli unpacker escono una volta che il codice decompresso esce, quindi è improbabile che l'unpacker passi l'esecuzione al codice decompresso all'inizio.
* Cerca **JMP** o **CALL** a **registri** o **regioni** di **memoria**. Cerca anche **funzioni che pushano argomenti e un indirizzo di direzione e poi chiamano `retn`**, perché il ritorno della funzione in quel caso potrebbe chiamare l'indirizzo appena pushato nello stack prima di chiamarlo.
* Metti un **breakpoint** su `VirtualAlloc` poiché questo alloca spazio in memoria dove il programma può scrivere il codice decompresso. Esegui "run to user code" o usa F8 per **arrivare al valore dentro EAX** dopo l'esecuzione della funzione e "**seguire quell'indirizzo nel dump**". Non si sa mai se quella è la regione in cui verrà salvato il codice decompresso.
* **`VirtualAlloc`** con il valore "**40**" come argomento significa Read+Write+Execute (qui verrà copiato del codice che necessita di esecuzione).
* Mentre si decomprime il codice, è normale trovare **diverse chiamate** a **operazioni aritmetiche** e funzioni come **`memcopy`** o **`Virtual`**`Alloc`. Se ti trovi in una funzione che apparentemente esegue solo operazioni aritmetiche e forse qualche `memcopy`, la raccomandazione è cercare di **trovare la fine della funzione** (forse un JMP o una chiamata a qualche registro) **o** almeno la **chiamata all'ultima funzione** ed eseguire fino ad allora poiché il codice non è interessante.
* Mentre si decomprime il codice, **fai attenzione** ogni volta che **cambi regione di memoria**, poiché un cambio di regione di memoria può indicare l'inizio del codice decompresso. Puoi facilmente scaricare una regione di memoria utilizzando Process Hacker (processo --> proprietà --> memoria).
* Mentre si cerca di decomprimere il codice, un buon modo per **sapere se si sta già lavorando con il codice decompresso** (quindi puoi semplicemente scaricarlo) è **controllare le stringhe del binario**. Se in qualche punto esegui un salto (magari cambiando la regione di memoria) e ti accorgi che **sono state aggiunte molte più stringhe**, allora puoi sapere **che stai lavorando con il codice decompresso**.\
Tuttavia, se il pacchetto contiene già molte stringhe, puoi contare quante stringhe contengono la parola "http" e vedere se questo numero aumenta.
* Quando scarichi un eseguibile da una regione di memoria, puoi correggere alcuni header utilizzando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** repository di [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
