{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}


# Identificazione di binari impacchettati

* **mancanza di stringhe**: È comune trovare che i binari impacchettati non abbiano quasi nessuna stringa.
* Molte **stringhe inutilizzate**: Inoltre, quando un malware utilizza qualche tipo di pacchetto commerciale, è comune trovare molte stringhe senza riferimenti incrociati. Anche se queste stringhe esistono, ciò non significa che il binario non sia impacchettato.
* Puoi anche utilizzare alcuni strumenti per cercare di scoprire quale pacchetto è stato utilizzato per impacchettare un binario:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Raccomandazioni di base

* **Inizia** ad analizzare il binario impacchettato **dal basso in IDA e sali**. Gli unpacker escono una volta che il codice decompresso esce, quindi è improbabile che l'unpacker passi l'esecuzione al codice decompresso all'inizio.
* Cerca **JMP** o **CALL** a **registri** o **regioni** di **memoria**. Cerca anche **funzioni che spingono argomenti e una direzione di indirizzo e poi chiamano `retn`**, perché il ritorno della funzione in quel caso potrebbe chiamare l'indirizzo appena spinto nello stack prima di chiamarlo.
* Metti un **breakpoint** su `VirtualAlloc` poiché questo alloca spazio in memoria dove il programma può scrivere codice decompresso. "Esegui fino al codice utente" o usa F8 per **ottenere il valore all'interno di EAX** dopo aver eseguito la funzione e "**segui quell'indirizzo nel dump**". Non sai mai se quella è la regione in cui il codice decompresso verrà salvato.
* **`VirtualAlloc`** con il valore "**40**" come argomento significa Lettura+Scrittura+Esecuzione (alcuni codici che necessitano di esecuzione verranno copiati qui).
* **Durante l'unpacking** del codice è normale trovare **diverse chiamate** a **operazioni aritmetiche** e funzioni come **`memcopy`** o **`Virtual`**`Alloc`. Se ti trovi in una funzione che apparentemente esegue solo operazioni aritmetiche e forse qualche `memcopy`, la raccomandazione è di cercare di **trovare la fine della funzione** (forse un JMP o una chiamata a qualche registro) **o** almeno la **chiamata all'ultima funzione** e correre fino a lì poiché il codice non è interessante.
* Durante l'unpacking del codice **nota** ogni volta che **cambi regione di memoria** poiché un cambiamento di regione di memoria può indicare l'**inizio del codice decompresso**. Puoi facilmente dumpare una regione di memoria utilizzando Process Hacker (processo --> proprietà --> memoria).
* Durante il tentativo di decompattare il codice, un buon modo per **sapere se stai già lavorando con il codice decompresso** (così puoi semplicemente dumpare) è **controllare le stringhe del binario**. Se a un certo punto esegui un salto (forse cambiando la regione di memoria) e noti che **sono state aggiunte molte più stringhe**, allora puoi sapere **che stai lavorando con il codice decompresso**.\
Tuttavia, se il pacchetto contiene già molte stringhe, puoi vedere quante stringhe contengono la parola "http" e vedere se questo numero aumenta.
* Quando dumpi un eseguibile da una regione di memoria, puoi correggere alcuni header utilizzando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
