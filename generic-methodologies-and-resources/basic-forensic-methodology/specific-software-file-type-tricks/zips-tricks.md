# Trucchi ZIP

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}

Gli **strumenti da riga di comando** per gestire i **file zip** sono essenziali per diagnosticare, riparare e craccare i file zip. Ecco alcuni utilità chiave:

- **`unzip`**: Rivela il motivo per cui un file zip potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato del file zip.
- **`zipinfo`**: Elenca i contenuti di un file zip senza estrarli.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Prova a riparare file zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il cracking brute-force delle password zip, efficace per password fino a circa 7 caratteri.

La [specificazione del formato del file Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli esaustivi sulla struttura e gli standard dei file zip.

È cruciale notare che i file zip protetti da password **non crittografano i nomi dei file o le dimensioni dei file** al loro interno, una vulnerabilità non condivisa con i file RAR o 7z che crittografano queste informazioni. Inoltre, i file zip crittografati con il vecchio metodo ZipCrypto sono vulnerabili a un **attacco in testo normale** se è disponibile una copia non crittografata di un file compresso. Questo attacco sfrutta il contenuto conosciuto per craccare la password del file zip, una vulnerabilità dettagliata nell'articolo di [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e ulteriormente spiegata in [questo articolo accademico](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Tuttavia, i file zip protetti con crittografia **AES-256** sono immuni a questo attacco in testo normale, dimostrando l'importanza di scegliere metodi di crittografia sicuri per i dati sensibili.

## Riferimenti
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/) 

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
