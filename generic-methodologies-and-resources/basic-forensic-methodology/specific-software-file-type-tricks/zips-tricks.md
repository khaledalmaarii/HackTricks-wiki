# Trucchi ZIP

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Gli **strumenti da riga di comando** per la gestione dei **file zip** sono essenziali per diagnosticare, riparare e craccare i file zip. Ecco alcuni utilità chiave:

- **`unzip`**: Mostra il motivo per cui un file zip potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato del file zip.
- **`zipinfo`**: Elenca il contenuto di un file zip senza estrarlo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Prova a riparare file zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il cracking a forza bruta delle password dei file zip, efficace per password di circa 7 caratteri.

La [specifica del formato del file Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e gli standard dei file zip.

È fondamentale notare che i file zip protetti da password **non crittografano i nomi dei file o le dimensioni dei file** al loro interno, una falla di sicurezza non condivisa con i file RAR o 7z che crittografano queste informazioni. Inoltre, i file zip crittografati con il vecchio metodo ZipCrypto sono vulnerabili a un **attacco di testo in chiaro** se è disponibile una copia non crittografata di un file compresso. Questo attacco sfrutta il contenuto noto per craccare la password del file zip, una vulnerabilità descritta nell'articolo di [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e spiegata ulteriormente in [questo articolo accademico](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Tuttavia, i file zip protetti con crittografia **AES-256** sono immuni a questo attacco di testo in chiaro, dimostrando l'importanza di scegliere metodi di crittografia sicuri per i dati sensibili.

## Riferimenti
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
