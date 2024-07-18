# Local Cloud Storage

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

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

In Windows, puoi trovare la cartella OneDrive in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E all'interno di `logs\Personal` è possibile trovare il file `SyncDiagnostics.log` che contiene alcuni dati interessanti riguardanti i file sincronizzati:

* Dimensione in byte
* Data di creazione
* Data di modifica
* Numero di file nel cloud
* Numero di file nella cartella
* **CID**: ID univoco dell'utente OneDrive
* Tempo di generazione del report
* Dimensione dell'HD del sistema operativo

Una volta trovato il CID, è consigliato **cercare file contenenti questo ID**. Potresti essere in grado di trovare file con il nome: _**\<CID>.ini**_ e _**\<CID>.dat**_ che potrebbero contenere informazioni interessanti come i nomi dei file sincronizzati con OneDrive.

## Google Drive

In Windows, puoi trovare la cartella principale di Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Questa cartella contiene un file chiamato Sync\_log.log con informazioni come l'indirizzo email dell'account, nomi dei file, timestamp, hash MD5 dei file, ecc. Anche i file eliminati appaiono in quel file di log con il corrispondente MD5.

Il file **`Cloud_graph\Cloud_graph.db`** è un database sqlite che contiene la tabella **`cloud_graph_entry`**. In questa tabella puoi trovare il **nome** dei **file sincronizzati**, il tempo di modifica, la dimensione e il checksum MD5 dei file.

I dati della tabella del database **`Sync_config.db`** contengono l'indirizzo email dell'account, il percorso delle cartelle condivise e la versione di Google Drive.

## Dropbox

Dropbox utilizza **database SQLite** per gestire i file. In questo\
Puoi trovare i database nelle cartelle:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

E i principali database sono:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

L'estensione ".dbx" significa che i **database** sono **criptati**. Dropbox utilizza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Per comprendere meglio la crittografia che utilizza Dropbox, puoi leggere [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Tuttavia, le informazioni principali sono:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithm**: PBKDF2
* **Iterations**: 1066

Oltre a queste informazioni, per decriptare i database hai ancora bisogno di:

* La **chiave DPAPI criptata**: Puoi trovarla nel registro all'interno di `NTUSER.DAT\Software\Dropbox\ks\client` (esporta questi dati come binari)
* I **hive** **`SYSTEM`** e **`SECURITY`**
* Le **chiavi master DPAPI**: Che possono essere trovate in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Il **nome utente** e la **password** dell'utente Windows

Poi puoi utilizzare lo strumento [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Se tutto va come previsto, lo strumento indicherà la **chiave primaria** che devi **utilizzare per recuperare quella originale**. Per recuperare quella originale, utilizza semplicemente questa [ricetta cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) mettendo la chiave primaria come "passphrase" all'interno della ricetta.

L'hex risultante è la chiave finale utilizzata per criptare i database che può essere decriptata con:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Il **`config.dbx`** database contiene:

* **Email**: L'email dell'utente
* **usernamedisplayname**: Il nome dell'utente
* **dropbox\_path**: Percorso dove si trova la cartella di dropbox
* **Host\_id: Hash** utilizzato per autenticarsi nel cloud. Questo può essere revocato solo dal web.
* **Root\_ns**: Identificatore dell'utente

Il **`filecache.db`** database contiene informazioni su tutti i file e le cartelle sincronizzati con Dropbox. La tabella `File_journal` è quella con più informazioni utili:

* **Server\_path**: Percorso dove si trova il file all'interno del server (questo percorso è preceduto dal `host_id` del client).
* **local\_sjid**: Versione del file
* **local\_mtime**: Data di modifica
* **local\_ctime**: Data di creazione

Altre tabelle all'interno di questo database contengono informazioni più interessanti:

* **block\_cache**: hash di tutti i file e le cartelle di Dropbox
* **block\_ref**: Collega l'ID hash della tabella `block_cache` con l'ID file nella tabella `file_journal`
* **mount\_table**: Cartelle condivise di dropbox
* **deleted\_fields**: File eliminati da Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) per costruire e **automatizzare flussi di lavoro** facilmente alimentati dagli **strumenti** della comunità **più avanzati** del mondo.\
Accedi oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
