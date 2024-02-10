# Archiviazione locale su cloud

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare flussi di lavoro** con gli strumenti comunitari più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

In Windows, è possibile trovare la cartella di OneDrive in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E all'interno di `logs\Personal` è possibile trovare il file `SyncDiagnostics.log` che contiene alcuni dati interessanti riguardanti i file sincronizzati:

* Dimensione in byte
* Data di creazione
* Data di modifica
* Numero di file nel cloud
* Numero di file nella cartella
* **CID**: ID univoco dell'utente di OneDrive
* Ora di generazione del rapporto
* Dimensione dell'HD del sistema operativo

Una volta trovato il CID, è consigliabile **cercare file che contengano questo ID**. Potresti essere in grado di trovare file con il nome: _**\<CID>.ini**_ e _**\<CID>.dat**_ che possono contenere informazioni interessanti come i nomi dei file sincronizzati con OneDrive.

## Google Drive

In Windows, è possibile trovare la cartella principale di Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Questa cartella contiene un file chiamato Sync\_log.log con informazioni come l'indirizzo email dell'account, i nomi dei file, i timestamp, gli hash MD5 dei file, ecc. Anche i file eliminati appaiono in quel file di registro con il relativo MD5 corrispondente.

Il file **`Cloud_graph\Cloud_graph.db`** è un database sqlite che contiene la tabella **`cloud_graph_entry`**. In questa tabella è possibile trovare il **nome** dei **file sincronizzati**, l'ora di modifica, la dimensione e il checksum MD5 dei file.

I dati della tabella del database **`Sync_config.db`** contengono l'indirizzo email dell'account, il percorso delle cartelle condivise e la versione di Google Drive.

## Dropbox

Dropbox utilizza **database SQLite** per gestire i file. In questo\
È possibile trovare i database nelle cartelle:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

E i principali database sono:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

L'estensione ".dbx" significa che i **database** sono **criptati**. Dropbox utilizza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Per capire meglio la crittografia utilizzata da Dropbox, puoi leggere [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Tuttavia, le informazioni principali sono:

* **Entropia**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritmo**: PBKDF2
* **Iterazioni**: 1066

Oltre a queste informazioni, per decrittare i database hai ancora bisogno di:

* La **chiave DPAPI crittografata**: Puoi trovarla nel registro all'interno di `NTUSER.DAT\Software\Dropbox\ks\client` (esporta questi dati come binario)
* I file **`SYSTEM`** e **`SECURITY`**
* Le **chiavi master DPAPI**: Che possono essere trovate in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Il **nome utente** e la **password** dell'utente Windows

Quindi puoi utilizzare lo strumento [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Se tutto va come previsto, lo strumento indicherà la **chiave primaria** che devi **usare per recuperare quella originale**. Per recuperare quella originale, utilizza questa [ricetta di cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) inserendo la chiave primaria come "passphrase" all'interno della ricetta.

L'hex risultante è la chiave finale utilizzata per crittografare i database che possono essere decrittati con:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Il database **`config.dbx`** contiene:

* **Email**: L'email dell'utente
* **usernamedisplayname**: Il nome dell'utente
* **dropbox\_path**: Percorso in cui si trova la cartella di Dropbox
* **Host\_id: Hash** utilizzato per l'autenticazione al cloud. Questo può essere revocato solo dal web.
* **Root\_ns**: Identificatore dell'utente

Il database **`filecache.db`** contiene informazioni su tutti i file e le cartelle sincronizzate con Dropbox. La tabella `File_journal` è quella con più informazioni utili:

* **Server\_path**: Percorso in cui si trova il file all'interno del server (questo percorso è preceduto dall'`host_id` del client).
* **local\_sjid**: Versione del file
* **local\_mtime**: Data di modifica
* **local\_ctime**: Data di creazione

Altre tabelle all'interno di questo database contengono informazioni più interessanti:

* **block\_cache**: hash di tutti i file e le cartelle di Dropbox
* **block\_ref**: Collega l'ID hash della tabella `block_cache` con l'ID del file nella tabella `file_journal`
* **mount\_table**: Cartelle condivise di Dropbox
* **deleted\_fields**: File eliminati da Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro supportati dagli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
