# Plaaslike Wolkmagazyn

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) om maklik te bou en **outomatiseer werkstrome** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

In Windows kan jy die OneDrive-folder vind in `\Users\<gebruikersnaam>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind wat 'n paar interessante data bevat rakende die gesinkroniseerde lêers:

* Grootte in bytes
* Skeppingsdatum
* Wysigingsdatum
* Aantal lêers in die wolk
* Aantal lêers in die folder
* **CID**: Unieke ID van die OneDrive-gebruiker
* Verslaggenereringstyd
* Grootte van die HD van die OS

Sodra jy die CID gevind het, word dit aanbeveel om **lêers te soek wat hierdie ID bevat**. Jy mag lêers met die naam vind: _**\<CID>.ini**_ en _**\<CID>.dat**_ wat interessante inligting kan bevat soos die name van lêers wat met OneDrive gesinkroniseer is.

## Google Drive

In Windows kan jy die hoof Google Drive-folder vind in `\Users\<gebruikersnaam>\AppData\Local\Google\Drive\user_default`\
Hierdie folder bevat 'n lêer genaamd Sync\_log.log met inligting soos die e-posadres van die rekening, lêernaam, tydstempels, MD5-hashes van die lêers, ens. Selfs verwyderde lêers verskyn in daardie log-lêer met die ooreenstemmende MD5.

Die lêer **`Cloud_graph\Cloud_graph.db`** is 'n sqlite-databasis wat die tabel **`cloud_graph_entry`** bevat. In hierdie tabel kan jy die **naam** van die **gesinkroniseerde** **lêers**, gewysigde tyd, grootte, en die MD5-kontrolesom van die lêers vind.

Die tabeldata van die databasis **`Sync_config.db`** bevat die e-posadres van die rekening, die pad van die gedeelde lêers en die Google Drive-weergawe.

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur. Hierdie\
Jy kan die databasisse vind in die volgende folders:

* `\Users\<gebruikersnaam>\AppData\Local\Dropbox`
* `\Users\<gebruikersnaam>\AppData\Local\Dropbox\Instance1`
* `\Users\<gebruikersnaam>\AppData\Roaming\Dropbox`

En die hoofdatabasisse is:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Die ".dbx"-uitbreiding beteken dat die **databasisse** **gekripteer** is. Dropbox gebruik **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Om die kriptering wat Dropbox gebruik beter te verstaan, kan jy lees [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Nietemin, die hoofinligting is:

* **Entropie**: d114a55212655f74bd772e37e64aee9b
* **Sout**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritme**: PBKDF2
* **Iterasies**: 1066

Afgesien van daardie inligting, om die databasisse te dekripteer, het jy steeds nodig:

* Die **gekripteerde DPAPI-sleutel**: Jy kan dit in die register binne `NTUSER.DAT\Software\Dropbox\ks\client` vind (eksporteer hierdie data as binêr)
* Die **`SYSTEM`** en **`SECURITY`**-bytjies
* Die **DPAPI-meestersleutels**: Wat gevind kan word in `\Users\<gebruikersnaam>\AppData\Roaming\Microsoft\Protect`
* Die **gebruikersnaam** en **wagwoord** van die Windows-gebruiker

Dan kan jy die instrument [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)** gebruik:**

![](<../../../.gitbook/assets/image (443).png>)

As alles soos verwag verloop, sal die instrument die **primêre sleutel** aandui wat jy moet gebruik om die oorspronklike een te herstel. Om die oorspronklike een te herstel, gebruik net hierdie [cyber\_chef kwitansie](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\) deur die primêre sleutel as die "wagwoord" binne die kwitansie te plaas.

Die resulterende heks is die finale sleutel wat gebruik word om die databasisse te kripteer wat gedekripteer kan word met:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`** databasis bevat:

- **E-pos**: Die e-pos van die gebruiker
- **usernamedisplayname**: Die naam van die gebruiker
- **dropbox\_path**: Pad waar die dropbox vouer geleë is
- **Host\_id: Hash** wat gebruik word om na die wolk te verifieer. Dit kan slegs van die web af herroep word.
- **Root\_ns**: Gebruiker-identifiseerder

Die **`filecache.db`** databasis bevat inligting oor al die lêers en vouers wat gesinkroniseer is met Dropbox. Die tabel `File_journal` is die een met die meeste nuttige inligting:

- **Server\_path**: Pad waar die lêer binne die bediener geleë is (hierdie pad word voorafgegaan deur die `host_id` van die klient).
- **local\_sjid**: Weergawe van die lêer
- **local\_mtime**: Wysigingsdatum
- **local\_ctime**: Skeppingsdatum

Ander tabelle binne hierdie databasis bevat meer interessante inligting:

- **block\_cache**: hasj van al die lêers en vouers van Dropbox
- **block\_ref**: Verband die hasj-ID van die tabel `block_cache` met die lêer-ID in die tabel `file_journal`
- **mount\_table**: Deel vouers van dropbox
- **deleted\_fields**: Dropbox verwyderde lêers
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) om maklik te bou en **outomatiseer werkafvloei** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

- As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
- Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
- Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
