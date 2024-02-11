# Plaaslike Wolklêerstoor

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en outomatiseer met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

In Windows kan jy die OneDrive-vouer vind in `\Users\<gebruikersnaam>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind wat interessante data bevat oor die gesinkroniseerde lêers:

* Grootte in bytes
* Skeppingsdatum
* Wysigingsdatum
* Aantal lêers in die wolk
* Aantal lêers in die vouer
* **CID**: Unieke ID van die OneDrive-gebruiker
* Verslaggenereringstyd
* Grootte van die bedryfstelsel se harde skyf

Nadat jy die CID gevind het, word dit aanbeveel om **lêers te soek wat hierdie ID bevat**. Jy kan lêers met die naam vind: _**\<CID>.ini**_ en _**\<CID>.dat**_ wat interessante inligting kan bevat, soos die name van lêers wat met OneDrive gesinkroniseer is.

## Google Drive

In Windows kan jy die hoof Google Drive-vouer vind in `\Users\<gebruikersnaam>\AppData\Local\Google\Drive\user_default`\
Hierdie vouer bevat 'n lêer genaamd Sync\_log.log met inligting soos die e-posadres van die rekening, lêernaam, tydstempels, MD5-hashes van die lêers, ens. Selfs uitgevee lêers verskyn in daardie loglêer met die ooreenstemmende MD5.

Die lêer **`Cloud_graph\Cloud_graph.db`** is 'n sqlite-databasis wat die tabel **`cloud_graph_entry`** bevat. In hierdie tabel kan jy die **naam** van die **gesinkroniseerde** **lêers**, gewysigde tyd, grootte en die MD5-kontrolegetal van die lêers vind.

Die tabeldata van die databasis **`Sync_config.db`** bevat die e-posadres van die rekening, die pad van die gedeelde vouers en die Google Drive-weergawe.

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur. In hierdie\
Jy kan die databasisse in die volgende vouers vind:

* `\Users\<gebruikersnaam>\AppData\Local\Dropbox`
* `\Users\<gebruikersnaam>\AppData\Local\Dropbox\Instance1`
* `\Users\<gebruikersnaam>\AppData\Roaming\Dropbox`

En die belangrikste databasisse is:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Die ".dbx"-uitbreiding beteken dat die **databasisse** **gekripteer** is. Dropbox gebruik **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Om die kriptering wat Dropbox gebruik beter te verstaan, kan jy lees [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Die belangrikste inligting is egter:

* **Entropie**: d114a55212655f74bd772e37e64aee9b
* **Sout**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritme**: PBKDF2
* **Iterasies**: 1066

Afgesien van daardie inligting, om die databasisse te ontsluit, het jy steeds nodig:

* Die **gekripteerde DPAPI-sleutel**: Jy kan dit in die register vind binne `NTUSER.DAT\Software\Dropbox\ks\client` (voer hierdie data uit as binêr)
* Die **`SYSTEM`** en **`SECURITY`**-bytjies
* Die **DPAPI-hoofsleutels**: Wat gevind kan word in `\Users\<gebruikersnaam>\AppData\Roaming\Microsoft\Protect`
* Die **gebruikersnaam** en **wagwoord** van die Windows-gebruiker

Dan kan jy die instrument [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)** gebruik:**

![](<../../../.gitbook/assets/image (448).png>)

As alles soos verwag verloop, sal die instrument die **primêre sleutel** aandui wat jy moet **gebruik om die oorspronklike sleutel te herstel**. Om die oorspronklike sleutel te herstel, gebruik jy net hierdie [cyber\_chef-resep](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) en plaas die primêre sleutel as die "wagwoord" binne die resep.

Die resulterende heks is die finale sleutel wat gebruik word om die databasisse te kripteer, wat ontsluit kan word met:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`** databasis bevat:

* **E-pos**: Die e-pos van die gebruiker
* **usernamedisplayname**: Die naam van die gebruiker
* **dropbox\_path**: Pad waar die Dropbox-lys geleë is
* **Host\_id: Hash** wat gebruik word om te verifieer by die wolk. Dit kan slegs vanaf die web herroep word.
* **Root\_ns**: Gebruikersidentifiseerder

Die **`filecache.db`** databasis bevat inligting oor al die lêers en vouers wat met Dropbox gesinchroniseer is. Die tabel `File_journal` bevat die meeste nuttige inligting:

* **Server\_path**: Pad waar die lêer binne die bediener geleë is (hierdie pad word voorafgegaan deur die `host_id` van die kliënt).
* **local\_sjid**: Weergawe van die lêer
* **local\_mtime**: Wysigingsdatum
* **local\_ctime**: Skeppingsdatum

Ander tabelle binne hierdie databasis bevat meer interessante inligting:

* **block\_cache**: hash van al die lêers en vouers van Dropbox
* **block\_ref**: Verbind die hash-ID van die tabel `block_cache` met die lêer-ID in die tabel `file_journal`
* **mount\_table**: Deel vouers van Dropbox
* **deleted\_fields**: Dropbox verwyderde lêers
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en outomatiseer met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
