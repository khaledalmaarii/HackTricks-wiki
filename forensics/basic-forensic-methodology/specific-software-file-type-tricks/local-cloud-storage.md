# Plaaslike Wolk Berging

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkvloei te outomatiseer** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

In Windows kan jy die OneDrive-gids vind in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind wat interessante data bevat rakende die gesinkroniseerde lêers:

* Grootte in bytes
* Skeppingsdatum
* Wysigingsdatum
* Aantal lêers in die wolk
* Aantal lêers in die gids
* **CID**: Unieke ID van die OneDrive-gebruiker
* Verslaggenerasietyd
* Grootte van die HD van die OS

Sodra jy die CID gevind het, word dit aanbeveel om **lêers te soek wat hierdie ID bevat**. Jy mag dalk lêers met die naam: _**\<CID>.ini**_ en _**\<CID>.dat**_ vind wat interessante inligting kan bevat soos die name van lêers wat met OneDrive gesinkroniseer is.

## Google Drive

In Windows kan jy die hoof Google Drive-gids vind in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Hierdie gids bevat 'n lêer genaamd Sync\_log.log met inligting soos die e-posadres van die rekening, lêernaam, tydstempels, MD5-hashes van die lêers, ens. Selfs verwyderde lêers verskyn in daardie loglêer met die ooreenstemmende MD5.

Die lêer **`Cloud_graph\Cloud_graph.db`** is 'n sqlite-databasis wat die tabel **`cloud_graph_entry`** bevat. In hierdie tabel kan jy die **naam** van die **gesinkroniseerde** **lêers**, gewysigde tyd, grootte, en die MD5-has van die lêers vind.

Die tabeldata van die databasis **`Sync_config.db`** bevat die e-posadres van die rekening, die pad van die gedeelde gidse en die Google Drive weergawe.

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur. In hierdie\
Jy kan die databasisse in die gidse vind:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

En die hoofdatabasisse is:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Die ".dbx" uitbreiding beteken dat die **databasisse** **versleuteld** is. Dropbox gebruik **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Om beter te verstaan die versleuteling wat Dropbox gebruik, kan jy lees [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Tog, die hoofinligting is:

* **Entropie**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritme**: PBKDF2
* **Herhalings**: 1066

Afgesien van daardie inligting, om die databasisse te ontsleutel, het jy steeds nodig:

* Die **versleutelde DPAPI-sleutel**: Jy kan dit in die register vind binne `NTUSER.DAT\Software\Dropbox\ks\client` (eksporteer hierdie data as binêr)
* Die **`SYSTEM`** en **`SECURITY`** hives
* Die **DPAPI meester sleutels**: Wat in `\Users\<username>\AppData\Roaming\Microsoft\Protect` gevind kan word
* Die **gebruikersnaam** en **wagwoord** van die Windows-gebruiker

Dan kan jy die hulpmiddel [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

As alles volgens verwagting verloop, sal die hulpmiddel die **primêre sleutel** aandui wat jy moet **gebruik om die oorspronklike een te herstel**. Om die oorspronklike een te herstel, gebruik net hierdie [cyber\_chef resep](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) en plaas die primêre sleutel as die "wagfrase" binne die resep.

Die resulterende hex is die finale sleutel wat gebruik word om die databasisse te versleutel wat ontsleuteld kan word met:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** databasis bevat:

* **Email**: Die e-pos van die gebruiker
* **usernamedisplayname**: Die naam van die gebruiker
* **dropbox\_path**: Pad waar die dropbox-gids geleë is
* **Host\_id: Hash** wat gebruik word om aan die wolk te autentiseer. Dit kan slegs vanaf die web herroep word.
* **Root\_ns**: Gebruiker identifiseerder

Die **`filecache.db`** databasis bevat inligting oor al die lêers en gidse wat met Dropbox gesinkroniseer is. Die tabel `File_journal` is die een met die meeste nuttige inligting:

* **Server\_path**: Pad waar die lêer binne die bediener geleë is (hierdie pad word voorafgegaan deur die `host_id` van die kliënt).
* **local\_sjid**: Weergawe van die lêer
* **local\_mtime**: Wysigingsdatum
* **local\_ctime**: Skeppingsdatum

Ander tabelle binne hierdie databasis bevat meer interessante inligting:

* **block\_cache**: hash van al die lêers en gidse van Dropbox
* **block\_ref**: Verbind die hash ID van die tabel `block_cache` met die lêer ID in die tabel `file_journal`
* **mount\_table**: Deel gidse van dropbox
* **deleted\_fields**: Dropbox verwyderde lêers
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkvloei** te **automate** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
