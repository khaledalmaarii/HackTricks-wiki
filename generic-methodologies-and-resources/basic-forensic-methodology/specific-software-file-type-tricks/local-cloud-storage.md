# Lokale Cloud-Speicherung

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

In Windows finden Sie den OneDrive-Ordner in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Und im Inneren von `logs\Personal` ist es möglich, die Datei `SyncDiagnostics.log` zu finden, die einige interessante Daten zu den synchronisierten Dateien enthält:

* Größe in Bytes
* Erstellungsdatum
* Änderungsdatum
* Anzahl der Dateien in der Cloud
* Anzahl der Dateien im Ordner
* **CID**: Eindeutige ID des OneDrive-Benutzers
* Zeit der Berichtserstellung
* Größe der HD des Betriebssystems

Sobald Sie die CID gefunden haben, wird empfohlen, **nach Dateien zu suchen, die diese ID enthalten**. Möglicherweise finden Sie Dateien mit den Namen: _**\<CID>.ini**_ und _**\<CID>.dat**_, die interessante Informationen wie die Namen der mit OneDrive synchronisierten Dateien enthalten können.

## Google Drive

In Windows finden Sie den Hauptordner von Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Dieser Ordner enthält eine Datei namens Sync\_log.log mit Informationen wie der E-Mail-Adresse des Kontos, Dateinamen, Zeitstempeln, MD5-Hashes der Dateien usw. Selbst gelöschte Dateien erscheinen in dieser Protokolldatei mit dem entsprechenden MD5.

Die Datei **`Cloud_graph\Cloud_graph.db`** ist eine SQLite-Datenbank, die die Tabelle **`cloud_graph_entry`** enthält. In dieser Tabelle finden Sie den **Namen** der **synchronisierten** **Dateien**, die Änderungszeit, Größe und die MD5-Prüfziffer der Dateien.

Die Tabellendaten der Datenbank **`Sync_config.db`** enthalten die E-Mail-Adresse des Kontos, den Pfad der freigegebenen Ordner und die Google Drive-Version.

## Dropbox

Dropbox verwendet **SQLite-Datenbanken**, um die Dateien zu verwalten. In diesem\
Sie finden die Datenbanken in den Ordnern:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Und die Hauptdatenbanken sind:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Die ".dbx"-Erweiterung bedeutet, dass die **Datenbanken** **verschlüsselt** sind. Dropbox verwendet **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Um die Verschlüsselung, die Dropbox verwendet, besser zu verstehen, können Sie [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lesen.

Die wichtigsten Informationen sind jedoch:

* **Entropie**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithmus**: PBKDF2
* **Iterationen**: 1066

Neben diesen Informationen benötigen Sie zur Entschlüsselung der Datenbanken auch:

* Den **verschlüsselten DPAPI-Schlüssel**: Sie finden ihn in der Registrierung unter `NTUSER.DAT\Software\Dropbox\ks\client` (exportieren Sie diese Daten als Binärdatei)
* Die **`SYSTEM`**- und **`SECURITY`**-Hives
* Die **DPAPI-Master-Schlüssel**: Diese finden Sie in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Den **Benutzernamen** und das **Passwort** des Windows-Benutzers

Dann können Sie das Tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Wenn alles wie erwartet verläuft, zeigt das Tool den **primären Schlüssel** an, den Sie **verwenden müssen, um den ursprünglichen wiederherzustellen**. Um den ursprünglichen wiederherzustellen, verwenden Sie einfach dieses [cyber\_chef-Rezept](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)), wobei der primäre Schlüssel als "Passphrase" im Rezept eingegeben wird.

Das resultierende Hex ist der endgültige Schlüssel, der zur Verschlüsselung der Datenbanken verwendet wird, die entschlüsselt werden können mit:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`** Datenbank enthält:

* **Email**: Die E-Mail des Benutzers
* **usernamedisplayname**: Der Name des Benutzers
* **dropbox\_path**: Pfad, wo der Dropbox-Ordner gespeichert ist
* **Host\_id: Hash** verwendet zur Authentifizierung in der Cloud. Dies kann nur über das Web widerrufen werden.
* **Root\_ns**: Benutzeridentifikator

Die **`filecache.db`** Datenbank enthält Informationen über alle Dateien und Ordner, die mit Dropbox synchronisiert sind. Die Tabelle `File_journal` enthält die nützlichsten Informationen:

* **Server\_path**: Pfad, wo die Datei auf dem Server gespeichert ist (dieser Pfad wird durch die `host_id` des Clients vorangestellt).
* **local\_sjid**: Version der Datei
* **local\_mtime**: Änderungsdatum
* **local\_ctime**: Erstellungsdatum

Andere Tabellen in dieser Datenbank enthalten interessantere Informationen:

* **block\_cache**: Hash aller Dateien und Ordner von Dropbox
* **block\_ref**: Verknüpft die Hash-ID der Tabelle `block_cache` mit der Datei-ID in der Tabelle `file_journal`
* **mount\_table**: Freigegebene Ordner von Dropbox
* **deleted\_fields**: Gelöschte Dateien von Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
