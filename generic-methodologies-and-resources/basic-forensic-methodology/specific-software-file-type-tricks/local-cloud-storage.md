# Lokaler Cloud-Speicher

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys senden.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mithilfe der weltweit **fortschrittlichsten Community-Tools** **Workflows zu erstellen und zu automatisieren**.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

In Windows finden Sie den OneDrive-Ordner unter `\Users\<Benutzername>\AppData\Local\Microsoft\OneDrive`. Und im Ordner `logs\Personal` ist es möglich, die Datei `SyncDiagnostics.log` zu finden, die einige interessante Daten zu den synchronisierten Dateien enthält:

* Größe in Bytes
* Erstellungsdatum
* Änderungsdatum
* Anzahl der Dateien in der Cloud
* Anzahl der Dateien im Ordner
* **CID**: Eindeutige ID des OneDrive-Benutzers
* Berichterstellungszeit
* Größe der Festplatte des Betriebssystems

Nachdem Sie die CID gefunden haben, wird empfohlen, **Dateien zu suchen, die diese ID enthalten**. Möglicherweise finden Sie Dateien mit den Namen: _**\<CID>.ini**_ und _**\<CID>.dat**_, die interessante Informationen wie die Namen der mit OneDrive synchronisierten Dateien enthalten können.

## Google Drive

In Windows finden Sie den Haupt-Google Drive-Ordner unter `\Users\<Benutzername>\AppData\Local\Google\Drive\user_default`\
Dieser Ordner enthält eine Datei namens Sync\_log.log mit Informationen wie der E-Mail-Adresse des Kontos, Dateinamen, Zeitstempel, MD5-Hashes der Dateien usw. Selbst gelöschte Dateien erscheinen in dieser Protokolldatei mit dem entsprechenden MD5.

Die Datei **`Cloud_graph\Cloud_graph.db`** ist eine SQLite-Datenbank, die die Tabelle **`cloud_graph_entry`** enthält. In dieser Tabelle finden Sie den **Namen** der **synchronisierten** **Dateien**, das Änderungsdatum, die Größe und den MD5-Prüfsummenwert der Dateien.

Die Tabellendaten der Datenbank **`Sync_config.db`** enthalten die E-Mail-Adresse des Kontos, den Pfad der freigegebenen Ordner und die Google Drive-Version.

## Dropbox

Dropbox verwendet **SQLite-Datenbanken** zur Verwaltung der Dateien. In diesen\
Sie finden die Datenbanken in den Ordnern:

* `\Users\<Benutzername>\AppData\Local\Dropbox`
* `\Users\<Benutzername>\AppData\Local\Dropbox\Instance1`
* `\Users\<Benutzername>\AppData\Roaming\Dropbox`

Und die Hauptdatenbanken sind:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Die Erweiterung ".dbx" bedeutet, dass die **Datenbanken verschlüsselt** sind. Dropbox verwendet **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Um das von Dropbox verwendete Verschlüsselungsverfahren besser zu verstehen, können Sie [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lesen.

Die wichtigsten Informationen sind jedoch:

* **Entropie**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithmus**: PBKDF2
* **Iterationen**: 1066

Neben diesen Informationen benötigen Sie zum Entschlüsseln der Datenbanken noch:

* Den **verschlüsselten DPAPI-Schlüssel**: Sie finden ihn in der Registrierung unter `NTUSER.DAT\Software\Dropbox\ks\client` (exportieren Sie diese Daten als Binärdatei)
* Die **`SYSTEM`**- und **`SECURITY`**-Hives
* Die **DPAPI-Meisterschlüssel**: Diese finden Sie in `\Users\<Benutzername>\AppData\Roaming\Microsoft\Protect`
* Den **Benutzernamen** und das **Passwort** des Windows-Benutzers

Dann können Sie das Tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)** verwenden:**

![](<../../../.gitbook/assets/image (448).png>)

Wenn alles wie erwartet verläuft, zeigt das Tool den **Primärschlüssel** an, den Sie benötigen, um den ursprünglichen Schlüssel wiederherzustellen. Um den ursprünglichen Schlüssel wiederherzustellen, verwenden Sie einfach dieses [Cyber\_Chef-Rezept](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\) und setzen den Primärschlüssel als "Passphrase" in das Rezept.

Der resultierende Hexadezimalwert ist der endgültige Schlüssel, der zur Verschlüsselung der Datenbanken verwendet wird und mit dem entschlüsselt werden kann:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die Datenbank **`config.dbx`** enthält:

- **E-Mail**: Die E-Mail des Benutzers
- **usernamedisplayname**: Der Name des Benutzers
- **dropbox\_path**: Pfad, in dem sich der Dropbox-Ordner befindet
- **Host\_id: Hash** zur Authentifizierung in der Cloud. Dies kann nur über das Web widerrufen werden.
- **Root\_ns**: Benutzerkennung

Die Datenbank **`filecache.db`** enthält Informationen zu allen Dateien und Ordnern, die mit Dropbox synchronisiert sind. Die Tabelle `File_journal` enthält die meisten nützlichen Informationen:

- **Server\_path**: Pfad, in dem sich die Datei auf dem Server befindet (dieser Pfad wird vom `host_id` des Clients vorangestellt).
- **local\_sjid**: Version der Datei
- **local\_mtime**: Änderungsdatum
- **local\_ctime**: Erstellungsdatum

Andere Tabellen in dieser Datenbank enthalten weitere interessante Informationen:

- **block\_cache**: Hash aller Dateien und Ordner von Dropbox
- **block\_ref**: Verknüpft die Hash-ID der Tabelle `block_cache` mit der Datei-ID in der Tabelle `file_journal`
- **mount\_table**: Freigegebene Ordner von Dropbox
- **deleted\_fields**: Gelöschte Dateien von Dropbox
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos Workflows zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
- Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
