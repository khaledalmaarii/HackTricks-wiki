# macOS Schlüsselbund

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware**n **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihr Tool **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

***

## Haupt-Schlüsselbunde

* Der **Benutzer-Schlüsselbund** (`~/Library/Keychains/login.keycahin-db`), der dazu dient, **benutzerspezifische Anmeldeinformationen** wie Anwendungspasswörter, Internetpasswörter, benutzererstellte Zertifikate, Netzwerkpässe und benutzererstellte öffentliche/private Schlüssel zu speichern.
* Der **System-Schlüsselbund** (`/Library/Keychains/System.keychain`), der **systemweite Anmeldeinformationen** wie WLAN-Passwörter, Systemstammzertifikate, System-Private Keys und Systemanwendungspasswörter speichert.

### Zugriff auf Passwort-Schlüsselbund

Diese Dateien sind zwar nicht von Natur aus geschützt und können **heruntergeladen** werden, sind jedoch verschlüsselt und erfordern das **Klartextpasswort des Benutzers zur Entschlüsselung**. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) könnte zur Entschlüsselung verwendet werden.

## Schutz der Schlüsselbundeinträge

### Zugriffssteuerungslisten (ACLs)

Jeder Eintrag im Schlüsselbund wird von **Zugriffssteuerungslisten (ACLs)** geregelt, die festlegen, wer verschiedene Aktionen auf dem Schlüsselbundeintrag ausführen kann, einschließlich:

* **ACLAuhtorizationExportClear**: Ermöglicht dem Inhaber, den Klartext des Geheimnisses zu erhalten.
* **ACLAuhtorizationExportWrapped**: Ermöglicht dem Inhaber, den Klartext mit einem anderen bereitgestellten Passwort verschlüsselt zu erhalten.
* **ACLAuhtorizationAny**: Ermöglicht dem Inhaber, beliebige Aktionen auszuführen.

Die ACLs werden zusätzlich von einer **Liste vertrauenswürdiger Anwendungen** begleitet, die diese Aktionen ohne Aufforderung ausführen können. Dies könnte sein:

* **N`il`** (keine Autorisierung erforderlich, **jeder ist vertrauenswürdig**)
* Eine **leere** Liste (**niemand** ist vertrauenswürdig)
* **Liste** spezifischer **Anwendungen**.

Außerdem könnte der Eintrag den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der zur Identifizierung der **Team-ID, Apple** und **cdhash** verwendet wird.

* Wenn die **Team-ID** angegeben ist, muss die verwendete Anwendung die **gleiche Team-ID** haben, um auf den Eintragswert **ohne** Aufforderung zugreifen zu können.
* Wenn **Apple** angegeben ist, muss die App von **Apple signiert** sein.
* Wenn der **cdhash** angegeben ist, muss die App den spezifischen **cdhash** haben.

### Erstellen eines Schlüsselbundeintrags

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:

* Alle Apps können verschlüsseln.
* **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer aufzufordern).
* Alle Apps können die Integritätsprüfung sehen.
* Keine Apps können ACLs ändern.
* Die **PartitionID** ist auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Schlüsselbund erstellt**, gelten die Regeln etwas anders:

* Alle Apps können verschlüsseln.
* Nur die **erstellende Anwendung** (oder andere explizit hinzugefügte Apps) können exportieren/entschlüsseln (ohne den Benutzer aufzufordern).
* Alle Apps können die Integritätsprüfung sehen.
* Keine Apps können ACLs ändern.
* Die **PartitionID** ist auf **`teamid:[Team-ID hier]`** gesetzt.

## Zugriff auf den Schlüsselbund

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
Die **Auflistung und das Dumpen von Schlüsselbunden** von Geheimnissen, die **keine Aufforderung generieren**, können mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) durchgeführt werden.
{% endhint %}

Auflisten und **Informationen** zu jedem Schlüsselbundeintrag erhalten:

* Die API **`SecItemCopyMatching`** gibt Informationen zu jedem Eintrag und es gibt einige Attribute, die beim Verwenden festgelegt werden können:
* **`kSecReturnData`**: Wenn true, wird versucht, die Daten zu entschlüsseln (auf false setzen, um potenzielle Pop-ups zu vermeiden)
* **`kSecReturnRef`**: Erhalten Sie auch eine Referenz zum Schlüsselbundeintrag (auf true setzen, falls Sie später feststellen, dass Sie ohne Pop-up entschlüsseln können)
* **`kSecReturnAttributes`**: Metadaten zu Einträgen erhalten
* **`kSecMatchLimit`**: Wie viele Ergebnisse zurückgegeben werden sollen
* **`kSecClass`**: Art des Schlüsselbundeintrags

Erhalten Sie die **Zugriffssteuerungslisten (ACLs)** für jeden Eintrag:

* Mit der API **`SecAccessCopyACLList`** können Sie die **Zugriffssteuerungsliste für den Schlüsselbundeintrag** erhalten, und es wird eine Liste von ACLs zurückgegeben (wie `ACLAuhtorizationExportClear` und die zuvor genannten), wobei jede Liste Folgendes enthält:
* Beschreibung
* **Vertrauenswürdige Anwendungsliste**. Dies könnte sein:
* Eine App: /Applications/Slack.app
* Ein Binär: /usr/libexec/airportd
* Eine Gruppe: group://AirPort

Exportieren der Daten:

* Die API **`SecKeychainItemCopyContent`** gibt den Klartext zurück
* Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, aber möglicherweise müssen Passwörter festgelegt werden, um den Inhalt verschlüsselt zu exportieren

Und dies sind die **Anforderungen**, um ein Geheimnis **ohne Aufforderung zu exportieren**:

* Wenn **1+ vertraute** Apps aufgelistet sind:
* Benötigen die entsprechenden **Autorisierungen** (**`Nil`**, oder Teil der erlaubten Liste von Apps in der Autorisierung, um auf die geheimen Informationen zuzugreifen)
* Code-Signatur muss mit **PartitionID** übereinstimmen
* Code-Signatur muss mit der einer **vertrauten App** übereinstimmen (oder Mitglied der richtigen KeychainAccessGroup sein)
* Wenn **alle Anwendungen vertraut sind**:
* Benötigen die entsprechenden **Autorisierungen**
* Code-Signatur muss mit **PartitionID** übereinstimmen
* Wenn **keine PartitionID vorhanden ist**, ist dies nicht erforderlich

{% hint style="danger" %}
Daher, wenn **eine Anwendung aufgeführt ist**, müssen Sie **Code in diese Anwendung einschleusen**.

Wenn **Apple** in der **PartitionID** angegeben ist, könnten Sie darauf mit **`osascript`** zugreifen, sodass alles, was allen Anwendungen mit Apple in der PartitionID vertraut, darauf zugreifen kann. **`Python`** könnte auch dafür verwendet werden.
{% endhint %}

### Zwei zusätzliche Attribute

* **Unsichtbar**: Es handelt sich um ein boolesches Flag, um den Eintrag aus der **UI** Schlüsselbund-App zu **verstecken**
* **Allgemein**: Dient zur Speicherung von **Metadaten** (daher NICHT VERSCHLÜSSELT)
* Microsoft speicherte alle Auffrischungstoken zum Zugriff auf sensible Endpunkte im Klartext.

## Referenzen

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von der **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware**n **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Suchmaschine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
{% endhint %}
