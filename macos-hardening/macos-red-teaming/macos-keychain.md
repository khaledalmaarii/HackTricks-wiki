# macOS Schlüsselbund

<details>

<summary>Lernen Sie das Hacken von AWS von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die HackTricks- und HackTricks Cloud-GitHub-Repositories senden.

</details>

## Haupt-Schlüsselbünde

- Der **Benutzer-Schlüsselbund** (`~/Library/Keychains/login.keycahin-db`), der zum Speichern von benutzerspezifischen Anmeldeinformationen wie Anwendungspasswörtern, Internetpasswörtern, benutzergenerierten Zertifikaten, Netzwerkpässen und benutzergenerierten öffentlichen/privaten Schlüsseln verwendet wird.
- Der **System-Schlüsselbund** (`/Library/Keychains/System.keychain`), der systemweite Anmeldeinformationen wie WLAN-Passwörter, Systemstammzertifikate, System-Private Keys und Systemanwendungspasswörter speichert.

### Zugriff auf den Passwort-Schlüsselbund

Diese Dateien sind zwar nicht inhärent geschützt und können heruntergeladen werden, sind jedoch verschlüsselt und erfordern das Klartextpasswort des Benutzers, um entschlüsselt zu werden. Ein Tool wie [Chainbreaker](https://github.com/n0fate/chainbreaker) kann zur Entschlüsselung verwendet werden.

## Schutz der Schlüsselbund-Einträge

### ACLs

Jeder Eintrag im Schlüsselbund wird durch Zugriffssteuerungslisten (ACLs) geregelt, die festlegen, wer verschiedene Aktionen auf den Schlüsselbund-Eintrag ausführen kann, einschließlich:

- **ACLAuhtorizationExportClear**: Ermöglicht dem Inhaber das Abrufen des Klartexts des Geheimnisses.
- **ACLAuhtorizationExportWrapped**: Ermöglicht dem Inhaber das Abrufen des Klartexts, der mit einem anderen bereitgestellten Passwort verschlüsselt ist.
- **ACLAuhtorizationAny**: Ermöglicht dem Inhaber das Ausführen beliebiger Aktionen.

Die ACLs werden durch eine Liste vertrauenswürdiger Anwendungen ergänzt, die diese Aktionen ohne Aufforderung ausführen können. Dies könnte sein:

- **N`il`** (keine Autorisierung erforderlich, **jeder ist vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- **Liste** spezifischer **Anwendungen**.

Der Eintrag kann auch den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **Team-ID, Apple** und **cdhash** verwendet wird.

- Wenn die **Team-ID** angegeben ist, muss die verwendete Anwendung die **gleiche Team-ID** haben, um auf den Eintragswert **ohne Aufforderung** zugreifen zu können.
- Wenn **Apple** angegeben ist, muss die App von **Apple** signiert sein.
- Wenn **cdhash** angegeben ist, muss die App den spezifischen **cdhash** haben.

### Erstellen eines Schlüsselbund-Eintrags

Beim Erstellen eines **neuen Eintrags** mit **`Keychain Access.app`** gelten folgende Regeln:

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer zur Eingabe aufzufordern).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **PartitionID** ist auf **`apple`** festgelegt.

Wenn eine **Anwendung einen Eintrag im Schlüsselbund erstellt**, gelten leicht unterschiedliche Regeln:

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere explizit hinzugefügte Apps) können exportieren/entschlüsseln (ohne den Benutzer zur Eingabe aufzufordern).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **PartitionID** ist auf **`teamid:[Team-ID hier]`** festgelegt.

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
Die **Aufzählung und das Auslesen** von Geheimnissen im Schlüsselbund, die **keine Aufforderung generieren**, können mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) durchgeführt werden.
{% endhint %}

Liste und erhalte **Informationen** zu jedem Eintrag im Schlüsselbund:

* Die API **`SecItemCopyMatching`** gibt Informationen zu jedem Eintrag zurück und es gibt einige Attribute, die beim Verwenden festgelegt werden können:
* **`kSecReturnData`**: Wenn true, wird versucht, die Daten zu entschlüsseln (auf false setzen, um potenzielle Pop-ups zu vermeiden)
* **`kSecReturnRef`**: Erhalte auch eine Referenz auf den Schlüsselbundeintrag (auf true setzen, falls du später feststellst, dass du ohne Pop-up entschlüsseln kannst)
* **`kSecReturnAttributes`**: Erhalte Metadaten zu den Einträgen
* **`kSecMatchLimit`**: Wie viele Ergebnisse zurückgegeben werden sollen
* **`kSecClass`**: Welche Art von Schlüsselbundeintrag

Erhalte die **ACLs** für jeden Eintrag:

* Mit der API **`SecAccessCopyACLList`** kannst du die **ACL für den Schlüsselbundeintrag** abrufen und es wird eine Liste von ACLs zurückgegeben (wie `ACLAuhtorizationExportClear` und die zuvor erwähnten), wobei jede Liste Folgendes enthält:
* Beschreibung
* **Vertrauenswürdige Anwendungsliste**. Dies kann sein:
* Eine App: /Applications/Slack.app
* Eine Binärdatei: /usr/libexec/airportd
* Eine Gruppe: group://AirPort

Exportiere die Daten:

* Die API **`SecKeychainItemCopyContent`** gibt den Klartext zurück
* Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, aber es müssen möglicherweise Passwörter festgelegt werden, um den Inhalt verschlüsselt zu exportieren

Und dies sind die **Anforderungen**, um ein Geheimnis **ohne Aufforderung** exportieren zu können:

* Wenn **1 oder mehr vertrauenswürdige** Apps aufgelistet sind:
* Benötige die entsprechenden **Autorisierungen** (**`Nil`** oder Teil der erlaubten Liste von Apps in der Autorisierung, um auf die geheimen Informationen zugreifen zu können)
* Die Codesignatur muss mit der **PartitionID** übereinstimmen
* Die Codesignatur muss mit der einer **vertrauenswürdigen App** übereinstimmen (oder ein Mitglied der richtigen KeychainAccessGroup sein)
* Wenn **alle Anwendungen vertrauenswürdig** sind:
* Benötige die entsprechenden **Autorisierungen**
* Die Codesignatur muss mit der **PartitionID** übereinstimmen
* Wenn **keine PartitionID** vorhanden ist, ist dies nicht erforderlich

{% hint style="danger" %}
Daher musst du, wenn **1 Anwendung aufgelistet ist**, Code in diese Anwendung **einschleusen**.

Wenn **apple** in der **PartitionID** angegeben ist, kannst du über **`osascript`** darauf zugreifen. Alles, was allen Anwendungen mit apple in der PartitionID vertraut, kann verwendet werden. **`Python`** kann ebenfalls dafür verwendet werden.
{% endhint %}

### Zwei zusätzliche Attribute

* **Invisible**: Es handelt sich um ein boolesches Flag, um den Eintrag in der **UI** Keychain-App zu **verbergen**
* **General**: Es dient zur Speicherung von **Metadaten** (es ist also NICHT VERSCHLÜSSELT)
* Microsoft hat alle Auffrischungstoken zum Zugriff auf sensible Endpunkte im Klartext gespeichert.

## Referenzen

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Lerne das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn du dein **Unternehmen in HackTricks bewerben möchtest** oder **HackTricks als PDF herunterladen** möchtest, sieh dir die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Hol dir das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecke [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teile deine Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repos** sendest.

</details>
