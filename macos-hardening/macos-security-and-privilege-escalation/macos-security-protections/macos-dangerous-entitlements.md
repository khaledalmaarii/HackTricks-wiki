# macOS Gefährliche Berechtigungen & TCC-Berechtigungen

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

{% hint style="warning" %}
Beachten Sie, dass Berechtigungen, die mit **`com.apple`** beginnen, nicht für Drittanbieter verfügbar sind, nur Apple kann sie gewähren.
{% endhint %}

## Hoch

### `com.apple.rootless.install.heritable`

Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht es, **SIP zu umgehen**. Überprüfen Sie [hier für weitere Informationen](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die Berechtigung **`com.apple.rootless.install`** ermöglicht es, **SIP zu umgehen**. Überprüfen Sie [dies für weitere Informationen](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (früher `task_for_pid-allow` genannt)**

Diese Berechtigung ermöglicht es, den **Task-Port für jeden** Prozess außer dem Kernel zu erhalten. Überprüfen Sie [**dies für weitere Informationen**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Diese Berechtigung ermöglicht es anderen Prozessen mit der Berechtigung **`com.apple.security.cs.debugger`**, den Task-Port des Prozesses, der vom Binärcode mit dieser Berechtigung ausgeführt wird, zu erhalten und **Code einzuspeisen**. Überprüfen Sie [**dies für weitere Informationen**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps mit der Debugging-Tool-Berechtigung können `task_for_pid()` aufrufen, um einen gültigen Task-Port für nicht signierte und Drittanbieter-Apps mit der Berechtigung `Get Task Allow` auf `true` abzurufen. Selbst mit der Debugging-Tool-Berechtigung kann ein Debugger jedoch **nicht die Task-Ports** von Prozessen erhalten, die **nicht über die `Get Task Allow`-Berechtigung verfügen** und daher durch die System Integrity Protection geschützt sind. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Diese Berechtigung ermöglicht es, Frameworks, Plug-ins oder Bibliotheken zu laden, die weder von Apple signiert sind noch mit derselben Team-ID wie die Hauptausführbare Datei signiert sind, sodass ein Angreifer missbräuchlich eine beliebige Bibliothek laden kann, um Code einzuspeisen. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Diese Berechtigung ist sehr ähnlich wie **`com.apple.security.cs.disable-library-validation`**, aber **anstatt** die Bibliotheksvalidierung direkt zu deaktivieren, ermöglicht sie dem Prozess, einen `csops`-Systemaufruf zu tätigen, um sie zu deaktivieren.\
Überprüfen Sie [**dies für weitere Informationen**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Diese Berechtigung ermöglicht es, DYLD-Umgebungsvariablen zu verwenden, die zum Einspeisen von Bibliotheken und Code verwendet werden können. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

Laut [**diesem Blog**](https://objective-see.org/blog/blog\_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) ermöglichen diese Berechtigungen die **Änderung** der **TCC**-Datenbank.

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Berechtigungen ermöglichen es, Software **ohne die Erlaubnis des Benutzers zu installieren**, was für eine **Privilege Escalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Berechtigung erforderlich, um den **Kernel zur Ladung einer Kernelerweiterung** aufzufordern.

### **`com.apple.private.icloud-account-access`**

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC-Dienst zu kommunizieren, der **iCloud-Token bereitstellt**.

**iMovie** und **Garageband** hatten diese Berechtigung.

Für weitere **Informationen** über den Exploit zum **Erhalt von iCloud-Token** aus dieser Berechtigung sehen Sie sich den Vortrag an: [**#OBTS v5.0: "Was auf Ihrem Mac passiert, bleibt in Apples iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies ermöglicht

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die nach einem Neustart geschützten SSV-Inhalte zu aktualisieren. Wenn Sie wissen, wie, senden Sie bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die nach einem Neustart geschützten SSV-Inhalte zu aktualisieren. Wenn Sie wissen, wie, senden Sie bitte einen PR!

### `keychain-access-groups`

Diese Berechtigung listet die **Schlüsselbundgruppen** auf, auf die die Anwendung Zugriff hat:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Gibt Berechtigungen für **Voller Festplattenzugriff**, eine der höchsten Berechtigungen, die Sie haben können.

### **`kTCCServiceAppleEvents`**

Ermöglicht der App, Ereignisse an andere Anwendungen zu senden, die häufig für die **Automatisierung von Aufgaben** verwendet werden. Durch die Kontrolle anderer Apps kann sie die den anderen Apps gewährten Berechtigungen missbrauchen.

Indem sie sie dazu bringt, den Benutzer nach seinem Passwort zu fragen:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Oder sie dazu bringen, **beliebige Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank der Benutzer zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Erlaubt es, das **Attribut `NFSHomeDirectory`** eines Benutzers zu **ändern**, das seinen Pfad zum Benutzerordner ändert und somit das Umgehen von TCC ermöglicht.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt das Ändern von Dateien innerhalb von App-Bundles (innerhalb von app.app), was standardmäßig **nicht erlaubt ist**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu überprüfen, wer auf diese Berechtigung zugreifen kann unter _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung_.

### `kTCCServiceAccessibility`

Der Prozess wird in der Lage sein, die macOS-Zugänglichkeitsfunktionen **missbrauchen**, was bedeutet, dass er beispielsweise Tastenanschläge ausführen kann. Er könnte also Zugriff anfordern, um eine App wie den Finder zu steuern und den Dialog mit dieser Berechtigung zu genehmigen.

## Medium

### `com.apple.security.cs.allow-jit`

Diese Berechtigung ermöglicht es, **Speicher zu erstellen, der schreibbar und ausführbar ist**, indem das `MAP_JIT`-Flag an die `mmap()`-Systemfunktion übergeben wird. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Diese Berechtigung ermöglicht es, C-Code zu **überschreiben oder zu patchen**, die veraltete **`NSCreateObjectFileImageFromMemory`** zu verwenden (die grundsätzlich unsicher ist) oder das **DVDPlayback**-Framework zu verwenden. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Das Hinzufügen dieser Berechtigung macht Ihre App anfällig für häufige Sicherheitslücken in speichersicheren Code-Sprachen. Überlegen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Diese Berechtigung ermöglicht es, **Abschnitte ihrer eigenen ausführbaren Dateien** auf der Festplatte zu ändern, um erzwungen zu beenden. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Die Berechtigung zur Deaktivierung des Schutzes vor ausführbaren Seiten ist eine extreme Berechtigung, die einen grundlegenden Sicherheitsschutz aus Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App ohne Erkennung neu zu schreiben. Verwenden Sie möglichst engere Berechtigungen.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Diese Berechtigung ermöglicht das Einhängen eines nullfs-Dateisystems (standardmäßig verboten). Tool: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogbeitrag wird diese TCC-Berechtigung normalerweise in der Form gefunden:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlauben Sie dem Prozess, **um alle TCC-Berechtigungen zu bitten**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
