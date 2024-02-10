# macOS Gefährliche Berechtigungen & TCC-Berechtigungen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

{% hint style="warning" %}
Beachten Sie, dass Berechtigungen, die mit **`com.apple`** beginnen, nicht für Dritte verfügbar sind. Nur Apple kann sie gewähren.
{% endhint %}

## Hoch

### `com.apple.rootless.install.heritable`

Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht es, **SIP zu umgehen**. Weitere Informationen finden Sie [hier](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die Berechtigung **`com.apple.rootless.install`** ermöglicht es, **SIP zu umgehen**. Weitere Informationen finden Sie [hier](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (früher `task_for_pid-allow` genannt)**

Diese Berechtigung ermöglicht den Zugriff auf den **Task-Port für jeden** Prozess, außer dem Kernel. Weitere Informationen finden Sie [**hier**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Diese Berechtigung ermöglicht es anderen Prozessen mit der Berechtigung **`com.apple.security.cs.debugger`**, den Task-Port des Prozesses, der von der Binärdatei mit dieser Berechtigung ausgeführt wird, zu erhalten und **Code einzuspritzen**. Weitere Informationen finden Sie [**hier**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps mit der Berechtigung Debugging Tool können `task_for_pid()` aufrufen, um einen gültigen Task-Port für nicht signierte und Drittanbieter-Apps mit der Berechtigung `Get Task Allow` auf `true` abzurufen. Selbst mit der Berechtigung für das Debugging-Tool kann ein Debugger **nicht die Task-Ports** von Prozessen abrufen, die **nicht über die Berechtigung `Get Task Allow` verfügen** und daher durch System Integrity Protection geschützt sind. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Diese Berechtigung ermöglicht das Laden von Frameworks, Plug-Ins oder Bibliotheken, die weder von Apple signiert noch mit derselben Team-ID signiert sind wie die Hauptausführungsdatei. Ein Angreifer könnte missbräuchlich eine beliebige Bibliothek laden, um Code einzuspritzen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Diese Berechtigung ist sehr ähnlich wie **`com.apple.security.cs.disable-library-validation`**, ermöglicht jedoch anstelle einer direkten Deaktivierung der Bibliotheksvalidierung dem Prozess, einen `csops`-Systemaufruf zum Deaktivieren der Validierung aufzurufen.\
Weitere Informationen finden Sie [**hier**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Diese Berechtigung ermöglicht die Verwendung von DYLD-Umgebungsvariablen, die zum Einspritzen von Bibliotheken und Code verwendet werden können. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog\_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) ermöglichen diese Berechtigungen die **Änderung** der **TCC-Datenbank**.

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Berechtigungen ermöglichen die **Installation von Software ohne Benutzerberechtigungen**, was für eine **Privileg-Eskalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Berechtigung, um den Kernel zum Laden einer Kernelerweiterung aufzufordern.

### **`com.apple.private.icloud-account-access`**

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem XPC-Dienst **`com.apple.iCloudHelper`** zu kommunizieren, der **iCloud-Token bereitstellt**.

**iMovie** und **Garageband** hatten diese Berechtigung.

Für weitere **Informationen** über den Exploit zum **Erhalten von iCloud-Token** aus dieser Berechtigung sehen Sie sich den Vortrag an: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies ermöglicht

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) wird erwähnt, dass dies verwendet werden könnte, um die nach einem Neustart geschützten SSV-Inhalte zu aktualisieren. Wenn Sie wissen, wie es funktioniert, senden Sie bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) wird erwähnt, dass dies verwendet werden könnte, um die nach einem Neustart geschützten SSV-Inhalte zu aktualisieren. Wenn Sie wissen, wie es funktioniert, senden Sie bitte einen PR!

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

Gibt **Vollzugriff auf die Festplatte**, eine der höchsten Berechtigungen, die Sie haben können.

### **`kTCCServiceAppleEvents`**

Ermöglicht der App, Ereignisse an andere Anwendungen zu senden, die häufig für die **Automatisierung von Aufgaben** verwendet werden. Durch die Kontrolle anderer Apps kann sie die den anderen Apps gewährten Berechtigungen missbrauchen.

Zum Beispiel kann sie sie auffordern, den Benutzer nach seinem Passwort zu fragen:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Oder sie dazu bringen, **beliebige Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Ermöglicht unter anderem das **Schreiben in die TCC-Datenbank des Benutzers**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Ermöglicht das **Ändern** des **`NFSHomeDirectory`**-Attributs eines Benutzers, der den Pfad seines Home-Ordners ändert, und ermöglicht es daher, die TCC zu **umgehen**.

### **`kTCCServiceSystemPolicyAppBundles`**

Ermöglicht das Ändern von Dateien innerhalb von App-Bundles (innerhalb von app.app), was standardmäßig **nicht erlaubt** ist.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Es ist möglich, herauszufinden, wer auf diese Berechtigung zugreifen kann, indem man zu _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung_ geht.

### `kTCCServiceAccessibility`

Der Prozess kann die macOS-Barrierefreiheitsfunktionen **missbrauchen**, was bedeutet, dass er zum Beispiel Tastatureingaben simulieren kann. Er könnte also Zugriff auf die Steuerung einer App wie Finder beantragen und den Dialog mit dieser Berechtigung genehmigen.

## Medium

### `com.apple.security.cs.allow-jit`

Diese Berechtigung ermöglicht das Erstellen von Speicher, der schreib- und ausführbar ist, indem die `MAP_JIT`-Flag an die `mmap()`-Systemfunktion übergeben wird. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Diese Berechtigung ermöglicht das Überschreiben oder Patchen von C-Code, die Verwendung der veralteten **`NSCreateObjectFileImageFromMemory`** (die grundsätzlich unsicher ist) oder die Verwendung des **DVDPlayback**-Frameworks. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Das Hinzufügen dieser Berechtigung macht Ihre App anfällig für gängige Sicherheitslücken in speicherunsicheren Programmiersprachen. Überlegen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Diese Berechtigung ermöglicht das **Ändern von Abschnitten der eigenen ausführbaren Dateien** auf der Festplatte, um einen erzwungenen Abbruch zu erzwingen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Die Berechtigung zur Deaktivierung des Schutzes vor ausführbarem Speicher ist eine extreme Berechtigung, die einen grundlegenden Sicherheitsschutz Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App unbemerkt zu ändern. Verwenden Sie möglichst spezifischere Berechtigungen.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Diese Berechtigung ermöglicht das Mounten eines nullfs-Dateisystems (standardmäßig nicht erlaubt). Tool: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogpost findet sich diese TCC-Berechtigung normalerweise in der Form:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlaube dem Prozess, **um alle TCC-Berechtigungen zu bitten**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Lerne AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn du dein **Unternehmen in HackTricks bewerben möchtest** oder **HackTricks als PDF herunterladen möchtest**, schau dir die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Hol dir das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecke [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folge** uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teile deine Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories einreichst.**

</details>
