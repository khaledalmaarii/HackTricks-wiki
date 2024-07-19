# macOS Dangerous Entitlements & TCC perms

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

{% hint style="warning" %}
Beachte, dass Berechtigungen, die mit **`com.apple`** beginnen, nicht für Dritte verfügbar sind, nur Apple kann sie gewähren.
{% endhint %}

## Hoch

### `com.apple.rootless.install.heritable`

Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht es, **SIP zu umgehen**. Siehe [dies für mehr Informationen](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die Berechtigung **`com.apple.rootless.install`** ermöglicht es, **SIP zu umgehen**. Siehe [dies für mehr Informationen](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (früher `task_for_pid-allow`)**

Diese Berechtigung ermöglicht es, den **Task-Port für jeden** Prozess, außer dem Kernel, zu erhalten. Siehe [**dies für mehr Informationen**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Diese Berechtigung erlaubt es anderen Prozessen mit der Berechtigung **`com.apple.security.cs.debugger**, den Task-Port des Prozesses zu erhalten, der von der Binärdatei mit dieser Berechtigung ausgeführt wird, und **Code darauf zu injizieren**. Siehe [**dies für mehr Informationen**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps mit der Debugging-Tool-Berechtigung können `task_for_pid()` aufrufen, um einen gültigen Task-Port für nicht signierte und Drittanbieter-Apps mit der Berechtigung `Get Task Allow`, die auf `true` gesetzt ist, abzurufen. Selbst mit der Debugging-Tool-Berechtigung kann ein Debugger jedoch **die Task-Ports** von Prozessen, die **nicht die Berechtigung `Get Task Allow` haben**, und die daher durch die Systemintegritätsschutz geschützt sind, **nicht abrufen**. Siehe [**dies für mehr Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Diese Berechtigung ermöglicht es, **Frameworks, Plug-ins oder Bibliotheken zu laden, ohne entweder von Apple signiert zu sein oder mit derselben Team-ID wie die Hauptanwendung signiert zu sein**, sodass ein Angreifer einige beliebige Bibliotheksladungen missbrauchen könnte, um Code zu injizieren. Siehe [**dies für mehr Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Diese Berechtigung ist sehr ähnlich zu **`com.apple.security.cs.disable-library-validation`**, aber **anstatt** die Bibliotheksvalidierung **direkt zu deaktivieren**, erlaubt sie dem Prozess, **einen `csops`-Systemaufruf zu tätigen, um sie zu deaktivieren**.\
Siehe [**dies für mehr Informationen**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Diese Berechtigung ermöglicht es, **DYLD-Umgebungsvariablen** zu verwenden, die zum Injizieren von Bibliotheken und Code verwendet werden könnten. Siehe [**dies für mehr Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog\_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ermöglichen diese Berechtigungen, die **TCC**-Datenbank zu **modifizieren**.

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Berechtigungen ermöglichen es, **Software zu installieren, ohne den Benutzer um Erlaubnis zu fragen**, was für eine **Privilegieneskalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Berechtigung, die benötigt wird, um den **Kernel zu bitten, eine Kernel-Erweiterung zu laden**.

### **`com.apple.private.icloud-account-access`**

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC-Dienst zu kommunizieren, der **iCloud-Token** bereitstellt.

**iMovie** und **Garageband** hatten diese Berechtigung.

Für mehr **Informationen** über den Exploit, um **iCloud-Token** aus dieser Berechtigung zu erhalten, siehe den Vortrag: [**#OBTS v5.0: "Was auf deinem Mac passiert, bleibt in Apples iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies erlaubt.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn du weißt, wie, sende bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn du weißt, wie, sende bitte einen PR!

### `keychain-access-groups`

Diese Berechtigung listet die **Keychain**-Gruppen auf, auf die die Anwendung Zugriff hat:
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

Gibt **Vollzugriff auf die Festplatte**-Berechtigungen, eine der höchsten TCC-Berechtigungen, die man haben kann.

### **`kTCCServiceAppleEvents`**

Erlaubt der App, Ereignisse an andere Anwendungen zu senden, die häufig zum **Automatisieren von Aufgaben** verwendet werden. Durch die Kontrolle anderer Apps kann es die Berechtigungen missbrauchen, die diesen anderen Apps gewährt wurden.

Wie zum Beispiel, sie dazu zu bringen, den Benutzer nach seinem Passwort zu fragen:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Oder sie dazu bringen, **willkürliche Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank der Benutzer zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Erlaubt es, das **`NFSHomeDirectory`**-Attribut eines Benutzers zu **ändern**, was seinen Home-Ordner-Pfad ändert und somit ermöglicht, **TCC zu umgehen**.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt das Modifizieren von Dateien innerhalb von App-Bundles (innerhalb von app.app), was **standardmäßig nicht erlaubt** ist.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu überprüfen, wer diesen Zugriff hat in _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung._

### `kTCCServiceAccessibility`

Der Prozess wird in der Lage sein, die **Zugänglichkeitsfunktionen von macOS auszunutzen**, was bedeutet, dass er beispielsweise Tastenanschläge drücken kann. Er könnte also Zugriff anfordern, um eine App wie Finder zu steuern und den Dialog mit dieser Berechtigung zu genehmigen.

## Mittel

### `com.apple.security.cs.allow-jit`

Diese Berechtigung erlaubt es, **Speicher zu erstellen, der beschreibbar und ausführbar ist**, indem das `MAP_JIT`-Flag an die `mmap()`-Systemfunktion übergeben wird. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Diese Berechtigung erlaubt es, **C-Code zu überschreiben oder zu patchen**, die längst veraltete **`NSCreateObjectFileImageFromMemory`** (die grundsätzlich unsicher ist) zu verwenden oder das **DVDPlayback**-Framework zu nutzen. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Das Einbeziehen dieser Berechtigung setzt Ihre App gängigen Schwachstellen in speicherunsicheren Programmiersprachen aus. Überlegen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Diese Berechtigung erlaubt es, **Abschnitte seiner eigenen ausführbaren Dateien** auf der Festplatte zu ändern, um gewaltsam zu beenden. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Die Berechtigung zum Deaktivieren des Schutzes für ausführbaren Speicher ist eine extreme Berechtigung, die einen grundlegenden Sicherheitschutz Ihrer App entfernt, wodurch es einem Angreifer möglich wird, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Bevorzugen Sie, wenn möglich, engere Berechtigungen.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Diese Berechtigung erlaubt es, ein nullfs-Dateisystem zu mounten (standardmäßig verboten). Tool: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogbeitrag wird diese TCC-Berechtigung normalerweise in folgender Form gefunden:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlaube dem Prozess, **nach allen TCC-Berechtigungen zu fragen**.

### **`kTCCServicePostEvent`**
{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
</details>
