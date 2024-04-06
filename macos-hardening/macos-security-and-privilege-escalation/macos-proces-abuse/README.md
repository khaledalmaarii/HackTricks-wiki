# macOS Proces Abuse

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## MacOS Prozessmissbrauch

MacOS bietet wie jedes andere Betriebssystem eine Vielzahl von Methoden und Mechanismen, damit **Prozesse interagieren, kommunizieren und Daten teilen** können. Obwohl diese Techniken für eine effiziente Systemfunktion unerlässlich sind, können sie auch von Angreifern missbraucht werden, um **bösartige Aktivitäten auszuführen**.

### Bibliotheksinjektion

Bei der Bibliotheksinjektion handelt es sich um eine Technik, bei der ein Angreifer einen Prozess dazu zwingt, eine bösartige Bibliothek zu laden. Sobald injiziert, läuft die Bibliothek im Kontext des Zielprozesses und gewährt dem Angreifer die gleichen Berechtigungen und Zugriffsmöglichkeiten wie dem Prozess.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Funktionshaken

Beim Funktionshaken handelt es sich um das **Abfangen von Funktionsaufrufen** oder Nachrichten innerhalb eines Softwarecodes. Durch das Haken von Funktionen kann ein Angreifer das Verhalten eines Prozesses **ändern**, sensible Daten beobachten oder sogar die Kontrolle über den Ausführungsfluss übernehmen.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Interprozesskommunikation

Die Interprozesskommunikation (IPC) bezieht sich auf verschiedene Methoden, mit denen separate Prozesse **Daten teilen und austauschen** können. Obwohl IPC für viele legitime Anwendungen grundlegend ist, kann sie auch missbraucht werden, um die Prozessisolierung zu umgehen, sensible Informationen preiszugeben oder nicht autorisierte Aktionen auszuführen.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injektion von Electron-Anwendungen

Elektron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, könnten anfällig für Prozessinjektionen sein:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Chromium-Injektion

Es ist möglich, die Flags `--load-extension` und `--use-fake-ui-for-media-stream` zu verwenden, um einen **Man-in-the-Browser-Angriff** durchzuführen, der es ermöglicht, Tastenanschläge, Datenverkehr, Cookies zu stehlen, Skripte in Seiten einzufügen usw.:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIB-Dateien **definieren Benutzeroberflächenelemente (UI)** und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch **beliebige Befehle ausführen** und **Gatekeeper stoppt nicht**, wenn eine bereits ausgeführte Anwendung erneut ausgeführt wird, wenn eine **NIB-Datei geändert** wird. Daher könnten sie verwendet werden, um beliebige Programme beliebige Befehle ausführen zu lassen:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Injektion von Java-Anwendungen

Es ist möglich, bestimmte Java-Funktionen (wie die **`_JAVA_OPTS`**-Umgebungsvariable) zu missbrauchen, um eine Java-Anwendung **beliebigen Code/Befehle** ausführen zu lassen.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net-Anwendungen-Injektion

Es ist möglich, Code in .Net-Anwendungen einzuspritzen, indem die .Net-Debugging-Funktionalität missbraucht wird (nicht durch macOS-Schutzmechanismen wie Laufzeithärtung geschützt).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl-Injektion

Überprüfen Sie verschiedene Optionen, um ein Perl-Skript dazu zu bringen, beliebigen Code auszuführen:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby-Injektion

Es ist auch möglich, Ruby-Umgebungsvariablen zu missbrauchen, um beliebige Skripte beliebigen Code ausführen zu lassen:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python-Injektion

Wenn die Umgebungsvariable **`PYTHONINSPECT`** gesetzt ist, wird der Python-Prozess nach Abschluss in eine Python-CLI wechseln. Es ist auch möglich, **`PYTHONSTARTUP`** zu verwenden, um ein Python-Skript anzugeben, das am Anfang einer interaktiven Sitzung ausgeführt werden soll.\
Beachten Sie jedoch, dass das **`PYTHONSTARTUP`**-Skript nicht ausgeführt wird, wenn **`PYTHONINSPECT`** die interaktive Sitzung erstellt.

Andere Umgebungsvariablen wie **`PYTHONPATH`** und **`PYTHONHOME`** könnten ebenfalls nützlich sein, um einen Python-Befehl beliebigen Codes ausführen zu lassen.

Beachten Sie, dass ausführbare Dateien, die mit **`pyinstaller`** kompiliert wurden, diese Umgebungsvariablen nicht verwenden, auch wenn sie mit einem eingebetteten Python ausgeführt werden.

{% hint style="danger" %}
Insgesamt konnte ich keinen Weg finden, um Python dazu zu bringen, beliebigen Code durch den Missbrauch von Umgebungsvariablen auszuführen.\
Die meisten Menschen installieren jedoch Python mit **Hombrew**, das Python an einem **beschreibbaren Speicherort** für den Standard-Admin-Benutzer installiert. Sie können es mit etwas wie folgendem übernehmen:

```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```

Selbst **root** wird diesen Code ausführen, wenn Python ausgeführt wird.
{% endhint %}

## Erkennung

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) ist eine Open-Source-Anwendung, die **Prozessinjektionen erkennen und blockieren** kann:

* Verwendung von **Umgebungsvariablen**: Es überwacht das Vorhandensein der folgenden Umgebungsvariablen: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** und **`ELECTRON_RUN_AS_NODE`**
* Verwendung von **`task_for_pid`**-Aufrufen: Um festzustellen, wenn ein Prozess den **Task-Port eines anderen** erhalten möchte, um Code in den Prozess einzuspritzen.
* **Parameter von Electron-Apps**: Jemand kann die Befehlszeilenargumente **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** verwenden, um eine Electron-App im Debugging-Modus zu starten und somit Code einzuspritzen.
* Verwendung von **Symbolischen Links** oder **Hardlinks**: Typischerweise besteht der häufigste Missbrauch darin, einen Link mit unseren Benutzerberechtigungen zu platzieren und ihn auf einen Ort mit höheren Berechtigungen zu verweisen. Die Erkennung ist sowohl für Hardlinks als auch für Symbolische Links sehr einfach. Wenn der Prozess, der den Link erstellt, ein **unterschiedliches Berechtigungsniveau** als die Zieldatei hat, wird ein **Alarm** ausgelöst. Leider ist im Fall von Symbolischen Links eine Blockierung nicht möglich, da wir vor der Erstellung keine Informationen über das Ziel des Links haben. Dies ist eine Einschränkung des Apple EndpointSecuriy-Frameworks.

### Von anderen Prozessen ausgeführte Aufrufe

In [**diesem Blog-Beitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfahren Sie, wie es möglich ist, die Funktion **`task_name_for_pid`** zu verwenden, um Informationen über andere **Prozesse, die Code in einen Prozess einspritzen**, zu erhalten und dann Informationen über diesen anderen Prozess zu erhalten.

Beachten Sie, dass zum Aufrufen dieser Funktion Sie **die gleiche UID** wie der Prozess, der ausgeführt wird, oder **root** sein müssen (und sie gibt Informationen über den Prozess zurück, nicht über eine Möglichkeit, Code einzuspritzen).

## Referenzen

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
