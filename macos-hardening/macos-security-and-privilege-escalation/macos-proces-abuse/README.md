# macOS Prozessmissbrauch

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## macOS Prozessmissbrauch

MacOS bietet wie jedes andere Betriebssystem verschiedene Methoden und Mechanismen, um **Prozesse zu interagieren, zu kommunizieren und Daten auszutauschen**. Obwohl diese Techniken für eine effiziente Systemfunktion unerlässlich sind, können sie auch von Angreifern missbraucht werden, um **bösartige Aktivitäten** durchzuführen.

### Bibliotheksinjektion

Bei der Bibliotheksinjektion zwingt ein Angreifer einen Prozess, eine bösartige Bibliothek zu laden. Sobald sie injiziert ist, läuft die Bibliothek im Kontext des Zielprozesses und ermöglicht dem Angreifer die gleichen Berechtigungen und Zugriffe wie der Prozess.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Funktionen-Hooking

Beim Funktionen-Hooking werden Funktionsaufrufe oder Nachrichten innerhalb eines Softwarecodes **abgefangen**. Durch das Hooking von Funktionen kann ein Angreifer das Verhalten eines Prozesses **ändern**, sensible Daten beobachten oder sogar die Ausführungsreihenfolge kontrollieren.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Interprozesskommunikation

Die Interprozesskommunikation (IPC) bezieht sich auf verschiedene Methoden, mit denen separate Prozesse **Daten teilen und austauschen** können. Obwohl IPC für viele legitime Anwendungen grundlegend ist, kann es auch missbraucht werden, um die Prozessisolierung zu umgehen, sensible Informationen preiszugeben oder nicht autorisierte Aktionen durchzuführen.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injektion von Electron-Anwendungen

Electron-Anwendungen, die mit bestimmten Umgebungsvariablen ausgeführt werden, können anfällig für Prozessinjektionen sein:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIB-Dateien definieren Benutzeroberflächenelemente und deren Interaktionen innerhalb einer Anwendung. Sie können jedoch auch beliebige Befehle ausführen, und Gatekeeper verhindert nicht, dass eine bereits ausgeführte Anwendung ausgeführt wird, wenn eine NIB-Datei geändert wird. Daher können sie verwendet werden, um beliebige Programme beliebige Befehle ausführen zu lassen:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Injektion von Java-Anwendungen

Es ist möglich, bestimmte Java-Funktionen (wie die Umgebungsvariable **`_JAVA_OPTS`**) zu missbrauchen, um eine Java-Anwendung beliebigen Code/Befehle ausführen zu lassen.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Injektion von .Net-Anwendungen

Es ist möglich, Code in .Net-Anwendungen einzufügen, indem die .Net-Debugging-Funktionen (die nicht durch macOS-Schutzmechanismen wie Laufzeitverhärtung geschützt sind) missbraucht werden.

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

Wenn die Umgebungsvariable **`PYTHONINSPECT`** gesetzt ist, wechselt der Python-Prozess nach Abschluss in eine Python-CLI. Es ist auch möglich, **`PYTHONSTARTUP`** zu verwenden, um ein Python-Skript anzugeben, das am Anfang einer interaktiven Sitzung ausgeführt werden soll.\
Beachten Sie jedoch, dass das **`PYTHONSTARTUP`**-Skript nicht ausgeführt wird, wenn **`PYTHONINSPECT`** die interaktive Sitzung erstellt.

Andere Umgebungsvariablen wie **`PYTHONPATH`** und **`PYTHONHOME`** können ebenfalls nützlich sein, um einen Python-Befehl beliebigen Code ausführen zu lassen.

Beachten Sie, dass ausführbare Dateien, die mit **`pyinstaller`** kompiliert wurden, diese Umgebungsvariablen nicht verwenden, auch wenn sie mit einem eingebetteten Python ausgeführt werden.

{% hint style="danger" %}
Insgesamt konnte ich keinen Weg finden, um Python dazu zu bringen, beliebigen Code unter Ausnutzung von Umgebungsvariablen auszuführen.\
Die meisten Menschen installieren jedoch Python mit **Hombrew**, das Python an einem **beschreibbaren Speicherort** für den Standardadministrator installiert. Sie können es mit etwas wie folgt übernehmen:
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
* Verwendung von **`task_for_pid`**-Aufrufen: Um festzustellen, wann ein Prozess den **Task-Port eines anderen** erhalten möchte, um Code in den Prozess einzufügen.
* **Electron-App-Parameter**: Jemand kann die Befehlszeilenargumente **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** verwenden, um eine Electron-App im Debugging-Modus zu starten und somit Code einzufügen.
* Verwendung von **Symbolischen Links** oder **Hardlinks**: Typischerweise besteht der häufigste Missbrauch darin, einen Link mit unseren Benutzerberechtigungen zu erstellen und ihn auf einen Ort mit höheren Berechtigungen zu verweisen. Die Erkennung ist sowohl für Hardlinks als auch für Symbolische Links sehr einfach. Wenn der Prozess, der den Link erstellt, ein **anderes Berechtigungsniveau** als die Zieldatei hat, wird ein **Alarm** ausgelöst. Leider ist eine Blockierung im Fall von Symbolischen Links nicht möglich, da wir vor der Erstellung keine Informationen über das Ziel des Links haben. Dies ist eine Einschränkung des Apple EndpointSecurity-Frameworks.

### Von anderen Prozessen ausgeführte Aufrufe

In [**diesem Blog-Beitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfahren Sie, wie es möglich ist, die Funktion **`task_name_for_pid`** zu verwenden, um Informationen über andere **Prozesse abzurufen, die Code in einen Prozess injizieren**, und dann Informationen über diesen anderen Prozess zu erhalten.

Beachten Sie, dass Sie, um diese Funktion aufzurufen, **die gleiche UID** wie der Prozess haben müssen, der ausgeführt wird, oder **root** sein müssen (und sie gibt Informationen über den Prozess zurück, nicht eine Möglichkeit, Code einzufügen).

## Referenzen

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
