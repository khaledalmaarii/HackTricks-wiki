# macOS Office Sandbox-Bypasses

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

### Sandbox-Bypass mit Word über Launch Agents

Die Anwendung verwendet eine **benutzerdefinierte Sandbox** mit der Berechtigung **`com.apple.security.temporary-exception.sbpl`** und diese benutzerdefinierte Sandbox erlaubt das Schreiben von Dateien überall, solange der Dateiname mit `~$` beginnt: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daher war das Umgehen so einfach wie das **Schreiben eines `plist`** LaunchAgents in `~/Library/LaunchAgents/~$escape.plist`.

Überprüfen Sie den [**ursprünglichen Bericht hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Sandbox-Bypass mit Word über Login-Elemente und zip

Denken Sie daran, dass Word nach der ersten Umgehung beliebige Dateien schreiben kann, deren Name mit `~$` beginnt, obwohl es nach dem Patch der vorherigen Schwachstelle nicht mehr möglich war, in `/Library/Application Scripts` oder in `/Library/LaunchAgents` zu schreiben.

Es wurde entdeckt, dass es innerhalb der Sandbox möglich ist, ein **Login-Element** (Apps, die ausgeführt werden, wenn sich der Benutzer anmeldet) zu erstellen. Diese Apps werden jedoch **nicht ausgeführt**, es sei denn, sie sind **notarized**, und es ist **nicht möglich, Argumente hinzuzufügen** (Sie können also nicht einfach eine Reverse-Shell mit **`bash`** ausführen).

Nach der vorherigen Sandbox-Umgehung hat Microsoft die Option zum Schreiben von Dateien in `~/Library/LaunchAgents` deaktiviert. Es wurde jedoch entdeckt, dass, wenn Sie eine **Zip-Datei als Login-Element** verwenden, das `Archive-Dienstprogramm` sie einfach an ihrem aktuellen Speicherort entpackt. Da der Ordner `LaunchAgents` im Standardfall nicht im Ordner `~/Library` erstellt wird, war es möglich, eine **plist in `LaunchAgents/~$escape.plist`** zu zippen und die Zip-Datei in **`~/Library`** zu platzieren, damit sie beim Entpacken das Ziel der Persistenz erreicht.

Überprüfen Sie den [**ursprünglichen Bericht hier**](https://objective-see.org/blog/blog\_0x4B.html).

### Sandbox-Bypass mit Word über Login-Elemente und .zshenv

(Denken Sie daran, dass Word nach der ersten Umgehung beliebige Dateien schreiben kann, deren Name mit `~$` beginnt).

Die vorherige Technik hatte jedoch eine Einschränkung: Wenn der Ordner **`~/Library/LaunchAgents`** existiert, weil eine andere Software ihn erstellt hat, würde sie fehlschlagen. Daher wurde eine andere Login-Element-Kette für dies entdeckt.

Ein Angreifer könnte die Dateien **`.bash_profile`** und **`.zshenv`** mit dem Payload zum Ausführen erstellen und sie dann zippen und die Zip-Datei im Benutzerordner des Opfers schreiben: **`~/~$escape.zip`**.

Fügen Sie dann die Zip-Datei zu den **Login-Elementen** hinzu und dann zur **`Terminal`**-App. Wenn sich der Benutzer erneut anmeldet, wird die Zip-Datei im Benutzerordner entpackt und überschreibt **`.bash_profile`** und **`.zshenv`**, und daher wird das Terminal eine dieser Dateien ausführen (abhängig davon, ob bash oder zsh verwendet wird).

Überprüfen Sie den [**ursprünglichen Bericht hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Sandbox-Bypass mit Word über Open und Umgebungsvariablen

Aus sandboxierten Prozessen ist es immer noch möglich, andere Prozesse mit dem Dienstprogramm **`open`** aufzurufen. Darüber hinaus werden diese Prozesse **innerhalb ihrer eigenen Sandbox** ausgeführt.

Es wurde entdeckt, dass das Open-Dienstprogramm die Option **`--env`** hat, um eine App mit **spezifischen Umgebungsvariablen** auszuführen. Daher war es möglich, die Datei **`.zshenv`** in einem Ordner **innerhalb** der Sandbox zu erstellen und `open` mit `--env` zu verwenden, um die **`HOME`-Variable** auf diesen Ordner einzustellen und die `Terminal`-App zu öffnen, die die `.zshenv`-Datei ausführt (aus irgendeinem Grund musste auch die Variable `__OSINSTALL_ENVIROMENT` gesetzt werden).

Überprüfen Sie den [**ursprünglichen Bericht hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Sandbox-Bypass mit Word über Open und stdin

Das Dienstprogramm **`open`** unterstützte auch den Parameter **`--stdin`** (und nach der vorherigen Umgehung war es nicht mehr möglich, `--env` zu verwenden).

Die Sache ist, dass selbst wenn **`python`** von Apple signiert wurde, es kein Skript mit dem Attribut **`quarantine`** ausführen wird. Es war jedoch möglich, ihm ein Skript von stdin zu übergeben, sodass es nicht überprüft, ob es unter Quarantäne gestellt wurde oder nicht:&#x20;

1. Legen Sie eine Datei **`~$exploit.py`** mit beliebigen Python-Befehlen ab.
2. Führen Sie _open_ **`–stdin='~$exploit.py' -a Python`** aus, das die Python-App mit unserer abgelegten Datei als Standardeingabe ausführt. Python führt unseren Code problemlos aus, und da es sich um einen Kindprozess von _launchd_ handelt, ist er nicht an die Sandbox-Regeln von Word gebunden.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
