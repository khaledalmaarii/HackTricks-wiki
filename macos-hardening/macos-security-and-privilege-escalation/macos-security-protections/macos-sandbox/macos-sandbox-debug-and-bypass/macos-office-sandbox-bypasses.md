# macOS Office Sandbox Bypasses

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

### Word Sandbox-Bypass über Launch Agents

Die Anwendung verwendet eine **benutzerdefinierte Sandbox** mit der Berechtigung **`com.apple.security.temporary-exception.sbpl`** und diese benutzerdefinierte Sandbox erlaubt das Schreiben von Dateien überall, solange der Dateiname mit `~$` beginnt: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daher war das Entkommen so einfach wie **das Schreiben einer `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Überprüfe den [**originalen Bericht hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox-Bypass über Login Items und zip

Denke daran, dass Word von der ersten Umgehung an beliebige Dateien schreiben kann, deren Name mit `~$` beginnt, obwohl es nach dem Patch der vorherigen Schwachstelle nicht möglich war, in `/Library/Application Scripts` oder in `/Library/LaunchAgents` zu schreiben.

Es wurde entdeckt, dass es innerhalb der Sandbox möglich ist, ein **Login Item** (Apps, die beim Anmelden des Benutzers ausgeführt werden) zu erstellen. Diese Apps **werden jedoch nicht ausgeführt**, es sei denn, sie sind **notarisiert** und es ist **nicht möglich, Argumente hinzuzufügen** (man kann also nicht einfach eine Reverse-Shell mit **`bash`** ausführen).

Nach dem vorherigen Sandbox-Bypass deaktivierte Microsoft die Option, Dateien in `~/Library/LaunchAgents` zu schreiben. Es wurde jedoch entdeckt, dass, wenn man eine **Zip-Datei als Login Item** hinzufügt, das `Archive Utility` sie einfach **entpackt** an ihrem aktuellen Standort. Da der Ordner `LaunchAgents` von `~/Library` standardmäßig nicht erstellt wird, war es möglich, eine plist in `LaunchAgents/~$escape.plist` zu **zippen** und die Zip-Datei in **`~/Library`** zu **platzieren**, sodass sie beim Dekomprimieren das Ziel für die Persistenz erreicht.

Überprüfe den [**originalen Bericht hier**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox-Bypass über Login Items und .zshenv

(Denke daran, dass Word von der ersten Umgehung an beliebige Dateien schreiben kann, deren Name mit `~$` beginnt).

Die vorherige Technik hatte jedoch eine Einschränkung: Wenn der Ordner **`~/Library/LaunchAgents`** existiert, weil eine andere Software ihn erstellt hat, würde es fehlschlagen. Daher wurde eine andere Kette von Login Items für dies entdeckt.

Ein Angreifer könnte die Dateien **`.bash_profile`** und **`.zshenv`** mit dem Payload erstellen und sie dann zippen und **die Zip-Datei im Benutzerordner des Opfers schreiben**: **`~/~$escape.zip`**.

Dann füge die Zip-Datei zu den **Login Items** hinzu und dann die **`Terminal`**-App. Wenn der Benutzer sich erneut anmeldet, wird die Zip-Datei im Benutzerverzeichnis entpackt, wodurch **`.bash_profile`** und **`.zshenv`** überschrieben werden und daher wird das Terminal eine dieser Dateien ausführen (je nachdem, ob bash oder zsh verwendet wird).

Überprüfe den [**originalen Bericht hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox-Bypass mit Open und env-Variablen

Von sandboxed Prozessen ist es weiterhin möglich, andere Prozesse mit dem **`open`**-Utility aufzurufen. Darüber hinaus werden diese Prozesse **innerhalb ihrer eigenen Sandbox** ausgeführt.

Es wurde entdeckt, dass das Open-Utility die Option **`--env`** hat, um eine App mit **spezifischen env**-Variablen auszuführen. Daher war es möglich, die **`.zshenv`-Datei** innerhalb eines Ordners **innerhalb** der **Sandbox** zu erstellen und `open` mit `--env` zu verwenden, um die **`HOME`-Variable** auf diesen Ordner zu setzen, der die `Terminal`-App öffnet, die die `.zshenv`-Datei ausführt (aus irgendeinem Grund war es auch notwendig, die Variable `__OSINSTALL_ENVIROMENT` zu setzen).

Überprüfe den [**originalen Bericht hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox-Bypass mit Open und stdin

Das **`open`**-Utility unterstützte auch den Parameter **`--stdin`** (und nach dem vorherigen Bypass war es nicht mehr möglich, `--env` zu verwenden).

Das Problem ist, dass selbst wenn **`python`** von Apple signiert war, es **kein Skript** mit dem **`quarantine`**-Attribut **ausführen wird**. Es war jedoch möglich, ihm ein Skript von stdin zu übergeben, sodass nicht überprüft wird, ob es quarantiniert war oder nicht:&#x20;

1. Lege eine **`~$exploit.py`**-Datei mit beliebigen Python-Befehlen ab.
2. Führe _open_ **`–stdin='~$exploit.py' -a Python`** aus, was die Python-App mit unserer abgelegten Datei als Standard-Eingabe ausführt. Python führt unseren Code gerne aus, und da es ein Kindprozess von _launchd_ ist, unterliegt es nicht den Sandbox-Regeln von Word.

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
