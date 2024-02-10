# Linux Umgebungsvariablen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Sie können eine globale Variable für Ihre aktuelle Sitzung erstellen, indem Sie Folgendes tun:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist für Ihre aktuellen Sitzungen und deren Kindprozesse zugänglich.

Sie können eine Variable **entfernen**, indem Sie Folgendes tun:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Die **lokalen Variablen** können nur von der **aktuellen Shell/dem aktuellen Skript** **abgerufen** werden.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Liste aktueller Variablen

To list the current environment variables in Linux, you can use the `printenv` command. This command will display all the variables and their values in the current environment.

```bash
printenv
```

Alternatively, you can use the `env` command to achieve the same result:

```bash
env
```

Both commands will provide you with a list of the current environment variables, which can be useful for troubleshooting or understanding the system's configuration.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Gemeinsame Variablen

Von: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** - die Anzeige, die von **X** verwendet wird. Diese Variable ist normalerweise auf **:0.0** eingestellt, was die erste Anzeige auf dem aktuellen Computer bedeutet.
* **EDITOR** - der bevorzugte Texteditor des Benutzers.
* **HISTFILESIZE** - die maximale Anzahl von Zeilen, die in der Verlaufsdatei enthalten sind.
* **HISTSIZE** - Anzahl der Zeilen, die der Verlaufsdatei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
* **HOME** - Ihr Home-Verzeichnis.
* **HOSTNAME** - der Hostname des Computers.
* **LANG** - Ihre aktuelle Sprache.
* **MAIL** - der Speicherort des Postfachs des Benutzers. Normalerweise **/var/spool/mail/USER**.
* **MANPATH** - die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
* **OSTYPE** - der Typ des Betriebssystems.
* **PS1** - die Standard-Eingabeaufforderung in Bash.
* **PATH** - speichert den Pfad aller Verzeichnisse, die ausführbare Binärdateien enthalten, die Sie nur durch Angabe des Dateinamens und nicht durch relativen oder absoluten Pfad ausführen möchten.
* **PWD** - das aktuelle Arbeitsverzeichnis.
* **SHELL** - der Pfad zur aktuellen Befehlsshell (z. B. **/bin/bash**).
* **TERM** - der aktuelle Terminaltyp (z. B. **xterm**).
* **TZ** - Ihre Zeitzone.
* **USER** - Ihr aktueller Benutzername.

## Interessante Variablen zum Hacken

### **HISTFILESIZE**

Ändern Sie den **Wert dieser Variable auf 0**, damit die **Verlaufsdatei** (\~/.bash\_history) **gelöscht wird**, wenn Sie **Ihre Sitzung beenden**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändern Sie den **Wert dieser Variable auf 0**, damit bei **Beendigung Ihrer Sitzung** keine Befehle zur **Verlaufsdatei** (\~/.bash\_history) hinzugefügt werden.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Die Prozesse verwenden den hier deklarierten **Proxy**, um eine Verbindung zum Internet über **http oder https** herzustellen.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Die Prozesse werden den in **diesen Umgebungsvariablen** angegebenen Zertifikaten vertrauen.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Ändern Sie das Aussehen Ihrer Eingabeaufforderung.

[**Hier ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Normaler Benutzer:

![](<../.gitbook/assets/image (88).png>)

Ein, zwei und drei im Hintergrund laufende Jobs:

![](<../.gitbook/assets/image (89).png>)

Ein im Hintergrund laufender Job, einer gestoppt und der letzte Befehl wurde nicht korrekt beendet:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
