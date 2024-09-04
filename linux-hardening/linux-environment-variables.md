# Linux-Umgebungsvariablen

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Sie können eine globale Variable für Ihre aktuelle Sitzung erstellen, indem Sie:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable wird von Ihren aktuellen Sitzungen und deren Kindprozessen zugänglich sein.

Sie können eine Variable **entfernen** mit:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Die **lokalen Variablen** können nur von der **aktuellen Shell/Skript** **zugegriffen** werden.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Aktuelle Variablen auflisten
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – der Bildschirm, der von **X** verwendet wird. Diese Variable ist normalerweise auf **:0.0** gesetzt, was den ersten Bildschirm auf dem aktuellen Computer bedeutet.
* **EDITOR** – der bevorzugte Texteditor des Benutzers.
* **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der Verlaufdatei enthalten sind.
* **HISTSIZE** – Anzahl der Zeilen, die zur Verlaufdatei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
* **HOME** – dein Home-Verzeichnis.
* **HOSTNAME** – der Hostname des Computers.
* **LANG** – deine aktuelle Sprache.
* **MAIL** – der Speicherort des Mail-Spools des Benutzers. Normalerweise **/var/spool/mail/USER**.
* **MANPATH** – die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
* **OSTYPE** – der Typ des Betriebssystems.
* **PS1** – die Standardaufforderung in bash.
* **PATH** – speichert den Pfad aller Verzeichnisse, die die Binärdateien enthalten, die du ausführen möchtest, indem du nur den Namen der Datei angibst und nicht den relativen oder absoluten Pfad.
* **PWD** – das aktuelle Arbeitsverzeichnis.
* **SHELL** – der Pfad zur aktuellen Befehlszeilen-Shell (zum Beispiel **/bin/bash**).
* **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
* **TZ** – deine Zeitzone.
* **USER** – dein aktueller Benutzername.

## Interesting variables for hacking

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit die **Verlaufdatei** (\~/.bash\_history) **gelöscht wird**, wenn du deine **Sitzung beendest**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändern Sie **den Wert dieser Variablen auf 0**, damit beim **Beenden Ihrer Sitzung** kein Befehl in die **Historie-Datei** (\~/.bash\_history) aufgenommen wird.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Die Prozesse verwenden den hier deklarierten **Proxy**, um über **http oder https** eine Verbindung zum Internet herzustellen.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Ändern Sie, wie Ihr Prompt aussieht.

[**Das ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Regulärer Benutzer:

![](<../.gitbook/assets/image (740).png>)

Ein, zwei und drei Hintergrundjobs:

![](<../.gitbook/assets/image (145).png>)

Ein Hintergrundjob, ein gestoppter und der letzte Befehl wurde nicht korrekt beendet:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
