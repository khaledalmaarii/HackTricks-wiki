# Linux Umgebungsvariablen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Globale Variablen

Die globalen Variablen **werden von** **Kindprozessen** geerbt.

Sie können eine globale Variable für Ihre aktuelle Sitzung erstellen, indem Sie:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable wird von Ihren aktuellen Sitzungen und deren untergeordneten Prozessen zugänglich sein.

Sie können eine Variable **entfernen**, indem Sie:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Die **lokalen Variablen** können nur von der **aktuellen Shell/dem aktuellen Skript** **zugegriffen** werden.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Liste aktuelle Variablen
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Gemeinsame Variablen

Von: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – das Display, das von **X** verwendet wird. Diese Variable ist normalerweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bedeutet.
* **EDITOR** – der bevorzugte Texteditor des Benutzers.
* **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der Verlaufsdatei enthalten sind.
* **HISTSIZE** – Anzahl der Zeilen, die der Verlaufsdatei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
* **HOME** – Ihr Benutzerverzeichnis.
* **HOSTNAME** – der Hostname des Computers.
* **LANG** – Ihre aktuelle Sprache.
* **MAIL** – der Speicherort des Benutzer-Mail-Spool. Normalerweise **/var/spool/mail/BENUTZER**.
* **MANPATH** – die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
* **OSTYPE** – der Typ des Betriebssystems.
* **PS1** – die Standard-Prompt in bash.
* **PATH** – speichert den Pfad aller Verzeichnisse, die Binärdateien enthalten, die Sie ausführen möchten, indem Sie nur den Dateinamen angeben und nicht den relativen oder absoluten Pfad.
* **PWD** – das aktuelle Arbeitsverzeichnis.
* **SHELL** – der Pfad zur aktuellen Befehlsshell (zum Beispiel **/bin/bash**).
* **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
* **TZ** – Ihre Zeitzone.
* **USER** – Ihr aktueller Benutzername.

## Interessante Variablen für Hacking

### **HISTFILESIZE**

Ändern Sie den **Wert dieser Variablen auf 0**, damit beim **Beenden Ihrer Sitzung** die **Verlaufsdatei** (\~/.bash\_history) **gelöscht wird**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändern Sie den **Wert dieser Variablen auf 0**, damit bei **Beendigung Ihrer Sitzung** keine Befehle zur **Verlaufsdatei** (\~/.bash\_history) hinzugefügt werden.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Die Prozesse werden den hier deklarierten **Proxy** verwenden, um eine Verbindung zum Internet über **http oder https** herzustellen.
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

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Normaler Benutzer:

![](<../.gitbook/assets/image (740).png>)

Ein, zwei und drei im Hintergrund laufende Jobs:

![](<../.gitbook/assets/image (145).png>)

Ein Hintergrundjob, ein gestoppter Job und der letzte Befehl wurde nicht korrekt beendet:

![](<../.gitbook/assets/image (715).png>)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
