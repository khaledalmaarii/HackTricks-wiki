# DDexec / EverythingExec

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Kontext

In Linux muss ein Programm existieren und als Datei zugänglich sein, um ausgeführt werden zu können (so funktioniert `execve()`). Diese Datei kann auf der Festplatte oder im RAM (tmpfs, memfd) liegen, aber Sie benötigen einen Dateipfad. Dadurch wird es sehr einfach, zu kontrollieren, was auf einem Linux-System ausgeführt wird. Es erleichtert die Erkennung von Bedrohungen und Angreiferwerkzeugen oder verhindert, dass nicht privilegierte Benutzer ausführbare Dateien überhaupt irgendwo platzieren können.

Aber diese Technik ist hier, um all das zu ändern. Wenn Sie den gewünschten Prozess nicht starten können... **übernehmen Sie einfach einen bereits vorhandenen**.

Diese Technik ermöglicht es Ihnen, gängige Schutztechniken wie schreibgeschützt, noexec, Whitelist für Dateinamen, Whitelist für Hashes zu umgehen...

## Abhängigkeiten

Das endgültige Skript hängt von den folgenden Tools ab, um zu funktionieren. Sie müssen auf dem System, das Sie angreifen, zugänglich sein (standardmäßig finden Sie sie überall):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Die Technik

Wenn Sie den Speicher eines Prozesses beliebig ändern können, können Sie ihn übernehmen. Dies kann verwendet werden, um einen bereits vorhandenen Prozess zu übernehmen und durch ein anderes Programm zu ersetzen. Dies kann entweder durch Verwendung des `ptrace()`-Systemaufrufs (der das Ausführen von Systemaufrufen erfordert oder gdb auf dem System verfügbar haben muss) oder interessanterweise durch Schreiben in `/proc/$pid/mem` erreicht werden.

Die Datei `/proc/$pid/mem` ist eine Eins-zu-Eins-Abbildung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` in x86-64). Dies bedeutet, dass das Lesen oder Schreiben dieser Datei an einer Offset-Position `x` dem Lesen oder Ändern des Inhalts an der virtuellen Adresse `x` entspricht.

Nun haben wir vier grundlegende Probleme zu bewältigen:

* Im Allgemeinen können nur der Root-Benutzer und der Programm-Besitzer die Datei ändern.
* ASLR.
* Wenn wir versuchen, an eine Adresse zu lesen oder zu schreiben, die nicht im Adressraum des Programms abgebildet ist, erhalten wir einen E/A-Fehler.

Diese Probleme haben Lösungen, die zwar nicht perfekt sind, aber gut:

* Die meisten Shell-Interpreter ermöglichen die Erstellung von Dateideskriptoren, die dann von Kindprozessen geerbt werden. Wir können einen Dateideskriptor erstellen, der auf die `mem`-Datei der Shell mit Schreibberechtigungen zeigt... so dass Kindprozesse, die diesen Dateideskriptor verwenden, den Speicher der Shell ändern können.
* ASLR ist kein Problem, wir können die `maps`-Datei der Shell oder eine andere aus dem procfs überprüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
* Wir müssen uns also über die Datei bewegen (`lseek()`). Dies kann von der Shell aus nicht gemacht werden, es sei denn, man verwendet das berüchtigte `dd`.

### Detaillierter

Die Schritte sind relativ einfach und erfordern keine besondere Expertise, um sie zu verstehen:

* Analysieren Sie die auszuführende Binärdatei und den Loader, um herauszufinden, welche Abbildungen sie benötigen. Erstellen Sie dann einen "Shell"-Code, der im Wesentlichen die gleichen Schritte ausführt, die der Kernel bei jedem Aufruf von `execve()` durchführt:
* Erstellen Sie diese Abbildungen.
* Lesen Sie die Binärdateien in sie ein.
* Richten Sie Berechtigungen ein.
* Initialisieren Sie schließlich den Stack mit den Argumenten für das Programm und platzieren Sie den Hilfsvektor (der vom Loader benötigt wird).
* Springen Sie in den Loader und lassen Sie ihn den Rest erledigen (Laden der für das Programm benötigten Bibliotheken).
* Ermitteln Sie aus der Datei `syscall` die Adresse, zu der der Prozess nach dem Ausführen des Systemaufrufs zurückkehren wird.
* Überschreiben Sie diesen Ort, der ausführbar sein wird, mit unserem Shellcode (über `mem` können wir unbeschreibbare Seiten ändern).
* Übergeben Sie das Programm, das wir ausführen möchten, an den stdin des Prozesses (wird von besagtem "Shell"-Code `read()`).
* An diesem Punkt liegt es am Loader, die erforderlichen Bibliotheken für unser Programm zu laden und in es zu springen.

**Schauen Sie sich das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **an**

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, von denen `tail` eine ist, die derzeit das Standardprogramm ist, das zum `lseek()` durch die `mem`-Datei verwendet wird (was der einzige Zweck für die Verwendung von `dd` war). Diese Alternativen sind:
```bash
tail
hexdump
cmp
xxd
```
Durch das Setzen der Variable `SEEKER` können Sie den verwendeten Sucher ändern, z. B.:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Wenn Sie einen anderen gültigen Sucher finden, der nicht im Skript implementiert ist, können Sie ihn immer noch verwenden, indem Sie die Variable `SEEKER_ARGS` festlegen:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockieren Sie das, EDRs.

## Referenzen
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
