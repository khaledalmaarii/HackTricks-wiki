# DDexec / EverythingExec

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>
{% endhint %}

## Kontext

In Linux muss ein Programm existieren und auf irgendeine Weise im Dateisystemhierarchie zugänglich sein, um ausgeführt zu werden (so funktioniert `execve()`). Diese Datei kann auf der Festplatte oder im RAM (tmpfs, memfd) liegen, aber Sie benötigen einen Dateipfad. Dies hat es sehr einfach gemacht, zu kontrollieren, was auf einem Linux-System ausgeführt wird, es erleichtert die Erkennung von Bedrohungen und Angriffswerkzeugen oder verhindert, dass sie versuchen, überhaupt etwas von sich aus auszuführen (_z. B._ keine nicht privilegierten Benutzer ausführen lassen, ausführbare Dateien irgendwo abzulegen).

Aber diese Technik ist hier, um all dies zu ändern. Wenn Sie den gewünschten Prozess nicht starten können... **dann kapern Sie einen bereits vorhandenen**.

Diese Technik ermöglicht es Ihnen, **übliche Schutztechniken wie schreibgeschützt, noexec, Whitelisting von Dateinamen, Hash-Whitelisting zu umgehen...**

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

Wenn Sie in der Lage sind, den Speicher eines Prozesses beliebig zu ändern, können Sie ihn übernehmen. Dies kann verwendet werden, um einen bereits vorhandenen Prozess zu kapern und durch ein anderes Programm zu ersetzen. Dies kann entweder durch Verwendung des `ptrace()`-Systemaufrufs (der es erfordert, die Fähigkeit zu haben, Systemaufrufe auszuführen oder gdb auf dem System verfügbar zu haben) oder interessanterweise durch Schreiben in `/proc/$pid/mem` erreicht werden.

Die Datei `/proc/$pid/mem` ist eine Eins-zu-Eins-Zuordnung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` in x86-64). Dies bedeutet, dass das Lesen oder Schreiben in diese Datei an einer Offset-Position `x` dasselbe ist wie das Lesen oder Ändern des Inhalts an der virtuellen Adresse `x`.

Nun haben wir vier grundlegende Probleme zu bewältigen:

* Im Allgemeinen können nur Root und der Programm-Besitzer die Datei ändern.
* ASLR.
* Wenn wir versuchen, an eine Adresse zu lesen oder zu schreiben, die nicht im Adressraum des Programms abgebildet ist, erhalten wir einen Ein-/Ausgabefehler.

Diese Probleme haben Lösungen, die zwar nicht perfekt sind, aber gut funktionieren:

* Die meisten Shell-Interpreter ermöglichen die Erstellung von Dateideskriptoren, die dann von Kindprozessen geerbt werden. Wir können einen Dateideskriptor erstellen, der auf die `mem`-Datei der Shell mit Schreibberechtigungen zeigt... sodass Kindprozesse, die diesen Dateideskriptor verwenden, den Speicher der Shell ändern können.
* ASLR ist kein Problem, wir können die `maps`-Datei der Shell oder eine andere aus dem procfs überprüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
* Also müssen wir über die Datei `lseek()` ausführen. Von der Shell aus kann dies nur mit dem berüchtigten `dd` erfolgen.

### Detaillierter

Die Schritte sind relativ einfach und erfordern kein spezielles Fachwissen, um sie zu verstehen:

* Analysieren Sie die auszuführende Binärdatei und den Loader, um herauszufinden, welche Zuordnungen sie benötigen. Erstellen Sie dann einen "Shell"-Code, der im Wesentlichen die gleichen Schritte ausführt, die der Kernel bei jedem Aufruf von `execve()` durchführt:
* Erstellen Sie diese Zuordnungen.
* Lesen Sie die Binärdateien in sie.
* Berechtigungen einrichten.
* Initialisieren Sie schließlich den Stapel mit den Argumenten für das Programm und platzieren Sie den Hilfsvektor (vom Loader benötigt).
* Springen Sie in den Loader und lassen Sie ihn den Rest erledigen (Laden von Bibliotheken, die vom Programm benötigt werden).
* Ermitteln Sie aus der `syscall`-Datei die Adresse, zu der der Prozess nach dem Ausführen des Systemaufrufs zurückkehren wird.
* Überschreiben Sie diesen Ort, der ausführbar sein wird, mit unserem Shellcode (über `mem` können wir nicht beschreibbare Seiten ändern).
* Übergeben Sie das Programm, das wir ausführen möchten, an die Standardeingabe des Prozesses (wird von diesem "Shell"-Code `read()`).
* Zu diesem Zeitpunkt liegt es am Loader, die für unser Programm erforderlichen Bibliotheken zu laden und in es zu springen.

**Schauen Sie sich das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, eine davon ist `tail`, das derzeit das Standardprogramm ist, das zum `lseek()` durch die `mem`-Datei verwendet wird (was der einzige Zweck für die Verwendung von `dd` war). Diese Alternativen sind:
```bash
tail
hexdump
cmp
xxd
```
Durch Festlegen der Variablen `SEEKER` können Sie den verwendeten Sucher ändern, z. B.:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Wenn Sie einen weiteren gültigen Sucher finden, der nicht im Skript implementiert ist, können Sie ihn trotzdem verwenden, indem Sie die Variable `SEEKER_ARGS` festlegen:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockiere dies, EDRs.

## Referenzen
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
Lerne & übe AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichst.

</details>
{% endhint %}
