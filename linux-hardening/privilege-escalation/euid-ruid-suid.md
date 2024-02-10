# euid, ruid, suid

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null bis zum Experten mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

### Benutzeridentifikationsvariablen

- **`ruid`**: Die **reale Benutzer-ID** bezeichnet den Benutzer, der den Prozess gestartet hat.
- **`euid`**: Als **effektive Benutzer-ID** bekannt, repräsentiert sie die Benutzeridentität, die vom System verwendet wird, um Prozessprivilegien festzustellen. Im Allgemeinen spiegelt `euid` `ruid` wider, mit Ausnahme von Fällen wie der Ausführung einer SetUID-Binärdatei, bei der `euid` die Identität des Dateibesitzers annimmt und bestimmte Betriebsberechtigungen gewährt.
- **`suid`**: Diese **gespeicherte Benutzer-ID** ist entscheidend, wenn ein Prozess mit hohen Privilegien (in der Regel als root ausgeführt) vorübergehend seine Privilegien aufgeben muss, um bestimmte Aufgaben auszuführen, nur um später seinen ursprünglichen erhöhten Status wiederzuerlangen.

#### Wichtiger Hinweis
Ein Prozess, der nicht als root ausgeführt wird, kann nur seine `euid` ändern, um mit der aktuellen `ruid`, `euid` oder `suid` übereinzustimmen.

### Verständnis der set*uid-Funktionen

- **`setuid`**: Entgegen erster Annahmen ändert `setuid` hauptsächlich `euid` anstelle von `ruid`. Für privilegierte Prozesse gleicht es `ruid`, `euid` und `suid` mit dem angegebenen Benutzer, oft root, ab und festigt diese IDs effektiv aufgrund der überschreibenden `suid`. Detaillierte Einblicke finden Sie in der [setuid-Manpage](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** und **`setresuid`**: Diese Funktionen ermöglichen die differenzierte Anpassung von `ruid`, `euid` und `suid`. Ihre Fähigkeiten hängen jedoch vom Privilegienlevel des Prozesses ab. Für Nicht-Root-Prozesse sind Änderungen auf die aktuellen Werte von `ruid`, `euid` und `suid` beschränkt. Im Gegensatz dazu können Root-Prozesse oder solche mit der `CAP_SETUID`-Fähigkeit beliebige Werte diesen IDs zuweisen. Weitere Informationen finden Sie in der [setresuid-Manpage](https://man7.org/linux/man-pages/man2/setresuid.2.html) und der [setreuid-Manpage](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Diese Funktionen sind nicht als Sicherheitsmechanismus konzipiert, sondern sollen den beabsichtigten Arbeitsablauf erleichtern, z. B. wenn ein Programm die Identität eines anderen Benutzers annimmt, indem es seine effektive Benutzer-ID ändert.

Es ist wichtig zu beachten, dass `setuid` zwar häufig zur Erhöhung der Privilegien auf root verwendet wird (da es alle IDs auf root ausrichtet), aber es ist entscheidend, zwischen diesen Funktionen zu unterscheiden, um das Verhalten der Benutzer-IDs in verschiedenen Szenarien zu verstehen und zu manipulieren.

### Programm-Ausführungsmechanismen in Linux

#### **`execve`-Systemaufruf**
- **Funktionalität**: `execve` startet ein Programm, das durch das erste Argument bestimmt wird. Es nimmt zwei Array-Argumente entgegen: `argv` für Argumente und `envp` für die Umgebung.
- **Verhalten**: Es behält den Speicherplatz des Aufrufers bei, aktualisiert jedoch den Stack, den Heap und die Datensegmente. Der Code des Programms wird durch das neue Programm ersetzt.
- **Erhaltung der Benutzer-ID**:
- `ruid`, `euid` und zusätzliche Gruppen-IDs bleiben unverändert.
- `euid` kann subtile Änderungen aufweisen, wenn das neue Programm das SetUID-Bit gesetzt hat.
- `suid` wird nach der Ausführung von `euid` aktualisiert.
- **Dokumentation**: Detaillierte Informationen finden Sie in der [`execve`-Manpage](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system`-Funktion**
- **Funktionalität**: Im Gegensatz zu `execve` erstellt `system` einen Kindprozess mit `fork` und führt einen Befehl in diesem Kindprozess mit `execl` aus.
- **Befehlsausführung**: Führt den Befehl über `sh` mit `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` aus.
- **Verhalten**: Da `execl` eine Form von `execve` ist, funktioniert es ähnlich, jedoch im Kontext eines neuen Kindprozesses.
- **Dokumentation**: Weitere Einblicke finden Sie in der [`system`-Manpage](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Verhalten von `bash` und `sh` mit SUID**
- **`bash`**:
- Hat eine `-p`-Option, die beeinflusst, wie `euid` und `ruid` behandelt werden.
- Ohne `-p` setzt `bash` `euid` auf `ruid`, wenn sie anfangs unterschiedlich sind.
- Mit `-p` wird das anfängliche `euid` beibehalten.
- Weitere Details finden Sie in der [`bash`-Manpage](https://linux.die.net/man/1/bash).
- **`sh`**:
- Besitzt keinen Mechanismus ähnlich wie `-p` in `bash`.
- Das Verhalten in Bezug auf Benutzer-IDs wird nicht explizit erwähnt, außer unter der `-i`-Option, die die Gleichheit von `euid` und `ruid` betont.
- Weitere Informationen finden Sie in der [`sh`-Manpage](https://man7.org/linux/man-pages/man1/sh.1p.html).

Diese Mechanismen, die sich in ihrem Betrieb unterscheiden, bieten eine vielseitige Auswahl an Optionen zum Ausführen und Wechseln zwischen Programmen, wobei spezifische Nuancen in der Verwaltung und Erhaltung von Benutzer-IDs bestehen.

### Testen des Verhaltens der Benutzer-IDs bei der Ausführung

Beispiele entnommen von https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, überprüfen Sie es für weitere Informationen

#### Fall 1: Verwendung von `setuid` mit `system`

**Ziel**: Verständnis der Auswirkungen von `setuid` in Kombination mit `system` und `bash` als `sh`.

**C-Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Kompilierung und Berechtigungen:**

Beim Kompilieren von Programmen unter Linux werden verschiedene Berechtigungen festgelegt, um die Ausführung und den Zugriff auf Dateien zu steuern. Diese Berechtigungen werden durch die Eigentümer- und Gruppenrechte sowie die Zugriffsrechte für andere Benutzer definiert.

Die Eigentümerrechte bestimmen, welche Aktionen der Eigentümer einer Datei ausführen kann. Dies umfasst das Lesen, Schreiben und Ausführen der Datei. Die Gruppenrechte legen fest, welche Aktionen Mitglieder der Gruppe, zu der die Datei gehört, ausführen können. Die Zugriffsrechte für andere Benutzer bestimmen, welche Aktionen alle anderen Benutzer ausführen können.

Die Berechtigungen werden in Form von Zahlenwerten dargestellt. Jeder Wert repräsentiert eine bestimmte Kombination von Berechtigungen. Zum Beispiel steht die Zahl 7 für die Berechtigungen "Lesen, Schreiben und Ausführen", während die Zahl 4 für "Lesen" steht.

Um die Berechtigungen einer Datei anzuzeigen, verwenden Sie den Befehl `ls -l`. Dies zeigt die Berechtigungen für den Eigentümer, die Gruppe und andere Benutzer an.

Um die Berechtigungen einer Datei zu ändern, verwenden Sie den Befehl `chmod`. Zum Beispiel können Sie mit `chmod 755 datei.txt` die Berechtigungen so ändern, dass der Eigentümer die Datei lesen, schreiben und ausführen kann, während die Gruppe und andere Benutzer die Datei nur lesen und ausführen können.

Es ist wichtig, die Berechtigungen sorgfältig zu verwalten, um die Sicherheit des Systems zu gewährleisten. Falsch konfigurierte Berechtigungen können dazu führen, dass unbefugte Benutzer auf sensible Informationen zugreifen oder schädlichen Code ausführen können.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

* `ruid` und `euid` starten jeweils als 99 (nobody) und 1000 (frank).
* `setuid` passt beide auf 1000 an.
* `system` führt `/bin/bash -c id` aus, aufgrund des Symlinks von sh zu bash.
* `bash`, ohne `-p`, passt `euid` an `ruid` an, sodass beide 99 (nobody) sind.

#### Fall 2: Verwendung von setreuid mit system

**C-Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Kompilierung und Berechtigungen:**

Beim Kompilieren von Programmen unter Linux werden verschiedene Berechtigungen festgelegt, um die Ausführung und den Zugriff auf Dateien zu steuern. Diese Berechtigungen werden durch die Eigentümer- und Gruppenrechte sowie die Zugriffsrechte für andere Benutzer definiert.

Die Eigentümerrechte bestimmen, welche Aktionen der Eigentümer einer Datei ausführen kann. Dies umfasst das Lesen, Schreiben und Ausführen der Datei. Die Gruppenrechte legen fest, welche Aktionen Mitglieder der Gruppe, zu der die Datei gehört, ausführen können. Die Zugriffsrechte für andere Benutzer bestimmen, welche Aktionen alle anderen Benutzer ausführen können.

Die Berechtigungen werden in Form von Zahlenwerten dargestellt. Jeder Wert repräsentiert eine bestimmte Kombination von Berechtigungen. Zum Beispiel steht die Zahl 7 für die Berechtigungen "Lesen, Schreiben und Ausführen", während die Zahl 4 für "Lesen" steht.

Um die Berechtigungen einer Datei anzuzeigen, verwenden Sie den Befehl `ls -l`. Dies zeigt die Berechtigungen für den Eigentümer, die Gruppe und andere Benutzer an.

Um die Berechtigungen einer Datei zu ändern, verwenden Sie den Befehl `chmod`. Zum Beispiel können Sie mit `chmod 755 datei.txt` die Berechtigungen so ändern, dass der Eigentümer die Datei lesen, schreiben und ausführen kann, während die Gruppe und andere Benutzer die Datei nur lesen und ausführen können.

Es ist wichtig, die Berechtigungen sorgfältig zu verwalten, um die Sicherheit des Systems zu gewährleisten. Falsch konfigurierte Berechtigungen können dazu führen, dass unbefugte Benutzer auf sensible Informationen zugreifen oder schädlichen Code ausführen können.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

* `setreuid` setzt sowohl ruid als auch euid auf 1000.
* `system` ruft bash auf, die aufgrund ihrer Gleichheit die Benutzer-IDs beibehält und effektiv als frank agiert.

#### Fall 3: Verwendung von setuid mit execve
Ziel: Erforschung der Interaktion zwischen setuid und execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

* `ruid` bleibt bei 99, aber `euid` wird auf 1000 gesetzt, entsprechend der Wirkung von `setuid`.

**C-Code-Beispiel 2 (Aufruf von Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

* Obwohl `euid` durch `setuid` auf 1000 gesetzt wird, setzt `bash` `euid` auf `ruid` (99) zurück, da `-p` fehlt.

**C Code Beispiel 3 (Verwendung von bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referenzen
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
