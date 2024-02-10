# CGroups

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlegende Informationen

**Linux Control Groups** oder **cgroups** sind eine Funktion des Linux-Kernels, die die Zuweisung, Begrenzung und Priorisierung von Systemressourcen wie CPU, Speicher und Festplatten-E/A für Prozessgruppen ermöglicht. Sie bieten einen Mechanismus zum **Verwalten und Isolieren der Ressourcennutzung** von Prozesssammlungen, der für Zwecke wie Ressourcenbegrenzung, Arbeitslastisolierung und Ressourcenpriorisierung zwischen verschiedenen Prozessgruppen vorteilhaft ist.

Es gibt **zwei Versionen von cgroups**: Version 1 und Version 2. Beide können gleichzeitig auf einem System verwendet werden. Der Hauptunterschied besteht darin, dass **cgroups Version 2** eine **hierarchische, baumartige Struktur** einführt, die eine nuanciertere und detailliertere Ressourcenverteilung zwischen Prozessgruppen ermöglicht. Darüber hinaus bringt Version 2 verschiedene Verbesserungen mit sich, darunter:

Neben der neuen hierarchischen Organisation hat cgroups Version 2 auch **weitere Änderungen und Verbesserungen** eingeführt, wie die Unterstützung für **neue Ressourcencontroller**, eine bessere Unterstützung für Legacy-Anwendungen und verbesserte Leistung.

Insgesamt bietet cgroups **Version 2 mehr Funktionen und bessere Leistung** als Version 1, aber letztere kann immer noch in bestimmten Szenarien verwendet werden, in denen die Kompatibilität mit älteren Systemen eine Rolle spielt.

Sie können die v1- und v2-cgroups für jeden Prozess auflisten, indem Sie die cgroup-Datei in /proc/\<pid> betrachten. Sie können mit diesem Befehl mit den cgroups Ihrer Shell beginnen:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Die Ausgabestruktur ist wie folgt:

- **Zahlen 2–12**: cgroups v1, wobei jede Zeile einen anderen cgroup darstellt. Die Controller für diese werden neben der Nummer angegeben.
- **Nummer 1**: Auch cgroups v1, aber ausschließlich für Verwaltungszwecke (festgelegt durch z.B. systemd) und ohne Controller.
- **Nummer 0**: Stellt cgroups v2 dar. Es werden keine Controller aufgelistet und diese Zeile ist exklusiv für Systeme, die nur cgroups v2 ausführen.
- Die **Namen sind hierarchisch**, ähnlich wie Dateipfade, und geben die Struktur und Beziehung zwischen verschiedenen cgroups an.
- **Namen wie /user.slice oder /system.slice** geben die Kategorisierung der cgroups an, wobei user.slice in der Regel für von systemd verwaltete Anmeldesitzungen und system.slice für Systemdienste verwendet wird.

### Anzeigen von cgroups

Das Dateisystem wird in der Regel zur **Zugriff auf cgroups** verwendet, im Gegensatz zur Unix-Systemaufrufschnittstelle, die traditionell für Kernelinteraktionen verwendet wird. Um die cgroup-Konfiguration einer Shell zu untersuchen, sollte die Datei **/proc/self/cgroup** überprüft werden, die die cgroup der Shell anzeigt. Anschließend kann man durch Navigieren zum Verzeichnis **/sys/fs/cgroup** (oder **`/sys/fs/cgroup/unified`**) und das Auffinden eines Verzeichnisses mit demselben Namen wie die cgroup verschiedene Einstellungen und Informationen zur Ressourcennutzung anzeigen.

![Cgroup-Dateisystem](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Die wichtigsten Schnittstellendateien für cgroups haben das Präfix **cgroup**. Die Datei **cgroup.procs**, die mit Standardbefehlen wie cat angezeigt werden kann, listet die Prozesse innerhalb der cgroup auf. Eine andere Datei, **cgroup.threads**, enthält Thread-Informationen.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Cgroups, die Shells verwalten, umfassen in der Regel zwei Controller, die den Speicherverbrauch und die Prozessanzahl regeln. Um mit einem Controller zu interagieren, sollten Dateien mit dem Präfix des Controllers konsultiert werden. Zum Beispiel würde **pids.current** verwendet, um die Anzahl der Threads in der cgroup zu ermitteln.

![Cgroup Memory](../../../.gitbook/assets/image%20(3)%20(5).png)

Das Vorhandensein von **max** in einem Wert deutet auf das Fehlen einer spezifischen Begrenzung für die cgroup hin. Aufgrund der hierarchischen Struktur von cgroups können jedoch Begrenzungen von einer cgroup auf einer niedrigeren Ebene in der Verzeichnishierarchie auferlegt werden.


### Manipulation und Erstellung von cgroups

Prozesse werden cgroups zugewiesen, indem ihre Prozess-ID (PID) in die Datei `cgroup.procs` geschrieben wird. Hierfür sind Root-Rechte erforderlich. Um beispielsweise einen Prozess hinzuzufügen:
```bash
echo [pid] > cgroup.procs
```
Ebenso wird das **Ändern von cgroup-Attributen, wie das Festlegen eines PID-Limits**, durch das Schreiben des gewünschten Werts in die entsprechende Datei durchgeführt. Um ein Maximum von 3.000 PIDs für eine cgroup festzulegen:
```bash
echo 3000 > pids.max
```
**Erstellen neuer cgroups** beinhaltet das Erstellen eines neuen Unterverzeichnisses innerhalb der cgroup-Hierarchie, was dazu führt, dass der Kernel automatisch die erforderlichen Schnittstellen-Dateien generiert. Obwohl cgroups ohne aktive Prozesse mit `rmdir` entfernt werden können, sollten bestimmte Einschränkungen beachtet werden:

- **Prozesse können nur in Blattcgroups platziert werden** (d.h. den am weitesten verschachtelten in einer Hierarchie).
- **Ein cgroup kann keinen Controller besitzen, der in seinem Elternteil fehlt**.
- **Controller für Untercgroups müssen explizit im `cgroup.subtree_control`-Datei deklariert werden**. Zum Beispiel, um CPU- und PID-Controller in einer Untercgroup zu aktivieren:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Die **Root-Cgroup** ist eine Ausnahme von diesen Regeln und ermöglicht eine direkte Prozessplatzierung. Dies kann verwendet werden, um Prozesse aus der systemd-Verwaltung zu entfernen.

Die **Überwachung der CPU-Auslastung** innerhalb einer Cgroup ist über die Datei `cpu.stat` möglich, die die insgesamt verbrauchte CPU-Zeit anzeigt und hilfreich ist, um die Nutzung über die Unterprozesse eines Dienstes zu verfolgen:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>CPU-Auslastungsstatistik wie in der Datei cpu.stat angezeigt</figcaption></figure>

## Referenzen
* **Buch: How Linux Works, 3. Auflage: Was jeder Superuser wissen sollte von Brian Ward**

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
