# CGroups

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

## Grundlegende Informationen

**Linux Control Groups** oder **cgroups** sind eine Funktion des Linux-Kernels, die die Zuweisung, Begrenzung und Priorisierung von Systemressourcen wie CPU, Speicher und Festplatten-E/A unter Prozessgruppen ermöglicht. Sie bieten einen Mechanismus zum **Verwalten und Isolieren der Ressourcennutzung** von Prozesssammlungen, der für Zwecke wie Ressourcenbegrenzung, Arbeitslastisolierung und Ressourcenpriorisierung zwischen verschiedenen Prozessgruppen vorteilhaft ist.

Es gibt **zwei Versionen von cgroups**: Version 1 und Version 2. Beide können gleichzeitig auf einem System verwendet werden. Der Hauptunterschied besteht darin, dass **cgroups Version 2** eine **hierarchische, baumartige Struktur** einführt, die eine nuanciertere und detailliertere Ressourcenverteilung zwischen Prozessgruppen ermöglicht. Darüber hinaus bringt Version 2 verschiedene Verbesserungen mit sich, darunter:

Neben der neuen hierarchischen Organisation hat cgroups Version 2 auch **mehrere andere Änderungen und Verbesserungen** eingeführt, wie die Unterstützung für **neue Ressourcencontroller**, eine bessere Unterstützung für Legacy-Anwendungen und verbesserte Leistung.

Insgesamt bietet cgroups **Version 2 mehr Funktionen und bessere Leistung** als Version 1, aber letztere kann in bestimmten Szenarien immer noch verwendet werden, wenn die Kompatibilität mit älteren Systemen ein Anliegen ist.

Sie können die v1- und v2-cgroups für jeden Prozess auflisten, indem Sie seine cgroup-Datei in /proc/\<pid> betrachten. Sie können damit beginnen, die cgroups Ihrer Shell mit diesem Befehl anzuzeigen:
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
* **Zahlen 2–12**: cgroups v1, wobei jede Zeile einen anderen cgroup darstellt. Die Controller für diese sind neben der Nummer angegeben.
* **Nummer 1**: Auch cgroups v1, jedoch ausschließlich für Verwaltungszwecke (festgelegt z.B. von systemd) und ohne Controller.
* **Nummer 0**: Stellt cgroups v2 dar. Es werden keine Controller aufgelistet, und diese Zeile ist exklusiv für Systeme, die nur cgroups v2 ausführen.
* Die **Namen sind hierarchisch**, ähneln Dateipfaden und zeigen die Struktur und Beziehung zwischen verschiedenen cgroups an.
* **Namen wie /user.slice oder /system.slice** geben die Kategorisierung von cgroups an, wobei user.slice typischerweise für von systemd verwaltete Anmeldesitzungen und system.slice für Systemdienste steht.

### Anzeigen von cgroups

Das Dateisystem wird typischerweise zur **Zugriff auf cgroups** verwendet, was sich von der Unix-Systemaufrufschnittstelle unterscheidet, die traditionell für Kernelinteraktionen verwendet wird. Um die cgroup-Konfiguration einer Shell zu untersuchen, sollte die Datei **/proc/self/cgroup** überprüft werden, die die cgroup der Shell offenbart. Anschließend kann man durch Navigieren zum Verzeichnis **/sys/fs/cgroup** (oder **`/sys/fs/cgroup/unified`**) und das Auffinden eines Verzeichnisses mit dem Namen der cgroup verschiedene Einstellungen und Ressourcennutzungsinformationen, die für die cgroup relevant sind, beobachten.

![Cgroup-Dateisystem](<../../../.gitbook/assets/image (1128).png>)

Die wichtigsten Schnittstellendateien für cgroups sind mit **cgroup** vorangestellt. Die Datei **cgroup.procs**, die mit Standardbefehlen wie cat angezeigt werden kann, listet die Prozesse innerhalb der cgroup auf. Eine weitere Datei, **cgroup.threads**, enthält Thread-Informationen.

![Cgroup-Prozesse](<../../../.gitbook/assets/image (281).png>)

Cgroups, die Shells verwalten, umfassen in der Regel zwei Controller, die die Speicherauslastung und die Prozessanzahl regulieren. Um mit einem Controller zu interagieren, sollten Dateien mit dem Präfix des Controllers konsultiert werden. Beispielsweise würde auf **pids.current** verwiesen, um die Anzahl der Threads in der cgroup festzustellen.

![Cgroup-Speicher](<../../../.gitbook/assets/image (677).png>)

Die Angabe von **max** in einem Wert deutet auf das Fehlen einer spezifischen Grenze für die cgroup hin. Aufgrund der hierarchischen Struktur von cgroups könnten jedoch Grenzen von einer cgroup auf einer niedrigeren Ebene im Verzeichnishierarchie auferlegt werden.

### Manipulation und Erstellung von cgroups

Prozesse werden cgroups zugewiesen, indem ihre Prozess-ID (PID) in die Datei `cgroup.procs` geschrieben wird. Dies erfordert Root-Berechtigungen. Zum Beispiel, um einen Prozess hinzuzufügen:
```bash
echo [pid] > cgroup.procs
```
Ebenso wird das **Ändern von cgroup-Attributen, wie das Festlegen eines PID-Limits**, durch Schreiben des gewünschten Werts in die entsprechende Datei durchgeführt. Um ein Maximum von 3.000 PIDs für eine cgroup festzulegen:
```bash
echo 3000 > pids.max
```
**Erstellen neuer cgroups** beinhaltet das Erstellen eines neuen Unterverzeichnisses innerhalb der cgroup-Hierarchie, was den Kernel dazu veranlasst, die erforderlichen Schnittstellen-Dateien automatisch zu generieren. Obwohl cgroups ohne aktive Prozesse mit `rmdir` entfernt werden können, sollten bestimmte Einschränkungen beachtet werden:

* **Prozesse können nur in Blattcgroups** platziert werden (d. h. die am meisten verschachtelten in einer Hierarchie).
* **Ein cgroup kann keinen Controller besitzen, der in seinem Elternteil fehlt**.
* **Controller für Kindcgroups müssen explizit im** `cgroup.subtree_control` **Datei deklariert werden**. Zum Beispiel, um CPU- und PID-Controller in einem Kindcgroup zu aktivieren:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Der **Root-Cgroup** ist eine Ausnahme von diesen Regeln und ermöglicht eine direkte Prozessplatzierung. Dies kann verwendet werden, um Prozesse aus dem systemd-Management zu entfernen.

**Die Überwachung der CPU-Auslastung** innerhalb eines cgroups ist durch die Datei `cpu.stat` möglich, die die insgesamt verbrauchte CPU-Zeit anzeigt und hilfreich ist, um die Nutzung über die Unterprozesse eines Dienstes zu verfolgen:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>CPU-Auslastungsstatistiken wie in der Datei cpu.stat angezeigt</p></figcaption></figure>

## Referenzen

* **Buch: How Linux Works, 3. Auflage: Was jeder Superuser wissen sollte von Brian Ward**
