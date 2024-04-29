# macOS Prozessmissbrauch

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

## Grundlegende Informationen zu Prozessen

Ein Prozess ist eine Instanz eines laufenden ausführbaren Programms, jedoch führen Prozesse keinen Code aus, sondern dies sind Threads. Daher sind **Prozesse lediglich Container für ausführbare Threads**, die Speicher, Deskriptoren, Ports, Berechtigungen bereitstellen...

Traditionell wurden Prozesse innerhalb anderer Prozesse gestartet (außer PID 1) durch Aufruf von **`fork`**, der eine genaue Kopie des aktuellen Prozesses erstellen würde, und dann würde der **Kindprozess** in der Regel **`execve`** aufrufen, um das neue ausführbare Programm zu laden und auszuführen. Dann wurde **`vfork`** eingeführt, um diesen Prozess schneller zu machen, ohne dass ein Speicherkopieren erforderlich ist.\
Dann wurde **`posix_spawn`** eingeführt, das **`vfork`** und **`execve`** in einem Aufruf kombiniert und Flags akzeptiert:

* `POSIX_SPAWN_RESETIDS`: Setzen der effektiven IDs auf reale IDs
* `POSIX_SPAWN_SETPGROUP`: Festlegen der Prozessgruppenzugehörigkeit
* `POSUX_SPAWN_SETSIGDEF`: Festlegen des Standardverhaltens für Signale
* `POSIX_SPAWN_SETSIGMASK`: Festlegen der Signalmaskierung
* `POSIX_SPAWN_SETEXEC`: Ausführen im selben Prozess (wie `execve` mit mehr Optionen)
* `POSIX_SPAWN_START_SUSPENDED`: Starten im ausgesetzten Zustand
* `_POSIX_SPAWN_DISABLE_ASLR`: Starten ohne ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Verwenden des Nano-Allokators von libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Erlauben von `rwx` auf Datensegmenten
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Standardmäßig alle Dateideskriptoren bei exec(2) schließen
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Zufällige Verschiebung der hohen Bits des ASLR

Darüber hinaus ermöglicht `posix_spawn` die Angabe eines Arrays von **`posix_spawnattr`**, das einige Aspekte des gestarteten Prozesses steuert, und **`posix_spawn_file_actions`**, um den Zustand der Deskriptoren zu ändern.

Wenn ein Prozess stirbt, sendet er den **Rückgabecode an den Elternprozess** (wenn der Elternprozess gestorben ist, ist der neue Elternprozess PID 1) mit dem Signal `SIGCHLD`. Der Elternprozess muss diesen Wert abrufen, indem er `wait4()` oder `waitid()` aufruft, und bis dies geschieht, bleibt das Kind in einem Zombiezustand, in dem es immer noch aufgeführt ist, aber keine Ressourcen verbraucht.

### PIDs

PIDs, Prozessidentifikatoren, identifizieren einen eindeutigen Prozess. In XNU sind die **PIDs** **64 Bit** groß und steigen monoton an und **wickeln sich nie** (um Missbrauch zu vermeiden).

### Prozessgruppen, Sitzungen & Koalitionen

**Prozesse** können in **Gruppen** eingefügt werden, um sie einfacher zu handhaben. Beispielsweise werden Befehle in einem Shell-Skript in derselben Prozessgruppe sein, sodass es möglich ist, sie zusammen mit kill zu **signalisieren**.\
Es ist auch möglich, **Prozesse in Sitzungen zu gruppieren**. Wenn ein Prozess eine Sitzung startet (`setsid(2)`), werden die Kindprozesse in die Sitzung gesetzt, es sei denn, sie starten ihre eigene Sitzung.

Koalition ist eine weitere Möglichkeit, Prozesse in Darwin zu gruppieren. Ein Prozess, der einer Koalition beitritt, kann auf Poolressourcen zugreifen, ein Ledger teilen oder Jetsam gegenübertreten. Koalitionen haben verschiedene Rollen: Leader, XPC-Dienst, Erweiterung.

### Anmeldeinformationen & Personae

Jeder Prozess hält **Anmeldeinformationen**, die **seine Berechtigungen identifizieren**. Jeder Prozess hat eine primäre `uid` und eine primäre `gid` (obwohl er mehreren Gruppen angehören kann).\
Es ist auch möglich, die Benutzer- und Gruppen-ID zu ändern, wenn das Binärprogramm das `setuid/setgid`-Bit hat.\
Es gibt mehrere Funktionen zum **Setzen neuer uids/gids**.

Das Systemaufruf **`persona`** bietet einen **alternativen** Satz von **Anmeldeinformationen**. Das Annehmen einer Persona setzt ihre uid, gid und Gruppenmitgliedschaften **auf einmal** voraus. Im [**Quellcode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) ist es möglich, die Struktur zu finden:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Threads Grundlegende Informationen

1. **POSIX Threads (pthreads):** macOS unterstützt POSIX-Threads (`pthreads`), die Teil einer Standard-Thread-API für C/C++ sind. Die Implementierung von pthreads in macOS befindet sich in `/usr/lib/system/libsystem_pthread.dylib` und stammt aus dem öffentlich verfügbaren `libpthread`-Projekt. Diese Bibliothek bietet die erforderlichen Funktionen zum Erstellen und Verwalten von Threads.
2. **Threads erstellen:** Die Funktion `pthread_create()` wird verwendet, um neue Threads zu erstellen. Intern ruft diese Funktion `bsdthread_create()` auf, was ein systemspezifischer system call für den XNU-Kernel (dem Kernel, auf dem macOS basiert) ist. Dieser system call verwendet verschiedene Flags, die aus `pthread_attr` (Attributen) abgeleitet sind und das Thread-Verhalten, einschließlich Zeitplanungsrichtlinien und Stackgröße, festlegen.
* **Standard-Stackgröße:** Die Standard-Stackgröße für neue Threads beträgt 512 KB, was für typische Operationen ausreichend ist, aber über Thread-Attribute angepasst werden kann, wenn mehr oder weniger Speicherplatz benötigt wird.
3. **Thread-Initialisierung:** Die Funktion `__pthread_init()` ist während der Thread-Einrichtung entscheidend und verwendet das `env[]`-Argument, um Umgebungsvariablen zu analysieren, die Details über den Speicherort und die Größe des Stacks enthalten können.

#### Thread-Beendigung in macOS

1. **Threads beenden:** Threads werden in der Regel durch Aufruf von `pthread_exit()` beendet. Diese Funktion ermöglicht es einem Thread, sauber zu beenden, erforderliche Aufräumarbeiten durchzuführen und dem Thread die Rückgabe eines Werts an mögliche Joiner zu ermöglichen.
2. **Thread-Aufräumen:** Beim Aufruf von `pthread_exit()` wird die Funktion `pthread_terminate()` aufgerufen, die die Entfernung aller zugehörigen Thread-Strukturen behandelt. Sie dealloziert Mach-Thread-Ports (Mach ist das Kommunikationssubsystem im XNU-Kernel) und ruft `bsdthread_terminate` auf, einen system call, der die mit dem Thread verbundenen Kernel-Level-Strukturen entfernt.

#### Synchronisierungsmechanismen

Um den Zugriff auf gemeinsam genutzte Ressourcen zu verwalten und Rennbedingungen zu vermeiden, bietet macOS mehrere Synchronisierungsprimitive. Diese sind in Multi-Thread-Umgebungen entscheidend, um die Datenintegrität und die Systemstabilität sicherzustellen:

1. **Mutexe:**
* **Regulärer Mutex (Signatur: 0x4D555458):** Standard-Mutex mit einem Speicherbedarf von 60 Bytes (56 Bytes für den Mutex und 4 Bytes für die Signatur).
* **Schneller Mutex (Signatur: 0x4d55545A):** Ähnlich wie ein regulärer Mutex, aber optimiert für schnellere Operationen, ebenfalls 60 Bytes groß.
2. **Bedingungsvariablen:**
* Werden verwendet, um auf das Eintreten bestimmter Bedingungen zu warten, mit einer Größe von 44 Bytes (40 Bytes plus einer 4-Byte-Signatur).
* **Attribute für Bedingungsvariablen (Signatur: 0x434e4441):** Konfigurationsattribute für Bedingungsvariablen, 12 Bytes groß.
3. **Einmal-Variable (Signatur: 0x4f4e4345):**
* Stellt sicher, dass ein Initialisierungscode nur einmal ausgeführt wird. Ihre Größe beträgt 12 Bytes.
4. **Lese-Schreib-Sperren:**
* Ermöglicht mehreren Lesern oder einem Schreiber gleichzeitig den Zugriff auf gemeinsam genutzte Daten.
* **Lese-Schreib-Sperre (Signatur: 0x52574c4b):** Größe von 196 Bytes.
* **Attribute für Lese-Schreib-Sperren (Signatur: 0x52574c41):** Attribute für Lese-Schreib-Sperren, 20 Bytes groß.

{% hint style="success" %}
Die letzten 4 Bytes dieser Objekte werden zur Erkennung von Überläufen verwendet.
{% endhint %}

### Thread-Lokale Variablen (TLV)

**Thread-Lokale Variablen (TLV)** im Kontext von Mach-O-Dateien (dem Format für ausführbare Dateien in macOS) werden verwendet, um Variablen zu deklarieren, die spezifisch für **jeden Thread** in einer Multi-Thread-Anwendung sind. Dies stellt sicher, dass jeder Thread eine eigene separate Instanz einer Variablen hat, was einen Konflikt vermeidet und die Datenintegrität ohne explizite Synchronisierungsmechanismen wie Mutexe gewährleistet.

In C und verwandten Sprachen können Sie eine threadlokale Variable mit dem Schlüsselwort **`__thread`** deklarieren. So funktioniert es in Ihrem Beispiel:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Dieser Ausschnitt definiert `tlv_var` als eine threadlokale Variable. Jeder Thread, der diesen Code ausführt, wird seine eigene `tlv_var` haben, und Änderungen, die ein Thread an `tlv_var` vornimmt, werden `tlv_var` in einem anderen Thread nicht beeinflussen.

Im Mach-O-Binary sind die Daten zu threadlokalen Variablen in spezifische Abschnitte organisiert:

* **`__DATA.__thread_vars`**: Dieser Abschnitt enthält Metadaten zu den threadlokalen Variablen, wie ihre Typen und Initialisierungsstatus.
* **`__DATA.__thread_bss`**: Dieser Abschnitt wird für threadlokale Variablen verwendet, die nicht explizit initialisiert sind. Es handelt sich um einen Teil des Speichers, der für nullinitialisierte Daten reserviert ist.

Mach-O bietet auch eine spezifische API namens **`tlv_atexit`** zur Verwaltung von threadlokalen Variablen beim Beenden eines Threads. Diese API ermöglicht es Ihnen, **Destruktoren zu registrieren** - spezielle Funktionen, die threadlokale Daten bereinigen, wenn ein Thread beendet wird.

### Threadprioritäten

Das Verständnis von Threadprioritäten beinhaltet die Betrachtung, wie das Betriebssystem entscheidet, welche Threads ausgeführt werden und wann. Diese Entscheidung wird durch den jedem Thread zugewiesenen Prioritätslevel beeinflusst. In macOS und Unix-ähnlichen Systemen wird dies mit Konzepten wie `nice`, `renice` und Quality of Service (QoS)-Klassen gehandhabt.

#### Nice und Renice

1. **Nice:**
* Der `nice`-Wert eines Prozesses ist eine Zahl, die seine Priorität beeinflusst. Jeder Prozess hat einen `nice`-Wert im Bereich von -20 (höchste Priorität) bis 19 (niedrigste Priorität). Der Standard-`nice`-Wert bei der Erstellung eines Prozesses beträgt in der Regel 0.
* Ein niedrigerer `nice`-Wert (näher an -20) macht einen Prozess "egoistischer" und gibt ihm mehr CPU-Zeit im Vergleich zu anderen Prozessen mit höheren `nice`-Werten.
2. **Renice:**
* `renice` ist ein Befehl, der verwendet wird, um den `nice`-Wert eines bereits laufenden Prozesses zu ändern. Dies kann verwendet werden, um die Priorität von Prozessen dynamisch anzupassen, indem ihre CPU-Zeitzuweisung basierend auf neuen `nice`-Werten erhöht oder verringert wird.
* Wenn ein Prozess beispielsweise vorübergehend mehr CPU-Ressourcen benötigt, könnten Sie seinen `nice`-Wert mit `renice` senken.

#### Quality of Service (QoS)-Klassen

QoS-Klassen sind ein modernerer Ansatz zur Behandlung von Threadprioritäten, insbesondere in Systemen wie macOS, die **Grand Central Dispatch (GCD)** unterstützen. QoS-Klassen ermöglichen es Entwicklern, Arbeit in verschiedene Ebenen zu kategorisieren, basierend auf ihrer Bedeutung oder Dringlichkeit. macOS verwaltet die Threadpriorisierung automatisch basierend auf diesen QoS-Klassen:

1. **Benutzerinteraktiv:**
* Diese Klasse ist für Aufgaben gedacht, die derzeit mit dem Benutzer interagieren oder sofortige Ergebnisse erfordern, um eine gute Benutzererfahrung zu bieten. Diese Aufgaben erhalten höchste Priorität, um die Benutzeroberfläche reaktionsschnell zu halten (z. B. Animationen oder Ereignisverarbeitung).
2. **Benutzerinitiiert:**
* Aufgaben, die der Benutzer initiiert und sofortige Ergebnisse erwartet, wie das Öffnen eines Dokuments oder das Klicken auf eine Schaltfläche, die Berechnungen erfordert. Diese haben eine hohe Priorität, aber unterhalb von benutzerinteraktiven Aufgaben.
3. **Dienstprogramm:**
* Diese Aufgaben sind lang laufend und zeigen in der Regel einen Fortschrittsindikator (z. B. Dateien herunterladen, Daten importieren). Sie haben eine niedrigere Priorität als benutzerinitiierte Aufgaben und müssen nicht sofort abgeschlossen werden.
4. **Hintergrund:**
* Diese Klasse ist für Aufgaben gedacht, die im Hintergrund ausgeführt werden und für den Benutzer nicht sichtbar sind. Dies können Aufgaben wie Indizieren, Synchronisieren oder Backups sein. Sie haben die niedrigste Priorität und minimale Auswirkungen auf die Systemleistung.

Durch die Verwendung von QoS-Klassen müssen Entwickler nicht die genauen Prioritätszahlen verwalten, sondern sich vielmehr auf die Art der Aufgabe konzentrieren, und das System optimiert die CPU-Ressourcen entsprechend.

Darüber hinaus gibt es verschiedene **Thread-Zeitplanungspolicen**, die Flows zur Spezifizierung eines Satzes von Zeitplanungsparametern, die der Scheduler berücksichtigen wird, angeben. Dies kann mit `thread_policy_[set/get]` durchgeführt werden. Dies könnte bei Angriffen auf Rennbedingungen nützlich sein.
### Python-Injektion

Wenn die Umgebungsvariable **`PYTHONINSPECT`** gesetzt ist, wird der Python-Prozess nach Abschluss in eine Python-CLI wechseln. Es ist auch möglich, **`PYTHONSTARTUP`** zu verwenden, um ein Python-Skript anzugeben, das am Anfang einer interaktiven Sitzung ausgeführt werden soll.\
Beachten Sie jedoch, dass das **`PYTHONSTARTUP`**-Skript nicht ausgeführt wird, wenn **`PYTHONINSPECT`** die interaktive Sitzung erstellt.

Andere Umgebungsvariablen wie **`PYTHONPATH`** und **`PYTHONHOME`** könnten ebenfalls nützlich sein, um einen Python-Befehl zur Ausführung beliebigen Codes zu bringen.

Beachten Sie, dass ausführbare Dateien, die mit **`pyinstaller`** kompiliert wurden, diese Umgebungsvariablen nicht verwenden, auch wenn sie mit einem eingebetteten Python ausgeführt werden.

{% hint style="danger" %}
Insgesamt konnte ich keinen Weg finden, um Python dazu zu bringen, beliebigen Code durch den Missbrauch von Umgebungsvariablen auszuführen.\
Die meisten Leute installieren jedoch Python mit **Hombrew**, das Python an einem **beschreibbaren Speicherort** für den Standard-Administratorbenutzer installiert. Sie können es mit etwas wie folgt übernehmen:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Selbst **root** wird diesen Code ausführen, wenn Python ausgeführt wird.
{% endhint %}

## Erkennung

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) ist eine Open-Source-Anwendung, die **Prozessinjektionen erkennen und blockieren** kann:

* Verwendung von **Umgebungsvariablen**: Es überwacht das Vorhandensein der folgenden Umgebungsvariablen: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** und **`ELECTRON_RUN_AS_NODE`**
* Verwendung von **`task_for_pid`**-Aufrufen: Um festzustellen, wenn ein Prozess den **Task-Port eines anderen** erhalten möchte, um Code in den Prozess einzuspritzen.
* **Parameter von Electron-Apps**: Jemand kann die Befehlszeilenargumente **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** verwenden, um eine Electron-App im Debugging-Modus zu starten und somit Code einzuspritzen.
* Verwendung von **Symbolischen Links** oder **Hardlinks**: Typischerweise besteht der häufigste Missbrauch darin, einen Link mit unseren Benutzerberechtigungen zu platzieren und ihn auf einen Ort mit höheren Berechtigungen zu verweisen. Die Erkennung ist sowohl für Hardlinks als auch für Symbolische Links sehr einfach. Wenn der Prozess, der den Link erstellt, ein **unterschiedliches Berechtigungsniveau** als die Zieldatei hat, wird ein **Alarm** ausgelöst. Leider ist im Fall von Symbolischen Links eine Blockierung nicht möglich, da wir vor der Erstellung keine Informationen über das Ziel des Links haben. Dies ist eine Einschränkung des Apple EndpointSecuriy-Frameworks.

### Von anderen Prozessen getätigte Aufrufe

In [**diesem Blog-Beitrag**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) erfahren Sie, wie es möglich ist, die Funktion **`task_name_for_pid`** zu verwenden, um Informationen über andere **Prozesse, die Code in einen Prozess einspritzen**, zu erhalten und dann Informationen über diesen anderen Prozess zu erhalten.

Beachten Sie, dass zum Aufrufen dieser Funktion Sie **die gleiche UID** wie der Prozess, der ausgeführt wird, oder **root** sein müssen (und es Informationen über den Prozess zurückgibt, nicht eine Möglichkeit, Code einzuspritzen).

## Referenzen

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
