# macOS Thread-Injektion über Task-Port

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Thread-Hijacking

Zunächst wird die Funktion **`task_threads()`** auf dem Task-Port aufgerufen, um eine Thread-Liste vom Remote-Task zu erhalten. Ein Thread wird zum Hijacking ausgewählt. Dieser Ansatz unterscheidet sich von herkömmlichen Code-Injektionsmethoden, da das Erstellen eines neuen Remote-Threads aufgrund der neuen Absicherung, die `thread_create_running()` blockiert, untersagt ist.

Um den Thread zu steuern, wird **`thread_suspend()`** aufgerufen, um seine Ausführung anzuhalten.

Die einzigen zulässigen Operationen auf dem Remote-Thread umfassen das **Anhalten** und **Starten** sowie das **Abrufen** und **Ändern** seiner Registerwerte. Remote-Funktionsaufrufe werden initiiert, indem die Register `x0` bis `x7` auf die **Argumente** gesetzt, `pc` auf die gewünschte Funktion ausgerichtet und der Thread aktiviert wird. Damit der Thread nach der Rückkehr nicht abstürzt, muss die Rückkehr erkannt werden.

Eine Strategie besteht darin, einen **Ausnahme-Handler** für den Remote-Thread mit `thread_set_exception_ports()` zu registrieren und das Register `lr` vor dem Funktionsaufruf auf eine ungültige Adresse zu setzen. Dadurch wird nach der Ausführung der Funktion eine Ausnahme ausgelöst, die eine Nachricht an den Ausnahme-Port sendet und eine Zustandsinspektion des Threads ermöglicht, um den Rückgabewert wiederherzustellen. Alternativ wird, wie von Ian Beers triple\_fetch-Exploit übernommen, `lr` auf eine endlose Schleife gesetzt. Die Register des Threads werden dann kontinuierlich überwacht, bis **`pc` auf diese Anweisung zeigt**.

## 2. Mach-Ports für die Kommunikation

Die nächste Phase umfasst die Einrichtung von Mach-Ports zur Erleichterung der Kommunikation mit dem Remote-Thread. Diese Ports sind entscheidend für den Transfer beliebiger Send- und Empfangsrechte zwischen Tasks.

Für die bidirektionale Kommunikation werden zwei Mach-Empfangsrechte erstellt: eines im lokalen und eines im Remote-Task. Anschließend wird ein Senderecht für jeden Port an den entsprechenden Task übertragen, um den Austausch von Nachrichten zu ermöglichen.

Bei Fokussierung auf den lokalen Port wird das Empfangsrecht vom lokalen Task gehalten. Der Port wird mit `mach_port_allocate()` erstellt. Die Herausforderung besteht darin, ein Senderecht für diesen Port in den Remote-Task zu übertragen.

Eine Strategie besteht darin, `thread_set_special_port()` zu nutzen, um ein Senderecht für den lokalen Port in den `THREAD_KERNEL_PORT` des Remote-Threads zu platzieren. Anschließend wird der Remote-Thread angewiesen, `mach_thread_self()` aufzurufen, um das Senderecht abzurufen.

Für den Remote-Port wird der Prozess im Wesentlichen umgekehrt. Der Remote-Thread wird angewiesen, einen Mach-Port über `mach_reply_port()` zu generieren (da `mach_port_allocate()` aufgrund seines Rückgabemechanismus ungeeignet ist). Nach der Port-Erstellung wird in dem Remote-Thread `mach_port_insert_right()` aufgerufen, um ein Senderecht zu etablieren. Dieses Recht wird dann mit `thread_set_special_port()` im Kernel abgelegt. Zurück im lokalen Task wird `thread_get_special_port()` auf dem Remote-Thread verwendet, um ein Senderecht für den neu zugewiesenen Mach-Port im Remote-Task zu erhalten.

Nach Abschluss dieser Schritte werden Mach-Ports eingerichtet, um die Grundlage für die bidirektionale Kommunikation zu schaffen.

## 3. Grundlegende Speicher-Lese-/Schreib-Primitive

In diesem Abschnitt liegt der Fokus auf der Verwendung des Ausführungs-Primitivs zur Einrichtung grundlegender Speicher-Lese- und Schreib-Primitive. Diese ersten Schritte sind entscheidend, um mehr Kontrolle über den Remote-Prozess zu erlangen, obwohl die Primitive in diesem Stadium noch nicht viele Zwecke erfüllen. Bald werden sie zu fortgeschritteneren Versionen aufgerüstet.

### Speicherlesen und -schreiben mit dem Ausführungs-Primitiv

Das Ziel ist es, Speicherlesen und -schreiben mit spezifischen Funktionen durchzuführen. Zum Lesen von Speicher werden Funktionen verwendet, die der folgenden Struktur ähneln:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Und zum Schreiben in den Speicher werden Funktionen ähnlich dieser Struktur verwendet:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Diese Funktionen entsprechen den gegebenen Assembly-Anweisungen:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifizierung geeigneter Funktionen

Eine Untersuchung der gängigen Bibliotheken ergab geeignete Kandidaten für diese Operationen:

1. **Speicher lesen:**
Die Funktion `property_getName()` aus der [Objective-C-Laufzeitbibliothek](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) wird als geeignete Funktion zum Lesen von Speicher identifiziert. Die Funktion ist nachstehend aufgeführt:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Diese Funktion verhält sich effektiv wie die `read_func`, indem sie das erste Feld von `objc_property_t` zurückgibt.

2. **Schreiben von Speicher:**
Das Finden einer vorgefertigten Funktion zum Schreiben von Speicher ist schwieriger. Die Funktion `_xpc_int64_set_value()` aus libxpc ist jedoch ein geeigneter Kandidat mit folgender Disassembly:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Um einen 64-Bit-Schreibvorgang an einer bestimmten Adresse durchzuführen, ist der Remote-Aufruf wie folgt strukturiert:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Mit diesen Grundlagen ist die Bühne für die Erstellung von gemeinsamem Speicher bereitet, was einen bedeutenden Fortschritt bei der Kontrolle des Remote-Prozesses darstellt.

## 4. Einrichtung des gemeinsamen Speichers

Das Ziel besteht darin, gemeinsamen Speicher zwischen lokalen und Remote-Aufgaben herzustellen, um den Datentransfer zu vereinfachen und das Aufrufen von Funktionen mit mehreren Argumenten zu erleichtern. Der Ansatz besteht darin, `libxpc` und seinen Objekttyp `OS_xpc_shmem` zu nutzen, der auf Mach-Speichereinträgen basiert.

### Prozessübersicht:

1. **Speicherzuweisung**:
- Weisen Sie den Speicher für die gemeinsame Nutzung mit `mach_vm_allocate()` zu.
- Verwenden Sie `xpc_shmem_create()`, um ein `OS_xpc_shmem`-Objekt für den zugewiesenen Speicherbereich zu erstellen. Diese Funktion verwaltet die Erstellung des Mach-Speichereintrags und speichert das Mach-Senderecht an Offset `0x18` des `OS_xpc_shmem`-Objekts.

2. **Erstellen von gemeinsamem Speicher im Remote-Prozess**:
- Weisen Sie Speicher für das `OS_xpc_shmem`-Objekt im Remote-Prozess mit einem Remote-Aufruf von `malloc()` zu.
- Kopieren Sie den Inhalt des lokalen `OS_xpc_shmem`-Objekts in den Remote-Prozess. Diese erste Kopie enthält jedoch falsche Mach-Speichereintragsnamen an Offset `0x18`.

3. **Korrektur des Mach-Speichereintrags**:
- Verwenden Sie die Methode `thread_set_special_port()`, um ein Senderecht für den Mach-Speichereintrag in die Remote-Aufgabe einzufügen.
- Korrigieren Sie das Feld des Mach-Speichereintrags an Offset `0x18`, indem Sie es mit dem Namen des Remote-Speichereintrags überschreiben.

4. **Abschließende Einrichtung des gemeinsamen Speichers**:
- Überprüfen Sie das Remote-`OS_xpc_shmem`-Objekt.
- Stellen Sie die gemeinsame Speicherzuordnung mit einem Remote-Aufruf von `xpc_shmem_remote()` her.

Durch Befolgen dieser Schritte wird der gemeinsame Speicher zwischen den lokalen und Remote-Aufgaben effizient eingerichtet, was einfache Datentransfers und die Ausführung von Funktionen mit mehreren Argumenten ermöglicht.

## Zusätzliche Code-Snippets

Für die Speicherzuweisung und die Erstellung des gemeinsamen Speicherobjekts:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Für das Erstellen und Korrigieren des gemeinsamen Speicherobjekts im Remote-Prozess:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
## 5. Vollständige Kontrolle erreichen

Nach erfolgreichem Aufbau des gemeinsamen Speichers und Erlangen beliebiger Ausführungsfähigkeiten haben wir im Wesentlichen die volle Kontrolle über den Zielprozess erlangt. Die Schlüsselfunktionen, die diese Kontrolle ermöglichen, sind:

1. **Beliebige Speicheroperationen**:
- Führen Sie beliebige Speicherlesevorgänge durch, indem Sie `memcpy()` aufrufen, um Daten aus dem gemeinsamen Bereich zu kopieren.
- Führen Sie beliebige Speicherschreibvorgänge aus, indem Sie `memcpy()` verwenden, um Daten in den gemeinsamen Bereich zu übertragen.

2. **Behandlung von Funktionsaufrufen mit mehreren Argumenten**:
- Für Funktionen, die mehr als 8 Argumente erfordern, ordnen Sie die zusätzlichen Argumente gemäß der Aufrufkonvention auf dem Stapel an.

3. **Mach-Port-Übertragung**:
- Übertragen Sie Mach-Ports zwischen Aufgaben über Mach-Nachrichten über zuvor eingerichtete Ports.

4. **Dateideskriptor-Übertragung**:
- Übertragen Sie Dateideskriptoren zwischen Prozessen mithilfe von Dateiports, einer Technik, die von Ian Beer in `triple_fetch` hervorgehoben wurde.

Diese umfassende Kontrolle ist in der [threadexec](https://github.com/bazad/threadexec)-Bibliothek zusammengefasst, die eine detaillierte Implementierung und eine benutzerfreundliche API für die Interaktion mit dem Opferprozess bietet.

## Wichtige Überlegungen:

- Stellen Sie sicher, dass `memcpy()` ordnungsgemäß für Speicherlese- und -schreiboperationen verwendet wird, um die Systemstabilität und die Datenintegrität zu gewährleisten.
- Beim Übertragen von Mach-Ports oder Dateideskriptoren sollten Sie ordnungsgemäße Protokolle einhalten und Ressourcen verantwortungsbewusst behandeln, um Lecks oder unbeabsichtigten Zugriff zu verhindern.

Durch Einhaltung dieser Richtlinien und Verwendung der `threadexec`-Bibliothek kann man Prozesse auf granularer Ebene effizient verwalten und mit ihnen interagieren, um die volle Kontrolle über den Zielprozess zu erlangen.

## Referenzen
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
