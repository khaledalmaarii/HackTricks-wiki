# macOS xpc\_connection\_get\_audit\_token Angriff

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

**Weitere Informationen finden Sie im Originalbeitrag: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. Hier ist eine Zusammenfassung:


## Grundlegende Informationen zu Mach-Nachrichten

Wenn Sie nicht wissen, was Mach-Nachrichten sind, schauen Sie sich diese Seite an:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Vorerst merken Sie sich ([Definition von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach-Nachrichten werden über einen _mach port_ gesendet, der ein **Kommunikationskanal mit einem einzelnen Empfänger und mehreren Sendern** ist, der in den Mach-Kernel integriert ist. **Mehrere Prozesse können Nachrichten** an einen Mach-Port senden, aber zu jedem Zeitpunkt kann **nur ein einzelner Prozess daraus lesen**. Ähnlich wie Dateideskriptoren und Sockets werden Mach-Ports vom Kernel zugewiesen und verwaltet, und Prozesse sehen nur eine Ganzzahl, die sie verwenden können, um dem Kernel anzuzeigen, welchen ihrer Mach-Ports sie verwenden möchten.

## XPC-Verbindung

Wenn Sie nicht wissen, wie eine XPC-Verbindung hergestellt wird, schauen Sie hier nach:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Zusammenfassung der Schwachstelle

Was für Sie interessant zu wissen ist, dass die Abstraktion von XPC eine **eins-zu-eins-Verbindung** ist, die jedoch auf einer Technologie basiert, die **mehrere Sender haben kann**:

* Mach-Ports haben einen einzelnen Empfänger und **mehrere Sender**.
* Das Audit-Token einer XPC-Verbindung ist das Audit-Token, das **aus der zuletzt empfangenen Nachricht kopiert wurde**.
* Das Erlangen des **Audit-Tokens** einer XPC-Verbindung ist für viele **Sicherheitsüberprüfungen** entscheidend.

Obwohl die vorherige Situation vielversprechend klingt, gibt es einige Szenarien, in denen dies keine Probleme verursacht ([von hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit-Tokens werden häufig für eine Autorisierungsprüfung verwendet, um zu entscheiden, ob eine Verbindung akzeptiert werden soll. Da dies mit einer Nachricht an den Dienstport geschieht, wird **noch keine Verbindung hergestellt**. Weitere Nachrichten an diesem Port werden einfach als zusätzliche Verbindungsanfragen behandelt. Daher sind **Überprüfungen vor der Annahme einer Verbindung nicht gefährdet** (das bedeutet auch, dass das Audit-Token innerhalb von `-listener:shouldAcceptNewConnection:` sicher ist). Wir suchen daher nach XPC-Verbindungen, die bestimmte Aktionen überprüfen.
* XPC-Ereignishandler werden synchron behandelt. Das bedeutet, dass der Ereignishandler für eine Nachricht abgeschlossen sein muss, bevor er für die nächste aufgerufen wird, auch in gleichzeitigen Dispatch-Warteschlangen. Daher kann das Audit-Token innerhalb eines **XPC-Ereignishandlers nicht von anderen normalen (nicht-Antwort!) Nachrichten überschrieben** werden.

Es gibt zwei verschiedene Methoden, wie dies ausgenutzt werden kann:

1. Variante 1:
* Der **Exploit** stellt eine Verbindung zu Dienst **A** und Dienst **B** her.
* Dienst **B** kann eine **privilegierte Funktion** in Dienst A aufrufen, die der Benutzer nicht kann.
* Dienst **A** ruft **`xpc_connection_get_audit_token`** auf, während er sich **nicht** im Ereignishandler für eine Verbindung in einem **`dispatch_async`** befindet.
* Daher könnte eine **andere** Nachricht das **Audit-Token überschreiben**, da sie außerhalb des Ereignishandlers asynchron weitergeleitet wird.
* Der Exploit übergibt **Dienst B das SEND-Recht an Dienst A**.
* Daher wird svc **B** tatsächlich die **Nachrichten** an Dienst **A** senden.
* Der Exploit versucht, die **privilegierte Aktion aufzurufen**. In einem RC svc **A überprüft** die Autorisierung dieser **Aktion**, während **svc B das Audit-Token überschrieben** hat (was dem Exploit Zugriff auf den Aufruf der privilegierten Aktion ermöglicht).
2. Variante 2:
* Dienst **B** kann eine **privilegierte Funktion** in Dienst A aufrufen, die der Benutzer nicht kann.
* Der Exploit stellt eine Verbindung zu **Dienst A** her, der dem Exploit eine **Nachricht erwartet, die eine Antwort** in einem bestimmten **Antwortport** sendet.
* Der Exploit sendet **Dienst B eine Nachricht**, die **diesen Antwortport** übergibt.
* Wenn Dienst **B antwortet**, sendet er die Nachricht an Dienst **A**, **während** der Exploit eine andere **Nachricht an Dienst A** sendet, um eine privilegierte Funktion zu erreichen und erwartet, dass die Antwort von Dienst B das Audit-Token im perfekten Moment überschreibt (Race Condition).

## Variante 1: Aufruf von xpc\_connection\_get\_audit\_token außerhalb eines Ereignishandlers <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Szenario:

* Zwei Mach-Dienste **`A`** und **`B`**, zu denen wir beide eine Verbindung herstellen können (basierend auf dem Sandbox-Profil und den Autorisierungsprüfungen vor der Annahme der Verbindung).
* _**A**_ muss eine **Autorisierungsprüfung** für eine bestimmte Aktion haben, die **`B`** übergeben kann (aber unsere App nicht).
* Zum Beispiel, wenn B einige **Berechtigungen** hat oder als **root** ausgeführt wird, könnte es ihm erlauben, A aufzufordern, eine privilegierte Aktion auszuführen.
* Für diese Autorisierungsprüfung erhält **`A`** das Audit-Token asynchron, zum Beispiel durch Aufruf von `xpc_connection_get_audit_token
4. Der nächste Schritt besteht darin, `diagnosticd` anzuweisen, die Überwachung eines ausgewählten Prozesses (möglicherweise des eigenen Benutzers) zu starten. Gleichzeitig werden eine Flut von Routine-1004-Nachrichten an `smd` gesendet. Das Ziel hierbei ist es, ein Tool mit erhöhten Berechtigungen zu installieren.
5. Diese Aktion löst eine Rennbedingung innerhalb der Funktion `handle_bless` aus. Die Zeitabstimmung ist entscheidend: Der Funktionsaufruf `xpc_connection_get_pid` muss die PID des Benutzerprozesses zurückgeben (da sich das privilegierte Tool im App-Bundle des Benutzers befindet). Die Funktion `xpc_connection_get_audit_token`, insbesondere innerhalb der Unterfunktion `connection_is_authorized`, muss jedoch auf das Audit-Token von `diagnosticd` verweisen.

## Variante 2: Weiterleitung von Antworten

In einer XPC (Cross-Process Communication)-Umgebung gibt es eine einzigartige Verhaltensweise bei der Behandlung von Antwortnachrichten, obwohl Ereignishandler nicht gleichzeitig ausgeführt werden. Es gibt speziell zwei verschiedene Methoden zum Senden von Nachrichten, die eine Antwort erwarten:

1. **`xpc_connection_send_message_with_reply`**: Hier wird die XPC-Nachricht empfangen und auf einer bestimmten Warteschlange verarbeitet.
2. **`xpc_connection_send_message_with_reply_sync`**: Im Gegensatz dazu wird bei dieser Methode die XPC-Nachricht auf der aktuellen Dispatch-Warteschlange empfangen und verarbeitet.

Diese Unterscheidung ist entscheidend, da dies die Möglichkeit bietet, **Antwortpakete gleichzeitig mit der Ausführung eines XPC-Ereignishandlers zu analysieren**. Beachtenswert ist, dass `_xpc_connection_set_creds` eine Sperrung implementiert, um eine teilweise Überschreibung des Audit-Tokens zu verhindern, jedoch keinen umfassenden Schutz für das gesamte Verbindungsobjekt bietet. Dadurch entsteht eine Sicherheitslücke, bei der das Audit-Token während des Intervalls zwischen der Analyse eines Pakets und der Ausführung seines Ereignishandlers ersetzt werden kann.

Um diese Sicherheitslücke auszunutzen, ist die folgende Konfiguration erforderlich:

- Zwei Mach-Dienste, die als **`A`** und **`B`** bezeichnet werden und beide eine Verbindung herstellen können.
- Der Dienst **`A`** sollte eine Autorisierungsprüfung für eine bestimmte Aktion enthalten, die nur **`B`** ausführen kann (die Anwendung des Benutzers nicht).
- Der Dienst **`A`** sollte eine Nachricht senden, die eine Antwort erwartet.
- Der Benutzer kann eine Nachricht an **`B`** senden, auf die es antworten wird.

Der Ausbeutungsprozess umfasst die folgenden Schritte:

1. Warten Sie darauf, dass der Dienst **`A`** eine Nachricht sendet, die eine Antwort erwartet.
2. Anstatt direkt an **`A`** zu antworten, wird der Antwortport übernommen und verwendet, um eine Nachricht an den Dienst **`B`** zu senden.
3. Anschließend wird eine Nachricht mit der verbotenen Aktion versendet, in der Erwartung, dass sie gleichzeitig mit der Antwort von **`B`** verarbeitet wird.

Nachfolgend finden Sie eine visuelle Darstellung des beschriebenen Angriffsszenarios:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Probleme bei der Entdeckung

- **Schwierigkeiten bei der Lokalisierung von Instanzen**: Die Suche nach Instanzen der Verwendung von `xpc_connection_get_audit_token` war sowohl statisch als auch dynamisch eine Herausforderung.
- **Methodik**: Frida wurde verwendet, um die Funktion `xpc_connection_get_audit_token` zu hooken und Anrufe zu filtern, die nicht aus Ereignishandlern stammen. Diese Methode war jedoch auf den gehookten Prozess beschränkt und erforderte aktive Nutzung.
- **Analysetools**: Tools wie IDA/Ghidra wurden verwendet, um erreichbare Mach-Dienste zu untersuchen, aber der Prozess war zeitaufwändig und wurde durch Aufrufe mit dem dyld Shared Cache erschwert.
- **Einschränkungen bei der Skripterstellung**: Versuche, die Analyse für Aufrufe von `xpc_connection_get_audit_token` aus `dispatch_async`-Blöcken zu skripten, wurden durch Komplexitäten beim Parsen von Blöcken und Interaktionen mit dem dyld Shared Cache behindert.

## Die Lösung <a href="#the-fix" id="the-fix"></a>

- **Gemeldete Probleme**: Ein Bericht wurde an Apple über die allgemeinen und spezifischen Probleme in `smd` gesendet.
- **Antwort von Apple**: Apple hat das Problem in `smd` behoben, indem `xpc_connection_get_audit_token` durch `xpc_dictionary_get_audit_token` ersetzt wurde.
- **Art der Lösung**: Die Funktion `xpc_dictionary_get_audit_token` gilt als sicher, da sie das Audit-Token direkt aus der Mach-Nachricht abruft, die mit der empfangenen XPC-Nachricht verknüpft ist. Sie ist jedoch nicht Teil der öffentlichen API, ähnlich wie `xpc_connection_get_audit_token`.
- **Fehlen einer umfassenderen Lösung**: Es ist unklar, warum Apple keine umfassendere Lösung implementiert hat, z. B. das Verwerfen von Nachrichten, die nicht mit dem gespeicherten Audit-Token der Verbindung übereinstimmen. Die Möglichkeit legitimer Änderungen des Audit-Tokens in bestimmten Szenarien (z. B. bei der Verwendung von `setuid`) könnte ein Faktor sein.
- **Aktueller Status**: Das Problem besteht weiterhin in iOS 17 und macOS 14 und stellt eine Herausforderung für diejenigen dar, die es identifizieren und verstehen möchten.

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
