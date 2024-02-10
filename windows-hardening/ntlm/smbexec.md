# SmbExec/ScExec

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Wie es funktioniert

**Smbexec** ist ein Tool zur Remote-Befehlsausführung auf Windows-Systemen, ähnlich wie **Psexec**, vermeidet jedoch das Platzieren von bösartigen Dateien auf dem Zielsystem.

### Wichtige Punkte zu **SMBExec**

- Es funktioniert, indem es einen temporären Dienst (z. B. "BTOBTO") auf der Zielmaschine erstellt, um Befehle über cmd.exe (%COMSPEC%) auszuführen, ohne Binärdateien abzulegen.
- Trotz seines unauffälligen Ansatzes generiert es für jeden ausgeführten Befehl Ereignisprotokolle und bietet eine Form einer nicht interaktiven "Shell".
- Der Befehl zum Verbinden mit **Smbexec** sieht wie folgt aus:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Ausführen von Befehlen ohne Binärdateien

- **Smbexec** ermöglicht die direkte Ausführung von Befehlen über Service binPaths und eliminiert die Notwendigkeit physischer Binärdateien auf dem Ziel.
- Diese Methode ist nützlich für die Ausführung einmaliger Befehle auf einem Windows-Ziel. Wenn sie beispielsweise mit dem `web_delivery`-Modul von Metasploit kombiniert wird, ermöglicht sie die Ausführung einer PowerShell-gerichteten umgekehrten Meterpreter-Payload.
- Durch das Erstellen eines Remote-Services auf dem Angreiferrechner mit binPath, der den bereitgestellten Befehl über cmd.exe ausführt, ist es möglich, die Payload erfolgreich auszuführen und eine Rückruf- und Payload-Ausführung mit dem Metasploit-Listener zu erreichen, selbst wenn Service-Antwortfehler auftreten.

### Befehlsbeispiel

Das Erstellen und Starten des Services kann mit den folgenden Befehlen erreicht werden:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Für weitere Details siehe [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Referenzen
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
