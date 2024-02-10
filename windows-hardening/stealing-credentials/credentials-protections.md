# Windows Credentials-Schutz

## Credentials-Schutz

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## WDigest

Das [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396)-Protokoll, das mit Windows XP eingeführt wurde, ist für die Authentifizierung über das HTTP-Protokoll vorgesehen und ist **standardmäßig aktiviert auf Windows XP bis Windows 8.0 und Windows Server 2003 bis Windows Server 2012**. Diese Standardeinstellung führt zu **Speicherung von Klartextpasswörtern in LSASS** (Local Security Authority Subsystem Service). Ein Angreifer kann Mimikatz verwenden, um diese Anmeldeinformationen zu **extrahieren**, indem er Folgendes ausführt:
```bash
sekurlsa::wdigest
```
Um diese Funktion ein- oder auszuschalten, müssen die Registrierungsschlüssel _**UseLogonCredential**_ und _**Negotiate**_ innerhalb von _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ auf "1" gesetzt werden. Wenn diese Schlüssel **fehlen oder auf "0" gesetzt sind**, ist WDigest **deaktiviert**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA-Schutz

Ab **Windows 8.1** hat Microsoft die Sicherheit von LSA verbessert, um **unbefugtes Lesen des Speichers oder Codeinjektionen durch nicht vertrauenswürdige Prozesse zu blockieren**. Diese Verbesserung beeinträchtigt die normale Funktion von Befehlen wie `mimikatz.exe sekurlsa:logonpasswords`. Um diesen verbesserten Schutz zu **aktivieren**, sollte der Wert _**RunAsPPL**_ in _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ auf 1 geändert werden:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Umgehung

Es ist möglich, diesen Schutz mithilfe des Mimikatz-Treibers mimidrv.sys zu umgehen:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, eine Funktion, die exklusiv für **Windows 10 (Enterprise- und Education-Editionen)** verfügbar ist, erhöht die Sicherheit von Maschinenanmeldeinformationen mithilfe des **Virtual Secure Mode (VSM)** und der **Virtualization Based Security (VBS)**. Es nutzt CPU-Virtualisierungserweiterungen, um wichtige Prozesse in einem geschützten Speicherbereich zu isolieren, der für das Hauptbetriebssystem nicht zugänglich ist. Diese Isolierung gewährleistet, dass selbst der Kernel nicht auf den Speicher in VSM zugreifen kann und Anmeldeinformationen effektiv vor Angriffen wie **Pass-the-Hash** schützt. Die **Local Security Authority (LSA)** arbeitet in dieser sicheren Umgebung als Trustlet, während der **LSASS**-Prozess im Hauptbetriebssystem lediglich als Kommunikator mit der LSA von VSM fungiert.

Standardmäßig ist **Credential Guard** nicht aktiviert und erfordert eine manuelle Aktivierung innerhalb einer Organisation. Es ist entscheidend, um die Sicherheit gegen Tools wie **Mimikatz** zu erhöhen, die in ihrer Fähigkeit, Anmeldeinformationen abzurufen, eingeschränkt sind. Es können jedoch immer noch Schwachstellen ausgenutzt werden, indem benutzerdefinierte **Security Support Providers (SSP)** hinzugefügt werden, um Anmeldeinformationen im Klartext während des Anmeldeversuchs zu erfassen.

Um den Aktivierungsstatus von **Credential Guard** zu überprüfen, kann der Registrierungsschlüssel **_LsaCfgFlags_** unter **_HKLM\System\CurrentControlSet\Control\LSA_** überprüft werden. Ein Wert von "**1**" zeigt die Aktivierung mit **UEFI-Sperre** an, "**2**" ohne Sperre und "**0**" bedeutet, dass es nicht aktiviert ist. Diese Registrierungsüberprüfung ist zwar ein starkes Indiz, aber nicht der einzige Schritt zur Aktivierung von Credential Guard. Detaillierte Anleitungen und ein PowerShell-Skript zur Aktivierung dieser Funktion sind online verfügbar.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Für ein umfassendes Verständnis und Anweisungen zur Aktivierung von **Credential Guard** in Windows 10 und zur automatischen Aktivierung in kompatiblen Systemen von **Windows 11 Enterprise und Education (Version 22H2)** besuchen Sie die [Dokumentation von Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Weitere Details zur Implementierung benutzerdefinierter SSPs zur Erfassung von Anmeldeinformationen finden Sie in [diesem Leitfaden](../active-directory-methodology/custom-ssp.md).


## RDP RestrictedAdmin-Modus

**Windows 8.1 und Windows Server 2012 R2** führten mehrere neue Sicherheitsfunktionen ein, darunter den **_Restricted Admin-Modus für RDP_**. Dieser Modus wurde entwickelt, um die Risiken von **[Pass-the-Hash-Angriffen](https://blog.ahasayen.com/pass-the-hash/)** zu verringern.

Traditionell werden bei einer Verbindung zu einem Remote-Computer über RDP Ihre Anmeldeinformationen auf dem Zielcomputer gespeichert. Dies birgt ein erhebliches Sicherheitsrisiko, insbesondere bei der Verwendung von Konten mit erhöhten Berechtigungen. Mit der Einführung des **_Restricted Admin-Modus_** wird dieses Risiko jedoch erheblich reduziert.

Bei der Initiierung einer RDP-Verbindung mit dem Befehl **mstsc.exe /RestrictedAdmin** erfolgt die Authentifizierung am Remote-Computer, ohne Ihre Anmeldeinformationen darauf zu speichern. Auf diese Weise werden Ihre Anmeldeinformationen im Falle einer Malware-Infektion oder wenn ein bösartiger Benutzer Zugriff auf den Remote-Server erhält, nicht kompromittiert, da sie nicht auf dem Server gespeichert sind.

Es ist wichtig zu beachten, dass im **Restricted Admin-Modus** der Zugriff auf Netzwerkressourcen aus der RDP-Sitzung nicht mit Ihren persönlichen Anmeldeinformationen erfolgt, sondern mit der **Identität der Maschine**.

Diese Funktion stellt einen bedeutenden Fortschritt bei der Sicherung von Remote-Desktop-Verbindungen dar und schützt sensible Informationen vor einer Offenlegung im Falle eines Sicherheitsverstoßes.

![](../../.gitbook/assets/ram.png)

Für weitere detaillierte Informationen besuchen Sie [diese Ressource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Zwischengespeicherte Anmeldeinformationen

Windows sichert **Domänenanmeldeinformationen** über die **Local Security Authority (LSA)** und unterstützt Anmeldevorgänge mit Sicherheitsprotokollen wie **Kerberos** und **NTLM**. Eine wichtige Funktion von Windows ist die Möglichkeit, die **letzten zehn Domänenanmeldungen** im Cache zu speichern, um sicherzustellen, dass Benutzer auch dann auf ihre Computer zugreifen können, wenn der **Domänencontroller offline** ist - ein Vorteil für Laptop-Benutzer, die sich häufig nicht im Netzwerk ihres Unternehmens befinden.

Die Anzahl der zwischengespeicherten Anmeldungen kann über einen bestimmten **Registrierungsschlüssel oder Gruppenrichtlinien** angepasst werden. Um diese Einstellung anzuzeigen oder zu ändern, wird der folgende Befehl verwendet:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Der Zugriff auf diese zwischengespeicherten Anmeldeinformationen ist streng kontrolliert und nur das **SYSTEM**-Konto hat die erforderlichen Berechtigungen, um sie anzuzeigen. Administratoren, die auf diese Informationen zugreifen müssen, müssen dies mit den Privilegien des SYSTEM-Benutzers tun. Die Anmeldeinformationen werden unter `HKEY_LOCAL_MACHINE\SECURITY\Cache` gespeichert.

**Mimikatz** kann verwendet werden, um diese zwischengespeicherten Anmeldeinformationen mit dem Befehl `lsadump::cache` auszulesen.

Für weitere Details bietet die ursprüngliche [Quelle](http://juggernaut.wikidot.com/cached-credentials) umfassende Informationen.

## Geschützte Benutzer

Die Mitgliedschaft in der Gruppe **Geschützte Benutzer** führt zu mehreren Sicherheitsverbesserungen für Benutzer und gewährleistet einen höheren Schutz vor Diebstahl und Missbrauch von Anmeldeinformationen:

- **Anmeldeinformationen weitergeben (CredSSP)**: Selbst wenn die Gruppenrichtlinieneinstellung für **Delegieren von Standardanmeldeinformationen zulassen** aktiviert ist, werden Klartext-Anmeldeinformationen von geschützten Benutzern nicht zwischengespeichert.
- **Windows Digest**: Ab **Windows 8.1 und Windows Server 2012 R2** werden Klartext-Anmeldeinformationen von geschützten Benutzern unabhängig vom Status von Windows Digest nicht zwischengespeichert.
- **NTLM**: Das System zwischenspeichert weder Klartext-Anmeldeinformationen noch NT-Einwegfunktionen (NTOWF) von geschützten Benutzern.
- **Kerberos**: Bei geschützten Benutzern erzeugt die Kerberos-Authentifizierung weder **DES**- noch **RC4-Schlüssel** und zwischenspeichert weder Klartext-Anmeldeinformationen noch langfristige Schlüssel über den Erwerb des initialen Ticket-Granting Tickets (TGT) hinaus.
- **Offline-Anmeldung**: Für geschützte Benutzer wird kein zwischengespeicherter Prüfwert bei der Anmeldung oder Entsperrung erstellt, was bedeutet, dass die Offline-Anmeldung für diese Konten nicht unterstützt wird.

Diese Schutzmaßnahmen werden aktiviert, sobald sich ein Benutzer, der Mitglied der Gruppe **Geschützte Benutzer** ist, am Gerät anmeldet. Dadurch werden kritische Sicherheitsmaßnahmen implementiert, um verschiedene Methoden des Angriffs auf Anmeldeinformationen zu verhindern.

Für weitere detaillierte Informationen konsultieren Sie die offizielle [Dokumentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabelle aus** [**den Dokumenten**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
