# Checkliste - Lokale Windows-Privileg-Eskalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

### **Bestes Tool zur Suche nach Windows-Privileg-Eskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminformationen](windows-local-privilege-escalation/#system-info)

* [ ] Erhalten Sie [**Systeminformationen**](windows-local-privilege-escalation/#system-info)
* [ ] Suchen Sie nach **Kernel**-[**Exploits mit Skripten**](windows-local-privilege-escalation/#version-exploits)
* [ ] Verwenden Sie **Google, um nach** Kernel-**Exploits zu suchen**
* [ ] Verwenden Sie **searchsploit, um nach** Kernel-**Exploits zu suchen**
* [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/#environment)?
* [ ] Passwörter im [**PowerShell-Verlauf**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interessante Informationen in [**Interneteinstellungen**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Laufwerke**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS-Exploit**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Protokollierung/AV-Aufzählung](windows-local-privilege-escalation/#enumeration)

* [ ] Überprüfen Sie die [**Audit-**] (windows-local-privilege-escalation/#audit-settings)und [**WEF-**] (windows-local-privilege-escalation/#wef)-Einstellungen
* [ ] Überprüfen Sie [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Überprüfen Sie, ob [**WDigest**] (windows-local-privilege-escalation/#wdigest) aktiv ist
* [ ] [**LSA-Schutz**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Gecachte Anmeldeinformationen**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Überprüfen Sie, ob ein [**AV**](windows-av-bypass) vorhanden ist
* [ ] [**AppLocker-Richtlinie**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Benutzerprivilegien**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Überprüfen Sie die [**aktuellen** Benutzer**privilegien**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Sind Sie [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Überprüfen Sie, ob Sie eine dieser Berechtigungen aktiviert haben (windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Benutzersitzungen**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Überprüfen Sie [**Benutzer-Homeverzeichnisse**](windows-local-privilege-escalation/#home-folders) (Zugriff?)
* [ ] Überprüfen Sie die [**Kennwortrichtlinie**](windows-local-privilege-escalation/#password-policy)
* [ ] Was befindet sich in der [**Zwischenablage**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/#network)

* [ ] Überprüfen Sie die **aktuellen** [**Netzwerkinformationen**](windows-local-privilege-escalation/#network)
* [ ] Überprüfen Sie **versteckte lokale Dienste**, die nach außen hin eingeschränkt sind

### [Laufende Prozesse](windows-local-privilege-escalation/#running-processes)

* [ ] Berechtigungen für Prozessbinärdateien [**Datei- und Ordnerberechtigungen**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Passwort-Mining im Speicher**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Unsichere GUI-Anwendungen**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Dienste](windows-local-privilege-escalation/#services)

* [ ] [Können Sie einen **Dienst ändern**?](windows-local-privilege-escalation#permissions)
* [ ] [Können Sie die **ausgeführte** **Binärdatei** eines **Dienstes ändern**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Können Sie das **Registry** eines **Dienstes ändern**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Können Sie von einem **nicht in Anführungszeichen gesetzten Dienst**-Binärpfad profitieren**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Anwendungen**](windows-local-privilege-escalation/#applications)

* [ ] **Schreibberechtigungen für installierte Anwendungen**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Startanwendungen**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Anfällige** [**Treiber**](windows-local-privilege-escalation/#drivers)

### [DLL-Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Können Sie in einem Ordner innerhalb von PATH **schreiben**?
* [ ] Gibt es eine bekannte Dienstbinärdatei, die versucht, eine nicht vorhandene DLL zu laden?
* [ ] Können Sie in einem **Binärordner** schreiben?
### [Netzwerk](windows-local-privilege-escalation/#netzwerk)

* [ ] Netzwerk enumerieren (Freigaben, Schnittstellen, Routen, Nachbarn, ...)
* [ ] Besondere Beachtung auf Netzwerkdienste, die auf localhost (127.0.0.1) lauschen

### [Windows-Anmeldeinformationen](windows-local-privilege-escalation/#windows-anmeldeinformationen)

* [ ] [**Winlogon**-Anmeldeinformationen](windows-local-privilege-escalation/#winlogon-anmeldeinformationen)
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault)-Anmeldeinformationen, die verwendet werden können?
* [ ] Interessante [**DPAPI-Anmeldeinformationen**](windows-local-privilege-escalation/#dpapi)?
* [ ] Passwörter von gespeicherten [**Wifi-Netzwerken**](windows-local-privilege-escalation/#wifi)?
* [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/#gespeicherte-rdp-verbindungen)?
* [ ] Passwörter in [**kürzlich ausgeführten Befehlen**](windows-local-privilege-escalation/#kürzlich-ausgeführte-befehle)?
* [ ] Passwörter des [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] Existiert [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Anmeldeinformationen?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [Dateien und Registry (Anmeldeinformationen)](windows-local-privilege-escalation/#dateien-und-registry-anmeldeinformationen)

* [ ] **Putty:** [**Anmeldeinformationen**](windows-local-privilege-escalation/#putty-anmeldeinformationen) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/#putty-ssh-hostschlüssel)
* [ ] [**SSH-Schlüssel in der Registry**](windows-local-privilege-escalation/#ssh-schlüssel-in-der-registry)?
* [ ] Passwörter in [**unbeaufsichtigten Dateien**](windows-local-privilege-escalation/#unbeaufsichtigte-dateien)?
* [ ] Irgendein [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-und-system-backups)-Backup?
* [ ] [**Cloud-Anmeldeinformationen**](windows-local-privilege-escalation/#cloud-anmeldeinformationen)?
* [ ] Datei [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Passwort in [**IIS Web-Konfigurationsdatei**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Interessante Informationen in [**Web-Logs**](windows-local-privilege-escalation/#logs)?
* [ ] Möchten Sie den Benutzer nach [**Anmeldeinformationen fragen**](windows-local-privilege-escalation/#ask-for-credentials)?
* [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Andere [**Registry mit Anmeldeinformationen**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] In [**Browser-Daten**](windows-local-privilege-escalation/#browsers-history) (Datenbanken, Verlauf, Lesezeichen, ...)?
* [ ] [**Generische Passwortsuche**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in Dateien und Registry
* [ ] [**Tools**](windows-local-privilege-escalation/#tools-that-search-for-passwords) zum automatischen Suchen von Passwörtern

### [Ausgelaufene Handler](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Haben Sie Zugriff auf einen Handler eines Prozesses, der von einem Administrator ausgeführt wird?

### [Named Pipe Client Impersonation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Überprüfen, ob Sie es missbrauchen können

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
