# Checkliste - Lokale Windows-Privilegieneskalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Bestes Tool zur Suche nach Windows lokalen Privilegieneskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminformationen](windows-local-privilege-escalation/#system-info)

* [ ] Erhalten Sie [**Systeminformationen**](windows-local-privilege-escalation/#system-info)
* [ ] Suchen Sie nach **Kernel** [**Exploits mit Skripten**](windows-local-privilege-escalation/#version-exploits)
* [ ] Verwenden Sie **Google, um nach** Kernel-**Exploits zu suchen**
* [ ] Verwenden Sie **searchsploit, um nach** Kernel-**Exploits zu suchen**
* [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/#environment)?
* [ ] Passwörter im [**PowerShell-Verlauf**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interessante Informationen in [**Interneteinstellungen**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Laufwerke**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS-Exploit**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Protokollierung/AV-Auflistung](windows-local-privilege-escalation/#enumeration)

* [ ] Überprüfen Sie die [**Audit-**](windows-local-privilege-escalation/#audit-settings)und [**WEF-Einstellungen**](windows-local-privilege-escalation/#wef)
* [ ] Überprüfen Sie [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Überprüfen Sie, ob [**WDigest** ](windows-local-privilege-escalation/#wdigest)aktiv ist
* [ ] [**LSA-Schutz**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Gecachte Anmeldeinformationen**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Überprüfen Sie, ob ein [**AV-Programm**](windows-av-bypass) vorhanden ist
* [**AppLocker-Richtlinie**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Benutzerrechte**](windows-local-privilege-escalation/#users-and-groups)
* Überprüfen Sie die [**aktuellen** Benutzer-**Rechte**](windows-local-privilege-escalation/#users-and-groups)
* Sind Sie [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/#privileged-groups)?
* Überprüfen Sie, ob Sie eine dieser Berechtigungen aktiviert haben: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Benutzersitzungen**](windows-local-privilege-escalation/#logged-users-sessions)?
* Überprüfen Sie [**Benutzer-Homeverzeichnisse**](windows-local-privilege-escalation/#home-folders) (Zugriff?)
* Überprüfen Sie die [**Kennwortrichtlinie**](windows-local-privilege-escalation/#password-policy)
* Was ist [**im Zwischenspeicher**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/#network)

* Überprüfen Sie die **aktuellen** [**Netzwerkinformationen**](windows-local-privilege-escalation/#network)
* Überprüfen Sie **versteckte lokale Dienste**, die nach außen hin eingeschränkt sind

### [Laufende Prozesse](windows-local-privilege-escalation/#running-processes)

* Prozessbinärdateien [**Datei- und Ordnerberechtigungen**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Passwort-Mining im Speicher**](windows-local-privilege-escalation/#memory-password-mining)
* [**Unsichere GUI-Apps**](windows-local-privilege-escalation/#insecure-gui-apps)
* Stehlen Sie Anmeldeinformationen mit **interessanten Prozessen** über `ProcDump.exe` ? (Firefox, Chrome, etc ...)

### [Dienste](windows-local-privilege-escalation/#services)

* [Können Sie einen **Dienst ändern**?](windows-local-privilege-escalation#permissions)
* [Können Sie die **ausgeführte** Binärdatei eines Dienstes **ändern**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Können Sie das **Registrierungs**-**ändern** eines Dienstes **ändern**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* Können Sie von einem **nicht in Anführungszeichen gesetzten Dienst**-Binärpfad profitieren?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Anwendungen**](windows-local-privilege-escalation/#applications)

* **Schreib**berechtigungen für installierte Anwendungen](windows-local-privilege-escalation/#write-permissions)
* [**Startanwendungen**](windows-local-privilege-escalation/#run-at-startup)
* **Anfällige** [**Treiber**](windows-local-privilege-escalation/#drivers)
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Können Sie **in jedem Ordner innerhalb des PATH schreiben**?
* [ ] Gibt es einen bekannten Dienst-Binary, der versucht, eine **nicht vorhandene DLL zu laden**?
* [ ] Können Sie **in einem Binärdateiordner schreiben**?

### [Netzwerk](windows-local-privilege-escalation/#network)

* [ ] Netzwerk enumerieren (Freigaben, Schnittstellen, Routen, Nachbarn, ...)
* [ ] Besonderes Augenmerk auf Netzwerkdienste richten, die auf localhost (127.0.0.1) lauschen

### [Windows-Anmeldeinformationen](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)Anmeldeinformationen
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) Anmeldeinformationen, die Sie verwenden könnten?
* [ ] Interessante [**DPAPI-Anmeldeinformationen**](windows-local-privilege-escalation/#dpapi)?
* [ ] Passwörter von gespeicherten [**WLAN-Netzwerken**](windows-local-privilege-escalation/#wifi)?
* [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Passwörter in [**kürzlich ausgeführten Befehlen**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager) Passwörter?
* [ ] [**AppCmd.exe** vorhanden](windows-local-privilege-escalation/#appcmd-exe)? Anmeldeinformationen?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [Dateien und Registrierung (Anmeldeinformationen)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Anmeldeinformationen**](windows-local-privilege-escalation/#putty-creds) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH-Schlüssel in der Registrierung**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Passwörter in [**unbeaufsichtigten Dateien**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Irgendein [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) Backup?
* [ ] [**Cloud-Anmeldeinformationen**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) Datei?
* [ ] [**Gecachtes GPP-Passwort**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Passwort in [**IIS-Webkonfigurationsdatei**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Interessante Informationen in [**Web** **Protokollen**](windows-local-privilege-escalation/#logs)?
* [ ] Möchten Sie [**Benutzer um Anmeldeinformationen bitten**](windows-local-privilege-escalation/#ask-for-credentials)?
* [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Andere [**Registrierung mit Anmeldeinformationen**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] In [**Browserdaten**](windows-local-privilege-escalation/#browsers-history) (Datenbanken, Verlauf, Lesezeichen, ...)?
* [**Generische Passwortsuche**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in Dateien und Registrierung
* [**Tools**](windows-local-privilege-escalation/#tools-that-search-for-passwords) zum automatischen Suchen von Passwörtern

### [Ausgelaufene Handler](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Haben Sie Zugriff auf einen Handler eines Prozesses, der von einem Administrator ausgeführt wird?

### [Pipe-Client-Imitation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Überprüfen, ob Sie es missbrauchen können

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
