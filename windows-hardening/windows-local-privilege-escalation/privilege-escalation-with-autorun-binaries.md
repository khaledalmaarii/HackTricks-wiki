# Otomatik Çalışan Dosyalarla Yetki Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Eğer **hacking kariyeri** ilginizi çekiyorsa ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı şekilde Lehçe yazılı ve konuşma gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic**, **başlangıçta** programları çalıştırmak için kullanılabilir. Başlangıçta çalışacak olan dosyaları görmek için:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zamanlanmış Görevler

**Görevler**, belirli bir sıklıkta çalıştırılmak üzere zamanlanabilir. Hangi ikili dosyaların zamanlanmış olarak çalıştırıldığını görmek için aşağıdaki komutu kullanabilirsiniz:
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
[Buradan not alın](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** kayıt defteri girişi, 64 bit Windows sürümü kullandığınızı gösterir. İşletim sistemi, 64 bit Windows sürümlerinde çalışan 32 bit uygulamalar için HKEY\_LOCAL\_MACHINE\SOFTWARE'nin ayrı bir görünümünü göstermek için bu anahtarı kullanır.
{% endhint %}

### Çalıştırılıyor

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

**Run** ve **RunOnce** olarak bilinen kayıt defteri anahtarları, kullanıcının sisteme oturum açtığında otomatik olarak programları çalıştırmak için tasarlanmıştır. Anahtarın veri değeri olarak atanan komut satırı, 260 karakter veya daha azla sınırlıdır.

**Servis çalıştırmaları** (başlangıçta hizmetlerin otomatik olarak başlatılmasını kontrol edebilir):

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

Windows Vista ve sonraki sürümlerde, **Run** ve **RunOnce** kayıt defteri anahtarları otomatik olarak oluşturulmaz. Bu anahtarlar içindeki girişler, programları doğrudan başlatabilir veya bağımlılıklarını belirtebilir. Örneğin, bir DLL dosyasını oturum açılışında yüklemek için **RunOnceEx** kayıt defteri anahtarını ve bir "Depend" anahtarını kullanabilirsiniz. Bu, "C:\\temp\\evil.dll" dosyasını sistem başlangıcında çalıştırmak için bir kayıt defteri girişi ekleyerek gösterilir.
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: Eğer **HKLM** içinde belirtilen herhangi bir kayıt defterine yazabilirseniz, farklı bir kullanıcı oturum açtığında ayrıcalıkları yükseltebilirsiniz.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Eğer **HKLM** içinde belirtilen herhangi bir kayıt defterindeki herhangi bir ikili dosyayı üzerine yazabilirseniz, farklı bir kullanıcı oturum açtığında bu ikili dosyayı bir arka kapı ile değiştirebilir ve ayrıcalıkları yükseltebilirsiniz.
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

**Başlangıç** klasörüne yerleştirilen kısayollar, kullanıcı oturumu açıldığında veya sistem yeniden başlatıldığında otomatik olarak hizmetleri veya uygulamaları başlatır. **Başlangıç** klasörünün konumu, hem **Yerel Makine** hem de **Geçerli Kullanıcı** kapsamları için kayıt defterinde tanımlanmıştır. Bu, belirtilen **Başlangıç** konumlarına eklenen herhangi bir kısayolun, bağlantılı hizmetin veya programın oturum açma veya yeniden başlatma işleminden sonra otomatik olarak başlamasını sağlar. Bu, programların otomatik olarak çalıştırılması için basit bir yöntemdir.

{% hint style="info" %}
Eğer **HKLM** altında herhangi bir \[Kullanıcı] Shell Klasörünü üzerine yazabilirseniz, onu sizin kontrolünüzde olan bir klasöre yönlendirebilir ve ayrıcalıkları yükselten bir arka kapı yerleştirebilirsiniz. Bu sayede bir kullanıcı sisteme oturum açtığında her zaman çalıştırılacak.
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

Genellikle, **Userinit** anahtarı **userinit.exe** olarak ayarlanır. Ancak, bu anahtar değiştirilirse, belirtilen yürütülebilir dosya da kullanıcı oturumu açıldığında **Winlogon** tarafından başlatılır. Benzer şekilde, **Shell** anahtarı Windows için varsayılan kabuk olan **explorer.exe**'ye işaret etmek amacıyla kullanılır.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Eğer kayıt defteri değerini veya ikili dosyayı üzerine yazabilirseniz, ayrıcalıkları yükseltebilirsiniz.
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

Windows Kayıt Defteri'nde `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında, varsayılan olarak `cmd.exe` olarak ayarlanmış bir **`AlternateShell`** değeri bulunur. Bu, başlangıçta "Komut İstemiyle Güvenli Mod" seçildiğinde (F8 tuşuna basarak) `cmd.exe` kullanıldığı anlamına gelir. Ancak, F8'e basmadan ve manuel olarak seçmeden bilgisayarınızı otomatik olarak bu modda başlatmak mümkündür.

"Komut İstemiyle Güvenli Modda" otomatik olarak başlamak için önyükleme seçeneği oluşturma adımları:

1. `boot.ini` dosyasının salt okunur, sistem ve gizli bayraklarını kaldırmak için `attrib c:\boot.ini -r -s -h` komutunu kullanın.
2. `boot.ini` dosyasını düzenlemek için açın.
3. Aşağıdaki gibi bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Yapılan değişiklikleri `boot.ini` dosyasına kaydedin.
5. Orijinal dosya özniteliklerini tekrar uygulayın: `attrib c:\boot.ini +r +s +h` komutunu kullanın.

- **Exploit 1:** **AlternateShell** kayıt defteri anahtarını değiştirmek, yetkisiz erişim için özel komut kabuğu kurulumuna olanak sağlar.
- **Exploit 2 (PATH Yazma İzinleri):** Sistem **PATH** değişkeninin herhangi bir bölümüne, özellikle `C:\Windows\system32`'den önce yazma izinlerine sahip olmak, Güvenli Modda sistem başlatıldığında bir arka kapı olabilecek özel bir `cmd.exe`'yi yürütmenizi sağlar.
- **Exploit 3 (PATH ve boot.ini Yazma İzinleri):** `boot.ini`'ye yazma erişimi, otomatik Güvenli Mod başlatmayı sağlar ve bir sonraki yeniden başlatmada yetkisiz erişimi kolaylaştırır.

Mevcut **AlternateShell** ayarını kontrol etmek için şu komutları kullanın:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Yüklü Bileşen

Active Setup, Windows'ta **masaüstü ortamı tamamen yüklenmeden önce başlatılan** bir özelliktir. Kullanıcı oturumu devam etmeden önce tamamlanması gereken belirli komutların öncelikli olarak yürütülmesini sağlar. Bu işlem, Run veya RunOnce kayıt defteri bölümlerindeki diğer başlangıç girişlerinden önce gerçekleşir.

Active Setup, aşağıdaki kayıt defteri anahtarları aracılığıyla yönetilir:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu anahtarlar içinde, belirli bir bileşene karşılık gelen çeşitli alt anahtarlar bulunur. Özellikle ilgi çeken anahtar değerleri şunlardır:

- **IsInstalled:**
- `0`, bileşenin komutunun yürütülmeyeceğini gösterir.
- `1`, komutun her kullanıcı için bir kez yürütüleceğini belirtir. Bu, `IsInstalled` değeri eksikse varsayılan davranıştır.
- **StubPath:** Active Setup tarafından yürütülecek komutu tanımlar. Başlatma `notepad` gibi herhangi bir geçerli komut satırı olabilir.

**Güvenlik İpuçları:**

- **`IsInstalled`** değeri `"1"` olarak ayarlanmış bir anahtarı değiştirmek veya yazmak, yetkisiz komut yürütme ve potansiyel olarak ayrıcalık yükseltme için kullanılabilir.
- Herhangi bir **`StubPath`** değerinde belirtilen ikili dosyayı değiştirmek de, yeterli izinlerle ayrıcalık yükseltme sağlayabilir.

Active Setup bileşenlerindeki **`StubPath`** yapılandırmalarını incelemek için aşağıdaki komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Tarayıcı Yardımcı Nesneleri

### Tarayıcı Yardımcı Nesneleri (BHO) Genel Bakışı

Tarayıcı Yardımcı Nesneleri (BHO), Microsoft'un Internet Explorer'ına ekstra özellikler ekleyen DLL modülleridir. Her başlangıçta Internet Explorer ve Windows Explorer'a yüklenirler. Ancak, **NoExplorer** anahtarının 1 olarak ayarlanmasıyla yüklenmeleri Windows Explorer örnekleriyle engellenebilir.

BHO'lar, Windows 10 üzerinde Internet Explorer 11 aracılığıyla uyumlu olsa da, daha yeni Windows sürümlerindeki varsayılan tarayıcı olan Microsoft Edge'de desteklenmez.

Bir sistemde kayıtlı BHO'ları keşfetmek için aşağıdaki kayıt defteri anahtarlarını inceleyebilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, kayıt defterindeki **CLSID** ile temsil edilir ve benzersiz bir tanımlayıcı olarak hizmet eder. Her CLSID hakkında ayrıntılı bilgiler `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Kayıt defterinde BHO'ları sorgulamak için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Uzantıları

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Dikkat edin, kayıt defteri her bir dll için yeni bir kayıt içerecektir ve bu **CLSID** tarafından temsil edilecektir. CLSID bilgisini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` içinde bulabilirsiniz.

### Yazı Tipi Sürücüleri

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Açık Komutu

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Resim Dosyası Yürütme Seçenekleri

Image File Execution Options (IFEO), Windows işletim sisteminde bir uygulamanın yürütülmesi sırasında özel ayarlar yapmamızı sağlayan bir mekanizmadır. Bu mekanizma, bir uygulamanın başlatılması sırasında belirli bir hedefe yönlendirilmesini veya ek işlemlerin gerçekleştirilmesini sağlar.

IFEO, kötü niyetli bir saldırganın yerel ayrıcalıklarını yükseltmek için kullanılabilecek bir yöntemdir. Saldırgan, IFEO'yu kullanarak bir uygulamanın yürütülmesini hedefleyebilir ve bu uygulama üzerinde ayrıcalıklı bir işlem gerçekleştirebilir.

Bu saldırıyı gerçekleştirmek için, saldırganın hedef uygulamanın kayıt defterindeki IFEO girdisini değiştirmesi gerekmektedir. Bu girdi, uygulamanın başlatılması sırasında başka bir uygulamanın yürütülmesini sağlar. Saldırgan, bu şekilde hedef uygulamanın ayrıcalıklarını kullanarak sistemde istenmeyen değişiklikler yapabilir veya başka saldırılar gerçekleştirebilir.

IFEO saldırılarını önlemek için, kayıt defterindeki IFEO girdilerini düzenli olarak kontrol etmek ve gereksiz olanları kaldırmak önemlidir. Ayrıca, güvenlik duvarı ve antivirüs yazılımı gibi koruma mekanizmalarının güncel ve etkin olduğundan emin olmak da önemlidir.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Dikkat edin, autorun dosyalarını bulabileceğiniz tüm siteler zaten **winpeas.exe** tarafından aranmıştır. Ancak daha kapsamlı bir otomatik çalıştırılan dosya listesi için [systinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) tarafından sunulan **autoruns** aracını kullanabilirsiniz:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Daha Fazla

**Registri gibi Autorun'ları [buradan](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2) bulabilirsiniz.**

## Referanslar

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Eğer **hacking kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı bir şekilde Lehçe yazılı ve konuşma gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud github reposuna PR göndererek paylaşın.**

</details>
