# Anti-Forensic Techniques

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

## Timestamps

Bir saldırgan, **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını, `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde MFT içinde bulmak mümkündür.

Her iki öznitelik de 4 zaman damgası içerir: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değişikliği** (MACE veya MACB).

**Windows gezgini** ve diğer araçlar, **`$STANDARD_INFORMATION`** içindeki bilgileri gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir** **ancak** **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle, **şüpheli** **faaliyetleri** **belirlemek** mümkündür.

### Usnjrnl

**USN Journal** (Güncelleme Sırası Numarası Günlüğü), NTFS'nin (Windows NT dosya sistemi) bir özelliğidir ve hacim değişikliklerini takip eder. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesine olanak tanır.

![](<../../.gitbook/assets/image (801).png>)

Önceki resim, dosya üzerinde bazı **değişikliklerin yapıldığını** gözlemleyebileceğimiz **aracın** gösterdiği **çıktıdır**.

### $LogFile

**Bir dosya sistemine yapılan tüm meta veri değişiklikleri**, [ön yazma günlüğü](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçte kaydedilir. Kaydedilen meta veriler, NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar, bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için kullanılabilir.

![](<../../.gitbook/assets/image (137).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı aracı kullanarak, **zaman damgalarının ne zaman değiştirildiğini** belirlemek mümkündür:

![](<../../.gitbook/assets/image (1089).png>)

* CTIME: Dosyanın oluşturulma zamanı
* ATIME: Dosyanın değiştirilme zamanı
* MTIME: Dosyanın MFT kayıt değişikliği
* RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli değiştirilmiş dosyaları belirlemenin bir diğer yolu, her iki öznitelikteki zamanı karşılaştırarak **uyumsuzluklar** aramaktır.

### Nanoseconds

**NTFS** zaman damgalarının **kesinliği** **100 nanosecond**'dir. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaları bulmak **çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç, hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak, Windows Vista'dan itibaren, bu bilgileri değiştirmek için canlı bir işletim sistemine ihtiyaç vardır.

## Data Hiding

NFTS, bir küme ve minimum bilgi boyutu kullanır. Bu, bir dosya bir buçuk küme kullanıyorsa, **geri kalan yarımın asla kullanılmayacağı** anlamına gelir, ta ki dosya silinene kadar. Bu nedenle, bu boşlukta **veri gizlemek mümkündür**.

Slacker gibi, bu "gizli" alanda veri gizlemeye olanak tanıyan araçlar vardır. Ancak, `$logfile` ve `$usnjrnl` analizi, bazı verilerin eklendiğini gösterebilir:

![](<../../.gitbook/assets/image (1060).png>)

Bu nedenle, FTK Imager gibi araçlar kullanarak boş alanı geri almak mümkündür. Bu tür araçların içeriği obfuscate veya hatta şifreli olarak kaydedebileceğini unutmayın.

## UsbKill

Bu, herhangi bir USB portunda bir değişiklik algılandığında bilgisayarı **kapatan** bir araçtır.\
Bunu keşfetmenin bir yolu, çalışan süreçleri incelemek ve **her bir çalışan python betiğini gözden geçirmektir**.

## Live Linux Distributions

Bu dağıtımlar, **RAM** belleği içinde **çalıştırılır**. Onları tespit etmenin tek yolu, **NTFS dosya sisteminin yazma izinleriyle monte edilmesidir**. Sadece okuma izinleriyle monte edilirse, ihlali tespit etmek mümkün olmayacaktır.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Birçok Windows günlükleme yöntemini devre dışı bırakmak, adli soruşturmayı çok daha zor hale getirebilir.

### Disable Timestamps - UserAssist

Bu, her çalıştırılan yürütülebilir dosyanın tarihlerini ve saatlerini saklayan bir kayıt anahtarıdır.

UserAssist'i devre dışı bırakmak için iki adım gereklidir:

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` adlı iki kayıt anahtarını sıfıra ayarlayın, böylece UserAssist'in devre dışı bırakılmasını istediğimizi belirtmiş oluruz.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen kayıt alt ağaçlarınızı temizleyin.

### Disable Timestamps - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan uygulamalar hakkında bilgi kaydedecektir. Ancak, bu aynı zamanda adli uygulamalar için de yararlı olabilir.

* `regedit`i çalıştırın
* Dosya yolunu seçin `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzerinde sağ tıklayın
* Her birinin değerini 1 (veya 3) yerine 0 olarak değiştirmek için Değiştir'i seçin
* Yeniden başlatın

### Disable Timestamps - Last Access Time

Bir NTFS hacminden bir klasör açıldığında, sistem, listedeki her klasör için **bir zaman damgası alanını güncellemek için zamanı alır**, bu alana son erişim zamanı denir. Yoğun kullanılan bir NTFS hacminde, bu performansı etkileyebilir.

1. Kayıt Defteri Düzenleyicisini (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` yoluna gidin.
3. `NtfsDisableLastAccessUpdate` anahtarını arayın. Eğer yoksa, bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın, bu işlem devre dışı bırakılacaktır.
4. Kayıt Defteri Düzenleyicisini kapatın ve sunucuyu yeniden başlatın.

### Delete USB History

Tüm **USB Aygıt Girişleri**, bir USB Aygıtını PC veya Dizüstü Bilgisayarınıza taktığınızda oluşturulan alt anahtarları içeren **USBSTOR** kayıt anahtarı altında Windows Kayıt Defteri'nde saklanır. Bu anahtarı burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silerek** USB geçmişini silmiş olursunuz.\
Ayrıca, bunları sildiğinizden emin olmak için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını kullanabilirsiniz (ve silmek için).

USB'ler hakkında bilgi kaydeden bir diğer dosya, `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu dosya da silinmelidir.

### Disable Shadow Copies

**Gölge kopyaları listeleyin** `vssadmin list shadowstorage`\
**Silin** `vssadmin delete shadow` komutunu çalıştırarak

Ayrıca, [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları izleyerek GUI üzerinden de silebilirsiniz.

Gölge kopyalarını devre dışı bırakmak için [buradaki adımları](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) izleyebilirsiniz:

1. Windows başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazarak Hizmetler programını açın.
2. Listeden "Volume Shadow Copy"yi bulun, seçin ve sağ tıklayarak Özellikler'e erişin.
3. "Başlangıç türü" açılır menüsünden Devre Dışı seçeneğini seçin ve ardından değişikliği onaylamak için Uygula ve Tamam'a tıklayın.

Hangi dosyaların gölge kopyasında kopyalanacağını yapılandırmayı da kayıt defterinde `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` değiştirerek yapabilirsiniz.

### Overwrite deleted files

* Bir **Windows aracı** kullanabilirsiniz: `cipher /w:C` Bu, şifreleme aracına C sürücüsündeki kullanılmayan disk alanından herhangi bir veriyi kaldırmasını belirtir.
* Ayrıca, [**Eraser**](https://eraser.heidi.ie) gibi araçlar da kullanabilirsiniz.

### Delete Windows event logs

* Windows + R --> eventvwr.msc --> "Windows Logs"u genişletin --> Her kategoriye sağ tıklayın ve "Logu Temizle" seçeneğini seçin
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Hizmetler bölümünde "Windows Event Log" hizmetini devre dışı bırakın
* `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### Disable $UsnJrnl

* `fsutil usn deletejournal /d c:`

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
