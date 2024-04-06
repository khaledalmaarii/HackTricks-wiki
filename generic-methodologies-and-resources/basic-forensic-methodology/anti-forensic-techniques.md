<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonu
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Zaman Damgaları

Bir saldırgan, tespit edilmekten kaçınmak için **dosyaların zaman damgalarını değiştirmek** isteyebilir.\
Zaman damgaları, MFT içindeki `$STANDARD_INFORMATION` __ ve __ `$FILE_NAME` özniteliklerinde bulunabilir.

Her iki öznitelik de 4 zaman damgasına sahiptir: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değiştirme** (MACE veya MACB).

**Windows Gezgini** ve diğer araçlar, bilgileri **`$STANDARD_INFORMATION`**'dan gösterir.

## TimeStomp - Anti-forensik Aracı

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgisini **değiştirir** **ancak** **`$FILE_NAME`** içindeki bilgiyi **değiştirmez**. Bu nedenle, **şüpheli** **aktiviteyi** **belirlemek mümkündür**.

## Usnjrnl

**USN Günlüğü** (Güncelleme Sıra Numarası Günlüğü), NTFS (Windows NT dosya sistemi) özelliğidir ve hacim değişikliklerini takip eder. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesine olanak tanır.

![](<../../.gitbook/assets/image (449).png>)

Önceki görüntü, araç tarafından gösterilen **çıktıdır** ve dosyaya bazı **değişikliklerin yapıldığı** görülebilir.

## $LogFile

Bir dosya sistemindeki **tüm meta veri değişiklikleri**, [ön yazma günlüğü](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçte kaydedilir. Kaydedilen meta veriler, NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar, bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için kullanılabilir.

![](<../../.gitbook/assets/image (450).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığı** görülebilir.

Aynı araç kullanılarak **zaman damgalarının hangi zamana değiştirildiği** belirlenebilir:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Dosyanın oluşturma zamanı
* ATIME: Dosyanın değiştirme zamanı
* MTIME: Dosyanın MFT kayıt değiştirme zamanı
* RTIME: Dosyanın erişim zamanı

## `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli değiştirilmiş dosyaları belirlemenin başka bir yolu, her iki öznitelikteki zamanı karşılaştırmak ve **uyumsuzlukları** aramaktır.

## Nanosaniyeler

**NTFS** zaman damgalarının **100 nanosaniye** hassasiyeti vardır. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyalar çok şüphelidir**.

## SetMace - Anti-forensik Aracı

Bu araç, `$STARNDAR_INFORMATION` ve `$FILE_NAME` özniteliklerini değiştirebilir. Ancak, Windows Vista'dan itibaren bu bilginin değiştirilmesi için bir canlı işletim sistemi gereklidir.

# Veri Gizleme

NFTS, bir küme ve minimum bilgi boyutu kullanır. Bu, bir dosyanın yarım küme kullanması durumunda **kalan yarımın hiçbir zaman kullanılmayacağı** anlamına gelir. Bu nedenle, bu "gizli" alanın içine veri **gizlemek mümkündür**.

Bu "gizli" alanlarda veri gizlemeye izin veren slacker gibi araçlar vardır. Bununla birlikte, `$logfile` ve `$usnjrnl` analizi, bazı verilerin eklendiğini gösterebilir:

![](<../../.gitbook/assets/image (452).png>)

Bu durumda, FTK Imager gibi araçlar kullanılarak gizli alan kurtarılabilir. Bu tür bir araç, içeriği şifreli veya hatta şifrelenmiş olarak kaydedebilir.

# UsbKill

Bu, USB bağlantı noktalarında herhangi bir değişiklik algılandığında bilgisayarı **kapatır** bir araçtır.\
Bunu keşfetmenin bir yolu, çalışan işlemleri incelemek ve **çalışan her python betimini gözden geçirmek** olacaktır.

# Canlı Linux Dağıtımları

Bu dağıtımlar, **RAM bellek içinde çalıştırılır**. Bunların tespit edilebilmesinin tek yolu, NTFS dosya sisteminin yazma izinleriyle bağlanması durumunda mümkün olacaktır. Salt okunur izinlerle bağlanıldığında, sızma tespit edilemez.

# Güvenli Silme

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows Yapılandırması

Forensik incelemeyi zorlaştırmak için çeşitli Windows günlükleme yöntemlerini devre dışı bırakmak mümkündür.

## Zaman Damgalarını Devre Dışı Bırakma - UserAssist

Bu, her bir yürütülebilir dosyanın kullanıcı tarafından çalıştırıldığı tarih ve saatleri tutan bir kayıt defteri anahtarıdır.

UserAssist'in devre dışı bırakılması için iki adım gereklidir:

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` adlı iki kayıt defteri anahtarı sıfıra ayarlanmalıdır. Böylece UserAssist'in devre dışı bırakılmasını istediğimizi belirtiriz.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen kayıt defteri alt ağaçlarını temizleyin.

## Zaman Damgalarını Devre Dışı Bırakma - Prefetch

Bu, Windows sisteminin performansını iyileştirmek amacıyla yürütülen uygulamalar hakkında bilgi saklar. Ancak, bu aynı zamanda forensik uygulamalar için de kullanışlı olabilir.

* `regedit`'i çalıştırın
* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` dosya yolunu seçin
* Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzer
## USB Geçmişini Silme

Tüm **USB Aygıt Girişleri**, USB cihazını bilgisayarınıza veya dizüstü bilgisayarınıza takmanız durumunda oluşturulan alt anahtarları içeren **USBSTOR** kaydı altında Windows Kayıt Defteri'nde saklanır. Bu anahtarı burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silerek** USB geçmişini silebilirsiniz.\
Ayrıca, USB'ler hakkında bilgi saklayan dosya `C:\Windows\INF` içindeki `setupapi.dev.log` dosyası da silinmelidir.

## Gölge Kopyalarını Devre Dışı Bırakma

Gölge kopyalarını `vssadmin list shadowstorage` komutuyla **listele**.\
Onları silmek için `vssadmin delete shadow` komutunu çalıştırın.

Ayrıca, [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları takip ederek GUI üzerinden de silebilirsiniz.

Gölge kopyalarını devre dışı bırakmak için [buradan adımları](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) izleyin:

1. Başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazarak Hizmetler programını açın.
2. Listeden "Volume Shadow Copy" bulun, seçin ve ardından sağ tıklayarak Özelliklere erişin.
3. "Başlangıç türü" açılır menüsünden "Devre Dışı" seçin ve değişikliği uygulamak için Uygula ve Tamam'a tıklayın.

Gölge kopyasında hangi dosyaların kopyalanacağının yapılandırmasını da kayıt defterinde `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` bölümünde değiştirmek mümkündür.

## Silinen Dosyaları Üzerine Yazma

* Bir **Windows aracı** olan `cipher /w:C` komutunu kullanabilirsiniz. Bu, C sürücüsündeki kullanılmayan disk alanından tüm verileri silmek için cipher'a talimat verir.
* [**Eraser**](https://eraser.heidi.ie) gibi araçları da kullanabilirsiniz.

## Windows Olay Günlüklerini Silme

* Windows + R --> eventvwr.msc --> "Windows Günlükleri"ni genişletin --> Her kategoriye sağ tıklayın ve "Günlüğü Temizle" seçeneğini seçin.
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windows Olay Günlüklerini Devre Dışı Bırakma

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Hizmetler bölümünde "Windows Event Log" hizmetini devre dışı bırakın.
* `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl` komutunu kullanın.

## $UsnJrnl'yi Devre Dışı Bırakma

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin!</summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin.
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da** takip edin.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
