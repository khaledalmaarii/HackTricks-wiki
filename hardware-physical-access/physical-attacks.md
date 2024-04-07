# Fiziksel Saldırılar

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## BIOS Şifresi Kurtarma ve Sistem Güvenliği

**BIOS'un sıfırlanması** birkaç farklı şekilde gerçekleştirilebilir. Çoğu anakart, yaklaşık **30 dakika** çıkarıldığında BIOS ayarlarını, şifreyi de dahil olmak üzere sıfırlayacak bir **pil** içerir. Alternatif olarak, anakart üzerindeki bir **jumper** belirli pinleri birleştirerek bu ayarları sıfırlamak için ayarlanabilir.

Donanım ayarlarının mümkün veya pratik olmadığı durumlarda, **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir sistem **Canlı CD/USB** üzerinden çalıştırılarak **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlanabilir ve BIOS şifresi kurtarmaya yardımcı olabilir.

BIOS şifresi bilinmediğinde, yanlışlıkla üç kez girilmesi genellikle bir hata koduna neden olur. Bu kod, [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılarak kullanılabilir bir şifre alınabilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemler için, **chipsec** aracı, **Secure Boot**'un devre dışı bırakılması da dahil olmak üzere UEFI ayarlarını analiz etmek ve değiştirmek için kullanılabilir. Bu, aşağıdaki komutla gerçekleştirilebilir:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analizi ve Soğuk Başlatma Saldırıları

RAM, güç kesildikten sonra genellikle **1 ila 2 dakika** boyunca verileri korur. Bu süre, sıvı nitrojen gibi soğutucu maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu uzatılmış süre boyunca, **dd.exe** ve **volatility** gibi araçlar kullanılarak bir **bellek dökümü** oluşturulabilir ve analiz edilebilir.

### Doğrudan Bellek Erişimi (DMA) Saldırıları

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi arabirimlerle uyumlu olarak DMA aracılığıyla **fiziksel bellek manipülasyonu** için tasarlanmış bir araçtır. Herhangi bir şifreyi kabul eden belleği yamalayarak giriş prosedürlerini atlamayı sağlar. Ancak, **Windows 10** sistemlerine karşı etkisizdir.

### Sistem Erişimi İçin Canlı CD/USB

**_sethc.exe_** veya **_Utilman.exe_** gibi sistem ikili dosyalarını **_cmd.exe_** kopyası ile değiştirmek, sistem ayrıcalıklarıyla bir komut istemini sağlayabilir. **chntpw** gibi araçlar, Windows kurulumunun **SAM** dosyasını düzenlemek için kullanılabilir, böylece şifre değişiklikleri yapılabilir.

**Kon-Boot**, Windows sistemlerine şifreyi bilmeden geçici olarak Windows çekirdeğini veya UEFI'yi değiştirerek oturum açmayı kolaylaştıran bir araçtır. Daha fazla bilgiye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresinden ulaşılabilir.

### Windows Güvenlik Özelliklerinin İşlenmesi

#### Başlatma ve Kurtarma Kısayolları

- **Supr**: BIOS ayarlarına erişim.
- **F8**: Kurtarma moduna gir.
- Windows logosundan sonra **Shift** tuşuna basarak otomatik oturumu atlayabilirsiniz.

#### KÖTÜ USB Cihazları

**Rubber Ducky** ve **Teensyduino** gibi cihazlar, hedef bilgisayara bağlandığında önceden tanımlanmış yükleri yürütebilen **kötü USB** cihazları oluşturmak için platformlar olarak hizmet eder.

#### Hacim Gölge Kopyası

Yönetici ayrıcalıkları, PowerShell aracılığıyla **SAM** dosyası dahil hassas dosyaların kopyalarının oluşturulmasına izin verir.

### BitLocker Şifrelemesini Atlatma

BitLocker şifrelemesi, **hafıza dökümü dosyası (MEMORY.DMP)** içindeki **kurtarma şifresi** bulunursa atlatılabilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

### Kurtarma Anahtarı Eklemek İçin Sosyal Mühendislik

Yeni bir BitLocker kurtarma anahtarı, bir kullanıcıyı sıfırlama işlemini basitleştirmek için sıfırlama işlemi ekleyen bir komutu çalıştırmaya ikna ederek sosyal mühendislik taktikleriyle eklenilebilir.
