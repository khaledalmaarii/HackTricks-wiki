# Fiziksel Saldırılar

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## BIOS Parola Kurtarma ve Sistem Güvenliği

**BIOS'un sıfırlanması**, birkaç farklı şekilde gerçekleştirilebilir. Çoğu anakart, BIOS ayarlarını, parolayı da dahil olmak üzere, sıfırlayacak olan bir **pil** içerir. Pil, yaklaşık **30 dakika** çıkarıldığında BIOS ayarlarını sıfırlar. Alternatif olarak, anakart üzerindeki bir **jumper**, belirli pinleri birleştirerek bu ayarları sıfırlamak için ayarlanabilir.

Donanım ayarlamalarının mümkün veya pratik olmadığı durumlarda, **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir **Canlı CD/USB** üzerinden sistem çalıştırarak, BIOS parola kurtarmada yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlanabilir.

BIOS parolasının bilinmediği durumlarda, yanlış girilmesi durumunda genellikle bir hata kodu ortaya çıkar. Bu kod, [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılarak kullanılabilir bir parola elde edilebilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemler için, **chipsec** aracı, UEFI ayarlarını analiz etmek ve değiştirmek için kullanılabilir. Bu, aşağıdaki komutla gerçekleştirilebilir:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analizi ve Soğuk Başlatma Saldırıları

RAM, güç kesildikten sonra verileri kısa bir süre tutar, genellikle **1 ila 2 dakika** boyunca. Bu süre, sıvı nitrojen gibi soğuk maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu uzatılmış süre boyunca, **dd.exe** ve **volatility** gibi araçlar kullanılarak bir **bellek dökümü** oluşturulabilir ve analiz edilebilir.

### Doğrudan Bellek Erişimi (DMA) Saldırıları

**INCEPTION**, DMA aracılığıyla fiziksel bellek manipülasyonu için tasarlanmış bir araçtır ve **FireWire** ve **Thunderbolt** gibi arabirimlerle uyumludur. Bu araç, belleği herhangi bir parolayı kabul edecek şekilde yamalayarak giriş prosedürlerini atlamayı sağlar. Ancak, **Windows 10** sistemlere karşı etkisizdir.

### Sistem Erişimi İçin Canlı CD/USB

**_sethc.exe_** veya **_Utilman.exe_** gibi sistem ikili dosyalarını **_cmd.exe_** bir kopyasıyla değiştirmek, sistem ayrıcalıklarıyla bir komut istemi sağlayabilir. **chntpw** gibi araçlar, bir Windows kurulumunun **SAM** dosyasını düzenlemek için kullanılabilir ve parola değişikliklerine izin verir.

**Kon-Boot**, Windows sistemlere mevcut parolayı bilmeden giriş yapmayı kolaylaştıran bir araçtır. Daha fazla bilgi için [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresine bakabilirsiniz.

### Windows Güvenlik Özelliklerinin İşlenmesi

#### Başlatma ve Kurtarma Kısayolları

- **Supr**: BIOS ayarlarına erişim.
- **F8**: Kurtarma moduna giriş.
- Windows logosu sonrasında **Shift** tuşuna basarak otomatik oturum açmayı atlayabilirsiniz.

#### Kötü USB Aygıtları

**Rubber Ducky** ve **Teensyduino** gibi aygıtlar, hedef bir bilgisayara bağlandığında önceden tanımlanmış yükleri yürütebilen **kötü USB** aygıtları oluşturmak için platform olarak kullanılır.

#### Volume Shadow Copy

Yönetici ayrıcalıkları, PowerShell aracılığıyla **SAM** dosyası dahil hassas dosyaların kopyalarının oluşturulmasına izin verir.

### BitLocker Şifresini Atlatma

BitLocker şifrelemesi, bir bellek döküm dosyası (**MEMORY.DMP**) içinde **kurtarma şifresi** bulunursa atlatılabilir. Bu amaçla, **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

### Kurtarma Anahtarı Eklemek İçin Sosyal Mühendislik

Sosyal mühendislik taktikleriyle yeni bir BitLocker kurtarma anahtarı eklemek mümkündür. Bir kullanıcıyı, şifreleme sürecini basitleştirmek için sıfırlardan oluşan yeni bir kurtarma anahtarı ekleyen bir komutu çalıştırmaya ikna etmek bu işlemi sağlar.
