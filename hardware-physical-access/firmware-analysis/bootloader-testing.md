<details>

<summary><strong>Sıfırdan kahramana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

Cihaz başlangıç yapılandırmalarını ve U-boot gibi bootloader'ları değiştirmek için aşağıdaki adımlar önerilir:

1. **Bootloader'ın Yorumlayıcı Kabuğuna Erişim**:
- Önyükleme sırasında, bootloader'ın yorumlayıcı kabuğuna erişmek için "0", boşluk veya diğer belirlenmiş "sihirli kodları" basın.

2. **Boot Argümanlarını Değiştirme**:
- Aşağıdaki komutları yürütün ve '`init=/bin/sh`'i önyükleme argümanlarına ekleyin, bir kabuk komutunun yürütülmesine izin vererek:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP Sunucusu Kurulumu**:
- Yerel bir ağ üzerinden görüntüleri yüklemek için bir TFTP sunucusunu yapılandırın:
%%%
#setenv ipaddr 192.168.2.2 #cihazın yerel IP'si
#setenv serverip 192.168.2.1 #TFTP sunucusu IP'si
#saveenv
#reset
#ping 192.168.2.1 #ağ erişimini kontrol et
#tftp ${loadaddr} uImage-3.6.35 #loadaddr, dosyayı yüklemek için adresi alır ve TFTP sunucusundaki görüntünün dosya adını alır
%%%

4. **`ubootwrite.py`'yi Kullanma**:
- Kök erişim elde etmek için U-boot görüntüsünü yazmak ve değiştirilmiş bir firmware göndermek için `ubootwrite.py`'yi kullanın.

5. **Hata Ayıklama Özelliklerini Kontrol Etme**:
- Ayrıntılı günlükleme, keyfi çekirdek yükleme veya güvenilmeyen kaynaklardan önyükleme gibi hata ayıklama özelliklerinin etkin olup olmadığını doğrulayın.

6. **Dikkatli Donanım Müdahalesi**:
- Cihazın önyükleme sırasında bir pini toprağa bağlamak ve SPI veya NAND flaş çipleriyle etkileşime geçerken dikkatli olun, özellikle çekirdek sıkıştırılmadan önce. Pinleri kısaltmadan önce NAND flaş çipinin veri sayfasına danışın.

7. **Sahte DHCP Sunucusu Yapılandırma**:
- Bir cihazın bir PXE önyükleme sırasında alması için kötü amaçlı parametrelere sahip sahte bir DHCP sunucusu kurun. Metasploit'in (MSF) DHCP yardımcı sunucusu gibi araçları kullanın. 'FILENAME' parametresini `'a";/bin/sh;#'` gibi komut enjeksiyon komutlarıyla değiştirerek cihazın önyükleme prosedürleri için giriş doğrulamasını test edin.

**Not**: Cihaz pinleriyle fiziksel etkileşim gerektiren adımlar (*yıldızla işaretlenmiş) cihazı zarar görmekten kaçınmak için son derece dikkatli bir şekilde ele alınmalıdır.


## Referanslar
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
