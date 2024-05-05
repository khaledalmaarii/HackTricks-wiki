# SPI

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Temel Bilgiler

SPI (Serial Peripheral Interface), gömülü sistemlerde kullanılan, IC'ler (Entegre Devreler) arasında kısa mesafe iletişimi için kullanılan Senkron Seri İletişim Protokolüdür. SPI İletişim Protokolü, saat ve Çip Seçim Sinyali tarafından orkestrasyonu yapılan ana-köle mimarisinden yararlanır. Ana-köle mimarisi, genellikle bir mikroişlemci olan ana birimden (master) EEPROM, sensörler, kontrol cihazları vb. gibi dış birimleri yöneten ve köle olarak kabul edilen cihazları içerir.

Bir ana birime birden fazla köle bağlanabilir ancak köleler birbirleriyle iletişim kuramaz. Köleler, saat ve çip seçim olmak üzere iki pin tarafından yönetilir. SPI, senkron bir iletişim protokolü olduğundan, giriş ve çıkış pinleri saat sinyallerini takip eder. Ana, bir köleyi seçmek ve onunla etkileşimde bulunmak için çip seçimini kullanır. Çip seçim yüksek olduğunda, köle cihaz seçilmezken, düşük olduğunda çip seçilmiş olur ve ana, köle ile etkileşimde bulunur.

MOSI (Master Out, Slave In) ve MISO (Master In, Slave Out), veri gönderme ve alma işlemlerinden sorumludur. Veri, çip seçimi düşük tutularak MOSI pini aracılığıyla köle cihaza gönderilir. Giriş verisi, köle cihaz satıcısının veri sayfasına göre talimatlar, bellek adresleri veya veri içerebilir. Geçerli bir girişte, MISO pini, veriyi ana birime iletmekten sorumludur. Çıkış verisi, giriş bittikten hemen sonra bir sonraki saat döngüsünde gönderilir. MISO pinleri, veri tamamen iletilene kadar veya ana, çip seçim pimini yüksek ayarladığında (bu durumda, köle iletimi durur ve ana o saat döngüsünden sonra dinlemez) veri iletmeye devam eder.

## EEPROM'lerden Firmware'in Dump Edilmesi

Firmware'in dump edilmesi, firmware'in analiz edilmesi ve içindeki güvenlik açıklarının bulunması için faydalı olabilir. Çoğu zaman, firmware internet üzerinde mevcut değildir veya model numarası, sürüm vb. gibi faktörlerin değişkenliği nedeniyle ilgisizdir. Bu nedenle, fiziksel cihazdan doğrudan firmware'in çıkarılması, tehditleri ararken belirli olabilmek için faydalı olabilir.

Seri Konsol elde etmek faydalı olabilir, ancak çoğu zaman dosyaların salt okunur olduğu durumlarla karşılaşılır. Bu, çeşitli nedenlerden dolayı analizi kısıtlar. Örneğin, paket gönderip almak için gereken araçlar firmware'de bulunmayabilir. Bu nedenle, binary dosyaları çıkarmak için tüm firmware'in sisteme dump edilmesi ve ardından analiz için binary dosyaların çıkarılması çok faydalı olabilir.

Ayrıca, kırmızı eğitim sırasında ve cihazlara fiziksel erişim elde ederken, firmware'in dump edilmesi dosyaları değiştirmeye veya kötü amaçlı dosyalar enjekte etmeye ve ardından bunları belleğe yeniden yüklemeye yardımcı olabilir, bu da cihaza bir arka kapı yerleştirmek için faydalı olabilir. Bu nedenle, firmware dump edilerek açılabilecek birçok olasılık vardır.

### CH341A EEPROM Programlayıcı ve Okuyucu

Bu cihaz, EEPROM'lerden firmware'leri dump etmek ve firmware dosyaları ile yeniden yüklemek için uygun bir araçtır. Bu, bilgisayar BIOS çipleriyle (sadece EEPROM'lar) çalışmak için popüler bir seçenek olmuştur. Bu cihaz USB üzerinden bağlanır ve başlamak için minimum araçlara ihtiyaç duyar. Ayrıca genellikle görevi hızlı bir şekilde tamamlar, bu nedenle fiziksel cihaz erişiminde de faydalı olabilir.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

EEPROM belleği CH341a Programlayıcı ile bağlayın ve cihazı bilgisayara takın. Cihaz algılanmıyorsa, bilgisayara sürücülerin yüklenmeye çalışılması önerilir. Ayrıca, EEPROM'un doğru yönde bağlı olduğundan emin olun (genellikle, VCC Pini USB konektörüne ters yönde yerleştirilir) aksi takdirde yazılımın çipi algılayamayacağından emin olun. Gerekirse diyagrama başvurun:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Son olarak, firmware'i dump etmek için flashrom, G-Flash (GUI) vb. gibi yazılımları kullanın. G-Flash, minimal bir GUI aracıdır, hızlıdır ve EEPROM'u otomatik olarak algılar. Bu, belgelerle çok uğraşmadan hızlı bir şekilde firmware'in çıkarılması gerekiyorsa faydalı olabilir.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Firmware'i dump ettikten sonra, binary dosyalar üzerinde analiz yapılabilir. Strings, hexdump, xxd, binwalk vb. gibi araçlar, firmware hakkında ve aynı zamanda tüm dosya sistemi hakkında birçok bilgi çıkarmak için kullanılabilir.

Firmware'den içeriği çıkarmak için binwalk kullanılabilir. Binwalk, hex imzaları için analiz yapar ve binary dosyadaki dosyaları tanımlar ve çıkarabilir.
```
binwalk -e <filename>
```
Dosya, kullanılan araçlar ve yapılandırmalara bağlı olarak .bin veya .rom olabilir.

{% hint style="danger" %}
Firmware çıkarma işlemi hassas bir süreçtir ve çok sabır gerektirir. Herhangi bir hata, firmware'in bozulmasına veya tamamen silinmesine neden olabilir ve cihazı kullanılamaz hale getirebilir. Firmware'i çıkarmadan önce belirli cihazı incelemeniz önerilir.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Pirate Bus'un PINOUT'unun **MOSI** ve **MISO** için pinler gösterdiği belirtilse de bazı SPI'lar **DI** ve **DO** olarak pinleri gösterebilir. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Windows veya Linux'ta, flash belleğin içeriğini dökmek için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını çalıştırarak şu şekilde bir şey yapabilirsiniz:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>
