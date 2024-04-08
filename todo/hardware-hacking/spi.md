# SPI

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Temel Bilgiler

SPI (Serial Peripheral Interface), gömülü sistemlerde kullanılan, IC'ler (Entegre Devreler) arasında kısa mesafe iletişimi için kullanılan Senkron Seri İletişim Protokolüdür. SPI İletişim Protokolü, saat ve Çip Seçim Sinyali tarafından orkestrasyonu yapılan master-slave mimarisinden yararlanır. Bir master-slave mimarisi, genellikle bir mikroişlemci olan bir ana bilgisayarın EEPROM, sensörler, kontrol cihazları vb. gibi harici bileşenleri yönettiği ve köle olarak kabul edilen cihazlardan oluşur.

Bir ana bilgisayara birden fazla köle bağlanabilir ancak köleler birbirleriyle iletişim kuramaz. Köleler, saat ve çip seçim olmak üzere iki pin tarafından yönetilir. SPI senkron bir iletişim protokolü olduğundan, giriş ve çıkış pinleri saat sinyallerini takip eder. Çip seçimi, ana bilgisayarın bir köleyi seçmesi ve onunla etkileşime girmesi için kullanılır. Çip seçimi yüksek olduğunda, köle cihaz seçilmezken, düşük olduğunda çip seçilmiş olur ve ana bilgisayar köle ile etkileşime geçer.

MOSI (Master Out, Slave In) ve MISO (Master In, Slave Out) veri gönderme ve alma işlemlerinden sorumludur. Veri, çip seçimi düşük tutulurken MOSI pini aracılığıyla köle cihaza gönderilir. Giriş verisi, köle cihaz satıcısının veri sayfasına göre talimatlar, bellek adresleri veya veriler içerir. Geçerli bir girişte, MISO pini verileri ana bilgisayara iletmekten sorumludur. Çıkış verisi, giriş bittikten hemen sonra bir sonraki saat döngüsünde gönderilir. MISO pinleri, veri tamamen iletilene kadar veya ana bilgisayar çip seçim pimini yüksek konumuna getirinceye kadar (bu durumda, köle veri iletmeyi durduracak ve ana bilgisayar o saat döngüsünden sonra dinlemeyecektir) veri iletmeye devam eder.

## EEPROM'lerden Firmware'in Dump Edilmesi

Firmware'in dump edilmesi, firmware'in analiz edilmesi ve içindeki güvenlik açıklarının bulunması için faydalı olabilir. Çoğu zaman, firmware internet üzerinde mevcut değildir veya model numarası, sürüm vb. gibi faktörlerin değişkenliği nedeniyle ilgisizdir. Bu nedenle, fiziksel cihazdan doğrudan firmware'in çıkarılması, tehditleri ararken belirli olabilmek için faydalı olabilir.

Seri Konsol almak faydalı olabilir, ancak çoğu zaman dosyaların salt okunur olduğu görülür. Bu, çeşitli nedenlerden dolayı analizi kısıtlar. Örneğin, paket gönderip almak için gereken araçlar firmware'de bulunmayabilir. Bu nedenle, dosyaları tersine mühendislik yapmak için firmware'in tamamının sisteme dump edilmesi ve analiz için dosyaların çıkarılması çok faydalı olabilir.

Ayrıca, kırmızı eğitim sırasında ve cihazlara fiziksel erişim sağlandığında, firmware'in dump edilmesi dosyaları değiştirmeye veya kötü amaçlı dosyalar enjekte etmeye ve ardından bunları belleğe yeniden yüklemeye yardımcı olabilir, bu da cihaza bir arka kapı yerleştirmek için faydalı olabilir. Bu nedenle, firmware dump edilerek açılabilecek birçok olasılık vardır.

### CH341A EEPROM Programlayıcı ve Okuyucu

Bu cihaz, EEPROM'lerden firmware'leri dump etmek ve firmware dosyaları ile yeniden yüklemek için uygun bir araçtır. Bu, bilgisayar BIOS yongalarıyla (sadece EEPROM'lar) çalışmak için popüler bir seçenek olmuştur. Bu cihaz USB üzerinden bağlanır ve başlamak için minimum araçlara ihtiyaç duyar. Ayrıca genellikle görevi hızlı bir şekilde tamamlar, bu nedenle fiziksel cihaz erişiminde de faydalı olabilir.

<img src="../../.gitbook/assets/board_image_ch341a.jpg" alt="drawing" width="400" align="center"/>

EEPROM belleği CH341a Programlayıcı ile bağlayın ve cihazı bilgisayara takın. Cihaz algılanmıyorsa, bilgisayara sürücülerin yüklenmeye çalışılması önerilir. Ayrıca, EEPROM'un doğru yönde bağlı olduğundan emin olun (genellikle VCC Pini USB konektörüne ters yönde yerleştirilir) aksi takdirde yazılımın çipi algılayamayacağından emin olun. Gerekirse diyagrama başvurun:

<img src="../../.gitbook/assets/connect_wires_ch341a.jpg" alt="drawing" width="350"/>

<img src="../../.gitbook/assets/eeprom_plugged_ch341a.jpg" alt="drawing" width="350"/>

Son olarak, firmware'i dump etmek için flashrom, G-Flash (GUI) vb. gibi yazılımları kullanın. G-Flash, EEPROM'u otomatik olarak algılayan hızlı ve minimal bir GUI aracıdır. Bu, belgelerle çok uğraşmadan hızlı bir şekilde firmware'in çıkarılması gerekiyorsa faydalı olabilir.

<img src="../../.gitbook/assets/connected_status_ch341a.jpg" alt="drawing" width="350"/>

Firmware'i dump ettikten sonra, analiz binary dosyalar üzerinde yapılabilir. Strings, hexdump, xxd, binwalk vb. gibi araçlar, firmware hakkında ve aynı zamanda tüm dosya sistemi hakkında birçok bilgi çıkarmak için kullanılabilir.

Firmware'den içeriği çıkarmak için binwalk kullanılabilir. Binwalk, hex imzaları için analiz yapar ve ikili dosyada dosyaları tanımlar ve bunları çıkarmak için yeteneklidir.
```
binwalk -e <filename>
```
<filename> dosyaları, kullanılan araçlar ve yapılandırmalara bağlı olarak .bin veya .rom olabilir.

{% hint style="danger" %} Firmware çıkarma işlemi hassas bir süreçtir ve sabır gerektirir. Herhangi bir hata, firmware'in bozulmasına veya tamamen silinmesine neden olabilir ve cihazı kullanılamaz hale getirebilir. Firmware'in çıkarılması denemeden önce belirli cihazı incelemeniz önerilir. {% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Pirate Bus'un PINOUT'unun **MOSI** ve **MISO** için pinler göstermesine rağmen bazı SPI'lar DI ve DO olarak pinleri gösterebilir. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

Windows veya Linux'ta [**`flashrom`**](https://www.flashrom.org/Flashrom) programını kullanarak flash belleğin içeriğini dökümlemek için şu şekilde bir komut çalıştırabilirsiniz:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
