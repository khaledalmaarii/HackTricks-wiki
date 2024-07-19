# SPI

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Temel Bilgiler

SPI (Seri Peripheral Arayüzü), entegre devreler (IC'ler) arasında kısa mesafeli iletişim için gömülü sistemlerde kullanılan Senkron Seri İletişim Protokolüdür. SPI İletişim Protokolü, Saat ve Çip Seçim Sinyali tarafından yönetilen master-slave mimarisini kullanır. Bir master-slave mimarisi, EEPROM, sensörler, kontrol cihazları gibi harici çevre birimlerini yöneten bir master (genellikle bir mikroişlemci) içerir ve bunlar köle olarak kabul edilir.

Bir master'a birden fazla köle bağlanabilir, ancak köleler birbirleriyle iletişim kuramaz. Köleler, saat ve çip seçimi olmak üzere iki pin ile yönetilir. SPI senkron bir iletişim protokolü olduğundan, giriş ve çıkış pinleri saat sinyallerini takip eder. Çip seçimi, master tarafından bir köleyi seçmek ve onunla etkileşimde bulunmak için kullanılır. Çip seçimi yüksek olduğunda, köle cihaz seçilmezken, düşük olduğunda çip seçilmiş olur ve master köle ile etkileşimde bulunur.

MOSI (Master Out, Slave In) ve MISO (Master In, Slave Out) veri gönderme ve alma işlemlerinden sorumludur. Veri, MOSI pininden köle cihaza gönderilirken çip seçimi düşük tutulur. Giriş verisi, köle cihaz tedarikçisinin veri sayfasına göre talimatlar, bellek adresleri veya veriler içerir. Geçerli bir girişte, MISO pini veriyi master'a iletmekten sorumludur. Çıkış verisi, giriş sona erdikten sonra bir sonraki saat döngüsünde tam olarak gönderilir. MISO pinleri, veri tamamen iletilene kadar veya master çip seçimi pinini yüksek ayarlayana kadar veri iletmeye devam eder (bu durumda, köle iletmeyi durdurur ve master o saat döngüsünden sonra dinlemez).

## EEPROM'lerden Firmware Dökümü

Firmware dökümü, firmware'i analiz etmek ve içindeki zayıflıkları bulmak için yararlı olabilir. Çoğu zaman, firmware internette mevcut değildir veya model numarası, versiyon gibi faktörlerin varyasyonları nedeniyle alakasızdır. Bu nedenle, tehditleri avlarken spesifik olmak için firmware'i doğrudan fiziksel cihazdan çıkarmak faydalı olabilir.

Seri Konsol almak faydalı olabilir, ancak çoğu zaman dosyaların yalnızca okunabilir olduğu durumlarla karşılaşılır. Bu, çeşitli nedenlerden dolayı analizi kısıtlar. Örneğin, paketleri göndermek ve almak için gereken araçlar firmware'de bulunmayabilir. Bu nedenle, ikili dosyaları tersine mühendislik yapmak için çıkarmak mümkün değildir. Bu nedenle, sistemde tüm firmware'in dökülmesi ve analiz için ikili dosyaların çıkarılması çok faydalı olabilir.

Ayrıca, kırmızı takım çalışması sırasında cihazlara fiziksel erişim sağlarken, firmware dökümü dosyaları değiştirmek veya kötü niyetli dosyalar eklemek ve ardından bunları belleğe yeniden yüklemek için yardımcı olabilir; bu da cihazda bir arka kapı yerleştirmek için faydalı olabilir. Bu nedenle, firmware dökümü ile açılabilecek birçok olasılık vardır.

### CH341A EEPROM Programlayıcı ve Okuyucu

Bu cihaz, EEPROM'lerden firmware dökmek ve bunları firmware dosyaları ile yeniden yüklemek için uygun fiyatlı bir araçtır. Bilgisayar BIOS yongaları (sadece EEPROM'lar) ile çalışmak için popüler bir seçim olmuştur. Bu cihaz USB üzerinden bağlanır ve başlamak için minimum araç gerektirir. Ayrıca, genellikle işi hızlı bir şekilde halleder, bu nedenle fiziksel cihaz erişiminde de faydalı olabilir.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

EEPROM belleği CH341a Programlayıcı ile bağlayın ve cihazı bilgisayara takın. Cihaz algılanmıyorsa, bilgisayara sürücü yüklemeyi deneyin. Ayrıca, EEPROM'un doğru yönde bağlandığından emin olun (genellikle, VCC Pin'ini USB konektörüne ters yönde yerleştirin), aksi takdirde yazılım çipi algılayamaz. Gerekirse diyagrama bakın:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Son olarak, firmware'i dökmek için flashrom, G-Flash (GUI) gibi yazılımlar kullanın. G-Flash, hızlı ve EEPROM'u otomatik olarak algılayan minimal bir GUI aracıdır. Bu, firmware'in hızlı bir şekilde çıkarılması gerektiğinde, belgelerle fazla uğraşmadan faydalı olabilir.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Firmware döküldükten sonra, analiz ikili dosyalar üzerinde yapılabilir. Strings, hexdump, xxd, binwalk gibi araçlar, firmware hakkında ve tüm dosya sistemi hakkında çok fazla bilgi çıkarmak için kullanılabilir.

Firmware'den içerik çıkarmak için binwalk kullanılabilir. Binwalk, hex imzalarını analiz eder ve ikili dosyadaki dosyaları tanımlar ve bunları çıkarmak için yeteneklidir.
```
binwalk -e <filename>
```
Bu, kullanılan araçlar ve yapılandırmalara göre .bin veya .rom olabilir.

{% hint style="danger" %}
Firmware çıkarımının hassas bir süreç olduğunu ve çok fazla sabır gerektirdiğini unutmayın. Herhangi bir yanlış işlem, firmware'i bozabilir veya tamamen silip cihazı kullanılamaz hale getirebilir. Firmware'i çıkarmaya çalışmadan önce belirli cihazı incelemeniz önerilir.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Pirate Bus'un PINOUT'u **MOSI** ve **MISO** için SPI'ye bağlanacak pinleri gösterse de, bazı SPIs pinleri DI ve DO olarak gösterebilir. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Windows veya Linux'ta, flash bellek içeriğini dökmek için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını kullanabilirsiniz, şöyle bir şey çalıştırarak:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
