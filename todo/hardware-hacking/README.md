# Donanım Hacking

<details>

<summary><strong>AWS hacking'i sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## JTAG

JTAG, bir sınır taraması gerçekleştirmenizi sağlar. Sınır taraması, her pin için gömülü sınır tarama hücrelerini ve kayıtları da içeren belirli devreleri analiz eder.

JTAG standardı, sınır taramaları gerçekleştirmek için **belirli komutlar** tanımlar, bunlar arasında şunlar bulunur:

* **BYPASS**, diğer yongalardan geçmeden belirli bir yongayı test etmenizi sağlar.
* **SAMPLE/PRELOAD**, cihaz normal çalışma modundayken giren ve çıkan verilerin bir örneğini alır.
* **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca şunlar gibi diğer komutları da destekleyebilir:

* Bir cihazı tanımlamak için **IDCODE**
* Cihazın iç testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

### Test Erişim Portu

Sınır taramaları, bileşende bulunan JTAG test desteği fonksiyonlarına erişim sağlayan genel amaçlı bir port olan dört telli **Test Erişim Portu (TAP)**'nın testlerini içerir. TAP, aşağıdaki beş sinyali kullanır:

* Test saat girişi (**TCK**) TCK, TAP denetleyicisinin tek bir eylem alacağını (yani, durum makinesinde bir sonraki duruma geçeceğini) ne sıklıkta tanımlayan **saattir**.
* Test modu seçimi (**TMS**) girişi TMS, **sonlu durum makinesini** kontrol eder. Her saat vuruşunda, cihazın JTAG TAP denetleyicisi TMS pimindeki gerilimi kontrol eder. Gerilim belirli bir eşik değerin altındaysa sinyal düşük kabul edilir ve 0 olarak yorumlanır, eğer gerilim belirli bir eşik değerin üzerindeyse sinyal yüksek kabul edilir ve 1 olarak yorumlanır.
* Test veri girişi (**TDI**) TDI, çipe **tarama hücreleri aracılığıyla veri gönderen** pindir. Her satıcı, bu pim üzerinden iletişim protokolünü tanımlamaktan sorumludur, çünkü JTAG bunu tanımlamaz.
* Test veri çıkışı (**TDO**) TDO, çipten **veri çıkaran** pindir.
* Test sıfırlama (**TRST**) girişi İsteğe bağlı TRST, sonlu durum makinesini **bilinen iyi bir duruma sıfırlar**. Alternatif olarak, TMS 1'de beş ardışık saat döngüsü boyunca tutulursa, TRST pini ne yaparsa yapsın bir sıfırlama çağırır, bu nedenle TRST isteğe bağlıdır.

Bazen bu pinlerin PCB'de işaretlendiğini görebilirsiniz. Diğer durumlarda **bulmanız gerekebilir**.

### JTAG Pinlerini Tanımlama

JTAG portlarını tespit etmenin en hızlı ama en pahalı yolu, özel olarak bu amaç için oluşturulmuş bir cihaz olan **JTAGulator**'ü kullanmaktır (ayrıca **UART pinout'larını da tespit edebilir**).

Bu cihazda bağlayabileceğiniz **24 kanal** bulunmaktadır. Daha sonra tüm olası kombinasyonların **IDCODE** ve **BYPASS** sınır tarama komutlarını göndererek **BF saldırısı** gerçekleştirir. Bir yanıt alırsa, her JTAG sinyali için karşılık gelen kanalı görüntüler.

JTAG pinout'larını tanımlamanın daha ucuz ama çok daha yavaş bir yolu, Arduino uyumlu bir mikrodenetleyici üzerine yüklenmiş olan [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) kullanarak yapılabilir.

**JTAGenum** kullanarak, önce sorgulama için kullanacağınız cihazın pinlerini **tanımlamanız gerekir**. Cihazın pinout diyagramına başvurmanız ve ardından bu pinleri hedef cihazınızın test noktalarına bağlamanız gerekir.

JTAG pinlerini tanımlamanın **üçüncü yolu**, PCB'yi bir pinout için inceleyerek bulmaktır. Bazı durumlarda, PCB'ler uygun şekilde **Tag-Connect arayüzünü** sağlayabilir, bu da kartın bir JTAG konektörüne sahip olduğunun açık bir göstergesidir. Bu arayüzün nasıl göründüğünü [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) adresinden görebilirsiniz. Ayrıca, PCB'lerdeki **çip setlerinin veri sayfalarını** incelemek, JTAG arayüzlerine işaret eden pinout diyagramlarını ortaya çıkarabilir.

## SDW

SWD, hata ayıklama için tasarlanmış ARM özel bir protokoldür.

SWD arayüzü **iki pin** gerektirir: çift yönlü bir **SWDIO** sinyali, JTAG'ın **TDI ve TDO pinlerine** eşdeğer olan ve bir saat olan ve JTAG'daki **TCK**'ya eşdeğer olan **SWCLK**. Birçok cihaz, hedefe bir SWD veya JTAG probunu bağlamanıza olanak tanıyan birleşik bir JTAG ve SWD arayüzü olan **Serial Wire veya JTAG Debug Port (SWJ-DP)**'yi destekler.
