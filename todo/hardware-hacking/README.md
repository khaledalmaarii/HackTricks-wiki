<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


#

# JTAG

JTAG, bir sınıra tarama yapmanıza olanak sağlar. Sınıra tarama, her bir pim için gömülü sınıra tarama hücrelerini ve kayıtlarını içeren belirli devreleri analiz eder.

JTAG standardı, aşağıdakiler de dahil olmak üzere **sınıra tarama yapmak için belirli komutlar** tanımlar:

* **BYPASS**, diğer yongalardan geçmekle uğraşmadan belirli bir yonga üzerinde test yapmanıza olanak sağlar.
* **SAMPLE/PRELOAD**, cihaz normal çalışma modundayken giren ve çıkan verilerin bir örneğini alır.
* **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca şunlar gibi diğer komutları da destekleyebilir:

* Bir cihazı tanımlamak için **IDCODE**
* Cihazın iç testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

## Test Erişim Bağlantı Noktası

Sınıra taramalar, bileşene yerleştirilmiş olan **Test Erişim Bağlantı Noktası (TAP)**'nın dört telli testlerini içerir. TAP, bir bileşende bulunan JTAG test desteği işlevlerine **erişim sağlayan genel amaçlı bir bağlantı noktasıdır**. TAP, aşağıdaki beş sinyali kullanır:

* Test saat girişi (**TCK**) TCK, TAP denetleyicisinin tek bir eylem yapacağı sıklığı (yani, durum makinesinde bir sonraki duruma geçme) tanımlayan **saattir**.
* Test modu seçimi (**TMS**) girişi TMS, **sonlu durum makinesini** kontrol eder. Her saat vuruşunda, cihazın JTAG TAP denetleyicisi, TMS pimindeki gerilimi kontrol eder. Gerilim belirli bir eşik değerinin altındaysa, sinyal düşük olarak kabul edilir ve 0 olarak yorumlanır, eğer gerilim belirli bir eşik değerinin üzerindeyse, sinyal yüksek olarak kabul edilir ve 1 olarak yorumlanır.
* Test veri girişi (**TDI**) TDI, tarama hücreleri aracılığıyla çipe **veri gönderen pindir**. JTAG bunu tanımlamadığı için, her bir satıcı bu pim üzerinden iletişim protokolünü tanımlamaktan sorumludur.
* Test veri çıkışı (**TDO**) TDO, çipten **veri gönderen pindir**.
* Test sıfırlama (**TRST**) girişi İsteğe bağlı TRST, sonlu durum makinesini **bilinen iyi bir duruma sıfırlar**. Alternatif olarak, TMS 1 olarak beş ardışık saat döngüsü boyunca tutulursa, TRST piniyle aynı şekilde bir sıfırlama çağırır, bu yüzden TRST isteğe bağlıdır.

Bazen bu pinlerin PCB üzerinde işaretlendiğini bulabilirsiniz. Diğer durumlarda **bulmanız** gerekebilir.

## JTAG pinlerini tanımlama

JTAG bağlantı noktalarını tespit etmenin en hızlı ama en pahalı yolu, bu amaçla özel olarak oluşturulmuş bir cihaz olan **JTAGulator**'ü kullanmaktır (aynı zamanda **UART pinoutlarını da tespit edebilir**).

24 kanala sahip olduğu için, JTAGulator'ü kartın pinlerine bağlayabilirsiniz. Ardından, tüm olası kombinasyonları göndererek **IDCODE** ve **BYPASS** sınıra tarama komutlarını **BF saldırısı** gerçekleştirir. Bir yanıt alırsa, her JTAG sinyali için ilgili kanalı görüntüler.

JTAG pinoutlarını tanımlamanın daha ucuz ama çok daha yavaş bir yolu, bir Arduino uyumlu mikrodenetleyiciye yüklenmiş olan [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) kullanmaktır.

**JTAGenum** kullanarak, öncelikle tespit için kullanacağınız probun pinlerini **tanımlarsınız**. Hedef cihazınızdaki test noktalarını, cihazın pinout diyagramına başvurarak bu pinlerle bağlantı kurmanız gerekecektir.

JTAG pinlerini tanımlamanın **üçüncü bir yolu**, PCB'yi bir pinout için **incelemek**tir. Bazı durumlarda, PCB'ler uygun bir şekilde **Tag-Connect arabirimini** sağlayabilir, bu da kartın bir JTAG konektörüne sahip olduğunun açık bir göstergesidir. Bu arabirimin nasıl göründüğünü [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) adresinde görebilirsiniz. Ayrıca, PCB üzerindeki yonga setlerinin **veri sayfalarını inceleyerek** JTAG arabirimlerine işaret eden pinout diyagramlarını bulabilirsiniz.

# SDW

SWD, hata ayıklama için tasarlanmış ARM özel bir protokoldür.

SWD arabirimi, **iki pin** gerektirir: çift yönlü bir **SWDIO** sinyali, JTAG'ın **TDI ve TDO pinlerine** eşdeğer olan ve bir saat olan **SWCLK**, ve JTAG'daki **TCK**'ya eşdeğer olan **SWCLK**. Birçok cihaz, SWD veya JTAG probunu hedefe bağlamanıza olanak sağlayan birleşik bir JTAG ve SWD arabirimi olan **Serial Wire veya JTAG Debug Port (SWJ-DP)**'yi destekler.
