# UART

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Temel Bilgiler

UART, verileri bir bitlik birimler halinde bileşenler arasında ileten bir seri protokoldür. Buna karşılık, paralel iletişim protokolleri verileri aynı anda birden fazla kanaldan iletilir. Yaygın seri protokoller arasında RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express ve USB bulunur.

Genel olarak, UART boşta iken (mantıksal 1 değerinde) hat yüksek tutulur. Daha sonra, veri transferinin başlangıcını belirtmek için verici, alıcıya bir başlangıç biti gönderir, bu sırada sinyal düşük tutulur (mantıksal 0 değerinde). Daha sonra, verici gerçek mesajı içeren beş ila sekiz veri biti gönderir, bunu isteğe bağlı bir çiftlik biti ve yapılandırmaya bağlı olarak bir veya iki durdurma biti (mantıksal 1 değerinde) izler. Hata denetimi için kullanılan çiftlik biti, uygulamada nadiren görülür. Durdurma biti (veya bitleri) iletimin sonunu belirtir.

En yaygın yapılandırmaya 8N1 adını veririz: sekiz veri biti, çiftlik biti olmadan ve bir durdurma biti. Örneğin, 8N1 UART yapılandırmasında karakter C'yi veya ASCII'de 0x43'ü göndermek isteseydik, aşağıdaki bitleri gönderirdik: 0 (başlangıç biti); 0, 1, 0, 0, 0, 0, 1, 1 (0x43'ün ikili değeri) ve 0 (durdurma biti).

![](<../../.gitbook/assets/image (761).png>)

UART ile iletişim kurmak için donanım araçları:

* USB-seri adaptör
* CP2102 veya PL2303 yongalarıyla adaptörler
* Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi çok amaçlı araçlar

### UART Bağlantı Noktalarını Tanımlama

UART'ın 4 bağlantı noktası vardır: **TX**(Gönder), **RX**(Al), **Vcc**(Gerilim) ve **GND**(Toprak). PCB'de **`TX`** ve **`RX`** harflerinin **yazılı olduğu** 4 bağlantı noktası bulabilirsiniz. Ancak işaret yoksa, bir **multimetre** veya **mantık analizörü** kullanarak kendiniz bulmanız gerekebilir.

Bir **multimetre** ve cihaz kapalıyken:

* **Topraklılık Testi** modunu kullanarak **GND** pimini tanımlamak için, arka ucu toprağa yerleştirin ve kırmızı ucu ile test edin, multimetreden bir ses duyana kadar. PCB'de birkaç GND pimi bulunabilir, bu nedenle UART'a ait olanı bulmuş olabilirsiniz veya olmayabilirsiniz.
* **VCC bağlantı noktasını** tanımlamak için **DC gerilim modunu** ayarlayın ve 20 V gerilime kadar ayarlayın. Siyah probu toprağa, kırmızı probu pine yerleştirin. Cihazı açın. Multimetre sabit bir 3.3 V veya 5 V gerilim ölçerse, Vcc pimini bulmuşsunuz demektir. Başka gerilimler alırsanız, diğer bağlantı noktaları ile tekrar deneyin.
* **TX** **bağlantı noktasını** tanımlamak için, **DC gerilim modunu** 20 V gerilime kadar ayarlayın, siyah probu toprağa, kırmızı probu pine yerleştirin ve cihazı açın. Gerilimin birkaç saniye boyunca dalgalanıp daha sonra Vcc değerinde sabitlendiğini bulursanız, muhtemelen TX bağlantı noktasını bulmuşsunuz demektir. Bu, cihazı açarken bazı hata ayıklama verileri gönderdiği içindir.
* **RX bağlantı noktası**, diğer 3'e en yakın olan olacaktır, en düşük gerilim dalgalanması ve tüm UART pinlerinin en düşük genel değerine sahiptir.

TX ve RX bağlantı noktalarını karıştırabilirsiniz ve hiçbir şey olmaz, ancak GND ve VCC bağlantı noktalarını karıştırırsanız devreyi yakabilirsiniz.

Bazı hedef cihazlarda, üretici tarafından RX veya TX veya hatta her ikisi devre dışı bırakılarak UART bağlantı noktası devre dışı bırakılabilir. Bu durumda, devre kartındaki bağlantıları izlemek ve bazı ayrık noktaları bulmak faydalı olabilir. UART algılamasının olmadığını ve devrenin kırıldığını doğrulamak için güçlü bir ipucu, cihazın garantisini kontrol etmektir. Cihazın garanti ile gönderilmiş olması durumunda, üretici bazı hata ayıklama arayüzleri (bu durumda UART) bırakır ve bu nedenle UART'ı bağlamış ve hata ayıklama yaparken tekrar bağlayacaktır. Bu ayrık pinler lehimleme veya jumper kabloları ile bağlanabilir.

### UART Baud Oranını Tanımlama

Doğru baud oranını tanımlamanın en kolay yolu, **TX piminden çıktıyı incelemek ve veriyi okumaya çalışmaktır**. Aldığınız veri okunabilir değilse, veri okunabilir hale gelene kadar bir sonraki mümkün baud oranına geçin. Bunu yapmak için bir USB-seri adaptör veya Bus Pirate gibi çok amaçlı bir cihaz kullanabilir ve [baudrate.py](https://github.com/devttys0/baudrate/) gibi bir yardımcı betikle eşleştirebilirsiniz. En yaygın baud oranları 9600, 38400, 19200, 57600 ve 115200'dür.

{% hint style="danger" %}
Bu protokolde bir cihazın TX'sini diğer cihazın RX'ine bağlamanız gerektiğini unutmamak önemlidir!
{% endhint %}

## CP210X UART to TTY Adaptörü

CP210X Yongası, NodeMCU (esp8266 ile) gibi birçok prototip kartında Seri İletişim için kullanılır. Bu adaptörler oldukça ucuzdur ve hedefin UART arabirimine bağlanmak için kullanılabilir. Cihazın 5 pimi vardır: 5V, GND, RXD, TXD, 3.3V. Herhangi bir hasar olmaması için hedef tarafından desteklenen gerilimi bağladığınızdan emin olun. Son olarak, Adaptörün RXD pimini hedefin TXD'sine ve Adaptörün TXD pimini hedefin RXD'sine bağlayın.

Adaptör algılanmazsa, CP210X sürücülerinin ana sistemde yüklü olduğundan emin olun. Adaptör algılandığında ve bağlandığında, picocom, minicom veya screen gibi araçlar kullanılabilir.

Linux/MacOS sistemlerine bağlı cihazları listelemek için:
```
ls /dev/
```
UART arayüzü ile temel etkileşim için aşağıdaki komutu kullanın:
```
picocom /dev/<adapter> --baud <baudrate>
```
Minicom'i yapılandırmak için aşağıdaki komutu kullanın:
```
minicom -s
```
`Seri port ayarları` seçeneğinde baud hızı ve cihaz adı gibi ayarları yapılandırın.

Yapılandırmadan sonra `minicom` komutunu kullanarak UART Konsolunu başlatın.

## Arduino UNO R3 Üzerinden UART (Çıkarılabilir Atmel 328p Yonga Kartları)

UART Seri USB adaptörleri mevcut değilse, Arduino UNO R3 hızlı bir hile ile kullanılabilir. Arduino UNO R3 genellikle her yerde bulunabilir olduğundan, bu yöntem çok zaman kazandırabilir.

Arduino UNO R3'ün kendisinde kart üzerinde bulunan bir USB'den Seri adaptörü vardır. UART bağlantısı almak için, sadece Arduino'dan Atmel 328p mikrodenetleyici yongasını çıkarın. Bu hile, Arduino UNO R3 varyantlarında (SMD versiyonunda kullanılan) kart üzerine lehimlenmemiş olan Atmel 328p'ye sahip olanlarda çalışır. Arduino'nun RX pini (Dijital Pin 0) ile UART Arayüzünün TX pini ve Arduino'nun TX pini (Dijital Pin 1) ile UART arayüzünün RX pini bağlanır.

Son olarak, UART arayüzüne göre baud hızını ayarlayarak Arduino IDE'yi kullanmanız önerilir.

## Bus Pirate

Bu senaryoda, programın tüm çıktılarını Seri Monitöre gönderen Arduino'nun UART iletişimini izleyeceğiz.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## UART Konsolu ile Firmware'in Dump Edilmesi

UART Konsolu, çalışma zamanı ortamındaki temel firmware ile çalışmanın harika bir yolunu sağlar. Ancak UART Konsolu erişimi salt okunur olduğunda birçok kısıtlama getirebilir. Birçok gömülü cihazda, firmware EEPROM'lerde depolanır ve geçici belleğe sahip işlemcilerde yürütülür. Dolayısıyla, firmware, üretim sırasında EEPROM içindeki orijinal firmware olduğundan ve herhangi yeni dosyalar geçici bellek nedeniyle kaybolacağından salt okunur olarak tutulur. Bu nedenle, gömülü firmware'lerle çalışırken firmware'in dump edilmesi değerli bir çabadır.

Bunu yapmanın birçok yolu vardır ve SPI bölümü, çeşitli cihazlarla EEPROM'dan firmware'in doğrudan çıkarılma yöntemlerini kapsar. Ancak, fiziksel cihazlar ve harici etkileşimlerle firmware'in dump edilmesini ilk denemeden önce UART ile yapmayı önerilir.

UART Konsolundan firmware dump etmek, öncelikle bootloader'lara erişim sağlamayı gerektirir. Birçok popüler satıcı, Linux'u yüklemek için <b>uboot</b> (Universal Bootloader) kullanır. Bu nedenle, <b>uboot</b>'a erişim sağlamak gereklidir.

<b>Boot</b> bootloader'ına erişmek için UART portunu bilgisayara bağlayın ve herhangi bir Seri Konsol aracını kullanın ve cihazın güç kaynağını bağlı olmaktan çıkarın. Kurulum hazır olduğunda Enter tuşuna basılı tutun. Son olarak, cihazın güç kaynağını bağlayın ve başlatın.

Bunu yapmak, <b>uboot</b>'un yüklenmesini kesintiye uğratacak ve bir menü sağlayacaktır. <b>uboot</b> komutlarını anlamak ve bunları listelemek için yardım menüsünü kullanmanız önerilir. Bu muhtemelen `help` komutudur. Farklı satıcılar farklı yapılandırmaları kullandıklarından, her birini ayrı ayrı anlamak gereklidir.

Genellikle, firmware'i dump etmek için kullanılan komut:
```
md
```
Bu, "bellek dökümü" anlamına gelir. Bu, belleği (EEPROM İçeriği) ekrana dökecektir. Bellek dökümünü yakalamak için işleme başlamadan önce Seri Konsol çıktısını günlüğe kaydetmeniz önerilir.

Son olarak, günlük dosyasından gereksiz tüm verileri çıkarın ve dosyayı `dosyaadı.rom` olarak saklayın ve içeriği çıkarmak için binwalk kullanın:
```
binwalk -e <filename.rom>
```
Bu, EEPROM'daki olası içerikleri, hex dosyasında bulunan imzalara göre listeleyecektir.

Ancak, kullanılsa bile <b>uboot</b>'un her zaman kilidinin açık olmadığını belirtmek gerekir. Enter tuşu bir şey yapmıyorsa, Boşluk Tuşu gibi farklı tuşları kontrol edin. Önyükleyicinin kilitli olup kesintiye uğramadığı durumlarda bu yöntem işe yaramaz. Cihaz için <b>uboot</b>'un önyükleyici olup olmadığını kontrol etmek için, cihazın önyükleme sırasında UART Konsolu çıktısını kontrol edin. Önyükleme sırasında <b>uboot</b> bahsediliyorsa, bu yöntem işe yarayabilir.

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizin HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
