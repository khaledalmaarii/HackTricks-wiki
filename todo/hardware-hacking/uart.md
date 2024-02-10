<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>


# Temel Bilgiler

UART, verileri bileşenler arasında tek bir bit olarak aktaran bir seri protokoldür. Buna karşılık, paralel iletişim protokolleri verileri aynı anda birden fazla kanaldan iletişir. Yaygın seri protokoller arasında RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express ve USB bulunur.

Genel olarak, UART boşta iken hat yüksek seviyede (mantıksal 1 değerinde) tutulur. Ardından, veri iletiminin başlangıcını bildirmek için verici, sinyalin düşük seviyede (mantıksal 0 değerinde) tutulduğu bir başlangıç biti gönderir. Daha sonra, verici, gerçek mesajı içeren beş ila sekiz veri biti, isteğe bağlı bir teklik biti ve yapılandırmaya bağlı olarak bir veya iki durdurma biti (mantıksal 1 değerinde) gönderir. Hata kontrolü için kullanılan teklik biti, pratikte nadiren görülür. Durdurma biti (veya bitleri), iletimin sonunu belirtir.

En yaygın yapılandırmaya 8N1 denir: sekiz veri biti, teklik yok ve bir durdurma biti. Örneğin, 8N1 UART yapılandırmasında karakter C'yi veya ASCII'de 0x43'ü göndermek istesek, aşağıdaki bitleri göndeririz: 0 (başlangıç biti); 0, 1, 0, 0, 0, 0, 1, 1 (2'lik tabanda 0x43 değeri) ve 0 (durma biti).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

UART ile iletişim kurmak için donanım araçları:

* USB-seri adaptör
* CP2102 veya PL2303 çipli adaptörler
* Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi çok amaçlı araçlar gibi

## UART Portlarını Tanımlama

UART'ın 4 portu vardır: **TX** (Gönder), **RX** (Al), **Vcc** (Gerilim) ve **GND** (Toprak). PCB üzerinde **TX** ve **RX** harflerinin **yazılı olduğu** 4 port bulabilirsiniz. Ancak işaret yoksa, bir **multimetre** veya bir **mantık analizörü** kullanarak kendiniz bulmanız gerekebilir.

Cihaz kapalıyken bir multimetre ve:

* **Süreklilik Testi** modunu kullanarak **GND** pimini tanımlamak için, arka ucu toprağa yerleştirin ve kırmızı ucu multimetreden bir ses duyana kadar test edin. PCB'de birkaç GND pimi bulunabilir, bu yüzden UART'a ait olanı bulmuş olabilirsiniz veya olmayabilirsiniz.
* **VCC portunu** tanımlamak için **DC gerilim modunu** ayarlayın ve 20 V gerilime kadar ayarlayın. Siyah probu toprağa ve kırmızı probu pine yerleştirin. Cihazı açın. Multimetre sürekli 3.3 V veya 5 V gerilim ölçerse, Vcc pimini buldunuz demektir. Başka gerilimler alırsanız, diğer portlarla tekrar deneyin.
* **TX portunu** tanımlamak için **DC gerilim modunu** 20 V gerilime kadar ayarlayın, siyah probu toprağa ve kırmızı probu pine yerleştirin ve cihazı açın. Gerilimin birkaç saniye boyunca dalgalanıp daha sonra Vcc değerinde sabitlendiğini bulursanız, muhtemelen TX portunu buldunuz demektir. Bu, açılırken bazı hata ayıklama verileri gönderdiği için olur.
* **RX portu**, diğer 3 porta en yakın olanı olacaktır, en düşük gerilim dalgalanması ve tüm UART pinlerinin en düşük genel değeri vardır.

TX ve RX portlarını karıştırabilirsiniz ve hiçbir şey olmaz, ancak GND ve VCC portlarını karıştırırsanız devreyi yakabilirsiniz.

Mantık analizörü ile:

## UART Baud Hızını Tanımlama

Doğru baud hızını tanımlamanın en kolay yolu, **TX piminin çıkışını incelemek ve veriyi okumaya çalışmaktır**. Alınan veri okunamazsa, veri okunabilir hale gelene kadar bir sonraki olası baud hızına geçin. Bunun için bir USB-seri adaptörü veya Bus Pirate gibi çok amaçlı bir cihaz kullanabilir ve [baudrate.py](https://github.com/devttys0/baudrate/) gibi bir yardımcı betikle eşleştirebilirsiniz. En yaygın baud hızları 9600, 38400, 19200, 57600 ve 115200'dür.

{% hint style="danger" %}
Bu protokolde, bir cihazın TX'sini diğerinin RX'ine bağlamanız gerektiğini unutmamak önemlidir!
{% endhint %}

# Bus Pirate

Bu senaryoda, Arduino'nun tüm program yazılarını Seri Monitöre gönderen UART iletişimini izleyeceğiz.
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
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
