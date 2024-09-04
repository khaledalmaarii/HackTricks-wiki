# UART

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


## Temel Bilgiler

UART, bileşenler arasında verileri bir seferde bir bit olarak ileten seri bir protokoldür. Buna karşılık, paralel iletişim protokolleri verileri birden fazla kanal üzerinden aynı anda iletir. Yaygın seri protokoller arasında RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express ve USB bulunur.

Genel olarak, UART boş durumda iken hat yüksek (mantıksal 1 değeri) tutulur. Ardından, bir veri transferinin başlangıcını belirtmek için, verici alıcıya bir başlangıç biti gönderir; bu esnada sinyal düşük (mantıksal 0 değeri) tutulur. Sonra, verici, gerçek mesajı içeren beş ila sekiz veri biti gönderir, ardından isteğe bağlı bir parite biti ve yapılandırmaya bağlı olarak bir veya iki durdurma biti (mantıksal 1 değeri) gelir. Hata kontrolü için kullanılan parite biti pratikte nadiren görülür. Durdurma biti (veya bitleri) iletimin sonunu belirtir.

En yaygın yapılandırmaya 8N1 denir: sekiz veri biti, parite yok ve bir durdurma biti. Örneğin, C karakterini veya ASCII'de 0x43'ü 8N1 UART yapılandırmasında göndermek isteseydik, şu bitleri gönderirdik: 0 (başlangıç biti); 0, 1, 0, 0, 0, 0, 1, 1 (0x43'ün ikili değeri) ve 0 (durdurma biti).

![](<../../.gitbook/assets/image (764).png>)

UART ile iletişim kurmak için donanım araçları:

* USB-serial adaptörü
* CP2102 veya PL2303 yongaları ile adaptörler
* Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi çok amaçlı araçlar

### UART Portlarını Tanımlama

UART'ın 4 portu vardır: **TX**(Gönder), **RX**(Al), **Vcc**(Gerilim) ve **GND**(Toprak). PCB üzerinde **`TX`** ve **`RX`** harfleri **yazılı** 4 port bulabilirsiniz. Ancak bir gösterge yoksa, bir **multimetre** veya **mantık analizörü** kullanarak kendiniz bulmanız gerekebilir.

**Multimetre** ile cihaz kapalıyken:

* **GND** pinini tanımlamak için **Devamlılık Testi** modunu kullanın, arka ucu toprağa yerleştirin ve kırmızı uçla test edin, multimetreden ses duyana kadar devam edin. PCB üzerinde birkaç GND pini bulunabilir, bu nedenle UART'a ait olanı bulmuş olabilirsiniz ya da olmayabilirsiniz.
* **VCC portunu** tanımlamak için, **DC gerilim modunu** ayarlayın ve 20 V gerilim ayarlayın. Siyah probu toprağa, kırmızı probu pin üzerine yerleştirin. Cihazı açın. Multimetre 3.3 V veya 5 V sabit bir gerilim ölçerse, Vcc pinini bulmuşsunuz demektir. Diğer gerilimler alırsanız, diğer portlarla tekrar deneyin.
* **TX** **portunu** tanımlamak için, **DC gerilim modunu** 20 V'a kadar ayarlayın, siyah probu toprağa, kırmızı probu pin üzerine yerleştirin ve cihazı açın. Gerilimin birkaç saniye dalgalandığını ve ardından Vcc değerinde sabitlendiğini bulursanız, muhtemelen TX portunu bulmuşsunuzdur. Bunun nedeni, açıldığında bazı hata ayıklama verileri göndermesidir.
* **RX portu**, diğer 3'e en yakın olanıdır, en düşük gerilim dalgalanmasına ve tüm UART pinleri arasında en düşük genel değere sahiptir.

TX ve RX portlarını karıştırabilirsiniz ve hiçbir şey olmaz, ancak GND ve VCC portlarını karıştırırsanız devreyi yakabilirsiniz.

Bazı hedef cihazlarda, üretici RX veya TX'yi veya her ikisini devre dışı bırakarak UART portunu devre dışı bırakmıştır. Bu durumda, devre kartındaki bağlantıları izlemek ve bazı çıkış noktaları bulmak faydalı olabilir. UART'ın tespit edilmediğini ve devrenin kesildiğini doğrulamak için güçlü bir ipucu, cihazın garantisini kontrol etmektir. Cihaz bazı garanti ile gönderildiyse, üretici bazı hata ayıklama arayüzleri (bu durumda, UART) bırakır ve bu nedenle UART'ı devre dışı bırakmış olmalı ve hata ayıklama sırasında tekrar bağlamalıdır. Bu çıkış pinleri lehimleme veya jumper kabloları ile bağlanabilir.

### UART Baud Hızını Tanımlama

Doğru baud hızını tanımlamanın en kolay yolu, **TX pininin çıkışına bakmak ve verileri okumaya çalışmaktır**. Aldığınız veriler okunabilir değilse, veriler okunabilir hale gelene kadar bir sonraki olası baud hızına geçin. Bunu yapmak için bir USB-serial adaptörü veya Bus Pirate gibi çok amaçlı bir cihaz kullanabilirsiniz, yardımcı bir betik ile birlikte, örneğin [baudrate.py](https://github.com/devttys0/baudrate/). En yaygın baud hızları 9600, 38400, 19200, 57600 ve 115200'dür.

{% hint style="danger" %}
Bu protokolde bir cihazın TX'ini diğerinin RX'ine bağlamanız gerektiğini unutmamak önemlidir!
{% endhint %}

## CP210X UART'dan TTY Adaptörü

CP210X Çipi, Seri İletişim için NodeMCU (esp8266 ile) gibi birçok prototipleme kartında kullanılır. Bu adaptörler nispeten ucuzdur ve hedefin UART arayüzüne bağlanmak için kullanılabilir. Cihazın 5 pini vardır: 5V, GND, RXD, TXD, 3.3V. Herhangi bir hasarı önlemek için hedefin desteklediği gerilimi bağladığınızdan emin olun. Son olarak, Adaptörün RXD pinini hedefin TXD'sine ve Adaptörün TXD pinini hedefin RXD'sine bağlayın.

Adaptör tespit edilmezse, CP210X sürücülerinin ana sistemde yüklü olduğundan emin olun. Adaptör tespit edildikten ve bağlandıktan sonra, picocom, minicom veya screen gibi araçlar kullanılabilir.

Linux/MacOS sistemlerine bağlı cihazları listelemek için:
```
ls /dev/
```
UART arayüzü ile temel etkileşim için aşağıdaki komutu kullanın:
```
picocom /dev/<adapter> --baud <baudrate>
```
Minicom için, bunu yapılandırmak için aşağıdaki komutu kullanın:
```
minicom -s
```
Ayarları `Serial port setup` seçeneğinde baudrate ve cihaz adı gibi yapılandırın.

Yapılandırmadan sonra, UART Konsolu'nu başlatmak için `minicom` komutunu kullanın.

## UART Via Arduino UNO R3 (Çıkarılabilir Atmel 328p Çip Kartları)

Eğer UART Serial to USB adaptörleri mevcut değilse, Arduino UNO R3 hızlı bir hack ile kullanılabilir. Arduino UNO R3 genellikle her yerde mevcut olduğundan, bu çok zaman kazandırabilir.

Arduino UNO R3'te, kartın kendisinde yerleşik bir USB to Serial adaptör bulunmaktadır. UART bağlantısını elde etmek için, Atmel 328p mikrodenetleyici çipini karttan çıkarın. Bu hack, Atmel 328p'nin kartta lehimlenmediği (SMD versiyonu kullanılır) Arduino UNO R3 varyantlarında çalışır. Arduino'nun RX pinini (Dijital Pin 0) UART Arayüzünün TX pinine ve Arduino'nun TX pinini (Dijital Pin 1) UART arayüzünün RX pinine bağlayın.

Son olarak, Serial Konsolu almak için Arduino IDE kullanmanız önerilir. Menüdeki `tools` bölümünde `Serial Console` seçeneğini seçin ve baud hızını UART arayüzüne göre ayarlayın.

## Bus Pirate

Bu senaryoda, programın tüm çıktısını Serial Monitor'a gönderen Arduino'nun UART iletişimini dinleyeceğiz.
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
## UART Konsolu ile Firmware Dökümü

UART Konsolu, çalışma ortamında temel firmware ile çalışmanın harika bir yolunu sağlar. Ancak, UART Konsolu erişimi yalnızca okunabilir olduğunda, birçok kısıtlama getirebilir. Birçok gömülü cihazda, firmware EEPROM'larda saklanır ve uçucu belleğe sahip işlemcilerde çalıştırılır. Bu nedenle, orijinal firmware üretim sırasında EEPROM'un içinde bulunduğundan, firmware yalnızca okunabilir olarak tutulur ve yeni dosyalar uçucu bellek nedeniyle kaybolur. Bu nedenle, gömülü firmware'lerle çalışırken firmware dökümü değerli bir çabadır.

Bunu yapmanın birçok yolu vardır ve SPI bölümü, çeşitli cihazlarla firmware'i doğrudan EEPROM'dan çıkarmak için yöntemleri kapsar. Ancak, fiziksel cihazlar ve harici etkileşimlerle firmware dökümünün riskli olabileceğinden, önce UART ile firmware dökümünü denemek önerilir.

UART Konsolu'ndan firmware dökümü, öncelikle bootloader'lara erişim sağlamayı gerektirir. Birçok popüler satıcı, Linux'u yüklemek için bootloader olarak uboot (Universal Bootloader) kullanır. Bu nedenle, uboot'a erişim sağlamak gereklidir.

Bootloader'a erişim sağlamak için, UART portunu bilgisayara bağlayın ve herhangi bir Seri Konsol aracını kullanın ve cihazın güç kaynağını bağlantısını kesin. Kurulum hazır olduğunda, Enter tuşuna basın ve basılı tutun. Son olarak, cihazın güç kaynağını bağlayın ve başlatmasına izin verin.

Bunu yapmak, uboot'un yüklenmesini kesintiye uğratacak ve bir menü sağlayacaktır. Uboot komutlarını anlamak ve bunları listelemek için yardım menüsünü kullanmak önerilir. Bu muhtemelen `help` komutudur. Farklı satıcılar farklı yapılandırmalar kullandığından, her birini ayrı ayrı anlamak gereklidir.

Genellikle, firmware dökümü için komut şudur:
```
md
```
hangi "memory dump" anlamına gelir. Bu, belleği (EEPROM İçeriği) ekrana dökecektir. Bellek dökümünü yakalamak için prosedüre başlamadan önce Seri Konsol çıktısını kaydetmek önerilir.

Son olarak, günlük dosyasından tüm gereksiz verileri çıkarın ve dosyayı `filename.rom` olarak saklayın ve içeriği çıkarmak için binwalk kullanın:
```
binwalk -e <filename.rom>
```
Bu, hex dosyasında bulunan imzalara göre EEPROM'dan olası içerikleri listeleyecektir.

Ancak, uboot'un kullanılıyor olsa bile her zaman kilidinin açık olmadığını belirtmek gerekir. Enter tuşu bir şey yapmıyorsa, Boşluk tuşu gibi farklı tuşları kontrol edin. Eğer bootloader kilitliyse ve kesintiye uğramıyorsa, bu yöntem işe yaramaz. Uboot'un cihaz için bootloader olup olmadığını kontrol etmek için, cihazın açılışı sırasında UART Konsolu'ndaki çıktıyı kontrol edin. Açılış sırasında uboot'u belirtebilir.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
