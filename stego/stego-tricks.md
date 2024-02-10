# Stego Hileleri

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zayıflıkları bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Dosyalardan Veri Çıkarma**

### **Binwalk**
Gömülü gizli dosya ve verileri aramak için bir araç. `apt` aracılığıyla yüklenir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk)'da mevcuttur.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Başlık ve altbilgilere dayanarak dosyaları kurtarır, png görüntüleri için kullanışlıdır. Kaynağı [GitHub](https://github.com/korczis/foremost) üzerinden `apt` ile kurulur.
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Dosya meta verilerini görüntülemeye yardımcı olur, [burada](https://www.sno.phy.queensu.ca/~phil/exiftool/) bulunabilir.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Exiftool'a benzer şekilde, meta verileri görüntülemek için kullanılır. `apt` ile kurulabilir, kaynak kodu [GitHub](https://github.com/Exiv2/exiv2)'da bulunur ve [resmi web sitesi](http://www.exiv2.org/) vardır.
```bash
exiv2 file # Shows the metadata
```
### **Dosya**
Uğraştığınız dosyanın türünü belirleyin.

### **Dizeler**
Dosyalardan okunabilir dizeleri çıkarır, çıktıyı filtrelemek için çeşitli kodlama ayarları kullanır.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Karşılaştırma (cmp)**
Bir dosyanın değiştirilmiş bir sürümünü çevrimiçi bulunan orijinal sürümüyle karşılaştırmak için kullanışlıdır.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Metinde Gizli Verileri Çıkarma**

### **Boşluklardaki Gizli Veriler**
Görünüşte boş olan boşluklarda görünmez karakterler bilgi saklayabilir. Bu verileri çıkarmak için [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) adresini ziyaret edin.



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Görüntülerden Veri Çıkarma**

### **GrafikMagick ile Görüntü Ayrıntılarını Belirleme**

[GraphicMagick](https://imagemagick.org/script/download.php), görüntü dosyası türlerini belirlemek ve potansiyel bozulmayı tespit etmek için kullanılır. Bir görüntüyü incelemek için aşağıdaki komutu çalıştırın:
```bash
./magick identify -verbose stego.jpg
```
Bir hasarlı görüntüyü onarmak için, bir meta veri yorumu eklemek yardımcı olabilir:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Veri Gizleme için Steghide**

Steghide, `JPEG, BMP, WAV ve AU` dosyaları içine veri gizlemeyi kolaylaştırır ve şifreli verileri gömmeyi ve çıkarmayı sağlar. Kurulumu `apt` kullanarak kolaydır ve [kaynak kodu GitHub'da mevcuttur](https://github.com/StefanoDeVuono/steghide).

**Komutlar:**
- `steghide info dosya` dosyanın gizli veri içerip içermediğini ortaya çıkarır.
- `steghide extract -sf dosya [--passphrase şifre]` gizli veriyi çıkarır, şifre isteğe bağlıdır.

Web tabanlı çıkarma için [bu web sitesini](https://futureboy.us/stegano/decinput.html) ziyaret edin.

**Stegcracker ile Bruteforce Saldırısı:**
- Steghide üzerinde şifre kırma denemeleri yapmak için [stegcracker](https://github.com/Paradoxis/StegCracker.git) şu şekilde kullanılır:
```bash
stegcracker <file> [<wordlist>]
```
### **PNG ve BMP Dosyaları için zsteg**

zsteg, PNG ve BMP dosyalarında gizli verileri ortaya çıkarmak için özelleşmiştir. Kurulum, `gem install zsteg` komutuyla yapılır ve [GitHub'da](https://github.com/zed-0xff/zsteg) kaynak kodu bulunur.

**Komutlar:**
- `zsteg -a dosya` bir dosya üzerinde tüm tespit yöntemlerini uygular.
- `zsteg -E dosya` veri çıkarma için bir payload belirtir.

### **StegoVeritas ve Stegsolve**

**stegoVeritas**, meta verileri kontrol eder, görüntü dönüşümleri yapar ve LSB brute forcing gibi diğer özellikleri uygular. Tüm seçeneklerin bir listesini görmek için `stegoveritas.py -h` komutunu kullanın ve tüm kontrolleri gerçekleştirmek için `stegoveritas.py stego.jpg` komutunu kullanın.

**Stegsolve**, gizli metinleri veya mesajları ortaya çıkarmak için çeşitli renk filtreleri uygular. [GitHub'da](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) bulunur.

### **Gizli İçerik Tespiti için FFT**

Hızlı Fourier Dönüşümü (FFT) teknikleri, görüntülerde gizli içeriği ortaya çıkarabilir. Faydalı kaynaklar şunlardır:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [GitHub'da FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **Ses ve Görüntü Dosyaları için Stegpy**

Stegpy, PNG, BMP, GIF, WebP ve WAV gibi formatları destekleyen görüntü ve ses dosyalarına bilgi gömmeyi sağlar. [GitHub'da](https://github.com/dhsdshdhk/stegpy) bulunur.

### **PNG Dosya Analizi için Pngcheck**

PNG dosyalarını analiz etmek veya doğrulamak için kullanılabilir:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Görüntü Analizi için Ek Araçlar**

Daha fazla keşif için şu adreslere göz atmayı düşünebilirsiniz:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Seslerden Veri Çıkarma**

**Ses steganografi**, bilgiyi ses dosyalarının içine gizlemek için benzersiz bir yöntem sunar. Gizli içeriği gömmek veya almak için farklı araçlar kullanılır.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide, JPEG, BMP, WAV ve AU dosyalarında veri gizlemek için tasarlanmış çok yönlü bir araçtır. Detaylı talimatlar [stego tricks belgelerinde](stego-tricks.md#steghide) sağlanmaktadır.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Bu araç, PNG, BMP, GIF, WebP ve WAV gibi çeşitli formatlarla uyumludur. Daha fazla bilgi için [Stegpy bölümüne](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) başvurun.

### **ffmpeg**
ffmpeg, ses dosyalarının bütünlüğünü değerlendirmek, ayrıntılı bilgi sağlamak ve herhangi bir uyumsuzluğu belirlemek için önemlidir.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg, en az anlamlı bit stratejisini kullanarak WAV dosyaları içinde veri gizleme ve çıkarma konusunda başarılıdır. [GitHub](https://github.com/ragibson/Steganography#WavSteg) üzerinden erişilebilir. Komutlar şunları içerir:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound, AES-256 kullanarak ses dosyaları içindeki bilgilerin şifrelenmesine ve tespit edilmesine olanak tanır. [Resmi sayfadan](http://jpinsoft.net/deepsound/download.aspx) indirilebilir.

### **Sonic Visualizer**
Ses dosyalarının görsel ve analitik incelemesi için çok değerli bir araç olan Sonic Visualizer, diğer yöntemlerle tespit edilemeyen gizli unsurları ortaya çıkarabilir. Daha fazlası için [resmi web sitesini](https://www.sonicvisualiser.org/) ziyaret edin.

### **DTMF Tones - Dial Tones**
Ses dosyalarında DTMF tonlarının tespiti, [bu DTMF tespit aracı](https://unframework.github.io/dtmf-detect/) ve [DialABC](http://dialabc.com/sound/detect/index.html) gibi çevrimiçi araçlar aracılığıyla gerçekleştirilebilir.

## **Diğer Teknikler**

### **Binary Length SQRT - QR Code**
Tam bir sayıya kare olan ikili veriler bir QR kodunu temsil edebilir. Kontrol etmek için bu kod parçasını kullanın:
```python
import math
math.sqrt(2500) #50
```
Binary to image dönüşümü için [dcode](https://www.dcode.fr/binary-image)'u kontrol edin. QR kodlarını okumak için [bu çevrimiçi barkod okuyucuyu](https://online-barcode-reader.inliteresearch.com/) kullanın.

### **Braille Çevirisi**
Braille çevirisi için [Branah Braille Çevirici](https://www.branah.com/braille-translator) mükemmel bir kaynaktır.

## **Referanslar**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek **hacking hilelerinizi paylaşın**.

</details>
