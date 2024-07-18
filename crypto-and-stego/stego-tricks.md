# Stego Numaraları

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking numaralarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

**Try Hard Güvenlik Grubu**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **Dosyalardan Veri Çıkarma**

### **Binwalk**

Gömülü gizli dosyaları ve verileri aramak için bir araç. `apt` aracılığıyla yüklenir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk)'da bulunabilir.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Önemli**

Dosyaları başlık ve altbilgilerine göre kurtarır, png görüntüleri için kullanışlıdır. Kaynağı [GitHub](https://github.com/korczis/foremost) üzerinden `apt` ile yüklenir.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Dosya meta verilerini görüntülemeye yardımcı olur, [burada](https://www.sno.phy.queensu.ca/~phil/exiftool/) mevcuttur.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Exiftool'a benzer şekilde, metaveri görüntüleme için kullanılır. `apt` üzerinden yüklenebilir, kaynak kodu [GitHub](https://github.com/Exiv2/exiv2) üzerinde bulunabilir ve resmi websitesi [burada](http://www.exiv2.org/) yer almaktadır.
```bash
exiv2 file # Shows the metadata
```
### **Dosya**

Uğraştığınız dosya türünü belirleyin.

### **Dizgeler**

Dosyalardan okunabilir dizgeleri çıkarmak için çeşitli kodlama ayarlarını kullanarak çıktıyı filtrelemek.
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

Çalışması değiştirilmiş bir dosyayı çevrimiçi bulunan orijinal sürümüyle karşılaştırmak için kullanışlıdır.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Metinde Gizli Verileri Çıkarma**

### **Boşluklardaki Gizli Veriler**

Görünüşte boş alanlardaki görünmez karakterler bilgi saklayabilir. Bu verileri çıkarmak için [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) adresini ziyaret edin.

## **Görüntülerden Veri Çıkarma**

### **GrafikMagick ile Görüntü Detaylarını Tanımlama**

[GraphicMagick](https://imagemagick.org/script/download.php), görüntü dosya türlerini belirlemek ve olası bozulmaları tanımlamak için kullanılır. Bir görüntüyü incelemek için aşağıdaki komutu çalıştırın:
```bash
./magick identify -verbose stego.jpg
```
Hasar görmüş bir resim üzerinde tamir denemek için, bir meta veri yorumu eklemek yardımcı olabilir:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Veri Gizleme İçin Steghide**

Steghide, `JPEG, BMP, WAV ve AU` dosyaları içine veri gizlemeyi kolaylaştırır, şifreli veri gömmeyi ve çıkarmayı sağlar. Kurulumu `apt` kullanarak basittir ve [kaynak kodu GitHub'da mevcuttur](https://github.com/StefanoDeVuono/steghide).

**Komutlar:**

* `steghide info dosya` dosyanın gizli veri içerip içermediğini ortaya çıkarır.
* `steghide extract -sf dosya [--passphrase şifre]` gizli veriyi çıkarır, şifre isteğe bağlıdır.

Web tabanlı çıkarma için [bu web sitesini](https://futureboy.us/stegano/decinput.html) ziyaret edin.

**Stegcracker ile Bruteforce Saldırısı:**

* Steghide üzerinde şifre kırma denemeleri yapmak için [stegcracker](https://github.com/Paradoxis/StegCracker.git) şu şekilde kullanılır:
```bash
stegcracker <file> [<wordlist>]
```
### **PNG ve BMP Dosyaları için zsteg**

zsteg, PNG ve BMP dosyalarındaki gizli verileri ortaya çıkarmak için uzmanlaşmıştır. Kurulum `gem install zsteg` komutuyla yapılır, [GitHub'daki kaynağına](https://github.com/zed-0xff/zsteg) ulaşılabilir.

**Komutlar:**

* `zsteg -a dosya` bir dosya üzerinde tüm tespit yöntemlerini uygular.
* `zsteg -E dosya` veri çıkarma için bir yük belirtir.

### **StegoVeritas ve Stegsolve**

**stegoVeritas**, metaverileri kontrol eder, görüntü dönüşümleri yapar ve diğer özellikler arasında LSB brute forcing uygular. Tüm seçeneklerin tam listesi için `stegoveritas.py -h` kullanın ve tüm kontrolleri gerçekleştirmek için `stegoveritas.py stego.jpg` komutunu kullanın.

**Stegsolve**, gizli metinleri veya mesajları ortaya çıkarmak için çeşitli renk filtreleri uygular. [GitHub'da](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) bulunabilir.

### **Gizli İçerik Tespiti için FFT**

Hızlı Fourier Dönüşümü (FFT) teknikleri, görüntülerde gizli içeriği ortaya çıkarabilir. Faydalı kaynaklar şunları içerir:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [GitHub'da FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **Ses ve Görüntü Dosyaları için Stegpy**

Stegpy, bilgi gömme işlemine izin verir ve PNG, BMP, GIF, WebP ve WAV gibi formatları destekler. [GitHub'da](https://github.com/dhsdshdhk/stegpy) bulunabilir.

### **PNG Dosyası Analizi için Pngcheck**

PNG dosyalarını analiz etmek veya doğrulamak için kullanılabilir.
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Görüntü Analizi için Ek Araçlar**

Daha fazla keşif için şu adresleri ziyaret etmeyi düşünün:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Görüntü Hata Düzeyi Analizi](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Ses Dosyalarından Veri Çıkarma**

**Ses steganografisi**, bilgileri ses dosyalarının içine gizlemek için benzersiz bir yöntem sunar. Farklı araçlar, gizli içeriği gömmek veya almak için kullanılır.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide, verileri JPEG, BMP, WAV ve AU dosyalarına gizlemek için tasarlanmış çok yönlü bir araçtır. Detaylı talimatlar [stego tricks belgelerinde](stego-tricks.md#steghide) sağlanmaktadır.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Bu araç, PNG, BMP, GIF, WebP ve WAV gibi çeşitli formatlarla uyumludur. Daha fazla bilgi için [Stegpy bölümüne](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) başvurun.

### **ffmpeg**

ffmpeg, ses dosyalarının bütünlüğünü değerlendirmek için hayati öneme sahiptir, detaylı bilgileri vurgular ve herhangi bir uyumsuzluğu belirler.
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

Deepsound, AES-256 kullanarak ses dosyaları içinde bilgi şifreleme ve tespit etmeye olanak tanır. [Resmi sayfadan](http://jpinsoft.net/deepsound/download.aspx) indirilebilir.

### **Sonic Visualizer**

Ses dosyalarının görsel ve analitik incelemesi için paha biçilmez bir araç olan Sonic Visualizer, diğer yöntemlerle algılanamayan gizli unsurları ortaya çıkarabilir. Daha fazlası için [resmi web sitesini](https://www.sonicvisualiser.org/) ziyaret edin.

### **DTMF Tones - Dial Tones**

Ses dosyalarındaki DTMF tonlarını tespit etmek, [bu DTMF dedektörü](https://unframework.github.io/dtmf-detect/) ve [DialABC](http://dialabc.com/sound/detect/index.html) gibi çevrimiçi araçlar aracılığıyla başarıyla gerçekleştirilebilir.

## **Diğer Teknikler**

### **Binary Length SQRT - QR Code**

Bir tam sayıya karesel olarak eşit olan ikili veriler bir QR kodu temsil edebilir. Bunun kontrolü için bu kısa kod parçasını kullanın:
```python
import math
math.sqrt(2500) #50
```
### **Braille Çevirisi**

Braille çevirisi için [Branah Braille Çevirmeni](https://www.branah.com/braille-translator) mükemmel bir kaynaktır.

## **Referanslar**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşarak PR'ler göndererek [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
