# Dosya/Veri Oyma ve Kurtarma Araçları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Oyma ve Kurtarma Araçları

Daha fazla araç için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Görüntülerden dosyaları çıkarmak için forensikte en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve dosyayı içe aktararak "gizli" dosyaları bulun. Autopsy, disk görüntüleri ve diğer türdeki görüntüleri desteklemek üzere oluşturulmuştur, ancak basit dosyaları desteklemez.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içerik bulmak için ikili dosyaları analiz etmek için bir araçtır. `apt` aracılığıyla yüklenebilir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk)'da bulunabilir.

**Kullanışlı komutlar**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Gizli dosyaları bulmak için başka yaygın bir araç **foremost**'tir. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` içinde bulabilirsiniz. Belirli dosyaları aramak istiyorsanız, onları yorum satırından çıkarın. Hiçbir şeyi yorum satırından çıkarmazsanız, foremost varsayılan olarak yapılandırılmış dosya türlerini arayacaktır.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, başka bir araçtır ve bir dosyanın içine gömülü olan dosyaları bulmak ve çıkarmak için kullanılabilir. Bu durumda, çıkarmak istediğiniz dosya türlerini belirtmek için yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) yorum satırlarını kaldırmanız gerekecektir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Bu araç Kali içinde gelir ancak burada da bulabilirsiniz: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Bu araç bir görüntüyü tarayabilir ve içindeki **pcap'leri çıkarabilir**, **ağ bilgilerini (URL'ler, alan adları, IP'ler, MAC'ler, e-postalar)** ve daha fazla **dosyayı** çıkarabilir. Yapmanız gereken tek şey:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

[PhotoRec](https://www.cgsecurity.org/wiki/TestDisk\_Download) bulunan bir araçtır.

GUI ve CLI sürümleriyle gelir. PhotoRec'in aramasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Kodu [buradan](https://code.google.com/archive/p/binvis/) ve [web sayfa aracını](https://binvis.io/#/) kontrol edin.

#### BinVis'in Özellikleri

* Görsel ve etkin **yapı görüntüleyici**
* Farklı odak noktaları için birden fazla çizim
* Bir örneğin bölümlerine odaklanma
* PE veya ELF yürütülebilir dosyalarda **dizileri ve kaynakları** görme
* Dosyalarda kriptoanaliz için **desenler** elde etme
* Paketleyici veya kodlayıcı algoritmaları **tespit etme**
* Desenlere göre **Steganografi** tanımlama
* **Görsel** ikili farklılaştırma

BinVis, siyah kutu senaryosunda **bilinmeyen bir hedefle tanışmak için harika bir başlangıç noktasıdır**.

## Özel Veri Kazıma Araçları

### FindAES

AES anahtarlarını arayarak anahtar programlarını arar. TrueCrypt ve BitLocker gibi kullanılan 128, 192 ve 256 bit anahtarları bulabilir.

İndirme bağlantısı [burada](https://sourceforge.net/projects/findaes/).

## Tamamlayıcı Araçlar

Resimleri terminalden görmek için [**viu** ](https://github.com/atanunq/viu)'yu kullanabilirsiniz.\
Bir pdf'i metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.
