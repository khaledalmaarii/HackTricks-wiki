<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Kesme araçları

## Autopsy

Görüntülerden dosyaları çıkarmak için forensikte en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve dosyayı içe aktarmak için kullanın. Autopsy, disk görüntüleri ve diğer türdeki görüntüleri desteklemek üzere tasarlanmıştır, ancak basit dosyaları desteklemez.

## Binwalk <a id="binwalk"></a>

**Binwalk**, gömülü dosyaları ve verileri aramak için bir araçtır. Resimler ve ses dosyaları gibi ikili dosyaları aramak için kullanılabilir.
`apt` ile kurulabilir, ancak [kaynak kodu](https://github.com/ReFirmLabs/binwalk) github'da bulunabilir.
**Kullanışlı komutlar**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Gizli dosyaları bulmak için yaygın bir araç olan **foremost** kullanılabilir. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` konumunda bulabilirsiniz. Belirli dosyaları aramak istiyorsanız, onları yorum satırından çıkarmanız yeterlidir. Hiçbir şeyi yorum satırından çıkarmazsanız, foremost varsayılan olarak yapılandırılmış dosya türlerini arayacaktır.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**, başka bir araçtır ve bir dosyanın içine gömülü olan dosyaları bulmak ve çıkarmak için kullanılabilir. Bu durumda, çıkarmak istediğiniz dosya türlerini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) açıklama satırını kaldırmanız gerekecektir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Bu araç, Kali içinde bulunur, ancak burada bulabilirsiniz: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Bu araç bir görüntüyü tarayabilir ve içindeki **pcap'leri**, **ağ bilgilerini (URL'ler, alan adları, IP'ler, MAC'ler, e-postalar)** ve daha fazla **dosyayı çıkarır**. Sadece şunu yapmanız yeterlidir:
```text
bulk_extractor memory.img -o out_folder
```
**Tüm bilgiler** arasında gezinin \(şifreler?\), **paketleri** analiz edin \(Pcaps analizini okuyun\), **garip alan adları** arayın \(kötü amaçlı yazılımlarla ilişkili veya **var olmayan** alan adları\).

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) adresinde bulabilirsiniz.

GUI ve CLI sürümüyle birlikte gelir. PhotoRec'in arama yapmasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Özel Veri Kesme Araçları

## FindAES

Anahtar programlarını arayarak AES anahtarlarını bulur. TrueCrypt ve BitLocker tarafından kullanılan 128, 192 ve 256 bit anahtarları bulabilir.

[buradan](https://sourceforge.net/projects/findaes/) indirin.

# Tamamlayıcı araçlar

Görüntüleri terminalde görmek için [**viu**](https://github.com/atanunq/viu) kullanabilirsiniz.
Bir pdf'i metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>
