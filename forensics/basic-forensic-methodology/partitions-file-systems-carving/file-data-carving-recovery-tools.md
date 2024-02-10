<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek **katkıda bulunun**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun ve daha hızlı düzeltebilin. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Parçalama ve Kurtarma Araçları

Daha fazla araç için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Görüntülerden dosyaları çıkarmak için forensikte en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve dosyayı içe alması için Autopsy'yi kullanın ve "gizli" dosyaları bulun. Autopsy, disk görüntüleri ve diğer türdeki görüntüleri desteklemek üzere tasarlanmıştır, ancak basit dosyaları desteklemez.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içeriği bulmak için ikili dosyaları analiz etmek için bir araçtır. `apt` aracılığıyla kurulabilir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk)'da bulunur.

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

**Scalpel**, dosyanın içine gömülü olan dosyaları bulmak ve çıkarmak için kullanılan başka bir araçtır. Bu durumda, çıkarmak istediğiniz dosya türlerini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) açıklama satırından çıkarmalısınız.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Bu araç, Kali içinde bulunur, ancak burada bulabilirsiniz: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Bu araç bir görüntüyü tarayabilir ve içindeki **pcap'leri**, **ağ bilgilerini (URL'ler, alan adları, IP'ler, MAC'ler, e-postalar)** ve daha fazla **dosyayı** çıkarır. Sadece şunu yapmanız yeterlidir:
```
bulk_extractor memory.img -o out_folder
```
**Tüm bilgileri** inceleyin (şifreler?), **paketleri** analiz edin ([**Pcaps analizi**](../pcap-inspection/) okuyun), **anormal alanlar** arayın (kötü amaçlı yazılımla ilişkili veya var olmayan alanlar).

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download) adresinde bulabilirsiniz.

GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in arama yapmasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Kodu [buradan](https://code.google.com/archive/p/binvis/) ve web sayfası aracını [buradan](https://binvis.io/#/) kontrol edin.

### BinVis'in Özellikleri

* Görsel ve etkin **yapı görüntüleyici**
* Farklı odak noktaları için birden fazla grafik
* Bir örneğin bölümlerine odaklanma
* PE veya ELF yürütülebilirlerindeki dize ve kaynakları görme
* Dosyalarda kriptoanaliz için **desenler** elde etme
* Paker veya kodlayıcı algoritmalarını **tespit etme**
* Desenlere göre Steganografiyi **tanımlama**
* **Görsel** ikili farklılaştırma

BinVis, bir siyah kutu senaryosunda bilinmeyen bir hedefle tanışmak için harika bir **başlangıç noktasıdır**.

# Özel Veri Kurtarma Araçları

## FindAES

TrueCrypt ve BitLocker tarafından kullanılan 128, 192 ve 256 bit anahtarları bulmak için anahtar programlarını arayarak AES anahtarlarını arar.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

# Tamamlayıcı araçlar

Görüntüleri terminalden görmek için [**viu**](https://github.com/atanunq/viu) kullanabilirsiniz.\
Bir PDF'i metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da** takip edin.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
