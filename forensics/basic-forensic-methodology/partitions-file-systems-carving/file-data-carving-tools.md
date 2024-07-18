{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}


# Oyma araçları

## Autopsy

Görüntülerden dosyalar çıkarmak için forensikte en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve dosyayı içe aktarmak için kullanın ve "gizli" dosyaları bulun. Autopsy, disk görüntüleri ve diğer türdeki görüntüleri desteklemek üzere inşa edilmiştir, ancak basit dosyaları desteklemez.

## Binwalk <a id="binwalk"></a>

**Binwalk**, gömülü dosyaları ve verileri aramak için görüntüler ve ses dosyaları gibi ikili dosyaları arayan bir araçtır.
`apt` ile yüklenebilir, ancak [kaynak kodu](https://github.com/ReFirmLabs/binwalk) github'da bulunabilir.
**Kullanışlı komutlar**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Gizli dosyaları bulmak için başka yaygın bir araç **foremost**'tir. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` içinde bulabilirsiniz. Belirli dosyaları aramak istiyorsanız, onları yorum satırından çıkarın. Hiçbir şeyi yorum satırından çıkarmazsanız, foremost varsayılan olarak yapılandırılmış dosya türlerini arayacaktır.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**, dosya içine gömülü dosyaları bulmak ve çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmak istediğiniz dosya türlerini yapılandırma dosyasından \(_/etc/scalpel/scalpel.conf_\) yorum satırından çıkarmalısınız.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Bu araç Kali içinde gelir ancak buradan bulabilirsiniz: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Bu araç bir görüntüyü tarayabilir ve içindeki **pcap'leri**, **ağ bilgilerini (URL'ler, alan adları, IP'ler, MAC'ler, e-postaları)** ve daha fazla **dosyayı çıkaracaktır**. Yapmanız gereken tek şey:
```text
bulk_extractor memory.img -o out_folder
```
**Tüm bilgileri** inceleyin \(şifreler mi?\), **paketleri** analiz edin \(okuyun[ **Pcaps analizi**](../pcap-inspection/)\), **garip alanlar** arayın \(zararlı yazılımlarla ilişkili alanlar veya **var olmayan**\).

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) adresinde bulabilirsiniz.

GUI ve CLI sürümüyle gelir. PhotoRec'in aramasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Özel Veri Kazıma Araçları

## FindAES

AES anahtarlarını anahtar şemalarını arayarak bulur. TrueCrypt ve BitLocker tarafından kullanılan 128, 192 ve 256 bit anahtarları bulabilir.

[buradan indirin](https://sourceforge.net/projects/findaes/).

# Tamamlayıcı araçlar

Resimleri terminalden görmek için [**viu** ](https://github.com/atanunq/viu)'yu kullanabilirsiniz.
Bir pdf'i metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.
