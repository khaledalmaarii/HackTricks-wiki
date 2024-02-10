# Bölümler/Dosya Sistemleri/Kazıma

## Bölümler/Dosya Sistemleri/Kazıma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da** takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Bölümler

Bir sabit disk veya **SSD diski**, verileri fiziksel olarak ayırmak amacıyla farklı bölümler içerebilir.\
Bir diskin **minimum** birimi **sektördür** (genellikle 512B'den oluşur). Bu nedenle, her bölüm boyutu bu boyutun katı olmalıdır.

### MBR (Master Boot Record)

MBR, **önyükleme kodunun 446B'sinden sonra diskin ilk sektörüne** ayrılır. Bu sektör, PC'ye bir bölümün ne olduğunu ve nereden bağlanması gerektiğini belirtmek için önemlidir.\
En fazla **4 bölüm** (en fazla **sadece 1** aktif/**önyüklenebilir**) izin verir. Ancak, daha fazla bölüm gerekiyorsa **genişletilmiş bölümler** kullanabilirsiniz. Bu ilk sektörün son baytı, önyükleme kaydı imzası olan **0x55AA**'dır. Yalnızca bir bölüm etkin olarak işaretlenebilir.\
MBR, **maksimum 2.2TB**'a izin verir.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

MBR'nin **440 ile 443** baytı arasında **Windows Disk İmzası** bulunabilir (Windows kullanılıyorsa). Sabit diskin mantıksal sürücü harfi, Windows Disk İmzasına bağlıdır. Bu imzanın değiştirilmesi, Windows'un önyüklenmesini engelleyebilir (araç: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Biçim**

| Offset      | Uzunluk    | Öğe                 |
| ----------- | ---------- | -------------------- |
| 0 (0x00)    | 446(0x1BE) | Önyükleme kodu       |
| 446 (0x1BE) | 16 (0x10)  | İlk Bölüm            |
| 462 (0x1CE) | 16 (0x10)  | İkinci Bölüm         |
| 478 (0x1DE) | 16 (0x10)  | Üçüncü Bölüm         |
| 494 (0x1EE) | 16 (0x10)  | Dördüncü Bölüm       |
| 510 (0x1FE) | 2 (0x2)    | İmza 0x55 0xAA       |

**Bölüm Kayıt Biçimi**

| Offset    | Uzunluk   | Öğe                                                     |
| --------- | --------- | -------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01)  | Etkin bayrak (0x80 = önyüklenebilir)                     |
| 1 (0x01)  | 1 (0x01)  | Başlangıç başlığı                                       |
| 2 (0x02)  | 1 (0x01)  | Başlangıç sektörü (bitler 0-5); silindirin üst bitleri (6-7) |
| 3 (0x03)  | 1 (0x01)  | Başlangıç silindiri en düşük 8 bit                       |
| 4 (0x04)  | 1 (0x01)  | Bölüm türü kodu (0x83 = Linux)                           |
| 5 (0x05)  | 1 (0x01)  | Bitiş başlığı                                         |
| 6 (0x06)  | 1 (0x01)  | Bitiş sektörü (bitler 0-5); silindirin üst bitleri (6-7) |
| 7 (0x07)  | 1 (0x01)  | Bitiş silindiri en düşük 8 bit                          |
| 8 (0x08)  | 4 (0x04)  | Bölümden önceki sektörler (little endian)                |
| 12 (0x0C) | 4 (0x04)  | Bölümdeki sektörler                                    |

Linux'ta bir MBR'yi bağlamak için önce başlangıç ofsetini almanız gerekir (`fdisk` ve `p` komutunu kullanabilirsiniz)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

Ve ardından aşağıdaki kodu kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Mantıksal blok adresleme)**

**Mantıksal blok adresleme** (**LBA**), genellikle sabit disk sürücüleri gibi ikincil depolama sistemlerinde saklanan veri bloklarının konumunu belirlemek için kullanılan yaygın bir şemadır. LBA, özellikle basit bir lineer adresleme şemasıdır; bloklar, bir tamsayı diziniyle belirlenir, ilk blok LBA 0, ikinci blok LBA 1 ve böyle devam eder.

### GPT (GUID Bölüm Tablosu)

GUID Bölüm Tablosu olarak bilinen GPT, MBR (Master Boot Record) ile karşılaştırıldığında gelişmiş yetenekleri nedeniyle tercih edilir. Bölümler için **benzersiz bir tanımlayıcıya** sahip olan GPT, birkaç yönden öne çıkar:

- **Konum ve Boyut**: Hem GPT hem de MBR, **sektör 0**'dan başlar. Ancak GPT, MBR'nin 32 bitine karşılık gelen **64 bit** üzerinde çalışır.
- **Bölüm Sınırları**: GPT, Windows sistemlerinde **128 bölümü** destekler ve **9.4ZB** veriye kadar yer sağlar.
- **Bölüm İsimleri**: Bölmelere 36 Unicode karakterle isim verme yeteneği sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Yedeklilik**: MBR'nin aksine, GPT bölümleme ve önyükleme verilerini tek bir yerde sınırlamaz. Bu veriyi diskin her yerine kopyalar, veri bütünlüğünü ve dayanıklılığını artırır.
- **Döngüsel Redundans Kontrolü (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulması aktif olarak izlenir ve tespit edildiğinde, GPT bozulmuş veriyi başka bir disk konumundan kurtarmaya çalışır.

**Koruyucu MBR (LBA0)**:

- GPT, koruyucu bir MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik, eski MBR tabanlı araçların yanlışlıkla GPT disklerini üzerine yazmasını önlemek için eski MBR alanında bulunur ve böylece GPT biçimli disklerdeki veri bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table)

BIOS hizmetleri aracılığıyla **GPT tabanlı önyükleme**yi destekleyen işletim sistemlerinde, ilk sektör aynı zamanda **önyükleyici** kodunun ilk aşamasını depolamak için kullanılabilir, ancak **değiştirilerek** GPT **bölümlerini** tanımak üzere. MBR'deki önyükleyici, 512 bayt sektör boyutunu varsaymamalıdır.

**Bölüm tablosu başlığı (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Bölüm tablosu başlığı, diske kullanılabilir blokları tanımlar. Ayrıca, bölüm tablosunu oluşturan bölüm girişlerinin sayısını ve boyutunu tanımlar (tablodaki 80 ve 84 ofsetler).

| Ofset    | Uzunluk  | İçerik                                                                                                                                                                          |
| -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00) | 8 bayt   | İmza ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya küçük uçlu makinelerde 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)) |
| 8 (0x08) | 4 bayt   | UEFI 2.8 için Revizyon 1.0 (00h 00h 01h 00h)                                                                                                                                     |
| 12 (0x0C)| 4 bayt   | Küçük uçlu başlık boyutu (genellikle 5Ch 00h 00h 00h veya 92 bayt)                                                                                                                |
| 16 (0x10)| 4 bayt   | Başlık için [CRC32](https://en.wikipedia.org/wiki/CRC32) (ofset +0'dan başlık boyutuna kadar) küçük uçlu, bu alan hesaplama sırasında sıfırlanır                                |
| 20 (0x14)| 4 bayt   | Rezerve edilmiş; sıfır olmalı                                                                                                                                                   |
| 24 (0x18)| 8 bayt   | Geçerli LBA (bu başlık kopyasının konumu)                                                                                                                                       |
| 32 (0x20)| 8 bayt   | Yedek LBA (diğer başlık kopyasının konumu)                                                                                                                                      |
| 40 (0x28)| 8 bayt   | Bölümler için ilk kullanılabilir LBA (birincil bölüm tablosu son LBA + 1)                                                                                                         |
| 48 (0x30)| 8 bayt   | Son kullanılabilir LBA (ikincil bölüm tablosu ilk LBA - 1)                                                                                                                       |
| 56 (0x38)| 16 bayt  | Karışık uçlu disk GUID'i                                                                                                                                                        |
| 72 (0x48)| 8 bayt   | Bölüm girişlerinin bir dizisinin başlangıç LBA'sı (her zaman birincil kopyada 2)                                                                                                 |
| 80 (0x50)| 4 bayt   | Dizideki bölüm girişlerinin sayısı                                                                                                                                              |
| 84 (0x54)| 4 bayt   | Tek bir bölüm girişinin boyutu (genellikle 80h veya 128)                                                                                                                         |
| 88 (0x58)| 4 bayt   | Küçük uçlu bölüm girişleri dizisinin CRC32'i                                                                                                                                    |
| 92 (0x5C)| \*       | Geri kalan blok için sıfır olması gereken rezerve edilmiş alan (512 bayt sektör boyutu için 420 bayt; ancak daha büyük sektör boyutlarıyla daha fazla olabilir)                   |

**Bölüm girişleri (LBA 2–33)**

| GUID bölüm girişi formatı |          |                                                                                                                   |
| ------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Ofset                    | Uzunluk  | İçerik                                                                                                            |
| 0 (0x00)                 | 16 bayt  | [Bölüm türü GUID'si](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (karışık uçlu)    |
| 16 (0x10)                | 16 bayt  | Benzersiz bölüm GUID'i (karışık uçlu)                                                                              |
| 32 (0x20)                | 8 bayt   | İlk LBA ([küçük uçlu](https://en.wikipedia.org/wiki/Little\_endian))                                               |
| 40 (0x28)                | 8 bayt   | Son LBA (dahil, genellikle tek sayı)                                                                               |
| 48 (0x30)                | 8 bayt   | Öznitelik bayrakları (örneğin, 60. bit salt okunur olarak belirtilir)                                               |
| 56 (0x38)                | 72 bayt  | Bölüm adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kod birimleri)                                      |

**Bölüm Tipleri**

![](<../../../.gitbook/assets/image (492).png>)

Daha fazla bölüm türü için [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table) adresine bakın.

### İnceleme

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile adli bilişim imajını bağladıktan sonra, Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**'ı** kullanarak ilk sektörü inceleyebilirsiniz. Aşağıdaki görüntüde, **MBR**'nin **0. sektörde** tespit edildiği ve yorumlandığı görülmektedir:

![](<../../../.gitbook/assets/image (494).png>)

Eğer bir **MBR yerine GPT tablosu** olsaydı, **1. sektörde** _EFI PART_ imzasının görünmesi gerekmektedir (önceki görüntüde boş olan yer).
## Dosya Sistemleri

### Windows dosya sistemleri listesi

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (Dosya Tahsis Tablosu)** dosya sistemi, temel bileşeni olan dosya tahsis tablosu etrafında tasarlanmıştır ve birimlerin başında yer alır. Bu sistem, veri bütünlüğünü korumak için tablonun **iki kopyasını** tutarak verileri korur. Tablo, kök klasörle birlikte, sistem başlatma süreci için **sabit bir konumda** olmalıdır.

Dosya sisteminin temel depolama birimi, genellikle birden çok sektörden oluşan bir **küme** olan 512B'dir. FAT, sürümler aracılığıyla evrim geçirmiştir:

- **FAT12**, 12 bitlik küme adreslerini destekler ve 4078 küme (UNIX ile birlikte 4084) işler.
- **FAT16**, 16 bitlik adreslere geçerek, 65.517 küme kadar yer sağlar.
- **FAT32**, 32 bitlik adreslerle daha da ilerleyerek, bir birimde etkileyici 268.435.456 küme kullanımına izin verir.

FAT sürümleri arasındaki önemli bir kısıtlama, dosya boyutu depolaması için kullanılan 32 bitlik alan tarafından uygulanan **4GB maksimum dosya boyutudur**.

Özellikle FAT12 ve FAT16 için kök dizininin temel bileşenleri şunlardır:

- **Dosya/Klasör Adı** (en fazla 8 karakter)
- **Öznitelikler**
- **Oluşturma, Değiştirme ve Son Erişim Tarihleri**
- **FAT Tablosu Adresi** (dosyanın başlangıç kümesini belirtir)
- **Dosya Boyutu**

### EXT

**Ext2**, önyükleme bölümü gibi **günlük tutmayan** bölümler için en yaygın dosya sistemidir. **Ext3/4** ise **günlük tutan** ve genellikle **diğer bölümler** için kullanılır.

## **Meta Veri**

Bazı dosyalar meta veri içerir. Bu bilgiler, dosyanın içeriği hakkında analist için ilginç olabilecek bilgilerdir çünkü dosya türüne bağlı olarak başlık, kullanılan MS Office sürümü, yazar, oluşturma ve son değiştirme tarihleri, kamera modeli, GPS koordinatları, görüntü bilgileri gibi bilgiler içerebilir.

Dosyanın meta verilerini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Silinmiş Dosyaların Kurtarılması**

### Kaydedilen Silinmiş Dosyalar

Daha önce görüldüğü gibi, bir dosya "silindiğinde" hala kaydedildiği birkaç yer vardır. Bu genellikle bir dosyanın bir dosya sisteminden silinmesiyle ilgili kayıtların sadece silindiğini, ancak verilerin dokunulmadığını gösterir. Ardından, dosyaların kayıtlarını (örneğin MFT) incelemek ve silinmiş dosyaları bulmak mümkündür.

Ayrıca, işletim sistemi genellikle dosya sistemine yapılan değişiklikler ve yedeklemeler hakkında birçok bilgi kaydeder, bu nedenle dosyayı veya mümkün olduğunca çok bilgiyi kurtarmak için bunları kullanmaya çalışmak mümkündür.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Dosya Kesme (Carving)**

**Dosya kesme (file carving)**, veri yığını içinde dosyaları bulmaya çalışan bir tekniktir. Bu tür araçların çalışma şekli genellikle 3 ana yoldan oluşur: **Dosya türü başlık ve dipnotlarına dayalı olarak**, dosya türü **yapılarına** dayalı olarak ve **içeriğe** dayalı olarak.

Bu teknik, **parçalanmış dosyaları kurtarmak için çalışmaz**. Bir dosya **bitişik sektörlerde depolanmıyorsa**, bu teknik onu veya en azından bir kısmını bulamaz.

Dosya Kesme için arama yapmak istediğiniz dosya türlerini belirterek birçok araç kullanabilirsiniz.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Veri Akışı **K**esme (Carving)

Veri Akışı Kesme, Dosya Kesme ile benzerdir, ancak **tamamlanmış dosyalar yerine ilginç parçaların** aranmasını sağlar.\
Örneğin, kaydedilen URL'leri içeren tam bir dosya aramak yerine, bu teknik URL'leri arar.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Güvenli Silme

Açıkçası, dosyaların ve onlarla ilgili kayıtların **"güvenli bir şekilde" silinmesi mümkündür**. Örneğin, bir dosyanın içeriğini birkaç kez gereksiz veriyle üzerine yazmak ve ardından dosya hakkındaki **$MFT** ve **$LOGFILE** kayıtlarını **kaldırmak** ve **Gölge Kopyalarını** silmek mümkündür.\
Bu işlemi gerçekleştirseniz bile, dosyanın varlığının hala kaydedildiği **diğer bölümler olabileceğini** fark edebilirsiniz ve bu, adli bilişim uzmanının görevinin bir parçasıdır.

## Kaynaklar

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Sertifikalı Dijital Adli Bilişim Windows**

<details>

<summary><strong>AWS hackleme yeteneklerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi paylaşarak PR göndererek [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
