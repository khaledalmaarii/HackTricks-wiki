# Bölümler/Dosya Sistemleri/Kesme

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın(https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin(https://peass.creator-spring.com)
* [**PEASS Ailesi**]'ni keşfedin(https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in koleksiyonu
* 💬 [**Discord grubuna**] katılın(https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] veya bizi **Twitter** 🐦 [**@hacktricks\_live**]'da takip edin(https://twitter.com/hacktricks\_live)**.**
* Hacking püf noktalarınızı paylaşarak PR'lar göndererek [**HackTricks**] ve [**HackTricks Cloud**] github depolarına katkıda bulunun(https://github.com/carlospolop/hacktricks).

</details>

## Bölümler

Bir sabit disk veya **SSD diski, verileri fiziksel olarak ayırmak amacıyla farklı bölümler içerebilir**.\
Diskin **minimum** birimi **sektör**dür (genellikle 512B'den oluşur). Bu nedenle, her bölüm boyutu bu boyutun katı olmalıdır.

### MBR (master Boot Record)

Bu, diskteki **ilk sektörde, önyükleme kodunun 446B'sinden sonra ayrılmıştır**. Bu sektör, PC'ye bir bölümün ne olduğunu ve nereden bağlanması gerektiğini göstermek için gereklidir.\
**4 bölümü** destekler (en fazla **yalnızca 1** aktif/**önyüklenebilir** olabilir). Ancak, daha fazla bölüme ihtiyacınız varsa **genişletilmiş bölümleri** kullanabilirsiniz. Bu ilk sektörün son baytı, önyükleme kaydı imzası **0x55AA**'dır. Yalnızca bir bölüm işaretlenebilir.\
MBR, **maksimum 2.2TB**'ye izin verir.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

MBR'nin 440 ile 443 baytı arasında **Windows Disk İmzası** bulunabilir (Windows kullanılıyorsa). Sabit diskin mantıksal sürücü harfi, Windows Disk İmzasına bağlıdır. Bu imzanın değiştirilmesi, Windows'un önyükleme yapmasını engelleyebilir (araç: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Biçim**

| Offset      | Uzunluk    | Öğe                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Önyükleme kodu      |
| 446 (0x1BE) | 16 (0x10)  | İlk Bölüm          |
| 462 (0x1CE) | 16 (0x10)  | İkinci Bölüm       |
| 478 (0x1DE) | 16 (0x10)  | Üçüncü Bölüm       |
| 494 (0x1EE) | 16 (0x10)  | Dördüncü Bölüm     |
| 510 (0x1FE) | 2 (0x2)    | İmza 0x55 0xAA      |

**Bölüm Kaydı Biçimi**

| Offset    | Uzunluk   | Öğe                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktif bayrak (0x80 = önyüklenebilir)                  |
| 1 (0x01)  | 1 (0x01) | Başlangıç başlık                                      |
| 2 (0x02)  | 1 (0x01) | Başlangıç sektörü (bitler 0-5); silindirin üst bitleri (6- 7) |
| 3 (0x03)  | 1 (0x01) | En düşük 8 bit başlangıç silindiri                    |
| 4 (0x04)  | 1 (0x01) | Bölüm türü kodu (0x83 = Linux)                        |
| 5 (0x05)  | 1 (0x01) | Bitiş başlık                                         |
| 6 (0x06)  | 1 (0x01) | Bitiş sektörü (bitler 0-5); silindirin üst bitleri (6- 7) |
| 7 (0x07)  | 1 (0x01) | En düşük 8 bit bitiş silindiri                        |
| 8 (0x08)  | 4 (0x04) | Bölümden önceki sektörler (little endian)             |
| 12 (0x0C) | 4 (0x04) | Bölümdeki sektörler                                   |

Linux'ta bir MBR'yi bağlamak için önce başlangıç ofsetini almanız gerekir (`fdisk` ve `p` komutunu kullanabilirsiniz)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ve ardından aşağıdaki kodu kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Mantıksal blok adresleme)**

**Mantıksal blok adresleme** (**LBA**), genellikle sabit disk sürücüleri gibi bilgisayar depolama cihazlarında depolanan veri bloklarının konumunu belirlemek için kullanılan yaygın bir şemadır. LBA, özellikle basit bir lineer adresleme şemasıdır; **bloklar bir tamsayı dizini ile belirlenir**, ilk blok LBA 0, ikinci blok LBA 1 ve böyle devam eder.

### GPT (GUID Bölüm Tablosu)

GUID Bölüm Tablosu olarak bilinen GPT, MBR (Ana Önyükleme Kaydı) ile karşılaştırıldığında gelişmiş yetenekleri nedeniyle tercih edilir. Bölümler için **benzersiz bir tanımlayıcıya** sahip olan GPT, birkaç açıdan öne çıkar:

* **Konum ve Boyut**: Hem GPT hem de MBR **0. sektörde** başlar. Ancak, GPT, MBR'nin 32 bitlik yapısına karşın **64 bitlik** bir yapı üzerinde çalışır.
* **Bölüm Sınırları**: GPT, Windows sistemlerinde **128 bölümü** destekler ve **9.4ZB** veriye kadar olan kapasiteyi barındırabilir.
* **Bölüm İsimleri**: Bölümlere en fazla 36 Unicode karakterle isim verme olanağı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

* **Yedeklilik**: MBR'nin aksine, GPT bölümlendirme ve önyükleme verilerini tek bir yerde sınırlamaz. Bu verileri diskin geneline kopyalar, veri bütünlüğünü ve dayanıklılığını artırır.
* **Döngüsel Redundans Kontrolü (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC'yi kullanır. Veri bozulması için aktif olarak izleme yapar ve tespit edildiğinde, GPT bozulmuş veriyi başka bir disk konumundan kurtarmaya çalışır.

**Koruyucu MBR (LBA0)**:

* GPT, koruyucu bir MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik, eski MBR tabanlı yardımcı programların yanlışlıkla GPT disklerini üzerine yazmasını engellemek amacıyla tasarlanmıştır, böylece GPT biçimli disklerde veri bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**Karma MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

BIOS hizmetleri aracılığıyla **GPT tabanlı önyükleme**yi destekleyen işletim sistemlerinde, ilk sektör genellikle **önyükleme yükleyicisinin** ilk aşamasını depolamak için kullanılır, ancak bu sektörlerin **GPT bölümlerini** tanımak üzere **değiştirilmiştir**. MBR'deki önyükleme yükleyicisi, 512 baytlık bir sektör boyutunu varsaymamalıdır.

**Bölüm tablosu başlığı (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Bölüm tablosu başlığı, disktaki kullanılabilir blokları tanımlar. Ayrıca, bölüm tablosunu oluşturan bölüm girişlerinin sayısını ve boyutunu tanımlar (tablodaki 80 ve 84 ofsetler).

| Ofset    | Uzunluk  | İçerik                                                                                                                                                                        |
| -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0 (0x00) | 8 bayt   | İmza ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)little-endian makinelerde) |
| 8 (0x08) | 4 bayt   | UEFI 2.8 için Revizyon 1.0 (00h 00h 01h 00h)                                                                                                                                   |
| 12 (0x0C)| 4 bayt   | Boyut küçük uçlu başlık boyutu (genellikle 5Ch 00h 00h 00h veya 92 bayt)                                                                                                      |
| 16 (0x10)| 4 bayt   | Başlık CRC32'si (başlangıç +0'dan başlayarak başlık boyutuna kadar) küçük uçlu, bu alan hesaplama sırasında sıfırlanır                                                             |
| 20 (0x14)| 4 bayt   | Ayrılmış; sıfır olmalıdır                                                                                                                                                     |
| 24 (0x18)| 8 bayt   | Geçerli LBA (bu başlık kopyasının konumu)                                                                                                                                      |
| 32 (0x20)| 8 bayt   | Yedek LBA (diğer başlık kopyasının konumu)                                                                                                                                     |
| 40 (0x28)| 8 bayt   | Bölümler için ilk kullanılabilir LBA (birincil bölüm tablosu son LBA + 1)                                                                                                      |
| 48 (0x30)| 8 bayt   | Son kullanılabilir LBA (ikincil bölüm tablosu ilk LBA − 1)                                                                                                                      |
| 56 (0x38)| 16 bayt  | Karışık uçlu disk GUID'i                                                                                                                                                      |
| 72 (0x48)| 8 bayt   | Bölüm girişlerinin bir dizi başlangıç LBA'sı (her zaman birincil kopyada 2)                                                                                                    |
| 80 (0x50)| 4 bayt   | Dizi içindeki bölüm girişlerinin sayısı                                                                                                                                        |
| 84 (0x54)| 4 bayt   | Tek bir bölüm girişinin boyutu (genellikle 80h veya 128)                                                                                                                        |
| 88 (0x58)| 4 bayt   | Küçük uçlu bölüm girişleri dizisinin CRC32'si                                                                                                                                  |
| 92 (0x5C)| \*       | Geri kalan blok için sıfır olmalıdır (512 bayt bir sektör boyutu için 420 bayt; ancak daha büyük sektör boyutlarıyla daha fazla olabilir)                                         |

**Bölüm girişleri (LBA 2–33)**

| GUID bölüm girişi formatı |          |                                                                                                                  |
| ------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| Ofset                     | Uzunluk  | İçerik                                                                                                           |
| 0 (0x00)                  | 16 bayt  | [Bölüm türü GUID'si](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (karışık uçlu)    |
| 16 (0x10)                 | 16 bayt  | Benzersiz bölüm GUID'i (karışık uçlu)                                                                            |
| 32 (0x20)                 | 8 bayt   | İlk LBA ([küçük uçlu](https://en.wikipedia.org/wiki/Little\_endian))                                              |
| 40 (0x28)                 | 8 bayt   | Son LBA (dahil, genellikle tek sayı)                                                                             |
| 48 (0x30)                 | 8 bayt   | Öznitelik bayrakları (örneğin, 60. bit salt okunur olarak işaretlenir)                                            |
| 56 (0x38)                 | 72 bayt  | Bölüm adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kod birimi)                                       |

**Bölüm Türleri**

![](<../../../.gitbook/assets/image (83).png>)

Daha fazla bölüm türü için [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### İnceleme

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile dijital delil imajını bağladıktan sonra, Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**'ı** kullanarak ilk sektörü inceleyebilirsiniz. Aşağıdaki görüntüde **MBR**'nin **0. sektörde** tespit edildiği ve yorumlandığı görülmektedir:

![](<../../../.gitbook/assets/image (354).png>)

Eğer bir **MBR yerine bir GPT tablosu** olsaydı, **1. sektörde** _EFI PART_ imzasının görünmesi gerekecekti (ki önceki görüntüde boş görünüyor).
## Dosya Sistemleri

### Windows dosya sistemleri listesi

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (Dosya Tahsis Tablosu)** dosya sistemi, çekirdek bileşeni olan dosya tahsis tablosu etrafında tasarlanmıştır ve genellikle birim başlangıcında konumlandırılır. Bu sistem, verileri koruyarak tablonun **iki kopyasını** tutarak, biri bozulsa bile veri bütünlüğünü sağlar. Tablo, kök klasör ile birlikte bir **sabit konumda** olmalıdır, sistem başlatma süreci için hayati öneme sahiptir.

Dosya sisteminin temel depolama birimi bir **küme, genellikle 512B** olup birden fazla sektörü içerir. FAT, şu sürümler aracılığıyla evrim geçirmiştir:

* **FAT12**, 12 bitlik küme adreslerini destekleyerek UNIX ile birlikte 4078 küme (4084) işleyebilir.
* **FAT16**, 16 bitlik adreslere yükselerek 65,517 küme kadar yer sağlar.
* **FAT32**, 32 bitlik adreslerle daha da ileri giderek etkileyici bir şekilde bir hacimde 268,435,456 küme sağlar.

FAT sürümleri arasındaki önemli bir kısıtlama, dosya boyutu depolama için kullanılan 32 bitlik alan tarafından uygulanan **maksimum 4GB dosya boyutudur**.

Özellikle FAT12 ve FAT16 için kök dizininin ana bileşenleri şunlardır:

* **Dosya/Klasör Adı** (en fazla 8 karakter)
* **Öznitelikler**
* **Oluşturma, Değiştirme ve Son Erişim Tarihleri**
* **FAT Tablo Adresi** (dosyanın başlangıç kümesini belirten)
* **Dosya Boyutu**

### EXT

**Ext2**, **gazetecilik yapmayan** bölümler için en yaygın dosya sistemidir (**çok fazla değişmeyen bölümler**) örneğin önyükleme bölümü. **Ext3/4** ise **gazetecilik yapan** ve genellikle **geri kalan bölümler** için kullanılır.

## **Meta Veri**

Bazı dosyalar meta veri içerir. Bu bilgi, dosyanın içeriği hakkında olabilir ve bazen bir analist için ilginç olabilir çünkü dosya türüne bağlı olarak şu tür bilgileri içerebilir:

* Başlık
* Kullanılan MS Office Sürümü
* Yazar
* Oluşturma ve Son Değiştirme Tarihleri
* Kamera modeli
* GPS koordinatları
* Görüntü bilgileri

Dosyanın meta verisini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Silinmiş Dosyaların Kurtarılması**

### Kaydedilen Silinmiş Dosyalar

Daha önce görüldüğü gibi, bir dosyanın "silinmesinden" sonra bile dosyanın hala kaydedildiği birkaç yer vardır. Bu genellikle bir dosyanın dosya sisteminden silinmesi sadece silindi olarak işaretlenir ancak veriye dokunulmaz. Sonra, dosyaların kayıtlarını incelemek ve silinmiş dosyaları bulmak mümkündür.

Ayrıca, işletim sistemi genellikle dosya sistemine yapılan değişiklikler ve yedeklemeler hakkında birçok bilgi kaydeder, bu nedenle dosyayı kurtarmak veya mümkün olduğunca çok bilgiyi kullanmak mümkündür.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Dosya Oyma**

**Dosya oyma**, veri yığını içinde dosyaları **bulmaya çalışan bir tekniktir**. Bu tür araçların çalışma şekli genellikle 3 ana yoldan oluşur: **Dosya türü başlıkları ve altbilgilerine dayalı**, dosya türlerine göre **yapılar** ve **içeriğe** dayalı.

Bu teknik **parçalanmış dosyaları kurtarmak için çalışmaz**. Bir dosya **ardışık sektörlerde depolanmıyorsa**, bu teknik dosyayı veya en azından bir kısmını bulamaz.

Arama yapmak istediğiniz dosya türlerini belirten dosya Oyma için kullanabileceğiniz birkaç araç vardır.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Veri Akışı **O**yma

Veri Akışı Oyma, Dosya Oyma'ya benzer ancak **tam dosyaları değil, ilginç parçaları arar**.\
Örneğin, kaydedilmiş URL'leri içeren tam bir dosya aramak yerine, bu teknik URL'leri arayacaktır.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Güvenli Silme

Açıkça, dosyaları **"güvenli bir şekilde" silmenin ve onlarla ilgili kayıtların bir kısmını silmenin** yolları vardır. Örneğin, bir dosyanın içeriğini birkaç kez gereksiz veriyle üzerine yazmak ve ardından dosya hakkındaki kayıtları **$MFT** ve **$LOGFILE**'dan kaldırmak ve **Gölge Kopyaları'nı kaldırmak** mümkündür.\
Bu işlemi gerçekleştirmenize rağmen dosyanın varlığının hala kaydedildiği diğer yerler olabileceğini fark edebilirsiniz ve bu, adli bilişim uzmanının işinin bir parçasıdır.

## Referanslar

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Sertifikalı Dijital Adli Bilişim Windows**
