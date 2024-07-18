# Partitions/File Systems/Carving

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

## Partitions

Bir sabit disk veya bir **SSD diski, verileri fiziksel olarak ayırma amacıyla farklı bölümler içerebilir**.\
Diskin **minimum** birimi **sektördür** (normalde 512B'den oluşur). Bu nedenle, her bölüm boyutu bu boyutun katı olmalıdır.

### MBR (master Boot Record)

**446B boot kodundan sonra diskin ilk sektöründe** tahsis edilmiştir. Bu sektör, PC'ye bir bölümün ne zaman ve nereden bağlanması gerektiğini belirtmek için gereklidir.\
En fazla **4 bölüm** (en fazla **1** aktif/**bootable** olabilir) olmasına izin verir. Ancak, daha fazla bölüme ihtiyacınız varsa **genişletilmiş bölümler** kullanabilirsiniz. Bu ilk sektörün **son baytı** boot kayıt imzası **0x55AA**'dır. Sadece bir bölüm aktif olarak işaretlenebilir.\
MBR, **maksimum 2.2TB**'ye izin verir.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

MBR'nin **440 ile 443 baytları arasında** **Windows Disk İmzası** bulunabilir (Windows kullanılıyorsa). Sabit diskin mantıksal sürücü harfi, Windows Disk İmzasına bağlıdır. Bu imzanın değiştirilmesi, Windows'un başlatılmasını engelleyebilir (araç: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot kodu           |
| 446 (0x1BE) | 16 (0x10)  | İlk Bölüm          |
| 462 (0x1CE) | 16 (0x10)  | İkinci Bölüm       |
| 478 (0x1DE) | 16 (0x10)  | Üçüncü Bölüm       |
| 494 (0x1EE) | 16 (0x10)  | Dördüncü Bölüm     |
| 510 (0x1FE) | 2 (0x2)    | İmza 0x55 0xAA     |

**Bölüm Kayıt Formatı**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktif bayrağı (0x80 = bootable)                       |
| 1 (0x01)  | 1 (0x01) | Başlangıç başlığı                                      |
| 2 (0x02)  | 1 (0x01) | Başlangıç sektörü (bit 0-5); silindirin üst bitleri (6- 7) |
| 3 (0x03)  | 1 (0x01) | Başlangıç silindiri en düşük 8 bit                     |
| 4 (0x04)  | 1 (0x01) | Bölüm türü kodu (0x83 = Linux)                        |
| 5 (0x05)  | 1 (0x01) | Bitiş başlığı                                          |
| 6 (0x06)  | 1 (0x01) | Bitiş sektörü (bit 0-5); silindirin üst bitleri (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Bitiş silindiri en düşük 8 bit                         |
| 8 (0x08)  | 4 (0x04) | Bölümden önceki sektörler (little endian)             |
| 12 (0x0C) | 4 (0x04) | Bölümdeki sektörler                                   |

Bir MBR'yi Linux'ta bağlamak için önce başlangıç ofsetini almanız gerekir (bunu `fdisk` ve `p` komutunu kullanarak yapabilirsiniz)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ve ardından aşağıdaki kodu kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Mantıksal blok adresleme)**

**Mantıksal blok adresleme** (**LBA**), bilgisayar depolama cihazlarında saklanan veri bloklarının konumunu belirtmek için yaygın olarak kullanılan bir şemadır; genellikle sabit disk sürücüleri gibi ikincil depolama sistemleridir. LBA, özellikle basit bir doğrusal adresleme şemasına sahiptir; **bloklar bir tam sayı indeksi ile konumlandırılır**, ilk blok LBA 0, ikinci LBA 1 şeklindedir.

### GPT (GUID Bölüm Tablosu)

GUID Bölüm Tablosu, GPT olarak bilinir ve MBR (Ana Önyükleme Kaydı) ile karşılaştırıldığında geliştirilmiş yetenekleri nedeniyle tercih edilmektedir. Bölümler için **küresel benzersiz tanımlayıcı** ile ayırt edici olan GPT, birkaç şekilde öne çıkmaktadır:

* **Konum ve Boyut**: Hem GPT hem de MBR **sektör 0**'da başlar. Ancak, GPT **64 bit** üzerinde çalışırken, MBR **32 bit** kullanır.
* **Bölüm Sınırları**: GPT, Windows sistemlerinde **128 bölüme** kadar destekler ve **9.4ZB**'a kadar veri depolayabilir.
* **Bölüm İsimleri**: Bölümlere 36 Unicode karaktere kadar isim verme imkanı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

* **Yedeklilik**: MBR'nin aksine, GPT bölümleme ve önyükleme verilerini tek bir yere hapsetmez. Bu verileri disk boyunca çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
* **Döngüsel Yedeklilik Kontrolü (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulmasını aktif olarak izler ve tespit edildiğinde, GPT bozulmuş veriyi başka bir disk konumundan kurtarmaya çalışır.

**Koruyucu MBR (LBA0)**:

* GPT, koruyucu bir MBR aracılığıyla geriye dönük uyumluluğu sürdürür. Bu özellik, eski MBR tabanlı yardımcı programların yanlışlıkla GPT disklerini üzerine yazmasını önlemek için tasarlanmıştır, böylece GPT formatlı disklerde veri bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**Hibrit MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

**EFI** yerine **BIOS** hizmetleri aracılığıyla **GPT tabanlı önyükleme** destekleyen işletim sistemlerinde, ilk sektör hala **önyükleyici** kodunun ilk aşamasını depolamak için kullanılabilir, ancak **GPT** **bölümlerini tanımak için değiştirilmiştir. MBR'deki önyükleyici, 512 baytlık bir sektör boyutu varsaymamalıdır.

**Bölüm tablosu başlığı (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Bölüm tablosu başlığı, disk üzerindeki kullanılabilir blokları tanımlar. Ayrıca, bölüm tablosunu oluşturan bölüm girişlerinin sayısını ve boyutunu tanımlar (tablodaki 80 ve 84 ofsetleri).

| Ofset    | Uzunluk   | İçerik                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bayt  | İmza ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)küçük sonlu makinelerde) |
| 8 (0x08)  | 4 bayt  | Revizyon 1.0 (00h 00h 01h 00h) UEFI 2.8 için                                                                                                                                     |
| 12 (0x0C) | 4 bayt  | Başlık boyutu küçük sonlu (bayt cinsinden, genellikle 5Ch 00h 00h 00h veya 92 bayt)                                                                                                    |
| 16 (0x10) | 4 bayt  | [CRC32](https://en.wikipedia.org/wiki/CRC32) başlığın CRC'si (ofset +0 başlık boyutuna kadar) küçük sonlu, bu alan hesaplama sırasında sıfırlanır                                |
| 20 (0x14) | 4 bayt  | Ayrılmış; sıfır olmalıdır                                                                                                                                                          |
| 24 (0x18) | 8 bayt  | Mevcut LBA (bu başlık kopyasının konumu)                                                                                                                                      |
| 32 (0x20) | 8 bayt  | Yedek LBA (diğer başlık kopyasının konumu)                                                                                                                                  |
| 40 (0x28) | 8 bayt  | Bölümler için ilk kullanılabilir LBA (birincil bölüm tablosunun son LBA'sı + 1)                                                                                                          |
| 48 (0x30) | 8 bayt  | Son kullanılabilir LBA (ikincil bölüm tablosunun ilk LBA'sı − 1)                                                                                                                       |
| 56 (0x38) | 16 bayt | Disk GUID'i karışık sonlu                                                                                                                                                       |
| 72 (0x48) | 8 bayt  | Bir dizi bölüm girişinin başlangıç LBA'sı (her zaman birincil kopyada 2)                                                                                                        |
| 80 (0x50) | 4 bayt  | Dizideki bölüm girişlerinin sayısı                                                                                                                                            |
| 84 (0x54) | 4 bayt  | Tek bir bölüm girişinin boyutu (genellikle 80h veya 128)                                                                                                                           |
| 88 (0x58) | 4 bayt  | Bölüm girişleri dizisinin küçük sonlu CRC32'si                                                                                                                               |
| 92 (0x5C) | \*       | Ayrılmış; blokun geri kalanında sıfır olmalıdır (512 baytlık bir sektör boyutu için 420 bayt; ancak daha büyük sektör boyutları ile daha fazla olabilir)                                         |

**Bölüm girişleri (LBA 2–33)**

| GUID bölüm giriş formatı |          |                                                                                                                   |
| ------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Ofset                    | Uzunluk   | İçerik                                                                                                          |
| 0 (0x00)                  | 16 bayt | [Bölüm türü GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (karışık sonlu) |
| 16 (0x10)                 | 16 bayt | Benzersiz bölüm GUID'i (karışık sonlu)                                                                              |
| 32 (0x20)                 | 8 bayt  | İlk LBA ([küçük sonlu](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                 | 8 bayt  | Son LBA (dahil, genellikle tek)                                                                                 |
| 48 (0x30)                 | 8 bayt  | Nitelik bayrakları (örneğin, bit 60 yalnızca okunur)                                                                   |
| 56 (0x38)                 | 72 bayt | Bölüm adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kod birimi)                                   |

**Bölüm Türleri**

![](<../../../.gitbook/assets/image (83).png>)

Daha fazla bölüm türü için [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### İnceleme

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile adli görüntüyü monte ettikten sonra, ilk sektörü Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)** kullanarak inceleyebilirsiniz.** Aşağıdaki görüntüde **sektör 0**'da bir **MBR** tespit edilmiştir ve yorumlanmıştır:

![](<../../../.gitbook/assets/image (354).png>)

Eğer bir **MBR yerine bir GPT tablosu** olsaydı, **sektör 1**'de _EFI PART_ imzası görünmelidir (önceki görüntüde bu alan boştur).

## Dosya Sistemleri

### Windows dosya sistemleri listesi

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (Dosya Tahsis Tablosu)** dosya sistemi, hacmin başlangıcında yer alan dosya tahsis tablosu etrafında tasarlanmıştır. Bu sistem, tablonun **iki kopyasını** tutarak verileri korur ve birinin bozulması durumunda veri bütünlüğünü sağlar. Tablo, kök klasör ile birlikte **sabit bir konumda** olmalıdır; bu, sistemin başlatma süreci için kritik öneme sahiptir.

Dosya sisteminin temel depolama birimi bir **küme, genellikle 512B**'dir ve birden fazla sektörden oluşur. FAT, sürümler boyunca evrim geçirmiştir:

* **FAT12**, 12 bit küme adreslerini destekler ve 4078 kümeye kadar işleyebilir (4084 UNIX ile).
* **FAT16**, 16 bit adreslere yükseltilerek 65,517 kümeye kadar destek sağlar.
* **FAT32**, 32 bit adreslerle daha da ilerleyerek hacim başına 268,435,456 kümeye izin verir.

FAT sürümleri arasında önemli bir sınırlama, **4GB maksimum dosya boyutu**'dur; bu, dosya boyutu depolamak için kullanılan 32 bit alan tarafından dayatılmaktadır.

FAT12 ve FAT16 için kök dizininin ana bileşenleri şunlardır:

* **Dosya/Klasör Adı** (en fazla 8 karakter)
* **Nitelikler**
* **Oluşturma, Değiştirme ve Son Erişim Tarihleri**
* **FAT Tablosu Adresi** (dosyanın başlangıç kümesini gösterir)
* **Dosya Boyutu**

### EXT

**Ext2**, **günlük tutmayan** bölümler (**çok fazla değişmeyen bölümler**) için en yaygın dosya sistemidir; **Ext3/4** ise **günlük tutan** sistemlerdir ve genellikle **diğer bölümler** için kullanılır.

## **Meta Veriler**

Bazı dosyalar meta veriler içerir. Bu bilgiler, dosyanın içeriği hakkında olup, bazen bir analist için ilginç olabilir; dosya türüne bağlı olarak, aşağıdaki gibi bilgiler içerebilir:

* Başlık
* Kullanılan MS Office Versiyonu
* Yazar
* Oluşturma ve son değiştirme tarihleri
* Kameranın modeli
* GPS koordinatları
* Görüntü bilgileri

Bir dosyanın meta verilerini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Silinmiş Dosyaların Kurtarılması**

### Günlük Kayıtlı Silinmiş Dosyalar

Daha önce görüldüğü gibi, bir dosya "silindikten" sonra hala kaydedildiği birkaç yer vardır. Bunun nedeni, genellikle bir dosyanın dosya sisteminden silinmesinin sadece silindiği olarak işaretlenmesidir, ancak veriye dokunulmaz. Bu nedenle, dosyaların kayıtlarını (MFT gibi) incelemek ve silinmiş dosyaları bulmak mümkündür.

Ayrıca, işletim sistemi genellikle dosya sistemi değişiklikleri ve yedeklemeleri hakkında çok fazla bilgi kaydeder, bu nedenle dosyayı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunları kullanmaya çalışmak mümkündür.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Dosya Oymacılığı**

**Dosya oymacılığı**, **veri yığınında dosyaları bulmaya çalışan** bir tekniktir. Bu tür araçların çalıştığı 3 ana yol vardır: **Dosya türü başlıkları ve alt başlıklarına dayalı**, dosya türü **yapılarına** dayalı ve **içerik**'e dayalı.

Bu tekniğin **parçalanmış dosyaları geri almak için çalışmadığını** unutmayın. Eğer bir dosya **bitişik sektörlerde saklanmıyorsa**, bu teknik onu veya en azından bir kısmını bulamayacaktır.

Aradığınız dosya türlerini belirterek dosya oymacılığı için kullanabileceğiniz birkaç araç vardır.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Veri Akışı **C**arving

Veri Akışı Oymacılığı, Dosya Oymacılığına benzer, ancak **tam dosyalar yerine, ilginç bilgi parçalarını arar**.\
Örneğin, günlük kaydedilmiş URL'leri içeren bir tam dosya aramak yerine, bu teknik URL'leri arayacaktır.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Güvenli Silme

Açıkça, dosyaları ve bunlarla ilgili günlüklerin bir kısmını **"güvenli" bir şekilde silmenin** yolları vardır. Örneğin, bir dosyanın içeriğini birkaç kez çöp verilerle **üst üste yazmak** ve ardından dosya ile ilgili **$MFT** ve **$LOGFILE**'dan **günlükleri kaldırmak** ve **Hacim Gölge Kopyalarını kaldırmak** mümkündür.\
Bu işlemi gerçekleştirirken, dosyanın varlığının hala kaydedildiği **diğer parçaların** olabileceğini fark edebilirsiniz; bu doğrudur ve adli uzmanların işinin bir parçası da bunları bulmaktır.

## Referanslar

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Sertifikalı Dijital Adli Windows**

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
