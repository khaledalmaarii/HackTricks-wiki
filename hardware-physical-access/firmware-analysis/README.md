# Firmware Analysis

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## **Giriş**

Firmware, donanım bileşenleriyle kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yöneterek cihazların doğru bir şekilde çalışmasını sağlayan temel bir yazılımdır. Cihazın açıldığı anda önemli talimatları erişilebilir hale getiren kalıcı bellekte depolanır ve işletim sisteminin başlatılmasına yol açar. Firmware'in incelenmesi ve potansiyel olarak değiştirilmesi, güvenlik açıklarını belirlemede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlama sürecinde kritik bir ilk adımdır. Bu süreç, aşağıdaki verilerin toplanmasını içerir:

* CPU mimarisi ve çalıştırdığı işletim sistemi
* Önyükleyici ayrıntıları
* Donanım düzeni ve veri sayfaları
* Kod tabanı metrikleri ve kaynak konumları
* Harici kütüphaneler ve lisans türleri
* Güncelleme geçmişleri ve düzenleyici sertifikalar
* Mimarlık ve akış diyagramları
* Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla, **açık kaynak istihbaratı (OSINT)** araçları çok değerlidir ve manuel ve otomatik inceleme süreçleriyle mevcut açık kaynak yazılım bileşenlerinin analizi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware elde etmek, karmaşıklık düzeyine bağlı olarak çeşitli yöntemlerle ele alınabilir:

* **Doğrudan** kaynaktan (geliştiriciler, üreticiler)
* Sağlanan talimatlarla **oluşturarak**
* Resmi destek sitelerinden **indirerek**
* Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanarak
* [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla doğrudan **bulut depolama**'ya erişme
* Orta adam saldırısı teknikleriyle güncellemeleri **intercept** etme
* **UART**, **JTAG** veya **PICit** gibi bağlantılar aracılığıyla cihazdan **çıkararak** elde etme
* Cihaz iletişimi içindeki güncelleme isteklerini **sniff** etme
* **Sabitlenmiş güncelleme uç noktalarını** belirleme ve kullanma
* **Önyükleyiciden** veya ağdan **dökme** yapma
* Tüm diğer yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak depolama yongasını **çıkararak ve okuyarak** elde etme

## Firmware'i Analiz Etme

Şimdi **firmware'e sahip olduğunuza** göre, onun hakkında bilgi çıkarmak için nasıl işlem yapacağınızı bilmelisiniz. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Eğer bu araçlarla çok fazla şey bulamazsanız, `binwalk -E <bin>` komutuyla görüntünün **entropisini** kontrol edin. Düşük entropi, muhtemelen şifrelenmediği anlamına gelir. Yüksek entropi ise muhtemelen şifreli (veya bazı şekillerde sıkıştırılmış) olduğunu gösterir.

Ayrıca, aşağıdaki araçları kullanarak firmware içine gömülü olan **dosyaları çıkarabilirsiniz**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemi Elde Etme

Önceki yorum satırında belirtilen `binwalk -ev <bin>` gibi araçlarla **dosya sistemi çıkarmanız gerekmektedir**.\
Binwalk genellikle bunu, genellikle aşağıdakilerden biri olan bir **dosya sistemi türü adında bir klasörün içine çıkarır**: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkarımı

Bazı durumlarda, binwalk'ın imzalarında **dosya sisteminin sihirli baytı bulunmayabilir**. Bu durumlarda, binwalk'ı kullanarak **dosya sisteminin ofsetini bulun ve sıkıştırılmış dosya sistemi**ni binary'den keserek ve aşağıdaki adımları kullanarak **manuel olarak çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Aşağıdaki **dd komutunu** kullanarak Squashfs dosya sistemini çıkarın.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Squashfs için (yukarıdaki örnekte kullanıldığı gibi)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra "`squashfs-root`" dizininde olacak.

* CPIO arşiv dosyaları için

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

* NAND flash ile ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve potansiyel güvenlik açıklarını anlamak için parçalamak önemlidir. Bu süreçte, firmware görüntüsünden değerli verileri analiz etmek ve çıkarmak için çeşitli araçlar kullanılır.

### İlk Analiz Araçları

İkili dosya ( `<bin>` olarak adlandırılır) için ilk inceleme için bir dizi komut sağlanmaktadır. Bu komutlar, dosya türlerini belirleme, dizeleri çıkarma, ikili verileri analiz etme ve bölüm ve dosya sistemine ilişkin ayrıntıları anlama konusunda yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Resimdeki şifreleme durumunu değerlendirmek için, **entropi** `binwalk -E <bin>` ile kontrol edilir. Düşük entropi, şifreleme eksikliğini gösterirken, yüksek entropi olası şifreleme veya sıkıştırmayı işaret eder.

**Gömülü dosyaları** çıkarmak için, **file-data-carving-recovery-tools** belgeleri ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemi Çıkarma

`binwalk -ev <bin>` kullanarak, genellikle dosya sistemi çıkarılabilir, genellikle dosya sistemi türünün adıyla (örneğin squashfs, ubifs) adlandırılan bir dizine. Bununla birlikte, **binwalk** sihirli baytların eksik olması nedeniyle dosya sistemi türünü tanıyamazsa, manuel çıkarma gereklidir. Bu, `binwalk` kullanarak dosya sisteminin ofsetini bulmayı ve ardından `dd` komutunu kullanarak dosya sisteminin çıkarılmasını içerir:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Sonrasında, dosya sistemi türüne (örneğin, squashfs, cpio, jffs2, ubifs) bağlı olarak içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra, güvenlik açıkları araştırılmaya başlanır. Güvensiz ağ hizmetleri, sabitlenmiş kimlik bilgileri, API uç noktaları, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş ikili dosyalar gibi unsurlara dikkat edilir.

İncelenmesi gereken **ana konumlar** ve **öğeler** şunlardır:

* Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
* **etc/ssl** içindeki SSL sertifikaları ve anahtarları
* Potansiyel güvenlik açıkları için yapılandırma ve betik dosyaları
* İleri analiz için gömülü ikili dosyalar
* Ortak IoT cihaz web sunucuları ve ikili dosyaları

Dosya sistemi içinde hassas bilgileri ve güvenlik açıklarını ortaya çıkarmak için birkaç araç bulunmaktadır:

* Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
* Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core)
* Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalar Üzerinde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodları hem de derlenmiş ikili dosyalar, güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, sömürülebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Dinamik Analiz İçin Firmware Emülasyonu

Firmware'in emülasyonu, bir cihazın işleyişinin veya bir programın dinamik analizinin yapılmasını sağlar. Bu yaklaşım, donanım veya mimari bağımlılıklarıyla karşılaşabilir, ancak kök dosya sistemi veya belirli ikili dosyaların, Raspberry Pi gibi uyumlu bir mimari ve bit düzenine sahip bir cihaza veya önceden oluşturulmuş bir sanal makineye aktarılması, daha fazla test yapmayı kolaylaştırabilir.

### Bireysel İkili Dosyaların Emülasyonu

Tek bir programın incelenmesi için programın bit düzeni ve CPU mimarisi belirlemek önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisi ikili bir dosyanın emülasyonu için aşağıdaki komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılırken, little-endian ikili dosyalar için `qemu-mipsel` tercih edilir.

#### ARM Mimarisi Emülasyonu

ARM ikili dosyaları için, emülasyon için `qemu-arm` emulatorü kullanılır.

### Tam Sistem Emülasyonu

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, tam firmware emülasyonunu kolaylaştırır ve süreci otomatikleştirir, dinamik analize yardımcı olur.

## Uygulamada Dinamik Analiz

Bu aşamada, analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemi ve dosya sistemi üzerinde kabuk erişimini sürdürmek önemlidir. Emülasyon, donanım etkileşimlerini mükemmel bir şekilde taklit etmeyebilir, bu nedenle zaman zaman emülasyon yeniden başlatmaları gerekebilir. Analiz, dosya sistemi üzerinde gezinmeyi, açığa çıkan web sayfalarını ve ağ hizmetlerini kullanmayı ve önyükleme yükleyicisi açıklarını keşfetmeyi içermelidir. Firmware bütünlük testleri, potansiyel arka kapı açıklarını belirlemek için önemlidir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir işlem veya ikili dosyanın işletim ortamıyla etkileşimde bulunmayı içerir. gdb-multiarch, Frida ve Ghidra gibi araçlar, kesme noktalarını ayarlamak ve bulanıklık ve diğer teknikler aracılığıyla zafiyetleri belirlemek için kullanılır.

## İkili Sömürü ve Kanıt-of-Kavram

Belirlenen zafiyetler için bir Kanıt-of-Kavram (PoC) geliştirmek, hedef mimariyi derinlemesine anlama ve düşük seviye dillerde programlama konusunda derin bir anlayış gerektirir. Gömülü sistemlerde ikili çalışma zamanı korumaları nadirdir, ancak varsa Return Oriented Programming (ROP) gibi teknikler gerekebilir.

## Firmware Analizi için Hazırlanmış İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla donatılmış firmware güvenlik testi için önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi için Hazırlanmış İşletim Sistemleri

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Nesnelerin İnterneti (IoT) cihazlarının güvenlik değerlendirmesi ve penetrasyon testi yapmanıza yardımcı olmak için tasarlanmış bir dağıtımdır. Tüm gerekli araçların yüklü olduğu önceden yapılandırılmış bir ortam sağlayarak size çok zaman kazandırır.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware güvenlik testi araçlarıyla yüklenmiş Ubuntu 18.04 tabanlı gömülü güvenlik testi işletim sistemi.

## Uygulama yapmak için Zafiyetli Firmware

Firmware'de zafiyetleri keşfetmek için aşağıdaki zafiyetli firmware projelerini bir başlangıç noktası olarak kullanabilirsiniz.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referanslar

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Eğitim ve Sertifika

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live).
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github reposuna PR göndererek katkıda bulunun.

</details>
