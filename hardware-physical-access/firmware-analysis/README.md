# Firmware Analizi

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## **Giriş**

Firmware, cihazların donanım bileşenleri arasındaki iletişimi yöneterek ve kolaylaştırarak kullanıcıların etkileşimde bulunduğu yazılım ile cihazların doğru bir şekilde çalışmasını sağlayan temel bir yazılımdır. Cihazın açıldığı anda önemli talimatları erişebilmesini sağlayan kalıcı bellekte depolanır ve işletim sisteminin başlatılmasına yol açar. Firmware'in incelenmesi ve potansiyel olarak değiştirilmesi, güvenlik açıklarını belirlemede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik ilk adımıdır. Bu süreç, şunlar hakkında veri toplamayı içerir:

* Çalıştığı CPU mimarisi ve işletim sistemi
* Bootloader özellikleri
* Donanım düzeni ve veri sayfaları
* Kod tabanı metrikleri ve kaynak konumları
* Harici kütüphaneler ve lisans türleri
* Güncelleme geçmişleri ve düzenleyici sertifikalar
* Mimarlık ve akış diyagramları
* Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla, **açık kaynak istihbaratı (OSINT)** araçları çok değerlidir ve mevcut açık kaynak yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analizi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware'e ulaşma, kendi karmaşıklık seviyesine sahip çeşitli yöntemlerle ele alınabilir:

* **Kaynaktan doğrudan** (geliştiriciler, üreticiler)
* Sağlanan talimatlarla **oluşturarak**
* Resmi destek sitelerinden **indirerek**
* Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanma
* [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla doğrudan **bulut depolama** erişimi
* Orta adam saldırı teknikleriyle güncellemeleri **intercept etme**
* **UART**, **JTAG** veya **PICit** gibi bağlantılar aracılığıyla cihazdan **çıkarma**
* Cihaz iletişimi içindeki güncelleme isteklerini **sızdırma**
* **Sabitlenmiş güncelleme uç noktalarını** tanımlama ve kullanma
* **Bootloader'dan veya ağdan** **dökme**
* Tüm diğer yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak depolama çipini **çıkarıp okuma**

## Firmware'in Analizi

Şimdi **firmware'e sahip olduğunuza** göre, onun hakkında bilgi çıkarmak için bilgi çıkarmalısınız. Bunun için kullanabileceğiniz farklı araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok fazla şey bulamazsanız, görüntünün **entropisini** `binwalk -E <bin>` ile kontrol edin, düşük entropi ise muhtemelen şifrelenmemiştir. Yüksek entropi ise muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları kullanarak **firmware içine gömülü dosyaları çıkarabilirsiniz**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ya da [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)) ile dosyayı inceleyebilirsiniz.

### Dosya Sistemi Elde Etme

Önceki yorumlanmış araçlar gibi `binwalk -ev <bin>` ile **dosya sistemini çıkarmış olmanız gerekir**.\
Binwalk genellikle bunu, genellikle squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs gibi olan **dosya sistemine adanmış bir klasörün içine çıkarır**.

#### Manuel Dosya Sistemi Çıkarma

Bazı durumlarda, binwalk'ün imzalarında **dosya sisteminin sihirli baytı olmayabilir**. Bu durumlarda, binwalk'ü kullanarak **dosya sisteminin ofsetini bulun ve sıkıştırılmış dosya sistemini kesin** ve dosya sistemini türüne göre aşağıdaki adımları kullanarak **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd komutunu** çalıştırarak Squashfs dosya sistemi kazıyın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

```shell
$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs
```

* Squashfs için (yukarıdaki örnekte kullanıldı)

```shell
$ unsquashfs dir.squashfs
```

Dosyalar daha sonra "`squashfs-root`" dizininde olacaktır.

* CPIO arşiv dosyaları

```shell
$ cpio -ivd --no-absolute-filenames -F <bin>
```

* Jffs2 dosya sistemleri için

```shell
$ jefferson rootfsfile.jffs2
```

* NAND flaş ile ubifs dosya sistemleri için

```shell
$ ubireader_extract_images -u UBI -s <start_offset> <bin>
```

```shell
$ ubidump.py <bin>
```

## Firmware Analizi

Firmware elde edildikten sonra, yapısını anlamak ve potansiyel güvenlik açıklarını belirlemek için parçalamak esastır. Bu süreç, firmware görüntüsünden değerli verileri çıkarmak ve analiz etmek için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak adlandırılan) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar, dosya türlerini tanımlamaya, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ve dosya sistem ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün şifreleme durumunu değerlendirmek için **entropy** değeri `binwalk -E <bin>` komutu ile kontrol edilir. Düşük entropy değeri şifreleme eksikliğini, yüksek entropy değeri ise olası şifreleme veya sıkıştırmayı gösterebilir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sisteminin Çıkarılması

`binwalk -ev <bin>` komutunu kullanarak genellikle dosya sistemi çıkarılabilir, genellikle dosya sistemi türünün adını taşıyan bir dizine (örneğin, squashfs, ubifs) çıkarılır. Ancak, **binwalk** dosya sistemi türünü tanıyamadığında sihirli baytların eksikliği nedeniyle manuel çıkarma gereklidir. Bu, `binwalk`'ın dosya sisteminin ofsetini bulmasını ve ardından `dd` komutunu kullanarak dosya sisteminin çıkarılmasını içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra, güvenlik açıklarının aranmasına başlanır. Güvensiz ağ daemonları, sabitlenmiş kimlik bilgileri, API uç noktaları, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş ikili dosyalar dikkatle incelenir.

İncelenmesi gereken **ana konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarlar
- Potansiyel güvenlik açıkları için yapılandırma ve betik dosyaları
- İleriki analiz için gömülü ikili dosyalar
- Ortak IoT cihazı web sunucuları ve ikili dosyalar

Dosya sistemi içinde hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar bulunmaktadır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalar Üzerinde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodları hem de derlenmiş ikili dosyalar, güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, sömürülebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Dinamik Analiz İçin Firmware Emülasyonu

Firmware'in emüle edilmesi, bir cihazın işleyişinin veya bireysel bir programın **dinamik analizinin** yapılmasını sağlar. Bu yaklaşım, donanım veya mimari bağımlılıklarıyla karşılaşabilir, ancak kök dosya sistemini veya belirli ikili dosyaları, Raspberry Pi gibi uyumlu mimariye ve bit sırasına sahip bir cihaza veya önceden oluşturulmuş bir sanal makineye aktarmak, daha fazla test yapmayı kolaylaştırabilir.

### Bireysel İkili Dosyaların Emülasyonu

Tek programları incelemek için programın bit sırasını ve CPU mimarisini belirlemek önemlidir.

#### MIPS Mimarisi ile Örnek

MIPS mimarisi ikili dosyasını emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### ARM Mimarisi Emülasyonu

ARM ikili dosyaları için, emülasyon için `qemu-arm` emülatörü kullanılır.

### Tam Sistem Emülasyonu

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) gibi araçlar, tam firmware emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

## Uygulamada Dinamik Analiz

Bu aşamada, analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve dosya sistemine erişimi sürdürmek esastır. Emülasyon, donanım etkileşimlerini mükemmel bir şekilde taklit etmeyebilir, bu nedenle zaman zaman emülasyon yeniden başlatmaları gerekebilir. Analiz, dosya sistemine tekrar bakmalı, açığa çıkarılan web sayfalarını ve ağ hizmetlerini kullanmalı ve önyükleme yükleyicisi açıklarını keşfetmelidir. Firmware bütünlük testleri, potansiyel arka kapı açıklarını belirlemek için kritiktir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir işlem veya ikili dosya ile işletim ortamında etkileşimde bulunmayı içerir; gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılarak kesme noktaları belirleme ve bulanıklık ve diğer teknikler aracılığıyla zayıflıkları tanımlama.

## İkili Sömürü ve Kanıt-of-Kavramı

Belirlenen zayıflıklar için bir PoC geliştirmek, hedef mimariyi derinlemesine anlama ve düşük seviye dillerde programlama gerektirir. Gömülü sistemlerde ikili çalışma zamanı korumaları nadirdir, ancak varsa, Return Oriented Programming (ROP) gibi teknikler gerekebilir.

## Firmware Analizi İçin Hazırlanmış İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla donatılmış firmware güvenlik testi için önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi İçin Hazırlanmış İşletim Sistemleri

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Nesnelerin İnterneti (IoT) cihazlarının güvenlik değerlendirmesi ve penetrasyon testi yapmanıza yardımcı olmak için tasarlanmış bir dağıtımdır. Gerekli tüm araçların yüklü olduğu önceden yapılandırılmış bir ortam sağlayarak size zaman kazandırır.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı gömülü güvenlik testi işletim sistemi, firmware güvenlik testi araçlarıyla önceden yüklenmiş.

## Uygulamada Zayıf Firmware

Firmware'deki zayıflıkları keşfetmek için aşağıdaki zayıf firmware projelerini başlangıç noktası olarak kullanın.

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
