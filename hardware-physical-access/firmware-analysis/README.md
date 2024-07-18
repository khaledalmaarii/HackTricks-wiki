# Firmware Analizi

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## **Giriş**

Firmware, cihazların donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yöneterek cihazların doğru bir şekilde çalışmasını sağlayan temel bir yazılımdır. Cihazın açıldığı anda önemli talimatları erişebilmesini sağlayan kalıcı bellekte depolanır ve işletim sisteminin başlatılmasına yol açar. Firmware'in incelenmesi ve potansiyel olarak değiştirilmesi, güvenlik açıklarının belirlenmesinde kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik ilk adımıdır. Bu süreç, şunlar hakkında veri toplamayı içerir:

* CPU mimarisi ve çalıştırdığı işletim sistemi
* Bootloader özellikleri
* Donanım düzeni ve veri sayfaları
* Kod tabanı metrikleri ve kaynak konumları
* Harici kütüphaneler ve lisans türleri
* Güncelleme geçmişleri ve düzenleyici sertifikalar
* Mimarlık ve akış diyagramları
* Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla, **açık kaynak istihbaratı (OSINT)** araçları çok değerlidir ve mevcut açık kaynaklı yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware elde etme, kendi karmaşıklık seviyesine sahip çeşitli yöntemlerle ele alınabilir:

* **Kaynaktan** (geliştiriciler, üreticiler) doğrudan
* Sağlanan talimatlarla **oluşturarak**
* Resmi destek sitelerinden **indirerek**
* Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanma
* [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla doğrudan **bulut depolama** erişimi
* Orta adam saldırısı teknikleriyle güncellemeleri **araştırarak**
* **UART**, **JTAG** veya **PICit** gibi bağlantılar aracılığıyla cihazdan **çıkarma**
* Cihaz iletişimi içindeki güncelleme isteklerini **sızdırma**
* Tanımlama ve **sabitlenmiş güncelleme uç noktalarını** kullanma
* **Bootloader'dan veya ağdan** dump alma
* Tüm diğer yöntemler başarısız olduğunda, uygun donanım araçları kullanarak depolama yongasını **çıkararak ve okuyarak**

## Firmware'in Analizi

Şimdi **firmware'e** sahip olduğunuza göre, onun hakkında bilgi çıkarmak için farklı araçlar kullanmanız gerekmektedir:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok fazla şey bulamazsanız, görüntünün **entropisini** `binwalk -E <bin>` ile kontrol edin, düşük entropi ise muhtemelen şifrelenmemiştir. Yüksek entropi ise muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, firmware içine gömülü **dosyaları çıkarmak için bu araçları kullanabilirsiniz**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ya da dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemi Elde Etme

Önceki yorumlanmış araçlar gibi `binwalk -ev <bin>` ile **dosya sistemini çıkarmış olmanız gerekiyor**.\
Binwalk genellikle bunu, genellikle şunlardan biri olan **dosya sistemi türü adında bir klasörün içine çıkarır**: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkarma

Bazı durumlarda, binwalk'ün imzalarında **dosya sisteminin sihirli baytı olmayabilir**. Bu durumlarda, binwalk'ü kullanarak **dosyanın dosya sistemi ofsetini bulun ve sıkıştırılmış dosya sistemini kesin** ve aşağıdaki adımları kullanarak dosya sistemini **el ile çıkarın**.
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

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Squashfs için (yukarıdaki örnekte kullanıldı)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra "`squashfs-root`" dizininde olacaktır.

* CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

* NAND flaş ile ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını anlamak ve potansiyel güvenlik açıklarını belirlemek için parçalamak esastır. Bu süreç, firmware görüntüsünden değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak adlandırılan) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar, dosya türlerini tanımlamaya, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ve dosya sistem detaylarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Şifreleme durumunu değerlendirmek için **entropy** değeri `binwalk -E <bin>` komutu ile kontrol edilir. Düşük entropy değeri şifreleme eksikliğini, yüksek entropy değeri ise olası şifreleme veya sıkıştırmayı gösterebilir.

**Gömülü dosyaları** çıkarmak için, **file-data-carving-recovery-tools** belgeleri ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sisteminin Çıkarılması

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir, genellikle dosya sistemi türünün adını taşıyan bir dizine (örneğin, squashfs, ubifs) çıkarılır. Ancak, **binwalk** dosya sistemi türünü tanıyamadığında sihirli baytların eksik olması nedeniyle manuel çıkarma gereklidir. Bu, `binwalk`'ın dosya sisteminin ofsetini bulmak için kullanılmasını ve ardından `dd` komutunun dosya sisteminin çıkarılmasını içerir:
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
- İleri analiz için gömülü ikili dosyalar
- Ortak IoT cihazı web sunucuları ve ikili dosyalar

Dosya sistemi içinde hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar bulunmaktadır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalar Üzerinde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodları hem de derlenmiş ikili dosyalar, güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, sömürülebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Dinamik Analiz İçin Firmware Emülasyonu

Firmware'in emüle edilmesi, bir cihazın işleyişinin veya bireysel bir programın **dinamik analizinin** yapılmasını sağlar. Bu yaklaşım, donanım veya mimari bağımlılıklarıyla karşılaşabilir, ancak kök dosya sistemini veya belirli ikili dosyaları, Raspberry Pi gibi mimari ve bitiş düzenine sahip bir cihaza veya önceden oluşturulmuş bir sanal makineye aktarmak, daha fazla test yapmayı kolaylaştırabilir.

### Bireysel İkili Dosyaların Emülasyonu

Tek programları incelemek için programın bitiş düzenini ve CPU mimarisini belirlemek önemlidir.

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

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analiz Araç Seti](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, tam firmware emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

## Uygulamada Dinamik Analiz

Bu aşamada, analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve dosya sistemine erişimi sürdürmek esastır. Emülasyon, donanım etkileşimlerini mükemmel bir şekilde taklit etmeyebilir, bu nedenle zaman zaman emülasyon yeniden başlatmaları gerekebilir. Analiz, dosya sistemine tekrar bakmalı, açığa çıkarılan web sayfalarını ve ağ hizmetlerini kullanmalı ve önyükleme yükleyicisi açıklarını keşfetmelidir. Firmware bütünlük testleri, potansiyel arka kapı açıklarını belirlemek için kritiktir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir işlem veya ikili dosya ile işletim ortamında etkileşimde bulunmayı içerir; gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılarak kesme noktaları belirleme ve bulma ve diğer teknikler aracılığıyla zafiyetleri tanımlama.

## İkili Sömürü ve Kanıt-of-Kavram

Belirlenen zafiyetler için bir PoC geliştirmek, hedef mimariyi derinlemesine anlama ve düşük seviye dillerde programlama gerektirir. Gömülü sistemlerde ikili çalışma zamanı korumaları nadirdir, ancak varsa, Return Oriented Programming (ROP) gibi teknikler gerekebilir.

## Firmware Analizi İçin Hazırlanmış İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla donatılmış firmware güvenlik testi için önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi İçin Hazırlanmış İşletim Sistemleri

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Nesnelerin İnterneti (IoT) cihazlarının güvenlik değerlendirmesi ve penetrasyon testi yapmanıza yardımcı olmak için tasarlanmış bir dağıtımdır. Tüm gerekli araçların yüklü olduğu önceden yapılandırılmış bir ortam sağlayarak size zaman kazandırır.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı gömülü güvenlik testi işletim sistemi, firmware güvenlik testi araçlarıyla önceden yüklenmiş.

## Uygulamada Zafiyetli Firmware

Firmware'deki zafiyetleri keşfetmek için aşağıdaki zafiyetli firmware projelerini bir başlangıç noktası olarak kullanın.

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
