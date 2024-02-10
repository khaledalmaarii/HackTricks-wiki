# Görüntü Edinme ve Bağlama

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Edinme

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
dcfldd, a variant of the dd command, is a powerful tool used for data acquisition and imaging in forensic investigations. It is commonly used to create bit-by-bit copies of disk images or individual files. The advantage of using dcfldd over dd is that it provides additional features such as on-the-fly hashing, progress reporting, and error handling.

dcfldd can be used to acquire images from various sources, including physical disks, logical volumes, and network streams. It supports multiple input and output formats, allowing for flexibility in the acquisition process. The tool also provides options for verifying the integrity of the acquired images by comparing hash values.

To use dcfldd, you need to specify the input and output devices or files. You can also configure additional options such as block size, hash algorithm, and progress reporting. Once the acquisition process is complete, you can analyze the acquired image using forensic tools to extract valuable information.

Overall, dcfldd is a reliable and efficient tool for acquiring disk images and files in forensic investigations. Its additional features make it a preferred choice for professionals in the field.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

FTK imager'i [**buradan indirebilirsiniz**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

[**ewf araçları**](https://github.com/libyal/libewf) kullanarak bir disk imajı oluşturabilirsiniz.
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## Mount

### Çeşitli türler

**Windows** üzerinde, **forensik imajı bağlamak** için Arsenal Image Mounter'ın ücretsiz sürümünü kullanmayı deneyebilirsiniz ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)).

### Ham (Raw)
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF (EnCase Evidence File) bir disk imajı formatıdır. Bu format, disk imajının bütünlüğünü korumak için kullanılır ve veri sızıntısı riskini en aza indirir. EWF formatı, birçok popüler dijital inceleme aracı tarafından desteklenir ve genellikle adli bilişim çalışmalarında kullanılır.

EWF dosyası, bir veya daha fazla fiziksel veya mantıksal disk bölümünün tam bir kopyasını içerir. Bu dosya, disk imajının doğruluğunu ve bütünlüğünü sağlamak için karma kontrol (hash) değerleriyle korunur. EWF formatı, disk imajının orijinalinden değişiklik yapılmasını önler ve adli bilişim analizlerinde güvenilir sonuçlar elde etmek için önemlidir.

EWF dosyasını oluşturmak için birkaç farklı yöntem vardır. Bunlardan biri, fiziksel bir disk veya disk bölümünün doğrudan bir EWF dosyasına kopyalanmasıdır. Diğer bir yöntem ise, bir disk imajının E01 formatında oluşturulması ve ardından EWF formatına dönüştürülmesidir.

EWF dosyasını incelemek veya analiz etmek için, öncelikle bu dosyayı bir disk imajı olarak "bağlamak" gerekmektedir. Bu işlem, EWF dosyasını bir sanal disk olarak monte etmek veya bir disk imajı aracılığıyla erişmek şeklinde gerçekleştirilebilir. Ardından, çeşitli adli bilişim araçları kullanılarak dosya sistemi ve veri analizi yapılabilir.

EWF formatı, adli bilişim çalışmalarında disk imajlarının güvenli ve doğru bir şekilde elde edilmesini sağlar. Bu nedenle, adli bilişim uzmanları ve diğer güvenlik profesyonelleri tarafından sıklıkla tercih edilen bir yöntemdir.
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

Bu, birimleri bağlamak için bir Windows Uygulamasıdır. İndirebilirsiniz buradan [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Hatalar

* **`/dev/loop0 salt okunur şekilde bağlanamıyor`** bu durumda **`-o ro,norecovery`** bayraklarını kullanmanız gerekmektedir.
* **`yanlış fs türü, hatalı seçenek, /dev/loop0 üzerinde hatalı süper blok, eksik kod sayfası veya yardımcı program veya başka bir hata.`** bu durumda bağlama, dosya sistemi ofseti disk görüntüsünden farklı olduğu için başarısız oldu. Sektör boyutunu ve Başlangıç sektörünü bulmanız gerekmektedir.
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
Not: Sektör boyutu **512** ve başlangıç **2048** olarak belirtilmiştir. Ardından görüntüyü şu şekilde bağlayın:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
