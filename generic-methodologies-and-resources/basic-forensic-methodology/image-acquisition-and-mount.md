# Görüntü Edinme ve Bağlama

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? Ya da en son PEASS sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **[💬](https://emojipedia.org/speech-balloon/) Discord grubuna** katılın veya [telegram grubuna](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak [hacktricks deposuna](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud deposuna](https://github.com/carlospolop/hacktricks-cloud) PR göndererek katkıda bulunun.**

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Edinme

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

FTK imajını [**buradan indirebilirsiniz**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Disk imajı oluşturmak için [**ewf araçları**](https://github.com/libyal/libewf) kullanabilirsiniz.
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

**Windows** üzerinde, **forensik görüntüyü bağlamak** için Arsenal Image Mounter'ın ücretsiz sürümünü deneyebilirsiniz ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)).

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF, or Expert Witness Format, is a file format used to store disk images. EWF files consist of two parts: the metadata information and the actual data. The metadata contains information about the acquisition process, while the data part contains the actual image of the disk. EWF files can be mounted using tools like ewfmount, which allows investigators to access the contents of the disk image without modifying the original data.
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

Windows Uygulamasıdır ve birimleri bağlamak için kullanılır. İndirebilirsiniz buradan [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Hatalar

* **`/dev/loop0 salt okunur olarak bağlanamaz`** bu durumda **`-o ro,norecovery`** bayraklarını kullanmanız gerekmektedir.
* **`yanlış fs türü, kötü seçenek, /dev/loop0 üzerinde kötü süper blok, eksik kod sayfası veya yardımcı program, veya diğer hata.`** bu durumda bağlamanın başarısız olduğu çünkü dosya sisteminin ofseti disk imajının ofsetinden farklıdır. Sektör boyutunu ve Başlangıç sektörünü bulmanız gerekmektedir:
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
Sektör boyutunun **512** ve başlangıcın **2048** olduğunu unutmayın. Ardından resmi şu şekilde bağlayın:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? **Şirketinizi HackTricks'te reklamını görmek ister misiniz**? ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks swag'ini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'larınızı [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud)** gönderin.

</details>
