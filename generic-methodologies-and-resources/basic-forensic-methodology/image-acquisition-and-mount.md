# Pozyskiwanie i Montowanie Obrazu

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do [repozytorium hacktricks](https://github.com/carlospolop/hacktricks) i [repozytorium hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Pozyskiwanie

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

Możesz [**pobrać obraz FTK stąd**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Możesz wygenerować obraz dysku za pomocą [**narzędzi ewf**](https://github.com/libyal/libewf).
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
## Montowanie

### Kilka typów

W systemie **Windows** można spróbować skorzystać z darmowej wersji narzędzia Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)), aby **zamontować obraz z dziedziny informatyki śledczej**.

### Surowy
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF
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

To aplikacja Windows do montowania woluminów. Możesz ją pobrać tutaj [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Błędy

* **`nie można zamontować /dev/loop0 tylko do odczytu`** w tym przypadku należy użyć flag **`-o ro,norecovery`**
* **`zły typ systemu plików, zła opcja, zły superblok na /dev/loop0, brak strony kodowej lub programu pomocniczego, lub inny błąd.`** w tym przypadku montaż nie powiódł się, ponieważ przesunięcie systemu plików jest inne niż obrazu dysku. Musisz znaleźć rozmiar sektora i sektor początkowy:
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
Zauważ, że rozmiar sektora wynosi **512**, a początek to **2048**. Następnie zamontuj obraz w ten sposób:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do [repozytorium hacktricks](https://github.com/carlospolop/hacktricks) i [repozytorium hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
