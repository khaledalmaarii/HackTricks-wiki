# Bildaufnahme & Mounten

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

## Erfassung

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd is a command-line tool that is used for creating and verifying disk images. It is an enhanced version of the dd command and provides additional features such as hashing, progress reporting, and error handling.

To acquire an image using dcfldd, you can use the following command:

```
dcfldd if=/dev/sda of=image.dd
```

This command will create an image of the `/dev/sda` device and save it as `image.dd`. You can replace `/dev/sda` with the appropriate device name for the disk you want to acquire.

To verify the integrity of an image using dcfldd, you can use the following command:

```
dcfldd if=image.dd vf=image.dd
```

This command will compare the hash values of the original image (`image.dd`) and the acquired image (`image.dd`). If the hash values match, it indicates that the image was acquired successfully without any errors.

dcfldd is a powerful tool that can be used in forensic investigations to acquire and verify disk images. It is important to use it correctly and understand its features to ensure accurate and reliable results.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Sie können den FTK Imager [**hier herunterladen**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Sie können ein Festplattenabbild mit den [**ewf-Tools**](https://github.com/libyal/libewf) generieren.
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
## Mounten

### Verschiedene Arten

Unter **Windows** können Sie versuchen, die kostenlose Version von Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) zu verwenden, um das forensische Image zu **mounten**.

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF (Expert Witness Format) ist ein Dateiformat, das häufig für die forensische Erfassung von Abbildern von Festplatten oder anderen Speichermedien verwendet wird. Es ermöglicht die Erstellung einer bitgenauen Kopie des Originaldatenträgers, einschließlich ungenutzter Bereiche und gelöschter Dateien.

Die Verwendung von EWF bietet mehrere Vorteile. Erstens ermöglicht es die Erfassung von Abbildern von Speichermedien, ohne den Originaldatenträger zu beeinträchtigen. Zweitens ermöglicht es die Komprimierung des Abbilds, um Speicherplatz zu sparen. Drittens ermöglicht es die Verwendung von Hash-Algorithmen, um die Integrität des Abbilds zu überprüfen.

Um ein EWF-Abbild zu erstellen, wird eine spezielle Software verwendet, die den Datenträger sektorweise ausliest und die Daten in das EWF-Format konvertiert. Das EWF-Abbild kann dann auf einem separaten Speichermedium gespeichert werden und für forensische Analysen verwendet werden.

Um ein EWF-Abbild zu mounten und darauf zuzugreifen, kann die Software "ewfmount" verwendet werden. Diese Software ermöglicht es, das EWF-Abbild als virtuelles Laufwerk zu mounten, so dass darauf wie auf eine normale Festplatte zugegriffen werden kann.

Die Verwendung von EWF bei der forensischen Analyse ist wichtig, um die Integrität der Beweise zu gewährleisten und sicherzustellen, dass keine Änderungen an den Originaldaten vorgenommen werden. Es ist auch wichtig, die richtigen Werkzeuge und Verfahren zu verwenden, um sicherzustellen, dass das EWF-Abbild korrekt erstellt und analysiert wird.
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

Es handelt sich um eine Windows-Anwendung zum Einbinden von Volumes. Sie können sie hier herunterladen [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Fehler

* **`kann /dev/loop0 nicht schreibgeschützt einbinden`** in diesem Fall müssen Sie die Flags **`-o ro,norecovery`** verwenden
* **`falscher Dateisystemtyp, ungültige Option, ungültiger Superblock auf /dev/loop0, fehlende Codepage oder Hilfsprogramm oder anderer Fehler.`** in diesem Fall ist das Einbinden fehlgeschlagen, da der Offset des Dateisystems von dem des Disk-Images abweicht. Sie müssen die Sektorgröße und den Startsektor finden:
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
Beachten Sie, dass die Sektorgröße **512** und der Start **2048** sind. Mounten Sie das Image dann wie folgt:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
