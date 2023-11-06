# छवि प्राप्ति और माउंट

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT संग्रह**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>

## प्राप्ति

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd is a command-line tool used for creating and verifying disk images. It is an enhanced version of the dd command and provides additional features such as hashing, progress reporting, and error handling.

To acquire an image using dcfldd, follow these steps:

1. Identify the source device or partition that you want to acquire an image from. You can use the `fdisk -l` command to list all available devices and partitions.

2. Determine the destination where you want to save the acquired image. Make sure you have enough storage space available.

3. Open a terminal and run the following command to acquire the image:

   ```
   dcfldd if=/dev/source of=/path/to/destination hash=md5 hashlog=/path/to/hashlog.log
   ```

   Replace `/dev/source` with the source device or partition and `/path/to/destination` with the desired destination path. The `hash` parameter specifies the hashing algorithm to use (e.g., md5, sha1, sha256), and the `hashlog` parameter specifies the path to save the hash log file.

4. Wait for the acquisition process to complete. dcfldd will display progress information, including the amount of data transferred and the estimated time remaining.

5. Once the acquisition is finished, verify the integrity of the acquired image by comparing the hash value with the original source. You can use the `md5sum` or `sha256sum` command to calculate the hash value of both the source and acquired image, and then compare them.

By following these steps, you can use dcfldd to acquire disk images for forensic analysis or data recovery purposes.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK इमेजर

आप यहाँ से [**FTK इमेजर डाउनलोड कर सकते हैं**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1)।
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

आप [**ewf टूल्स**](https://github.com/libyal/libewf) का उपयोग करके एक डिस्क इमेज बना सकते हैं।
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
## माउंट

### कई प्रकार

**Windows** में आप फ्री संस्करण का उपयोग करके Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) का प्रयास कर सकते हैं ताकि आप **फोरेंसिक इमेज को माउंट** कर सकें।

### रॉ
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

EWF (EnCase Evidence File) is a file format used for forensic disk imaging. It is commonly used in digital forensics to create a forensic image of a disk or a partition. The EWF format ensures the integrity and authenticity of the acquired image by storing the data in a forensically sound manner.

To acquire an image using EWF, you can follow these steps:

1. Identify the disk or partition you want to acquire an image of.
2. Use a forensic imaging tool that supports EWF, such as EnCase or FTK Imager.
3. Select the appropriate options in the imaging tool to create an EWF image.
4. Specify the destination where you want to save the image file.
5. Start the imaging process and wait for it to complete.

Once the image acquisition is complete, you can mount the EWF image to access its contents. This allows you to analyze the acquired data without modifying the original disk or partition.

To mount an EWF image, you can use tools like Arsenal Image Mounter or OSFMount. These tools create a virtual drive that represents the contents of the EWF image. You can then access the files and folders within the image as if they were on a physical disk.

Mounting an EWF image provides a convenient way to perform forensic analysis on the acquired data. It allows you to examine the image using forensic tools and techniques, without the risk of accidentally modifying or altering the original evidence.

Remember to always follow proper forensic procedures and guidelines when acquiring and analyzing digital evidence. This ensures the integrity and admissibility of the evidence in legal proceedings.
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

यह एक Windows एप्लिकेशन है जिसका उपयोग वॉल्यूम को माउंट करने के लिए किया जाता है। आप इसे यहाँ से डाउनलोड कर सकते हैं [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### त्रुटियाँ

* **`cannot mount /dev/loop0 read-only`** इस मामले में आपको फ्लैग **`-o ro,norecovery`** का उपयोग करना होगा।
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** इस मामले में माउंट विफल हुआ क्योंकि फ़ाइल सिस्टम का ऑफ़सेट डिस्क इमेज के ऑफ़सेट से अलग है। आपको सेक्टर साइज और स्टार्ट सेक्टर का पता लगाना होगा:
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
ध्यान दें कि सेक्टर आकार **512** है और प्रारंभ **2048** है। फिर इस तरह से इमेज को माउंट करें:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **फॉलो** करें या **Twitter** पर [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके।

</details>
