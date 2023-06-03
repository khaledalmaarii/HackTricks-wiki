# Acquisition d'image et montage

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Acquisition

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

dcfldd est une version améliorée de dd, qui permet de copier des données de manière plus rapide et plus efficace. Il offre également des fonctionnalités supplémentaires telles que la vérification de l'intégrité des données et la création de hachages de fichiers. Pour utiliser dcfldd, vous pouvez utiliser la commande suivante:

```
dcfldd if=/chemin/vers/image of=/dev/sdX bs=512 conv=noerror,sync hash=md5,sha256 hashwindow=10M hashlog=/chemin/vers/fichier_de_logs
```

- `if`: spécifie le chemin vers l'image que vous souhaitez copier
- `of`: spécifie le périphérique de destination sur lequel vous souhaitez copier l'image
- `bs`: spécifie la taille du bloc de données à copier
- `conv`: spécifie les options de conversion à utiliser lors de la copie des données
- `hash`: spécifie les algorithmes de hachage à utiliser pour vérifier l'intégrité des données
- `hashwindow`: spécifie la taille de la fenêtre de hachage
- `hashlog`: spécifie le chemin vers le fichier de logs dans lequel les hachages seront enregistrés.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Vous pouvez [**télécharger FTK Imager ici**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Vous pouvez générer une image de disque en utilisant les outils [**ewf**](https://github.com/libyal/libewf).
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
## Montage

### Plusieurs types

Sous **Windows**, vous pouvez essayer d'utiliser la version gratuite d'Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) pour **monter l'image de la forensique**.

### Raw
```bash
#Get file type
file evidence.img 
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

L'Expert Witness Compression Format (EWF) est un format de fichier utilisé pour stocker une image disque. Il est souvent utilisé dans les enquêtes judiciaires pour acquérir des preuves numériques. EWF est capable de compresser l'image disque, ce qui permet de réduire la taille du fichier et de faciliter le stockage et le transfert des données. 

Pour monter une image EWF, vous pouvez utiliser le logiciel `ewfmount`. Ce logiciel permet de monter l'image EWF en tant que périphérique de blocs, ce qui permet d'accéder aux données contenues dans l'image comme si elles étaient stockées sur un disque dur physique. 

Pour monter une image EWF, vous pouvez utiliser la commande suivante :

```
ewfmount image.E01 /mnt/image/
```

Cette commande monte l'image `image.E01` dans le répertoire `/mnt/image/`. Vous pouvez ensuite accéder aux données contenues dans l'image en naviguant dans le répertoire `/mnt/image/`. 

Une fois que vous avez terminé d'utiliser l'image, vous pouvez la démonter en utilisant la commande suivante :

```
ewfmount -u /mnt/image/
```

Cette commande démonte l'image montée dans le répertoire `/mnt/image/`.
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

Il s'agit d'une application Windows permettant de monter des volumes. Vous pouvez la télécharger ici [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Erreurs

* **`cannot mount /dev/loop0 read-only`** dans ce cas, vous devez utiliser les indicateurs **`-o ro,norecovery`**
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** dans ce cas, le montage a échoué car le décalage du système de fichiers est différent de celui de l'image de disque. Vous devez trouver la taille du secteur et le secteur de départ:
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
Notez que la taille de secteur est de **512** et le début est de **2048**. Ensuite, montez l'image comme ceci:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
