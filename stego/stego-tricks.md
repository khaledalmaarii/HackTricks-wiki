# Astuces de Stego

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Extraction de données de tous les fichiers

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk est un outil de recherche de fichiers binaires, tels que des images et des fichiers audio, pour trouver des fichiers et des données cachés.\
Il peut être installé avec `apt`, et la [source](https://github.com/ReFirmLabs/binwalk) peut être trouvée sur Github.\
**Commandes utiles**:\
`binwalk file` : Affiche les données intégrées dans le fichier donné\
`binwalk -e file` : Affiche et extrait les données du fichier donné\
`binwalk --dd ".*" file` : Affiche et extrait les données du fichier donné

### Foremost <a href="#foremost" id="foremost"></a>

Foremost est un programme qui récupère des fichiers en fonction de leurs en-têtes, de leurs pieds de page et de leurs structures de données internes. Je le trouve particulièrement utile lorsqu'il s'agit d'images png. Vous pouvez sélectionner les fichiers que Foremost extraira en modifiant le fichier de configuration dans **/etc/foremost.conf.**\
Il peut être installé avec `apt`, et la [source](https://github.com/korczis/foremost) peut être trouvée sur Github.\
**Commandes utiles:**\
`foremost -i file` : extrait les données du fichier donné.

### Exiftool <a href="#exiftool" id="exiftool"></a>

Parfois, des informations importantes sont cachées dans les métadonnées d'une image ou d'un fichier ; exiftool peut être très utile pour afficher les métadonnées du fichier.\
Vous pouvez l'obtenir [ici](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Commandes utiles:**\
`exiftool file` : affiche les métadonnées du fichier donné

### Exiv2 <a href="#exiv2" id="exiv2"></a>

Un outil similaire à exiftool.\
Il peut être installé avec `apt`, et la [source](https://github.com/Exiv2/exiv2) peut être trouvée sur Github.\
[Site officiel](http://www.exiv2.org/)\
**Commandes utiles:**\
`exiv2 file` : affiche les métadonnées du fichier donné

### File

Vérifiez quel type de fichier vous avez

### Strings

Extrait les chaînes de caractères du fichier.\
Commandes utiles:\
`strings -n 6 file`: Extrait les chaînes de caractères d'une longueur minimale de 6\
`strings -n 6 file | head -n 20`: Extrait les 20 premières chaînes de caractères d'une longueur minimale de 6\
`strings -n 6 file | tail -n 20`: Extrait les 20 dernières chaînes de caractères d'une longueur minimale de 6\
`strings -e s -n 6 file`: Extrait les chaînes de caractères 7 bits\
`strings -e S -n 6 file`: Extrait les chaînes de caractères 8 bits\
`strings -e l -n 6 file`: Extrait les chaînes de caractères 16 bits (little-endian)\
`strings -e b -n 6 file`: Extrait les chaînes de caractères 16 bits (big-endian)\
`strings -e L -n 6 file`: Extrait les chaînes de caractères 32 bits (little-endian)\
`strings -e B -n 6 file`: Extrait les chaînes de caractères 32 bits (big-endian)

### cmp - Comparaison

Si vous avez une image/audio/vidéo **modifiée**, vérifiez si vous pouvez **trouver l'originale exacte** sur internet, puis **comparez les deux** fichiers avec:
```
cmp original.jpg stego.jpg -b -l
```
## Extraction de données cachées dans du texte

### Données cachées dans les espaces

Si vous constatez qu'une **ligne de texte** est **plus grande** qu'elle ne devrait l'être, il est possible que des **informations cachées** soient incluses à l'intérieur des **espaces** à l'aide de caractères invisibles.󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
Pour **extraire** les **données**, vous pouvez utiliser : [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extraction de données à partir d'images

### identify

Outil [GraphicMagick](https://imagemagick.org/script/download.php) pour vérifier le type d'image d'un fichier. Vérifie également si l'image est corrompue.
```
./magick identify -verbose stego.jpg
```
Si l'image est endommagée, vous pouvez peut-être la restaurer en ajoutant simplement un commentaire de métadonnées (si elle est très endommagée, cela ne fonctionnera pas) :
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide est un programme de stéganographie qui cache des données dans différents types de fichiers image et audio. Il prend en charge les formats de fichier suivants : `JPEG, BMP, WAV et AU`. Il est également utile pour extraire des données intégrées et chiffrées à partir d'autres fichiers.\
Il peut être installé avec `apt`, et la [source](https://github.com/StefanoDeVuono/steghide) peut être trouvée sur Github.\
**Commandes utiles :**\
`steghide info fichier` : affiche des informations sur la présence ou non de données intégrées dans un fichier.\
`steghide extract -sf fichier [--passphrase mot de passe]` : extrait les données intégrées d'un fichier \[en utilisant un mot de passe]

Vous pouvez également extraire le contenu de steghide en utilisant le web : [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Bruteforcer** Steghide : [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <fichier> [<liste de mots>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg est un outil qui peut détecter des données cachées dans des fichiers png et bmp.\
Pour l'installer : `gem install zsteg`. La source peut également être trouvée sur [Github](https://github.com/zed-0xff/zsteg)\
**Commandes utiles :**\
`zsteg -a fichier` : Exécute chaque méthode de détection sur le fichier donné\
`zsteg -E fichier` : Extrait les données avec la charge utile donnée (exemple : zsteg -E b4,bgr,msb,xy nom.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capable d'une grande variété de trucs simples et avancés, cet outil peut vérifier les métadonnées des fichiers, créer des images transformées, forcer le LSB, et plus encore. Consultez `stegoveritas.py -h` pour connaître toutes ses fonctionnalités. Exécutez `stegoveritas.py stego.jpg` pour exécuter toutes les vérifications.

### Stegsolve

Parfois, il y a un message ou un texte caché dans l'image elle-même qui, pour le visualiser, doit avoir des filtres de couleur appliqués, ou certains niveaux de couleur modifiés. Bien que vous puissiez le faire avec quelque chose comme GIMP ou Photoshop, Stegsolve facilite la tâche. C'est un petit outil Java qui applique de nombreux filtres de couleur utiles sur les images ; dans les défis CTF, Stegsolve est souvent un véritable gain de temps.\
Vous pouvez l'obtenir depuis [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
Pour l'utiliser, il suffit d'ouvrir l'image et de cliquer sur les boutons `<` `>`.

### FFT

Pour trouver du contenu caché en utilisant la transformée de Fourier rapide :

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

Un programme pour encoder des informations dans des fichiers image et audio par le biais de la stéganographie. Il peut stocker les données soit en texte brut, soit chiffrées.\
Trouvez-le sur [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Obtenez des détails sur un fichier PNG (ou découvrez même s'il s'agit en réalité d'autre chose !).\
`apt-get install pngcheck` : Installe l'outil\
`pngcheck stego.png` : Obtenez des informations sur le PNG

### D'autres outils d'image qui méritent d'être mentionnés

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Extraction de données à partir de fichiers audio

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg peut être utilisé pour vérifier l'intégrité des fichiers audio, en signalant diverses informations sur le fichier, ainsi que les erreurs éventuelles qu'il trouve.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg est un outil Python3 qui peut cacher des données, en utilisant le bit de poids le moins élevé, dans des fichiers wav. Il peut également rechercher et extraire des données à partir de fichiers wav.\
Vous pouvez l'obtenir depuis [Github](https://github.com/ragibson/Steganography#WavSteg)\
Commandes utiles :\
`python3 WavSteg.py -r -b 1 -s fichier_audio -o fichier_sortie` : Extrait vers un fichier de sortie (en ne prenant que 1 bit de poids le moins élevé)\
`python3 WavSteg.py -r -b 2 -s fichier_audio -o fichier_sortie` : Extrait vers un fichier de sortie (en ne prenant que 2 bits de poids le moins élevé)

### Deepsound

Cachez, et vérifiez, des informations chiffrées avec AES-265 dans des fichiers audio. Téléchargez depuis [la page officielle](http://jpinsoft.net/deepsound/download.aspx).\
Pour rechercher des informations cachées, lancez simplement le programme et ouvrez le fichier audio. Si DeepSound trouve des données cachées, vous devrez fournir le mot de passe pour les déverrouiller.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer est un outil pour visualiser et analyser le contenu des fichiers audio. Il peut être très utile lors de défis de stéganographie audio ; vous pouvez révéler des formes cachées dans les fichiers audio que de nombreux autres outils ne détecteront pas.\
Si vous êtes bloqué, vérifiez toujours le spectrogramme de l'audio. [Site officiel](https://www.sonicvisualiser.org/)

### Tons DTMF - Tons de numérotation

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)
## Autres astuces

### Longueur binaire SQRT - Code QR

Si vous recevez des données binaires avec une longueur SQRT d'un nombre entier, cela pourrait être une sorte de code QR :
```
import math
math.sqrt(2500) #50
```
Pour convertir les "1" et les "0" binaires en une image appropriée : [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
Pour lire un code QR : [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braille

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **Références**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
