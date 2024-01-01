# Astuces de Stego

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes pour les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans toute votre pile technologique, des API aux applications web et systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Extraction de données de tous les fichiers

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk est un outil de recherche dans les fichiers binaires, comme les images et les fichiers audio, pour les fichiers cachés et les données intégrées.\
Il peut être installé avec `apt`, et le [source](https://github.com/ReFirmLabs/binwalk) est disponible sur Github.\
**Commandes utiles** :\
`binwalk fichier` : Affiche les données intégrées dans le fichier donné\
`binwalk -e fichier` : Affiche et extrait les données du fichier donné\
`binwalk --dd ".*" fichier` : Affiche et extrait les données du fichier donné

### Foremost <a href="#foremost" id="foremost"></a>

Foremost est un programme qui récupère les fichiers en fonction de leurs en-têtes, pieds de page et structures de données internes. Je le trouve particulièrement utile pour traiter les images png. Vous pouvez sélectionner les fichiers que Foremost extraira en modifiant le fichier de configuration dans **/etc/foremost.conf.**\
Il peut être installé avec `apt`, et le [source](https://github.com/korczis/foremost) est disponible sur Github.\
**Commandes utiles :**\
`foremost -i fichier` : extrait les données du fichier donné.

### Exiftool <a href="#exiftool" id="exiftool"></a>

Parfois, des informations importantes sont cachées dans les métadonnées d'une image ou d'un fichier ; exiftool peut être très utile pour visualiser les métadonnées d'un fichier.\
Vous pouvez l'obtenir [ici](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Commandes utiles :**\
`exiftool fichier` : montre les métadonnées du fichier donné

### Exiv2 <a href="#exiv2" id="exiv2"></a>

Un outil similaire à exiftool.\
Il peut être installé avec `apt`, et le [source](https://github.com/Exiv2/exiv2) est disponible sur Github.\
[Site officiel](http://www.exiv2.org/)\
**Commandes utiles :**\
`exiv2 fichier` : montre les métadonnées du fichier donné

### File

Vérifiez le type de fichier que vous avez

### Strings

Extrait les chaînes de caractères du fichier.\
Commandes utiles :\
`strings -n 6 fichier` : Extrait les chaînes avec une longueur minimale de 6\
`strings -n 6 fichier | head -n 20` : Extrait les 20 premières chaînes avec une longueur minimale de 6\
`strings -n 6 fichier | tail -n 20` : Extrait les 20 dernières chaînes avec une longueur minimale de 6\
`strings -e s -n 6 fichier` : Extrait les chaînes de 7 bits\
`strings -e S -n 6 fichier` : Extrait les chaînes de 8 bits\
`strings -e l -n 6 fichier` : Extrait les chaînes de 16 bits (little-endian)\
`strings -e b -n 6 fichier` : Extrait les chaînes de 16 bits (big-endian)\
`strings -e L -n 6 fichier` : Extrait les chaînes de 32 bits (little-endian)\
`strings -e B -n 6 fichier` : Extrait les chaînes de 32 bits (big-endian)

### cmp - Comparaison

Si vous avez une image/audio/vidéo **modifiée**, vérifiez si vous pouvez **trouver l'original exact** sur internet, puis **comparez les deux** fichiers avec :
```
cmp original.jpg stego.jpg -b -l
```
## Extraction de données cachées dans le texte

### Données cachées dans les espaces

Si vous constatez qu'une **ligne de texte** est **plus grande** qu'elle ne devrait l'être, alors des **informations cachées** pourraient être incluses à l'intérieur des **espaces** à l'aide de caractères invisibles.󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
Pour **extraire** les **données**, vous pouvez utiliser : [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extraction de données à partir d'images

### identify

Outil [GraphicMagick](https://imagemagick.org/script/download.php) pour vérifier le type d'image d'un fichier. Vérifie également si l'image est corrompue.
```
./magick identify -verbose stego.jpg
```
Si l'image est endommagée, vous pourriez être capable de la restaurer en ajoutant simplement un commentaire de métadonnées (si elle est très gravement endommagée, cela ne fonctionnera pas) :
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide est un programme de stéganographie qui cache des données dans divers types de fichiers image et audio. Il prend en charge les formats de fichiers suivants : `JPEG, BMP, WAV et AU`. Il est également utile pour extraire des données intégrées et cryptées d'autres fichiers.\
Il peut être installé avec `apt`, et le [source](https://github.com/StefanoDeVuono/steghide) est disponible sur Github.\
**Commandes utiles :**\
`steghide info file` : affiche des informations sur la présence ou non de données intégrées dans un fichier.\
`steghide extract -sf file [--passphrase password]` : extrait les données intégrées d'un fichier \[en utilisant un mot de passe]

Vous pouvez également extraire du contenu de steghide en utilisant le web : [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Bruteforcing** Steghide : [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg est un outil qui peut détecter des données cachées dans les fichiers png et bmp.\
Pour l'installer : `gem install zsteg`. La source est également disponible sur [Github](https://github.com/zed-0xff/zsteg)\
**Commandes utiles :**\
`zsteg -a file` : Exécute chaque méthode de détection sur le fichier donné\
`zsteg -E file` : Extrait les données avec la charge utile donnée (exemple : zsteg -E b4,bgr,msb,xy name.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capable d'une grande variété de trucs simples et avancés, cet outil peut vérifier les métadonnées des fichiers, créer des images transformées, forcer le LSB et plus encore. Consultez `stegoveritas.py -h` pour connaître toutes ses capacités. Exécutez `stegoveritas.py stego.jpg` pour lancer tous les contrôles.

### Stegsolve

Parfois, un message ou un texte caché dans l'image elle-même doit être visualisé en appliquant des filtres de couleur ou en modifiant certains niveaux de couleur. Bien que cela puisse être fait avec quelque chose comme GIMP ou Photoshop, Stegsolve le rend plus facile. C'est un petit outil Java qui applique de nombreux filtres de couleur utiles sur les images ; dans les défis CTF, Stegsolve est souvent un véritable gain de temps.\
Vous pouvez l'obtenir depuis [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
Pour l'utiliser, ouvrez simplement l'image et cliquez sur les boutons `<` `>`.

### FFT

Pour trouver du contenu caché en utilisant la transformation de Fourier rapide :

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

Un programme pour encoder des informations dans des fichiers image et audio via la stéganographie. Il peut stocker les données sous forme de texte en clair ou cryptées.\
Trouvez-le sur [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Obtenez des détails sur un fichier PNG (ou même découvrez s'il est en réalité autre chose !).\
`apt-get install pngcheck` : Installez l'outil\
`pngcheck stego.png` : Obtenez des informations sur le PNG

### Quelques autres outils d'image à mentionner

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [https://github.com/resurrecting-open-source-projects/outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [https://www.openstego.com/](https://www.openstego.com/)
* [https://diit.sourceforge.net/](https://diit.sourceforge.net/)

## Extraire des données des audios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg peut être utilisé pour vérifier l'intégrité des fichiers audio, en rapportant diverses informations sur le fichier, ainsi que toutes les erreurs trouvées.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg est un outil Python3 qui peut cacher des données, en utilisant le bit de poids faible, dans des fichiers wav. Il peut également rechercher et extraire des données de fichiers wav.\
Vous pouvez l'obtenir depuis [Github](https://github.com/ragibson/Steganography#WavSteg)\
Commandes utiles :\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extrait dans un fichier de sortie (en prenant seulement 1 lsb)\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extrait dans un fichier de sortie (en prenant seulement 2 lsb)

### Deepsound

Cachez et vérifiez les informations cryptées avec AES-265 dans les fichiers sonores. Téléchargez depuis [la page officielle](http://jpinsoft.net/deepsound/download.aspx).\
Pour rechercher des informations cachées, exécutez simplement le programme et ouvrez le fichier sonore. Si DeepSound trouve des données cachées, vous devrez fournir le mot de passe pour les déverrouiller.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer est un outil pour visualiser et analyser le contenu des fichiers audio. Il peut être très utile lors de défis de stéganographie audio ; vous pouvez révéler des formes cachées dans les fichiers audio que de nombreux autres outils ne détecteront pas.\
Si vous êtes bloqué, vérifiez toujours le spectrogramme de l'audio. [Site Officiel](https://www.sonicvisualiser.org/)

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
Pour convertir des "1" et "0" binaires en une image appropriée : [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
Pour lire un code QR : [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braille

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **Références**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités qui comptent le plus afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Apprenez le hacking AWS du débutant à l'expert avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
