# Astuces de Stego

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Groupe de sécurité Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **Extraction de données à partir de fichiers**

### **Binwalk**

Un outil pour rechercher des fichiers binaires à la recherche de fichiers et de données cachés. Il est installé via `apt` et son code source est disponible sur [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Récupère les fichiers en fonction de leurs en-têtes et pieds de page, utile pour les images png. Installé via `apt` avec sa source sur [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Aide à visualiser les métadonnées des fichiers, disponible [ici](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Similaire à exiftool, pour visualiser les métadonnées. Installable via `apt`, source sur [GitHub](https://github.com/Exiv2/exiv2), et possède un [site officiel](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Fichier**

Identifier le type de fichier avec lequel vous travaillez.

### **Chaînes de caractères**

Extrait les chaînes de caractères lisibles des fichiers, en utilisant divers paramètres d'encodage pour filtrer la sortie.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Comparaison (cmp)**

Utile pour comparer un fichier modifié avec sa version originale trouvée en ligne.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extraction de données cachées dans du texte**

### **Données cachées dans les espaces**

Les caractères invisibles dans des espaces apparemment vides peuvent cacher des informations. Pour extraire ces données, visitez [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extraction de données à partir d'images**

### **Identification des détails de l'image avec GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) sert à déterminer les types de fichiers d'image et à identifier d'éventuelles corruptions. Exécutez la commande ci-dessous pour inspecter une image :
```bash
./magick identify -verbose stego.jpg
```
Pour tenter de réparer une image endommagée, ajouter un commentaire de métadonnées pourrait aider :
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide pour la dissimulation de données**

Steghide facilite la dissimulation de données dans les fichiers `JPEG, BMP, WAV et AU`, capable d'incorporer et d'extraire des données chiffrées. L'installation est simple en utilisant `apt`, et son [code source est disponible sur GitHub](https://github.com/StefanoDeVuono/steghide).

**Commandes :**

* `steghide info fichier` révèle si un fichier contient des données cachées.
* `steghide extract -sf fichier [--mot de passe password]` extrait les données cachées, mot de passe en option.

Pour une extraction basée sur le web, visitez [ce site web](https://futureboy.us/stegano/decinput.html).

**Attaque par force brute avec Stegcracker :**

* Pour tenter le craquage de mot de passe sur Steghide, utilisez [stegcracker](https://github.com/Paradoxis/StegCracker.git) comme suit :
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg pour les fichiers PNG et BMP**

zsteg se spécialise dans la découverte de données cachées dans les fichiers PNG et BMP. L'installation se fait via `gem install zsteg`, avec sa [source sur GitHub](https://github.com/zed-0xff/zsteg).

**Commandes:**

* `zsteg -a fichier` applique toutes les méthodes de détection sur un fichier.
* `zsteg -E fichier` spécifie une charge utile pour l'extraction de données.

### **StegoVeritas et Stegsolve**

**stegoVeritas** vérifie les métadonnées, effectue des transformations d'image, et applique la force brute LSB, entre autres fonctionnalités. Utilisez `stegoveritas.py -h` pour une liste complète des options et `stegoveritas.py stego.jpg` pour exécuter toutes les vérifications.

**Stegsolve** applique divers filtres de couleur pour révéler des textes ou des messages cachés dans les images. Il est disponible sur [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT pour la détection de contenu caché**

Les techniques de Transformée de Fourier Rapide (FFT) peuvent révéler du contenu dissimulé dans les images. Des ressources utiles incluent:

* [Démo EPFL](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic sur GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy pour les fichiers audio et image**

Stegpy permet d'incorporer des informations dans des fichiers image et audio, prenant en charge des formats tels que PNG, BMP, GIF, WebP et WAV. Il est disponible sur [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck pour l'analyse des fichiers PNG**
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Outils supplémentaires pour l'analyse d'images**

Pour une exploration plus approfondie, envisagez de visiter :

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Analyse du Niveau d'Erreur d'Image](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Extraction de données à partir d'audios**

La **stéganographie audio** offre une méthode unique pour dissimuler des informations dans des fichiers sonores. Différents outils sont utilisés pour incorporer ou récupérer du contenu caché.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide est un outil polyvalent conçu pour cacher des données dans des fichiers JPEG, BMP, WAV et AU. Des instructions détaillées sont fournies dans la [documentation des astuces de stéganographie](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Cet outil est compatible avec une variété de formats, y compris PNG, BMP, GIF, WebP et WAV. Pour plus d'informations, consultez la [section Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg est essentiel pour évaluer l'intégrité des fichiers audio, mettant en lumière des informations détaillées et identifiant toute anomalie.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg excelle dans la dissimulation et l'extraction de données dans les fichiers WAV en utilisant la stratégie du bit de poids faible. Il est accessible sur [GitHub](https://github.com/ragibson/Steganography#WavSteg). Les commandes incluent :
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permet le chiffrement et la détection d'informations dans des fichiers audio en utilisant AES-256. Il peut être téléchargé depuis [la page officielle](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Un outil inestimable pour l'inspection visuelle et analytique des fichiers audio, Sonic Visualizer peut révéler des éléments cachés indétectables par d'autres moyens. Visitez le [site officiel](https://www.sonicvisualiser.org/) pour en savoir plus.

### **Tonalités DTMF - Tonalités de composition**

La détection des tonalités DTMF dans les fichiers audio peut être réalisée à l'aide d'outils en ligne tels que [ce détecteur DTMF](https://unframework.github.io/dtmf-detect/) et [DialABC](http://dialabc.com/sound/detect/index.html).

## **Autres Techniques**

### **Longueur Binaire SQRT - Code QR**

Des données binaires qui donnent un nombre entier en racine carrée peuvent représenter un code QR. Utilisez cet extrait de code pour vérifier :
```python
import math
math.sqrt(2500) #50
```
### **Traduction en français**

Pour la conversion binaire en image, consultez [dcode](https://www.dcode.fr/binary-image). Pour lire les codes QR, utilisez [ce lecteur de codes-barres en ligne](https://online-barcode-reader.inliteresearch.com/).

### **Traduction en Braille**

Pour traduire le Braille, le [traducteur Braille Branah](https://www.branah.com/braille-translator) est une excellente ressource.

## **Références**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**Groupe de sécurité Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
