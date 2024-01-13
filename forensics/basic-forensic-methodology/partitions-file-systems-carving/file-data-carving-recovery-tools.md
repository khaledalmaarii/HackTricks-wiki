<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Outils de Carving & Récupération

Plus d'outils sur [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

L'outil le plus couramment utilisé en forensique pour extraire des fichiers à partir d'images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-le ingérer le fichier pour trouver des fichiers "cachés". Notez qu'Autopsy est conçu pour prendre en charge les images de disque et d'autres types d'images, mais pas les fichiers simples.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** est un outil pour rechercher des fichiers binaires comme des images et des fichiers audio pour des fichiers et des données intégrés.\
Il peut être installé avec `apt`, cependant la [source](https://github.com/ReFirmLabs/binwalk) peut être trouvée sur github.\
**Commandes utiles** :
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous souhaitez rechercher des types de fichiers spécifiques, décommentez-les. Si vous ne décommentez rien, foremost recherchera les types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** est un autre outil qui peut être utilisé pour trouver et extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter du fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez qu'il extrait.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Cet outil est inclus dans Kali, mais vous pouvez le trouver ici : [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Cet outil peut analyser une image et va **extraire des pcaps** à l'intérieur, **des informations réseau (URLs, domaines, IPs, MACs, mails)** et plus de **fichiers**. Vous avez seulement à faire :
```
bulk_extractor memory.img -o out_folder
```
Parcourez **toutes les informations** que l'outil a recueillies (mots de passe ?), **analysez** les **paquets** (lire[ **Analyse de Pcaps**](../pcap-inspection/)), recherchez des **domaines étranges** (domaines liés à des **malwares** ou **inexistants**).

## PhotoRec

Vous pouvez le trouver sur [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Il est disponible en versions GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que vous souhaitez que PhotoRec recherche.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Consultez le [code](https://code.google.com/archive/p/binvis/) et la [page web de l'outil](https://binvis.io/#/).

### Fonctionnalités de BinVis

* Visualisation et interaction avec la **structure du fichier**
* Plusieurs graphiques pour différents points d'intérêt
* Concentration sur des parties d'un échantillon
* **Visualisation des chaînes de caractères et des ressources**, dans les exécutables PE ou ELF par exemple
* Obtention de **modèles** pour la cryptanalyse de fichiers
* **Détection** d'algorithmes de packers ou d'encodeurs
* **Identification** de stéganographie par des modèles
* **Différenciation visuelle** de fichiers binaires

BinVis est un excellent **point de départ pour se familiariser avec une cible inconnue** dans un scénario de boîte noire.

# Outils spécifiques de Data Carving

## FindAES

Recherche des clés AES en cherchant leurs plannings de clés. Capable de trouver des clés de 128, 192 et 256 bits, comme celles utilisées par TrueCrypt et BitLocker.

Téléchargez [ici](https://sourceforge.net/projects/findaes/).

# Outils complémentaires

Vous pouvez utiliser [**viu**](https://github.com/atanunq/viu) pour voir des images depuis le terminal.\
Vous pouvez utiliser l'outil de ligne de commande Linux **pdftotext** pour transformer un PDF en texte et le lire.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder surveille votre surface d'attaque, effectue des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
