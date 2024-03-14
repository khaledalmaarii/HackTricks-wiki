# Outils de récupération et de sculpture de fichiers/données

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Groupe de sécurité Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Outils de récupération et de sculpture

Plus d'outils sur [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

L'outil le plus couramment utilisé en informatique légale pour extraire des fichiers à partir d'images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-lui ingérer le fichier pour trouver des fichiers "cachés". Notez qu'Autopsy est conçu pour prendre en charge les images de disque et d'autres types d'images, mais pas les fichiers simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** est un outil d'analyse des fichiers binaires pour trouver du contenu intégré. Il est installable via `apt` et son code source se trouve sur [GitHub](https://github.com/ReFirmLabs/binwalk).

**Commandes utiles** :
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous voulez simplement rechercher des fichiers spécifiques, décommentez-les. Si vous ne décommentez rien, foremost recherchera les types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** est un autre outil qui peut être utilisé pour trouver et extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Cet outil est inclus dans kali mais vous pouvez le trouver ici: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Cet outil peut scanner une image et va **extraire des pcaps** à l'intérieur, des **informations réseau (URL, domaines, IPs, MAC, adresses e-mail)** et plus de **fichiers**. Vous n'avez qu'à faire:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

Vous pouvez le trouver sur [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Il est livré avec des versions GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que vous souhaitez que PhotoRec recherche.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Consultez le [code](https://code.google.com/archive/p/binvis/) et la [page web de l'outil](https://binvis.io/#/).

#### Caractéristiques de BinVis

* Visualiseur de **structure** visuelle et active
* Multiples graphiques pour différents points de focalisation
* Focalisation sur des parties d'un échantillon
* **Voir des chaînes et des ressources**, dans des exécutables PE ou ELF par exemple
* Obtenir des **motifs** pour la cryptanalyse sur des fichiers
* **Repérer** les algorithmes de compression ou de codage
* **Identifier** la stéganographie par des motifs
* **Différenciation** binaire visuelle

BinVis est un excellent **point de départ pour se familiariser avec une cible inconnue** dans un scénario de boîte noire.

## Outils spécifiques de récupération de données

### FindAES

Recherche des clés AES en recherchant leurs plannings de clés. Capable de trouver des clés de 128, 192 et 256 bits, comme celles utilisées par TrueCrypt et BitLocker.

Téléchargez [ici](https://sourceforge.net/projects/findaes/).

## Outils complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu) pour voir des images depuis le terminal.\
Vous pouvez utiliser l'outil de ligne de commande linux **pdftotext** pour transformer un pdf en texte et le lire.

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
