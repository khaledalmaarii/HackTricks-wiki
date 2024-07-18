{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Vérifiez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}


# Outils de récupération

## Autopsy

L'outil le plus couramment utilisé en informatique légale pour extraire des fichiers à partir d'images est [**Autopsy**](https://www.autopsy.com/download/). Téléchargez-le, installez-le et faites-le ingérer le fichier pour trouver des fichiers "cachés". Notez qu'Autopsy est conçu pour prendre en charge les images de disque et d'autres types d'images, mais pas les fichiers simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** est un outil de recherche de fichiers binaires tels que des images et des fichiers audio pour des fichiers et des données intégrés.
Il peut être installé avec `apt`, cependant la [source](https://github.com/ReFirmLabs/binwalk) peut être trouvée sur github.
**Commandes utiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Un autre outil courant pour trouver des fichiers cachés est **foremost**. Vous pouvez trouver le fichier de configuration de foremost dans `/etc/foremost.conf`. Si vous voulez simplement rechercher des fichiers spécifiques, décommentez-les. Si vous ne décommentez rien, foremost recherchera les types de fichiers configurés par défaut.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** est un autre outil qui peut être utilisé pour trouver et extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter dans le fichier de configuration \(_/etc/scalpel/scalpel.conf_\) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Cet outil est inclus dans kali mais vous pouvez le trouver ici: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Cet outil peut scanner une image et va **extraire des pcaps** à l'intérieur, des **informations réseau (URL, domaines, IPs, MAC, adresses e-mail)** et plus de **fichiers**. Vous n'avez qu'à faire:
```text
bulk_extractor memory.img -o out_folder
```
Parcourez **toutes les informations** que l'outil a rassemblées \(mots de passe?\), **analysez** les **paquets** \(lire [**Analyse des Pcaps**](../pcap-inspection/)\), recherchez des **domaines suspects** \(domaines liés aux **logiciels malveillants** ou **inexistants**\).

## PhotoRec

Vous pouvez le trouver sur [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Il est livré avec une version GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que vous souhaitez que PhotoRec recherche.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Outils spécifiques de récupération de données

## FindAES

Recherche les clés AES en recherchant leurs plannings de clés. Capable de trouver des clés de 128, 192 et 256 bits, comme celles utilisées par TrueCrypt et BitLocker.

Téléchargez [ici](https://sourceforge.net/projects/findaes/).

# Outils complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu) pour voir des images depuis le terminal.
Vous pouvez utiliser l'outil de ligne de commande Linux **pdftotext** pour transformer un PDF en texte et le lire.
