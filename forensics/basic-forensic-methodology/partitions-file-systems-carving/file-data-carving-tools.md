<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Outils de récupération de données

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

**Scalpel** est un autre outil qui peut être utilisé pour trouver et extraire des **fichiers intégrés dans un fichier**. Dans ce cas, vous devrez décommenter du fichier de configuration (_/etc/scalpel/scalpel.conf_) les types de fichiers que vous souhaitez extraire.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Cet outil est inclus dans Kali mais vous pouvez le trouver ici: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Cet outil peut scanner une image et **extraire des pcaps** à l'intérieur, des **informations réseau (URL, domaines, adresses IP, adresses MAC, e-mails)** et plus encore des **fichiers**. Vous n'avez qu'à faire:
```text
bulk_extractor memory.img -o out_folder
```
Parcourez **toutes les informations** que l'outil a rassemblées \(mots de passe ?\), **analysez** les **paquets** \(lire [**Pcaps analysis**](../pcap-inspection/)\), recherchez des **domaines étranges** \(domaines liés aux **logiciels malveillants** ou **inexistants**\).

## PhotoRec

Vous pouvez le trouver sur [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Il est livré avec une version GUI et CLI. Vous pouvez sélectionner les **types de fichiers** que vous souhaitez que PhotoRec recherche.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Outils de récupération de données spécifiques

## FindAES

Recherche les clés AES en recherchant leurs calendriers de clés. Capable de trouver des clés de 128, 192 et 256 bits, telles que celles utilisées par TrueCrypt et BitLocker.

Téléchargez [ici](https://sourceforge.net/projects/findaes/).

# Outils complémentaires

Vous pouvez utiliser [**viu** ](https://github.com/atanunq/viu) pour voir des images à partir du terminal.  
Vous pouvez utiliser l'outil de ligne de commande linux **pdftotext** pour transformer un pdf en texte et le lire.



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
