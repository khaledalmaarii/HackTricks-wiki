<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Horodatage

Un attaquant peut être intéressé par **la modification des horodatages des fichiers** pour éviter d'être détecté.\
Il est possible de trouver les horodatages à l'intérieur du MFT dans les attributs `$STANDARD_INFORMATION` __ et __ `$FILE_NAME`.

Les deux attributs ont 4 horodatages : **Modification**, **accès**, **création** et **modification du registre MFT** (MACE ou MACB).

**Windows explorer** et d'autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

## TimeStomp - Outil anti-forensique

Cet outil **modifie** les informations d'horodatage à l'intérieur de **`$STANDARD_INFORMATION`** **mais pas** les informations à l'intérieur de **`$FILE_NAME`**. Par conséquent, il est possible d'**identifier** une **activité suspecte**.

## Usnjrnl

Le **journal USN** (Update Sequence Number Journal), ou journal des modifications, est une fonctionnalité du système de fichiers Windows NT (NTFS) qui **maintient un enregistrement des modifications apportées au volume**.\
Il est possible d'utiliser l'outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) pour rechercher des modifications apportées à cet enregistrement.

![](<../../.gitbook/assets/image (449).png>)

L'image précédente est la **sortie** affichée par l'**outil** où il est possible d'observer que certaines **modifications ont été effectuées** sur le fichier.

## $LogFile

Toutes les modifications de métadonnées d'un système de fichiers sont enregistrées pour assurer la récupération cohérente des structures critiques du système de fichiers après un crash système. Cela s'appelle [
