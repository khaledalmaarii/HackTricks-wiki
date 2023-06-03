# Android Forensics

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Appareil verrouillé

Pour commencer à extraire des données d'un appareil Android, il doit être déverrouillé. S'il est verrouillé, vous pouvez :

* Vérifiez si le débogage via USB est activé sur l'appareil.
* Recherchez une possible [attaque de traces de doigts](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Essayez avec [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Acquisition de données

Créez une sauvegarde Android en utilisant adb et extrayez-la en utilisant [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) : `java -jar abe.jar unpack file.backup file.tar`

### Si l'accès root ou la connexion physique à l'interface JTAG

* `cat /proc/partitions` (recherchez le chemin d'accès à la mémoire flash, généralement la première entrée est _mmcblk0_ et correspond à toute la mémoire flash).
* `df /data` (Découvrez la taille de bloc du système).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (exécutez-le avec les informations recueillies à partir de la taille de bloc).

### Mémoire

Utilisez Linux Memory Extractor (LiME) pour extraire les informations de RAM. C'est une extension de noyau qui doit être chargée via adb.
