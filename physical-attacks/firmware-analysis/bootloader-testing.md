<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et les chargeurs de démarrage comme U-boot :

1. **Accéder à l'interpréteur de shell du chargeur de démarrage** :
- Pendant le démarrage, appuyez sur "0", espace ou d'autres "codes magiques" identifiés pour accéder à l'interpréteur de shell du chargeur de démarrage.

2. **Modifier les arguments de démarrage** :
- Exécutez les commandes suivantes pour ajouter '`init=/bin/sh`' aux arguments de démarrage, permettant l'exécution d'une commande shell :
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configurer un serveur TFTP** :
- Configurez un serveur TFTP pour charger des images sur un réseau local :
%%%
#setenv ipaddr 192.168.2.2 #IP locale de l'appareil
#setenv serverip 192.168.2.1 #IP du serveur TFTP
#saveenv
#reset
#ping 192.168.2.1 #vérifier l'accès au réseau
#tftp ${loadaddr} uImage-3.6.35 #loadaddr prend l'adresse pour charger le fichier et le nom du fichier de l'image sur le serveur TFTP
%%%

4. **Utiliser `ubootwrite.py`** :
- Utilisez `ubootwrite.py` pour écrire l'image U-boot et pousser un firmware modifié pour obtenir un accès root.

5. **Vérifier les fonctionnalités de débogage** :
- Vérifiez si des fonctionnalités de débogage telles que le journalisation verbose, le chargement de noyaux arbitraires ou le démarrage à partir de sources non fiables sont activées.

6. **Interférence matérielle prudente** :
- Soyez prudent lorsque vous connectez une broche à la terre et interagissez avec les puces flash SPI ou NAND pendant la séquence de démarrage de l'appareil, en particulier avant la décompression du noyau. Consultez la fiche technique de la puce flash NAND avant de court-circuiter les broches.

7. **Configurer un serveur DHCP malveillant** :
- Configurez un serveur DHCP malveillant avec des paramètres malveillants pour qu'un appareil les ingère lors d'un démarrage PXE. Utilisez des outils comme le serveur auxiliaire DHCP de Metasploit (MSF). Modifiez le paramètre 'FILENAME' avec des commandes d'injection de commande telles que `'a";/bin/sh;#'` pour tester la validation des entrées pour les procédures de démarrage de l'appareil.

**Remarque** : Les étapes impliquant une interaction physique avec les broches de l'appareil (*marquées d'astérisques) doivent être abordées avec une extrême prudence pour éviter d'endommager l'appareil.


## Références
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
