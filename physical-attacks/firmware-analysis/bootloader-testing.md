{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et les bootloaders comme U-boot :

1. **Accéder à l'Interpréteur Shell du Bootloader** :
- Pendant le démarrage, appuyez sur "0", espace, ou d'autres "codes magiques" identifiés pour accéder à l'interpréteur shell du bootloader.

2. **Modifier les Arguments de Démarrage** :
- Exécutez les commandes suivantes pour ajouter '`init=/bin/sh`' aux arguments de démarrage, permettant l'exécution d'une commande shell :
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configurer un Serveur TFTP** :
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

5. **Vérifier les Fonctionnalités de Débogage** :
- Vérifiez si des fonctionnalités de débogage comme la journalisation détaillée, le chargement de noyaux arbitraires, ou le démarrage à partir de sources non fiables sont activées.

6. **Interférence Matérielle Prudentielle** :
- Soyez prudent lors de la connexion d'une broche à la terre et de l'interaction avec des puces SPI ou NAND flash pendant la séquence de démarrage de l'appareil, en particulier avant que le noyau ne se décompresse. Consultez la fiche technique de la puce NAND flash avant de court-circuiter des broches.

7. **Configurer un Serveur DHCP Malveillant** :
- Configurez un serveur DHCP malveillant avec des paramètres malveillants pour qu'un appareil les ingère lors d'un démarrage PXE. Utilisez des outils comme le serveur auxiliaire DHCP de Metasploit (MSF). Modifiez le paramètre 'FILENAME' avec des commandes d'injection de commande telles que `'a";/bin/sh;#'` pour tester la validation des entrées pour les procédures de démarrage de l'appareil.

**Remarque** : Les étapes impliquant une interaction physique avec les broches de l'appareil (*marquées par des astérisques) doivent être abordées avec une extrême prudence pour éviter d'endommager l'appareil.


## Références
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
