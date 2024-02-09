# Attaques Physiques

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Récupération du Mot de Passe du BIOS et Sécurité du Système

La **réinitialisation du BIOS** peut être réalisée de plusieurs manières. La plupart des cartes mères incluent une **pile** qui, une fois retirée pendant environ **30 minutes**, réinitialisera les paramètres du BIOS, y compris le mot de passe. Alternativement, un **cavalier sur la carte mère** peut être ajusté pour réinitialiser ces paramètres en connectant des broches spécifiques.

Dans les situations où les ajustements matériels ne sont pas possibles ou pratiques, des **outils logiciels** offrent une solution. Exécuter un système à partir d'un **Live CD/USB** avec des distributions comme **Kali Linux** fournit un accès à des outils comme **_killCmos_** et **_CmosPWD_**, qui peuvent aider à la récupération du mot de passe du BIOS.

Dans les cas où le mot de passe du BIOS est inconnu, le saisir incorrectement **trois fois** entraînera généralement un code d'erreur. Ce code peut être utilisé sur des sites web comme [https://bios-pw.org](https://bios-pw.org) pour potentiellement récupérer un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant l'**UEFI** au lieu du BIOS traditionnel, l'outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, y compris la désactivation du **Secure Boot**. Cela peut être accompli avec la commande suivante :

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analyse de la RAM et Attaques Cold Boot

La RAM conserve les données brièvement après la coupure de l'alimentation, généralement pendant **1 à 2 minutes**. Cette persistance peut être étendue à **10 minutes** en appliquant des substances froides, telles que de l'azote liquide. Pendant cette période prolongée, une **copie de la mémoire** peut être créée à l'aide d'outils comme **dd.exe** et **volatility** pour l'analyse.

### Attaques d'Accès Direct à la Mémoire (DMA)

**INCEPTION** est un outil conçu pour la **manipulation physique de la mémoire** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en patchant la mémoire pour accepter n'importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

### Live CD/USB pour l'Accès au Système

Changer les binaires système comme **_sethc.exe_** ou **_Utilman.exe_** avec une copie de **_cmd.exe_** peut fournir une invite de commande avec des privilèges système. Des outils comme **chntpw** peuvent être utilisés pour modifier le fichier **SAM** d'une installation Windows, permettant des changements de mot de passe.

**Kon-Boot** est un outil qui facilite la connexion aux systèmes Windows sans connaître le mot de passe en modifiant temporairement le noyau Windows ou l'UEFI. Plus d'informations peuvent être trouvées sur [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Gestion des Fonctionnalités de Sécurité Windows

#### Raccourcis de Démarrage et de Récupération

- **Supr** : Accéder aux paramètres du BIOS.
- **F8** : Entrer en mode Récupération.
- Appuyer sur **Shift** après la bannière Windows peut contourner l'autologon.

#### Périphériques BAD USB

Des périphériques comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des périphériques **bad USB**, capables d'exécuter des charges prédéfinies lorsqu'ils sont connectés à un ordinateur cible.

#### Copie d'Ombre du Volume

Les privilèges administratifs permettent la création de copies de fichiers sensibles, y compris le fichier **SAM**, via PowerShell.

### Contournement du Chiffrement BitLocker

Le chiffrement BitLocker peut potentiellement être contourné si le **mot de passe de récupération** est trouvé dans un fichier de vidage mémoire (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cette fin.

### Ingénierie Sociale pour l'Ajout de Clé de Récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée grâce à des tactiques d'ingénierie sociale, convaincant un utilisateur d'exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, simplifiant ainsi le processus de déchiffrement.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
