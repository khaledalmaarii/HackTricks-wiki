# Attaques Physiques

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Récupération de Mot de Passe BIOS et Sécurité Système

**Réinitialiser le BIOS** peut être réalisé de plusieurs manières. La plupart des cartes mères incluent une **batterie** qui, lorsqu'elle est retirée pendant environ **30 minutes**, réinitialisera les paramètres du BIOS, y compris le mot de passe. Alternativement, un **jumper sur la carte mère** peut être ajusté pour réinitialiser ces paramètres en connectant des broches spécifiques.

Pour les situations où des ajustements matériels ne sont pas possibles ou pratiques, des **outils logiciels** offrent une solution. Exécuter un système à partir d'un **Live CD/USB** avec des distributions comme **Kali Linux** permet d'accéder à des outils comme **_killCmos_** et **_CmosPWD_**, qui peuvent aider à la récupération du mot de passe BIOS.

Dans les cas où le mot de passe BIOS est inconnu, entrer un mot de passe incorrect **trois fois** entraînera généralement un code d'erreur. Ce code peut être utilisé sur des sites comme [https://bios-pw.org](https://bios-pw.org) pour potentiellement récupérer un mot de passe utilisable.

### Sécurité UEFI

Pour les systèmes modernes utilisant **UEFI** au lieu du BIOS traditionnel, l'outil **chipsec** peut être utilisé pour analyser et modifier les paramètres UEFI, y compris la désactivation de **Secure Boot**. Cela peut être accompli avec la commande suivante :

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analyse de RAM et Attaques de Cold Boot

La RAM conserve des données brièvement après la coupure de l'alimentation, généralement pendant **1 à 2 minutes**. Cette persistance peut être prolongée jusqu'à **10 minutes** en appliquant des substances froides, comme de l'azote liquide. Pendant cette période prolongée, un **dump mémoire** peut être créé à l'aide d'outils comme **dd.exe** et **volatility** pour analyse.

### Attaques par Accès Direct à la Mémoire (DMA)

**INCEPTION** est un outil conçu pour la **manipulation de mémoire physique** via DMA, compatible avec des interfaces comme **FireWire** et **Thunderbolt**. Il permet de contourner les procédures de connexion en patchant la mémoire pour accepter n'importe quel mot de passe. Cependant, il est inefficace contre les systèmes **Windows 10**.

### Live CD/USB pour Accès Système

Changer des binaires système comme **_sethc.exe_** ou **_Utilman.exe_** avec une copie de **_cmd.exe_** peut fournir un invite de commande avec des privilèges système. Des outils comme **chntpw** peuvent être utilisés pour éditer le fichier **SAM** d'une installation Windows, permettant des changements de mot de passe.

**Kon-Boot** est un outil qui facilite la connexion aux systèmes Windows sans connaître le mot de passe en modifiant temporairement le noyau Windows ou UEFI. Plus d'informations peuvent être trouvées sur [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Gestion des Fonctionnalités de Sécurité Windows

#### Raccourcis de Démarrage et de Récupération

- **Supr** : Accéder aux paramètres BIOS.
- **F8** : Entrer en mode de récupération.
- Appuyer sur **Shift** après la bannière Windows peut contourner l'autologon.

#### Périphériques BAD USB

Des dispositifs comme **Rubber Ducky** et **Teensyduino** servent de plateformes pour créer des dispositifs **bad USB**, capables d'exécuter des charges utiles prédéfinies lorsqu'ils sont connectés à un ordinateur cible.

#### Volume Shadow Copy

Les privilèges d'administrateur permettent de créer des copies de fichiers sensibles, y compris le fichier **SAM**, via PowerShell.

### Contournement du Chiffrement BitLocker

Le chiffrement BitLocker peut potentiellement être contourné si le **mot de passe de récupération** est trouvé dans un fichier de dump mémoire (**MEMORY.DMP**). Des outils comme **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** peuvent être utilisés à cette fin.

### Ingénierie Sociale pour l'Ajout de Clé de Récupération

Une nouvelle clé de récupération BitLocker peut être ajoutée par des tactiques d'ingénierie sociale, convainquant un utilisateur d'exécuter une commande qui ajoute une nouvelle clé de récupération composée de zéros, simplifiant ainsi le processus de déchiffrement.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
