# Attaques physiques

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Mot de passe BIOS

### La batterie

La plupart des **cartes mères** ont une **batterie**. Si vous la **retirez** pendant **30 minutes**, les paramètres du BIOS seront **réinitialisés** (mot de passe inclus).

### Cavalier CMOS

La plupart des **cartes mères** ont un **cavalier** qui peut réinitialiser les paramètres. Ce cavalier connecte une broche centrale avec une autre, si vous **connectez ces broches, la carte mère sera réinitialisée**.

### Outils en direct

Si vous pouvez **exécuter** par exemple un **Kali** Linux à partir d'un CD/USB en direct, vous pouvez utiliser des outils comme _**killCmos**_ ou _**CmosPWD**_ (ce dernier est inclus dans Kali) pour **récupérer le mot de passe du BIOS**.

### Récupération de mot de passe BIOS en ligne

Entrez le mot de passe du BIOS **3 fois de suite de manière incorrecte**, puis le BIOS affichera un **message d'erreur** et sera bloqué.\
Visitez la page [https://bios-pw.org](https://bios-pw.org) et **entrez le code d'erreur** affiché par le BIOS et vous pourriez avoir de la chance et obtenir un **mot de passe valide** (la **même recherche peut vous montrer différents mots de passe et plus d'un peut être valide**).

## UEFI

Pour vérifier les paramètres de l'UEFI et effectuer une attaque, vous devriez essayer [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
En utilisant cet outil, vous pouvez facilement désactiver le Secure Boot :
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### Cold boot

La mémoire **RAM est persistante de 1 à 2 minutes** à partir du moment où l'ordinateur est éteint. Si vous appliquez du **froid** (de l'azote liquide, par exemple) sur la carte mémoire, vous pouvez prolonger cette durée jusqu'à **10 minutes**.

Ensuite, vous pouvez effectuer un **dump de mémoire** (en utilisant des outils tels que dd.exe, mdd.exe, Memoryze, win32dd.exe ou DumpIt) pour analyser la mémoire.

Vous devez **analyser** la mémoire **en utilisant Volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception est un outil de **manipulation de mémoire physique** et de piratage exploitant la DMA basée sur PCI. L'outil peut attaquer via **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card et toutes les autres interfaces HW PCI/PCIe.\
**Connectez** votre ordinateur à l'ordinateur de la victime via l'une de ces **interfaces** et **INCEPTION** essaiera de **patcher** la **mémoire physique** pour vous donner **accès**.

**Si INCEPTION réussit, tout mot de passe introduit sera valide.**

**Il ne fonctionne pas avec Windows10.**

## Live CD/USB

### Sticky Keys et plus

* **SETHC:** _sethc.exe_ est invoqué lorsque SHIFT est pressé 5 fois
* **UTILMAN:** _Utilman.exe_ est invoqué en appuyant sur WINDOWS+U
* **OSK:** _osk.exe_ est invoqué en appuyant sur WINDOWS+U, puis en lançant le clavier à l'écran
* **DISP:** _DisplaySwitch.exe_ est invoqué en appuyant sur WINDOWS+P

Ces binaires sont situés dans _**C:\Windows\System32**_. Vous pouvez **modifier** n'importe lequel d'entre eux pour une **copie** du binaire **cmd.exe** (également dans le même dossier) et chaque fois que vous invoquez l'un de ces binaires, une invite de commande en tant que **SYSTEM** apparaîtra.

### Modification de SAM

Vous pouvez utiliser l'outil _**chntpw**_ pour **modifier le fichier** _**SAM**_ d'un système de fichiers Windows monté. Ensuite, vous pourriez changer le mot de passe de l'utilisateur Administrateur, par exemple.\
Cet outil est disponible dans KALI.
```
chntpw -h
chntpw -l <path_to_SAM>
```
**À l'intérieur d'un système Linux, vous pouvez modifier les fichiers** _**/etc/shadow**_ **ou** _**/etc/passwd**_.

### **Kon-Boot**

**Kon-Boot** est l'un des meilleurs outils disponibles qui peut vous connecter à Windows sans connaître le mot de passe. Il fonctionne en **s'accrochant au BIOS du système et en modifiant temporairement le contenu du noyau Windows** lors du démarrage (les nouvelles versions fonctionnent également avec **UEFI**). Il vous permet ensuite d'entrer **n'importe quoi comme mot de passe** lors de la connexion. La prochaine fois que vous démarrez l'ordinateur sans Kon-Boot, le mot de passe d'origine sera de retour, les modifications temporaires seront supprimées et le système se comportera comme si rien ne s'était passé.\
En savoir plus: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

C'est un CD/USB en direct qui peut **modifier la mémoire** afin que vous **n'ayez pas besoin de connaître le mot de passe pour vous connecter**.\
Kon-Boot effectue également le tour de **StickyKeys** pour que vous puissiez appuyer sur _**Shift**_ **5 fois pour obtenir une invite de commande d'administrateur**.

## **Exécution de Windows**

### Raccourcis initiaux

### Raccourcis de démarrage

* supr - BIOS
* f8 - Mode de récupération
* _supr_ - BIOS ini
* _f8_ - Mode de récupération
* _Shitf_ (après la bannière Windows) - Aller à la page de connexion au lieu de l'autologon (éviter l'autologon)

### **BAD USBs**

#### **Tutoriels Rubber Ducky**

* [Tutoriel 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [Tutoriel 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Payloads et tutoriels](https://github.com/Screetsec/Pateensy)

Il existe également des tonnes de tutoriels sur **comment créer votre propre BAD USB**.

### Copie d'ombre de volume

Avec des privilèges d'administrateur et PowerShell, vous pouvez faire une copie du fichier SAM. [Voir ce code](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy).

## Contournement de Bitlocker

Bitlocker utilise **2 mots de passe**. Celui utilisé par l'**utilisateur**, et le mot de passe de **récupération** (48 chiffres).

Si vous avez de la chance et que le fichier _**C:\Windows\MEMORY.DMP**_ (c'est un vidage de mémoire) existe dans la session actuelle de Windows, vous pouvez essayer de **rechercher à l'intérieur le mot de passe de récupération**. Vous pouvez **obtenir ce fichier** et une **copie du système de fichiers** et ensuite utiliser _Elcomsoft Forensic Disk Decryptor_ pour obtenir le contenu (cela ne fonctionnera que si le mot de passe est dans le vidage de mémoire). Vous pouvez également **forcer le vidage de mémoire** en utilisant _**NotMyFault**_ de _Sysinternals_, mais cela redémarrera le système et doit être exécuté en tant qu'administrateur.

Vous pouvez également essayer une **attaque de force brute** en utilisant _**Passware Kit Forensic**_.

### Ingénierie sociale

Enfin, vous pouvez faire ajouter un nouveau mot de passe de récupération à l'utilisateur en le faisant exécuter en tant qu'administrateur:
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
Cela ajoutera une nouvelle clé de récupération (composée de 48 zéros) lors de la prochaine connexion.

Pour vérifier les clés de récupération valides, vous pouvez exécuter:
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
