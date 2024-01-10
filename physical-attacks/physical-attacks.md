# Attaques Physiques

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mot de passe BIOS

### La batterie

La plupart des **cartes mères** ont une **batterie**. Si vous la **retirez** pendant **30min**, les paramètres du BIOS seront **réinitialisés** (mot de passe inclus).

### Cavalier CMOS

La plupart des **cartes mères** ont un **cavalier** qui peut réinitialiser les paramètres. Ce cavalier connecte une broche centrale à une autre, si vous **connectez ces broches, la carte mère sera réinitialisée**.

### Outils en direct

Si vous pouviez **exécuter** par exemple un Linux **Kali** depuis un CD/USB Live, vous pourriez utiliser des outils comme _**killCmos**_ ou _**CmosPWD**_ (ce dernier est inclus dans Kali) pour essayer de **récupérer le mot de passe du BIOS**.

### Récupération en ligne du mot de passe BIOS

Entrez le mot de passe du BIOS **3 fois incorrectement**, puis le BIOS affichera un **message d'erreur** et sera bloqué.\
Visitez la page [https://bios-pw.org](https://bios-pw.org) et **introduisez le code d'erreur** affiché par le BIOS et vous pourriez avoir de la chance et obtenir un **mot de passe valide** (la **même recherche pourrait vous montrer différents mots de passe et plus d'un pourrait être valide**).

## UEFI

Pour vérifier les paramètres de l'UEFI et effectuer une sorte d'attaque, vous devriez essayer [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
En utilisant cet outil, vous pourriez facilement désactiver le Secure Boot :
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### Cold boot

La **mémoire RAM est persistante de 1 à 2 minutes** à partir du moment où l'ordinateur est éteint. Si vous appliquez du **froid** (azote liquide, par exemple) sur la carte mémoire, vous pouvez prolonger ce temps jusqu'à **10 minutes**.

Ensuite, vous pouvez faire un **dump de la mémoire** (en utilisant des outils comme dd.exe, mdd.exe, Memoryze, win32dd.exe ou DumpIt) pour analyser la mémoire.

Vous devriez **analyser** la mémoire **avec volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception est un outil de **manipulation de la mémoire physique** et de hacking exploitant le DMA basé sur PCI. L'outil peut attaquer via **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card et tout autre interface HW PCI/PCIe.\
**Connectez** votre ordinateur à l'ordinateur victime via l'une de ces **interfaces** et **INCEPTION** essaiera de **patcher** la **mémoire physique** pour vous donner **accès**.

**Si INCEPTION réussit, tout mot de passe introduit sera valide.**

**Il ne fonctionne pas avec Windows10.**

## Live CD/USB

### Sticky Keys et plus

* **SETHC :** _sethc.exe_ est invoqué lorsque SHIFT est pressé 5 fois
* **UTILMAN :** _Utilman.exe_ est invoqué en appuyant sur WINDOWS+U
* **OSK :** _osk.exe_ est invoqué en appuyant sur WINDOWS+U, puis en lançant le clavier à l'écran
* **DISP :** _DisplaySwitch.exe_ est invoqué en appuyant sur WINDOWS+P

Ces binaires se trouvent dans _**C:\Windows\System32**_. Vous pouvez **changer** l'un d'eux pour une **copie** du binaire **cmd.exe** (également dans le même dossier) et chaque fois que vous invoquez l'un de ces binaires, une invite de commande en tant que **SYSTEM** apparaîtra.

### Modification du SAM

Vous pouvez utiliser l'outil _**chntpw**_ pour **modifier le** _**fichier SAM**_ d'un système de fichiers Windows monté. Ensuite, vous pourriez changer le mot de passe de l'utilisateur Administrateur, par exemple.\
Cet outil est disponible dans KALI.
```
chntpw -h
chntpw -l <path_to_SAM>
```
**Dans un système Linux, vous pourriez modifier le fichier** _**/etc/shadow**_ **ou** _**/etc/passwd**_.

### **Kon-Boot**

**Kon-Boot** est l'un des meilleurs outils permettant de se connecter à Windows sans connaître le mot de passe. Il fonctionne en **s'insérant dans le BIOS du système et en modifiant temporairement le contenu du noyau de Windows** pendant le démarrage (les nouvelles versions fonctionnent également avec **UEFI**). Il vous permet ensuite de saisir **n'importe quoi comme mot de passe** lors de la connexion. La prochaine fois que vous démarrez l'ordinateur sans Kon-Boot, le mot de passe original sera de retour, les modifications temporaires seront supprimées et le système se comportera comme si rien ne s'était passé.\
En savoir plus : [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

C'est un CD/USB live qui peut **patcher la mémoire** afin que vous **n'ayez pas besoin de connaître le mot de passe pour vous connecter**.\
Kon-Boot effectue également l'astuce **StickyKeys** pour que vous puissiez appuyer _**Shift**_ **5 fois pour obtenir une invite de commande Administrateur**.

## **Exécution de Windows**

### Raccourcis initiaux

### Raccourcis de démarrage

* supr - BIOS
* f8 - Mode de récupération
* _supr_ - BIOS ini
* _f8_ - Mode de récupération
* _Shift_ (après la bannière windows) - Aller à la page de connexion au lieu de l'autologon (éviter l'autologon)

### **BAD USBs**

#### **Tutoriels Rubber Ducky**

* [Tutoriel 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [Tutoriel 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Charges utiles et tutoriels](https://github.com/Screetsec/Pateensy)

Il existe également de nombreux tutoriels sur **comment créer votre propre bad USB**.

### Copie de l'ombre de volume

Avec les privilèges d'administrateur et powershell, vous pourriez faire une copie du fichier SAM.[ Voir ce code](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy).

## Contournement de Bitlocker

Bitlocker utilise **2 mots de passe**. Celui utilisé par l'**utilisateur**, et le mot de passe de **récupération** (48 chiffres).

Si vous avez de la chance et que dans la session actuelle de Windows existe le fichier _**C:\Windows\MEMORY.DMP**_ (c'est un dump de mémoire), vous pourriez essayer de **rechercher à l'intérieur le mot de passe de récupération**. Vous pouvez **obtenir ce fichier** et une **copie du système de fichiers** puis utiliser _Elcomsoft Forensic Disk Decryptor_ pour obtenir le contenu (cela ne fonctionnera que si le mot de passe est dans le dump de mémoire). Vous pourriez également **forcer le dump de mémoire** en utilisant _**NotMyFault**_ de _Sysinternals_, mais cela redémarrera le système et doit être exécuté en tant qu'Administrateur.

Vous pourriez aussi tenter une **attaque par force brute** en utilisant _**Passware Kit Forensic**_.

### Ingénierie sociale

Enfin, vous pourriez amener l'utilisateur à ajouter un nouveau mot de passe de récupération en le faisant exécuter en tant qu'administrateur :
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
Cela ajoutera une nouvelle clé de récupération (composée de 48 zéros) lors de la prochaine connexion.

Pour vérifier les clés de récupération valides, vous pouvez exécuter :
```
manage-bde -protectors -get c:
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
