# Numéro de série macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


## Informations de base

Les appareils Apple post-2010 ont des numéros de série composés de **12 caractères alphanumériques**, chaque segment transmettant des informations spécifiques :

- **3 premiers caractères** : Indiquent l'**emplacement de fabrication**.
- **Caractères 4 et 5** : Indiquent l'**année et la semaine de fabrication**.
- **Caractères 6 à 8** : Servent d'**identifiant unique** pour chaque appareil.
- **4 derniers caractères** : Spécifient le **numéro de modèle**.

Par exemple, le numéro de série **C02L13ECF8J2** suit cette structure.

### **Emplacements de fabrication (3 premiers caractères)**
Certains codes représentent des usines spécifiques :
- **FC, F, XA/XB/QP/G8** : Divers endroits aux États-Unis.
- **RN** : Mexique.
- **CK** : Cork, Irlande.
- **VM** : Foxconn, République tchèque.
- **SG/E** : Singapour.
- **MB** : Malaisie.
- **PT/CY** : Corée.
- **EE/QT/UV** : Taïwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7** : Différents endroits en Chine.
- **C0, C3, C7** : Villes spécifiques en Chine.
- **RM** : Appareils reconditionnés.

### **Année de fabrication (4e caractère)**
Ce caractère varie de 'C' (représentant la première moitié de 2010) à 'Z' (deuxième moitié de 2019), avec des lettres différentes indiquant des périodes semestrielles différentes.

### **Semaine de fabrication (5e caractère)**
Les chiffres 1 à 9 correspondent aux semaines 1 à 9. Les lettres C-Y (à l'exclusion des voyelles et du 'S') représentent les semaines 10 à 27. Pour la deuxième moitié de l'année, 26 est ajouté à ce nombre.

### **Identifiant unique (Caractères 6 à 8)**
Ces trois chiffres garantissent que chaque appareil, même du même modèle et lot, a un numéro de série distinct.

### **Numéro de modèle (4 derniers caractères)**
Ces chiffres identifient le modèle spécifique de l'appareil.

### Référence

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
