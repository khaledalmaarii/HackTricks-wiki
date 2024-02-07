# Bundles macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

Les bundles dans macOS servent de conteneurs pour une variété de ressources, y compris des applications, des bibliothèques et d'autres fichiers nécessaires, les faisant apparaître comme des objets uniques dans Finder, tels que les fichiers `*.app` familiers. Le bundle le plus couramment rencontré est le bundle `.app`, bien que d'autres types comme `.framework`, `.systemextension` et `.kext` soient également courants.

### Composants essentiels d'un bundle

À l'intérieur d'un bundle, en particulier dans le répertoire `<application>.app/Contents/`, diverses ressources importantes sont stockées :

- **_CodeSignature** : Ce répertoire stocke des détails de signature de code essentiels pour vérifier l'intégrité de l'application. Vous pouvez inspecter les informations de signature de code en utilisant des commandes comme :
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS** : Contient le binaire exécutable de l'application qui s'exécute lors de l'interaction de l'utilisateur.
- **Resources** : Un référentiel pour les composants de l'interface utilisateur de l'application, y compris des images, des documents et des descriptions d'interface (fichiers nib/xib).
- **Info.plist** : Agit comme le fichier de configuration principal de l'application, crucial pour que le système reconnaisse et interagisse avec l'application de manière appropriée.

#### Clés importantes dans Info.plist

Le fichier `Info.plist` est un pilier pour la configuration de l'application, contenant des clés telles que :

- **CFBundleExecutable** : Spécifie le nom du fichier exécutable principal situé dans le répertoire `Contents/MacOS`.
- **CFBundleIdentifier** : Fournit un identifiant global pour l'application, largement utilisé par macOS pour la gestion des applications.
- **LSMinimumSystemVersion** : Indique la version minimale de macOS requise pour que l'application s'exécute.

### Exploration des bundles

Pour explorer le contenu d'un bundle, tel que `Safari.app`, la commande suivante peut être utilisée :
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Cette exploration révèle des répertoires tels que `_CodeSignature`, `MacOS`, `Resources`, et des fichiers comme `Info.plist`, chacun servant un but unique, de la sécurisation de l'application à la définition de son interface utilisateur et de ses paramètres opérationnels.

#### Répertoires de bundle supplémentaires

Au-delà des répertoires communs, les bundles peuvent également inclure :

- **Frameworks** : Contient des frameworks regroupés utilisés par l'application.
- **PlugIns** : Un répertoire pour les plug-ins et extensions qui améliorent les capacités de l'application.
- **XPCServices** : Contient des services XPC utilisés par l'application pour la communication hors processus.

Cette structure garantit que tous les composants nécessaires sont encapsulés dans le bundle, facilitant un environnement d'application modulaire et sécurisé.

Pour des informations plus détaillées sur les clés `Info.plist` et leur signification, la documentation des développeurs Apple fournit des ressources étendues : [Référence des clés Info.plist Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
