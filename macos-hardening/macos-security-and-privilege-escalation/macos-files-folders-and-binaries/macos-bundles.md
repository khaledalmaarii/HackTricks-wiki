# Paquets macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

En gros, un paquet est une **structure de répertoire** au sein du système de fichiers. Intéressant, par défaut ce répertoire **apparaît comme un objet unique dans Finder**.&#x20;

Le paquet **commun** que nous rencontrerons fréquemment est le paquet **`.app`**, mais de nombreux autres exécutables sont également empaquetés sous forme de paquets, tels que **`.framework`** et **`.systemextension`** ou **`.kext`**.

Les types de ressources contenues dans un paquet peuvent consister en des applications, des bibliothèques, des images, de la documentation, des fichiers d'en-tête, etc. Tous ces fichiers sont à l'intérieur de `<application>.app/Contents/`
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> Contient des **informations de signature de code** sur l'application (c.-à-d. hachages, etc.).
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> Contient **le binaire de l'application** (qui est exécuté lorsque l'utilisateur double-clique sur l'icône de l'application dans l'interface utilisateur).
* `Contents/Resources` -> Contient **les éléments de l'interface utilisateur de l'application**, tels que les images, documents et fichiers nib/xib (qui décrivent diverses interfaces utilisateur).
* `Contents/Info.plist` -> Le principal **fichier de configuration** de l'application. Apple note que « le système s'appuie sur la présence de ce fichier pour identifier des informations pertinentes sur \[l'\]application et tout fichier associé ».
* Les **fichiers Plist** contiennent des informations de configuration. Vous pouvez trouver des informations sur la signification des clés plist sur [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
*   Paires qui peuvent être intéressantes lors de l'analyse d'une application comprennent :\\

* **CFBundleExecutable**

Contient **le nom du binaire de l'application** (trouvé dans Contents/MacOS).

* **CFBundleIdentifier**

Contient l'identifiant de bundle de l'application (souvent utilisé par le système pour **identifier globalement** l'application).

* **LSMinimumSystemVersion**

Contient **la plus ancienne version** de **macOS** avec laquelle l'application est compatible.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
