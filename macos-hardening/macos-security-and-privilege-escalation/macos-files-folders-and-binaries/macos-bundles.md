# Bundles macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Fondamentalement, un bundle est une **structure de répertoire** dans le système de fichiers. De manière intéressante, par défaut, ce répertoire **ressemble à un seul objet dans Finder**.&#x20;

Le bundle **le plus courant** que nous rencontrerons est le **bundle `.app`**, mais de nombreux autres exécutables sont également empaquetés sous forme de bundles, tels que les bundles `.framework` et `.systemextension` ou `.kext`.

Les types de ressources contenues dans un bundle peuvent comprendre des applications, des bibliothèques, des images, de la documentation, des fichiers d'en-tête, etc. Tous ces fichiers se trouvent dans `<application>.app/Contents/`.
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> Contient des informations de **signature de code** sur l'application (c'est-à-dire des hachages, etc.).
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> Contient le **binaire de l'application** (qui est exécuté lorsque l'utilisateur double-clique sur l'icône de l'application dans l'interface utilisateur).
* `Contents/Resources` -> Contient les **éléments de l'interface utilisateur de l'application**, tels que des images, des documents et des fichiers nib/xib (qui décrivent diverses interfaces utilisateur).
* `Contents/Info.plist` -> Le **fichier de configuration principal** de l'application. Apple note que "le système se base sur la présence de ce fichier pour identifier les informations pertinentes sur l'application et les fichiers associés".
* Les fichiers **Plist** contiennent des informations de configuration. Vous pouvez trouver des informations sur la signification des clés plist à l'adresse [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
*   Les paires qui peuvent être intéressantes lors de l'analyse d'une application incluent :

* **CFBundleExecutable**

Contient le **nom du binaire de l'application** (trouvé dans Contents/MacOS).

* **CFBundleIdentifier**

Contient l'identifiant de bundle de l'application (souvent utilisé par le système pour **identifier** globalement l'application).

* **LSMinimumSystemVersion**

Contient la **plus ancienne version** de **macOS** avec laquelle l'application est compatible.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
