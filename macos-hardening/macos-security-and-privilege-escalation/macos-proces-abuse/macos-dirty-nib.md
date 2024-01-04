# macOS Dirty NIB

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Cette technique a été reprise du post** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Informations de base

Les fichiers NIB sont utilisés dans l'écosystème de développement d'Apple pour **définir les éléments de l'interface utilisateur (UI)** et leurs interactions au sein d'une application. Créés avec l'outil Interface Builder, ils contiennent des **objets sérialisés** comme des fenêtres, des boutons et des champs de texte, qui sont chargés au moment de l'exécution pour présenter l'UI conçue. Bien qu'encore utilisés, Apple a évolué vers la recommandation des Storyboards pour une représentation plus visuelle du flux UI d'une application.

{% hint style="danger" %}
De plus, les **fichiers NIB** peuvent également être utilisés pour **exécuter des commandes arbitraires** et si un fichier NIB est modifié dans une application, **Gatekeeper permettra toujours d'exécuter l'application**, donc ils peuvent être utilisés pour **exécuter des commandes arbitraires à l'intérieur des applications**.
{% endhint %}

## Injection Dirty NIB <a href="#dirtynib" id="dirtynib"></a>

D'abord, nous devons créer un nouveau fichier NIB, nous utiliserons XCode pour la majeure partie de la construction. Nous commençons par ajouter un Objet à l'interface et définir la classe sur NSAppleScript :

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

Pour l'objet, nous devons définir la propriété `source` initiale, ce que nous pouvons faire en utilisant les Attributs d'Exécution Définis par l'Utilisateur :

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

Cela met en place notre gadget d'exécution de code, qui va juste **exécuter AppleScript sur demande**. Pour déclencher réellement l'exécution de l'AppleScript, nous allons juste ajouter un bouton pour l'instant (vous pouvez bien sûr être créatif avec cela ;). Le bouton sera lié à l'objet `Apple Script` que nous venons de créer, et va **invoquer le sélecteur `executeAndReturnError:`** :

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

Pour les tests, nous utiliserons simplement l'Apple Script de :
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
Et si nous exécutons cela dans le débogueur XCode et appuyons sur le bouton :

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

Avec notre capacité à exécuter du code AppleScript arbitraire à partir d'un NIB, nous avons ensuite besoin d'une cible. Choisissons Pages pour notre démo initiale, qui est bien sûr une application Apple et ne devrait certainement pas être modifiable par nous.

Nous allons d'abord faire une copie de l'application dans `/tmp/` :
```bash
cp -a -X /Applications/Pages.app /tmp/
```
Ensuite, nous lancerons l'application pour éviter tout problème avec Gatekeeper et permettre la mise en cache des éléments :
```bash
open -W -g -j /Applications/Pages.app
```
Après avoir lancé (et tué) l'application pour la première fois, nous devrons remplacer un fichier NIB existant par notre fichier DirtyNIB. À des fins de démonstration, nous allons simplement remplacer le NIB du panneau À propos afin de pouvoir contrôler l'exécution :
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
Une fois que nous avons écrasé le nib, nous pouvons déclencher l'exécution en sélectionnant l'élément de menu `About` :

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Si nous examinons Pages de plus près, nous constatons qu'il dispose d'un droit d'accès privé permettant d'accéder aux Photos d'un utilisateur :

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

Nous pouvons donc mettre notre POC à l'épreuve en **modifiant notre AppleScript pour voler des photos** de l'utilisateur sans demande de confirmation :

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**Exemple de fichier .xib malveillant qui exécute du code arbitraire.**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## Créez votre propre DirtyNIB



## Contraintes de lancement

Elles **empêchent l'exécution d'applications en dehors de leurs emplacements attendus**, donc si vous copiez une application protégée par des contraintes de lancement dans `/tmp`, vous ne pourrez pas l'exécuter.\
[**Trouvez plus d'informations dans cet article**](../macos-security-protections/#launch-constraints)**.**

Cependant, en analysant le fichier **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**, vous pouvez toujours trouver **des applications qui ne sont pas protégées par des contraintes de lancement** et vous pourriez donc toujours **injecter** des fichiers **NIB** dans des emplacements arbitraires dans **ces applications** (consultez le lien précédent pour apprendre à trouver ces applications).

## Protections supplémentaires

À partir de macOS Somona, il existe des protections **empêchant d'écrire à l'intérieur des applications**. Cependant, il est toujours possible de contourner cette protection si, avant d'exécuter votre copie du binaire, vous changez le nom du dossier Contents :

1. Prenez une copie de `CarPlay Simulator.app` dans `/tmp/`
2. Renommez `/tmp/Carplay Simulator.app/Contents` en `/tmp/CarPlay Simulator.app/NotCon`
3. Lancez le binaire `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` pour le mettre en cache avec Gatekeeper
4. Remplacez `NotCon/Resources/Base.lproj/MainMenu.nib` par notre fichier `Dirty.nib`
5. Renommez en `/tmp/CarPlay Simulator.app/Contents`
6. Lancez `CarPlay Simulator.app` à nouveau

{% hint style="success" %}
Il semble que cela ne soit plus possible car macOS **empêche la modification des fichiers** à l'intérieur des paquets d'applications.\
Ainsi, après avoir exécuté l'application pour la mettre en cache avec Gatekeeper, vous ne pourrez pas modifier le paquet.\
Et si vous changez par exemple le nom du répertoire Contents en **NotCon** (comme indiqué dans l'exploit), puis exécutez le binaire principal de l'application pour la mettre en cache avec Gatekeeper, cela **déclenchera une erreur et n'exécutera pas**.
{% endhint %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
