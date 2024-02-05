# macOS Dirty NIB

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

**Pour plus de détails sur la technique, consultez l'article original sur : [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)**. Voici un résumé :

Les fichiers NIB, faisant partie de l'écosystème de développement d'Apple, sont destinés à définir des **éléments d'interface utilisateur** et leurs interactions dans les applications. Ils englobent des objets sérialisés tels que des fenêtres et des boutons, et sont chargés à l'exécution. Malgré leur utilisation continue, Apple préconise désormais l'utilisation de Storyboards pour une visualisation plus complète du flux de l'interface utilisateur.

### Problèmes de sécurité avec les fichiers NIB
Il est crucial de noter que les **fichiers NIB peuvent représenter un risque de sécurité**. Ils ont le potentiel d'**exécuter des commandes arbitraires**, et les modifications apportées aux fichiers NIB dans une application n'empêchent pas Gatekeeper d'exécuter l'application, ce qui constitue une menace significative.

### Processus d'injection Dirty NIB
#### Création et configuration d'un fichier NIB
1. **Configuration initiale** :
- Créez un nouveau fichier NIB à l'aide de XCode.
- Ajoutez un objet à l'interface, en définissant sa classe sur `NSAppleScript`.
- Configurez la propriété initiale `source` via les attributs d'exécution définis par l'utilisateur.

2. **Gadget d'exécution de code** :
- La configuration facilite l'exécution d'AppleScript sur demande.
- Intégrez un bouton pour activer l'objet `Apple Script`, déclenchant spécifiquement le sélecteur `executeAndReturnError:`.

3. **Test** :
- Un simple Apple Script à des fins de test :
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Testez en exécutant dans le débogueur XCode et en cliquant sur le bouton.

#### Ciblage d'une application (Exemple : Pages)
1. **Préparation** :
- Copiez l'application cible (par exemple, Pages) dans un répertoire séparé (par exemple, `/tmp/`).
- Lancez l'application pour contourner les problèmes de Gatekeeper et mettez-la en cache.

2. **Remplacement du fichier NIB** :
- Remplacez un fichier NIB existant (par exemple, le NIB du panneau À propos) par le fichier DirtyNIB créé.

3. **Exécution** :
- Déclenchez l'exécution en interagissant avec l'application (par exemple, en sélectionnant l'élément de menu `À propos`).

#### Preuve de concept : Accès aux données utilisateur
- Modifiez l'AppleScript pour accéder et extraire des données utilisateur, telles que des photos, sans le consentement de l'utilisateur.

### Exemple de code : Fichier .xib malveillant
- Accédez et examinez un [**exemple de fichier .xib malveillant**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) qui démontre l'exécution de code arbitraire.

### Traitement des contraintes de lancement
- Les contraintes de lancement empêchent l'exécution de l'application à partir d'emplacements inattendus (par exemple, `/tmp`).
- Il est possible d'identifier les applications non protégées par les contraintes de lancement et de les cibler pour l'injection de fichiers NIB.

### Protections supplémentaires macOS
À partir de macOS Sonoma, les modifications à l'intérieur des bundles d'applications sont restreintes. Cependant, les méthodes antérieures impliquaient :
1. Copier l'application dans un emplacement différent (par exemple, `/tmp/`).
2. Renommer les répertoires à l'intérieur du bundle de l'application pour contourner les protections initiales.
3. Après avoir exécuté l'application pour s'enregistrer auprès de Gatekeeper, modifier le bundle de l'application (par exemple, remplacer MainMenu.nib par Dirty.nib).
4. Renommer les répertoires et relancer l'application pour exécuter le fichier NIB injecté.

**Remarque** : Les récentes mises à jour de macOS ont atténué cette faille en empêchant les modifications de fichiers à l'intérieur des bundles d'applications après la mise en cache de Gatekeeper, rendant l'exploit inefficace.


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
