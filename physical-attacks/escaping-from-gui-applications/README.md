<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# Vérifier les actions possibles à l'intérieur de l'application GUI

Les **Dialogues courants** sont ces options de **sauvegarde d'un fichier**, **ouverture d'un fichier**, sélection d'une police, d'une couleur... La plupart d'entre eux **offriront une fonctionnalité d'Explorateur complète**. Cela signifie que vous pourrez accéder aux fonctionnalités de l'Explorateur si vous pouvez accéder à ces options :

* Fermer/Fermer sous
* Ouvrir/Ouvrir avec
* Imprimer
* Exporter/Importer
* Rechercher
* Scanner

Vous devriez vérifier si vous pouvez :

* Modifier ou créer de nouveaux fichiers
* Créer des liens symboliques
* Accéder à des zones restreintes
* Exécuter d'autres applications

## Exécution de commandes

Peut-être **en utilisant une option `Ouvrir avec`** vous pouvez ouvrir/exécuter une sorte de shell.

### Windows

Par exemple _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trouvez plus de binaires qui peuvent être utilisés pour exécuter des commandes (et effectuer des actions inattendues) ici : [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Plus ici : [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Contourner les restrictions de chemin

* **Variables d'environnement** : Il y a beaucoup de variables d'environnement qui pointent vers un chemin
* **Autres protocoles** : _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Liens symboliques**
* **Raccourcis** : CTRL+N (ouvrir une nouvelle session), CTRL+R (Exécuter des commandes), CTRL+SHIFT+ESC (Gestionnaire des tâches),  Windows+E (ouvrir l'explorateur), CTRL-B, CTRL-I (Favoris), CTRL-H (Historique), CTRL-L, CTRL-O (Boîte de dialogue Ouvrir/Fichier), CTRL-P (Boîte de dialogue Imprimer), CTRL-S (Enregistrer sous)
* Menu administratif caché : CTRL-ALT-F8, CTRL-ESC-F9
* **URI Shell** : _shell:Outils administratifs, shell:Bibliothèque de documents, shell:Bibliothèques, shell:ProfilsUtilisateurs, shell:Personnel, shell:DossierRechercheAccueil, shell:Réseau, shell:EnvoyerVers, shell:ProfilsUtilisateurs, shell:Outils administratifs communs, shell:PosteTravail, shell:DossierInternet_
* **Chemins UNC** : Chemins pour se connecter à des dossiers partagés. Vous devriez essayer de vous connecter au C$ de la machine locale ("\\\127.0.0.1\c$\Windows\System32")
* **Plus de chemins UNC :**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Téléchargez vos binaires

Console : [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorateur : [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Éditeur de registre : [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Accéder au système de fichiers depuis le navigateur

| CHEMIN                | CHEMIN              | CHEMIN               | CHEMIN                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Raccourcis

* Sticky Keys – Appuyez sur SHIFT 5 fois
* Mouse Keys – SHIFT+ALT+NUMLOCK
* Contraste élevé – SHIFT+ALT+PRINTSCN
* Touche de bascule – Maintenez NUMLOCK enfoncé pendant 5 secondes
* Touches de filtre – Maintenez la touche droite SHIFT enfoncée pendant 12 secondes
* WINDOWS+F1 – Recherche Windows
* WINDOWS+D – Afficher le bureau
* WINDOWS+E – Lancer l'explorateur Windows
* WINDOWS+R – Exécuter
* WINDOWS+U – Centre d'accessibilité
* WINDOWS+F – Recherche
* SHIFT+F10 – Menu contextuel
* CTRL+SHIFT+ESC – Gestionnaire des tâches
* CTRL+ALT+DEL – Écran de démarrage sur les nouvelles versions de Windows
* F1 – Aide F3 – Recherche
* F6 – Barre d'adresse
* F11 – Basculer en plein écran dans Internet Explorer
* CTRL+H – Historique Internet Explorer
* CTRL+T – Internet Explorer – Nouvel onglet
* CTRL+N – Internet Explorer – Nouvelle page
* CTRL+O – Ouvrir un fichier
* CTRL+S – Enregistrer CTRL+N – Nouveau RDP / Citrix

## Gestes

* Faites glisser du côté gauche vers la droite pour voir toutes les fenêtres ouvertes, minimisant l'application KIOSK et accédant directement à l'ensemble du système d'exploitation ;
* Faites glisser du côté droit vers la gauche pour ouvrir le Centre d'action, minimisant l'application KIOSK et accédant directement à l'ensemble du système d'exploitation ;
* Faites glisser depuis le bord supérieur pour rendre la barre de titre visible pour une application ouverte en mode plein écran ;
* Faites glisser vers le haut depuis le bas pour afficher la barre des tâches dans une application en plein écran.

## Astuces Internet Explorer

### 'Barre d'images'

C'est une barre d'outils qui apparaît en haut à gauche de l'image lorsqu'elle est cliquée. Vous pourrez Enregistrer, Imprimer, Envoyer par e-mail, Ouvrir "Mes images" dans l'Explorateur. Le Kiosque doit utiliser Internet Explorer.

### Protocole Shell

Tapez ces URL pour obtenir une vue de l'Explorateur :

* `shell:Outils administratifs`
* `shell:Bibliothèque de documents`
* `shell:Bibliothèques`
* `shell:ProfilsUtilisateurs`
* `shell:Personnel`
* `shell:DossierRechercheAccueil`
* `shell:Réseau`
* `shell:EnvoyerVers`
* `shell:ProfilsUtilisateurs`
* `shell:Outils administratifs communs`
* `shell:PosteTravail`
* `shell:DossierInternet`
* `Shell:Profil`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:DossierPanneauConfiguration`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panneau de configuration
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Poste de travail
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mes lieux réseau
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Afficher les extensions de fichier

Consultez cette page pour plus d'informations : [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Astuces des navigateurs

Sauvegardez les versions iKat :

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Créez une boîte de dialogue commune en utilisant JavaScript et accédez à l'explorateur de fichiers : `document.write('<input/type=file>')`
Source : https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestes et boutons

* Faites glisser vers le haut avec quatre (ou cinq) doigts / Double-tapez sur le bouton Accueil : Pour afficher la vue multitâche et changer d'application

* Faites glisser d'un côté ou de l'autre avec quatre ou cinq doigts : Pour changer vers l'application suivante/précédente

* Pincez l'écran avec cinq doigts / Touchez le bouton Accueil / Faites glisser vers le haut avec 1 doigt depuis le bas de l'écran en un mouvement rapide vers le haut : Pour accéder à l'Accueil

* Faites glisser un doigt depuis le bas de l'écran juste à 1-2 pouces (lentement) : Le dock apparaîtra

* Faites glisser vers le bas depuis le haut de l'écran avec 1 doigt : Pour afficher vos notifications

* Faites glisser vers le bas avec 1 doigt dans le coin supérieur droit de l'écran : Pour voir le centre de contrôle de l'iPad Pro

* Faites glisser 1 doigt depuis la gauche de l'écran sur 1-2 pouces : Pour voir la vue Aujourd'hui

* Faites glisser rapidement 1 doigt depuis le centre de l'écran vers la droite ou la gauche : Pour changer vers l'application suivante/précédente

* Maintenez enfoncé le bouton Marche/Arrêt en haut à droite de l'iPad + Déplacez le curseur Éteindre tout à droite : Pour éteindre

* Appuyez sur le bouton Marche/Arrêt en haut à droite de l'iPad et le bouton Accueil pendant quelques secondes : Pour forcer un arrêt complet

* Appuyez sur le bouton Marche/Arrêt en haut à droite de l'iPad et le bouton Accueil rapidement : Pour prendre une capture d'écran qui apparaîtra en bas à gauche de l'écran. Appuyez brièvement sur les deux boutons en même temps, car si vous les maintenez enfoncés quelques secondes, un arrêt complet sera effectué.

## Raccourcis

Vous devriez avoir un clavier iPad ou un adaptateur de clavier USB. Seuls les raccourcis qui pourraient aider à s'échapper de l'application seront montrés ici.

| Touche | Nom         |
| --- | ------------ |
| ⌘   | Commande      |
| ⌥   | Option (Alt) |
| ⇧   | Majuscule        |
| ↩   | Retour       |
| ⇥   | Tabulation          |
| ^   | Contrôle      |
| ←   | Flèche gauche   |
| →   | Flèche droite  |
| ↑   | Flèche vers le haut     |
| ↓   | Flèche vers le bas   |

### Raccourcis système

Ces raccourcis sont pour les paramètres visuels et sonores, en fonction de l'utilisation de l'iPad.

| Raccourci | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Diminuer la luminosité de l'écran                                                                    |
| F2       | Augmenter la luminosité de l'écran                                                                |
| F7       | Revenir en arrière d'une chanson                                                                  |
| F8       | Lecture/pause                                                                     |
| F9       | Passer à la chanson suivante                                                                      |
| F10      | Muet                                                                           |
| F11      | Diminuer le volume                                                                |
| F12      | Augmenter le volume                                                                |
| ⌘ Espace  | Afficher une liste des langues disponibles ; pour en choisir une, appuyez à nouveau sur la barre d'espace. |

### Navigation iPad

| Raccourci                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Aller à l'Accueil                                              |
| ⌘⇧H (Commande-Majuscule-H)                              | Aller à l'Accueil                                              |
| ⌘ (Espace)                                          | Ouvrir Spotlight                                          |
| ⌘⇥ (Commande-Tabulation)                                   | Liste des dix dernières applications utilisées                                 |
| ⌘\~                                                | Aller à la dernière application                                       |
| ⌘⇧3 (Commande-Majuscule-3)                              | Capture d'écran (apparaît en bas à gauche pour enregistrer ou agir dessus) |
| ⌘⇧4                                                | Capture d'écran et ouverture dans l'éditeur                    |
| Maintenir enfoncé ⌘                                   | Liste des raccourcis disponibles pour l'application                 |
| ⌘⌥D (Commande-Option/Alt-D)                         | Fait apparaître le dock                                      |
| ^⌥H (Contrôle-Option-H)                             | Bouton Accueil                                             |
| ^⌥H H (Contrôle-Option-H-H)                         | Afficher la barre de multitâche                                      |
| ^⌥I (Contrôle-Option-i)                             | Sélecteur d'éléments                                            |
| Échap                                             | Bouton Retour                                             |
| → (Flèche droite)                                    | Élément suivant                                               |
| ← (Flèche gauche)                                     | Élément précédent                                           |
| ↑↓ (Flèche vers le haut, Flèche vers le bas)                          | Appuyer simultanément sur l'élément sélectionné                        |
| ⌥ ↓ (Option-Flèche vers le bas)                            | Faire défiler vers le bas                                             |
| ⌥↑ (Option-Flèche vers le haut)                               | Faire défiler vers le haut                                               |
| ⌥← ou ⌥→ (Option-Flèche gauche ou Option-Flèche droite) | Faire défiler vers la gauche ou la droite                                    |
| ^⌥S (Contrôle-Option-S)                             | Activer ou désactiver la synthèse vocale VoiceOver                         |
| ⌘⇧⇥ (Commande-Majuscule-Tabulation)                            | Passer à l'application précédente                              |
| ⌘⇥ (Commande-Tabulation)                                   | Revenir à l'application d'origine                         |
| ←+→, puis Option
