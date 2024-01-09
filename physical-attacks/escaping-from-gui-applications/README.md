```markdown
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Vérifiez les actions possibles à l'intérieur de l'application GUI

Les **Dialogues Communs** sont ces options de **sauvegarde d'un fichier**, **ouverture d'un fichier**, sélection d'une police, d'une couleur... La plupart offriront une **fonctionnalité d'Explorateur complète**. Cela signifie que vous pourrez accéder aux fonctionnalités de l'Explorateur si vous pouvez accéder à ces options :

* Fermer/Enregistrer sous
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

## Exécution de Commande

Peut-être qu'en **utilisant l'option** _**Ouvrir avec**_ vous pouvez ouvrir/exécuter une sorte de shell.

### Windows

Par exemple _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trouvez plus de binaires qui peuvent être utilisés pour exécuter des commandes (et effectuer des actions inattendues) ici : [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Plus ici : [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Contournement des restrictions de chemin

* **Variables d'environnement** : Il y a beaucoup de variables d'environnement qui pointent vers un chemin
* **Autres protocoles** : _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Liens symboliques**
* **Raccourcis** : CTRL+N (ouvrir nouvelle session), CTRL+R (Exécuter Commandes), CTRL+SHIFT+ESC (Gestionnaire de tâches),  Windows+E (ouvrir explorateur), CTRL-B, CTRL-I (Favoris), CTRL-H (Historique), CTRL-L, CTRL-O (Dialogue Fichier/Ouvrir), CTRL-P (Dialogue Imprimer), CTRL-S (Enregistrer sous)
* Menu Administratif caché : CTRL-ALT-F8, CTRL-ESC-F9
* **URI Shell** : _shell:Outils d'administration, shell:Bibliothèque de documents, shell:Bibliothèques, shell:Profils d'utilisateur, shell:Personnel, shell:Dossier de recherche, shell:Système, shell:Dossier de lieux réseau, shell:Envoyer à, shell:Profils d'utilisateur, shell:Outils d'administration communs, shell:Dossier Mon Ordinateur, shell:Dossier Internet_
* **Chemins UNC** : Chemins pour se connecter aux dossiers partagés. Vous devriez essayer de vous connecter au C$ de la machine locale ("\\\127.0.0.1\c$\Windows\System32")
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

## Téléchargez vos Binaires

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

* Touches Collantes – Appuyez 5 fois sur SHIFT
* Touches Souris – SHIFT+ALT+VERROU NUM
* Contraste Élevé – SHIFT+ALT+IMPR ÉCRAN
* Touches Bascule – Maintenez VERROU NUM pendant 5 secondes
* Touches Filtre – Maintenez la touche SHIFT droite pendant 12 secondes
* WINDOWS+F1 – Recherche Windows
* WINDOWS+D – Afficher le Bureau
* WINDOWS+E – Lancer l'Explorateur Windows
* WINDOWS+R – Exécuter
* WINDOWS+U – Centre d'Accessibilité
* WINDOWS+F – Recherche
* SHIFT+F10 – Menu Contextuel
* CTRL+SHIFT+ESC – Gestionnaire de Tâches
* CTRL+ALT+SUPPR – Écran de démarrage sur les nouvelles versions de Windows
* F1 – Aide F3 – Recherche
* F6 – Barre d'Adresse
* F11 – Basculer en plein écran dans Internet Explorer
* CTRL+H – Historique Internet Explorer
* CTRL+T – Internet Explorer – Nouvel Onglet
* CTRL+N – Internet Explorer – Nouvelle Page
* CTRL+O – Ouvrir Fichier
* CTRL+S – Enregistrer CTRL+N – Nouveau RDP / Citrix

## Balayages

* Balayez de la gauche vers la droite pour voir toutes les fenêtres ouvertes, minimisant l'application KIOSK et accédant directement à tout le système d'exploitation ;
* Balayez de la droite vers la gauche pour ouvrir le Centre d'Action, minimisant l'application KIOSK et accédant directement à tout le système d'exploitation ;
* Balayez du haut vers le bas pour rendre la barre de titre visible pour une application ouverte en mode plein écran ;
* Balayez du bas vers le haut pour afficher la barre des tâches dans une application en plein écran.

## Astuces Internet Explorer

### 'Barre d'outils Image'

C'est une barre d'outils qui apparaît en haut à gauche de l'image lorsqu'elle est cliquée. Vous pourrez Enregistrer, Imprimer, Mailto, Ouvrir "Mes Images" dans l'Explorateur. Le Kiosque doit utiliser Internet Explorer.

### Protocole Shell

Tapez ces URL pour obtenir une vue Explorateur :

* `shell:Outils d'administration`
* `shell:Bibliothèque de documents`
* `shell:Bibliothèques`
* `shell:Profils d'utilisateur`
* `shell:Personnel`
* `shell:Dossier de recherche`
* `shell:Dossier de lieux réseau`
* `shell:Envoyer à`
* `shell:Profils d'utilisateur`
* `shell:Outils d'administration communs`
* `shell:Dossier Mon Ordinateur`
* `shell:Dossier Internet`
* `Shell:Profil`
* `Shell:ProgramFiles`
* `Shell:Système`
* `Shell:Dossier du Panneau de Contrôle`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panneau de Contrôle
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mon Ordinateur
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mes Lieux Réseau
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

# Astuces pour navigateurs

Versions de sauvegarde iKat :

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Créez un dialogue commun en utilisant JavaScript et accédez à l'explorateur de fichiers : `document.write('<input/type=file>')`
Source : https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestes et fonds

### Balayez vers le haut avec quatre (ou cinq) doigts / Double-tapez sur le bouton Home

Pour voir la vue multitâche et changer d'application

### Balayez d'un côté ou de l'autre avec quatre ou cinq doigts

Pour passer à l'application suivante/précédente

### Pincez l'écran avec cinq doigts / Touchez le bouton Home / Balayez vers le haut avec 1 doigt depuis le bas de l'écran dans un mouvement rapide vers le haut

Pour accéder à l'accueil

### Balayez un doigt depuis le bas de l'écran juste 1-2 pouces (lentement)

Le dock apparaîtra

### Balayez vers le bas depuis le haut de l'écran avec 1 doigt

Pour voir vos notifications

### Balayez vers le bas avec 1 doigt le coin supérieur droit de l'écran

Pour voir le centre de contrôle de l'iPad Pro

### Balayez 1 doigt depuis la gauche de l'écran 1-2 pouces

Pour voir la vue Aujourd'hui

### Balayez rapidement 1 doigt depuis le centre de l'écran vers la droite ou la gauche

Pour changer à l'application suivante/précédente

### Appuyez et maintenez le bouton On/**Off**/Veille en haut à droite de l'**iPad +** Déplacez le curseur Éteindre vers la droite,

Pour éteindre

### Appuyez sur le bouton On/**Off**/Veille en haut à droite de l'**iPad et le bouton Home pendant quelques secondes**

Pour forcer un arrêt complet

### Appuyez sur le bouton On/**Off**/Veille en haut à droite de l'**iPad et le bouton Home rapidement**

Pour prendre une capture d'écran qui apparaîtra dans le coin inférieur gauche de l'écran. Appuyez sur les deux boutons en même temps très brièvement car si vous les maintenez quelques secondes, un arrêt complet sera effectué.

## Raccourcis

Vous devriez avoir un clavier iPad ou un adaptateur de clavier USB. Seuls les raccourcis qui pourraient aider à s'échapper de l'application seront montrés ici.

| Touche | Nom           |
| ------ | ------------- |
| ⌘      | Commande      |
| ⌥      | Option (Alt)  |
| ⇧      | Majuscule     |
| ↩      | Retour        |
| ⇥      | Tabulation    |
| ^      | Contrôle      |
| ←      | Flèche Gauche |
| →      | Flèche Droite |
| ↑      | Flèche Haut   |
| ↓      | Flèche Bas    |

### Raccourcis système

Ces raccourcis sont pour les paramètres visuels et sonores, en fonction de l'utilisation de l'iPad.

| Raccourci | Action                                                                         |
| --------- | ------------------------------------------------------------------------------ |
| F1        | Assombrir l'écran                                                              |
| F2        | Éclaircir l'écran                                                              |
| F7        | Revenir une chanson en arrière                                                 |
| F8        | Lecture/pause                                                                  |
| F9        | Passer la chanson                                                              |
| F10       | Muet                                                                           |
| F11       | Diminuer le volume                                                             |
| F12       | Augmenter le volume                                                            |
| ⌘ Espace  | Afficher une liste de langues disponibles ; pour en choisir une, appuyez à nouveau sur la barre d'espace. |

### Navigation iPad

| Raccourci                                         | Action                                                  |
| ------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                | Aller à l'accueil                                       |
| ⌘⇧H (Commande-Majuscule-H)                        | Aller à l'accueil                                       |
| ⌘ (Espace)                                        | Ouvrir Spotlight                                        |
| ⌘⇥ (Commande-Tabulation)                          | Lister les dix dernières applications utilisées         |
| ⌘\~                                               | Aller à la dernière application                         |
| ⌘⇧3 (Commande-Majuscule-3)                        | Capture d'écran (flotte en bas à gauche pour sauvegarder ou agir dessus) |
| ⌘⇧4                                                | Capture d'écran et l'ouvrir dans l'éditeur              |
| Maintenir appuyé ⌘                                 | Liste des raccourcis disponibles pour l'application     |
| ⌘⌥D (Commande-Option/Alt-D)                       | Faire apparaître le dock                                |
| ^⌥H (Contrôle-Option-H)                           | Bouton d'accueil                                        |
| ^⌥H H (Contrôle-Option-H-H)                       | Afficher la barre multitâche                            |
| ^⌥I (Contrôle-Option-i)                           | Choix de l'élément                                      |
| Échapper                                           | Bouton de retour                                        |
| → (Flèche droite)                                  | Élément suivant                                         |
| ← (Flèche gauche)                                  | Élément précédent                                       |
| ↑↓ (Flèche haut, Flèche bas)                       | Appuyer simultanément sur l'élément sélectionné         |
| ⌥ ↓ (Option-Flèche bas)                            | Faire défiler vers le bas                               |
| ⌥↑ (Option-Flèche haut)                            | Faire défiler vers le haut                              |
| ⌥← ou ⌥→ (Option-Flèche gauche ou Option-Flèche droite) | Faire défiler vers la gauche ou la droite              |
| ^⌥S (Contrôle-Option-S)                            | Activer ou désactiver la parole de VoiceOver            |
| ⌘⇧⇥ (Commande-Majuscule-Tabulation)                | Passer à l'application précédente                       |
| ⌘⇥ (Commande-Tabulation)                           | Revenir à l'application d'origine                       |
| ←+→, puis Option + ← ou Option+→                   | Naviguer dans le Dock                                   |

### Raccourcis Safari

| Raccourci              | Action                                           |
| ---------------------- | ------------------------------------------------ |
| ⌘L (Commande-L)        | Ouvrir l'emplacement                             |
| ⌘T                     | Ouvrir un nouvel onglet                          |
| ⌘W                     | Fermer l'onglet actuel                           |
| ⌘R                     | Rafraîchir l'onglet actuel                       |
|
