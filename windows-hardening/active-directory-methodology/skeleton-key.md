# Attaque Skeleton Key

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

L'attaque **Skeleton Key** est une technique sophistiquée qui permet aux attaquants de **contourner l'authentification Active Directory** en **injectant un mot de passe maître** dans le contrôleur de domaine. Cela permet à l'attaquant de **s'authentifier en tant que n'importe quel utilisateur** sans leur mot de passe, leur accordant ainsi un **accès illimité** au domaine.

Elle peut être réalisée en utilisant [Mimikatz](https://github.com/gentilkiwi/mimikatz). Pour mener à bien cette attaque, les **droits d'administrateur de domaine sont requis**, et l'attaquant doit cibler chaque contrôleur de domaine pour garantir une violation complète. Cependant, l'effet de l'attaque est temporaire, car **redémarrer le contrôleur de domaine éradique le logiciel malveillant**, nécessitant une réimplémentation pour un accès soutenu.

L'**exécution de l'attaque** nécessite une seule commande : `misc::skeleton`.

## Atténuation

Les stratégies d'atténuation contre de telles attaques incluent la surveillance des ID d'événements spécifiques indiquant l'installation de services ou l'utilisation de privilèges sensibles. En particulier, rechercher l'ID d'événement Système 7045 ou l'ID d'événement Sécurité 4673 peut révéler des activités suspectes. De plus, exécuter `lsass.exe` en tant que processus protégé peut considérablement entraver les efforts des attaquants, car cela les oblige à utiliser un pilote en mode noyau, augmentant la complexité de l'attaque.

Voici les commandes PowerShell pour renforcer les mesures de sécurité :

- Pour détecter l'installation de services suspects, utilisez : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Pilote en mode noyau*"}`

- Spécifiquement, pour détecter le pilote de Mimikatz, la commande suivante peut être utilisée : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Pilote en mode noyau*" -and $_.message -like "*mimidrv*"}`

- Pour renforcer `lsass.exe`, il est recommandé de l'activer en tant que processus protégé : `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

La vérification après un redémarrage du système est cruciale pour s'assurer que les mesures de protection ont été appliquées avec succès. Cela est réalisable via : `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*processus protégé*`

## Références
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
