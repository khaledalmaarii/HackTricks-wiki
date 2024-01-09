# Skeleton Key

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Skeleton Key**

**De :** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

Il existe plusieurs méthodes pour compromettre les comptes Active Directory que les attaquants peuvent utiliser pour élever les privilèges et créer de la persistance une fois qu'ils se sont établis dans votre domaine. Le Skeleton Key est un malware particulièrement effrayant ciblant les domaines Active Directory pour rendre incroyablement facile le détournement de n'importe quel compte. Ce malware **s'injecte dans LSASS et crée un mot de passe maître qui fonctionnera pour n'importe quel compte dans le domaine**. Les mots de passe existants continueront également de fonctionner, il est donc très difficile de savoir que cette attaque a eu lieu à moins de savoir quoi chercher.

Sans surprise, c'est l'une des nombreuses attaques qui est empaquetée et très facile à réaliser en utilisant [Mimikatz](https://github.com/gentilkiwi/mimikatz). Examinons comment cela fonctionne.

### Exigences pour l'attaque Skeleton Key

Pour perpétrer cette attaque, **l'attaquant doit avoir des droits d'administrateur de domaine**. Cette attaque doit être **réalisée sur chaque contrôleur de domaine pour une compromission complète, mais même cibler un seul contrôleur de domaine peut être efficace**. **Redémarrer** un contrôleur de domaine **supprimera ce malware** et il devra être redéployé par l'attaquant.

### Réaliser l'attaque Skeleton Key

Réaliser l'attaque est très simple. Elle nécessite seulement la **commande suivante à exécuter sur chaque contrôleur de domaine** : `misc::skeleton`. Après cela, vous pouvez vous authentifier en tant que n'importe quel utilisateur avec le mot de passe par défaut de Mimikatz.

![Injecter une clé squelette en utilisant la commande misc::skeleton dans un contrôleur de domaine avec Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Voici une authentification pour un membre administrateur de domaine utilisant la clé squelette comme mot de passe pour obtenir un accès administratif à un contrôleur de domaine :

![Utiliser la clé squelette comme mot de passe avec la commande misc::skeleton pour obtenir un accès administratif à un contrôleur de domaine avec le mot de passe par défaut de Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Note : Si vous recevez un message disant : “System error 86 has occurred. The specified network password is not correct”, essayez simplement d'utiliser le format domaine\compte pour le nom d'utilisateur et cela devrait fonctionner.

![Utiliser le format domaine\compte pour le nom d'utilisateur si vous recevez un message disant System error 86 has occurred The specified network password is not correct](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

Si lsass a été **déjà patché** avec skeleton, alors cette **erreur** apparaîtra :

![](<../../.gitbook/assets/image (160).png>)

### Atténuations

* Événements :
* ID d'événement système 7045 - Un service a été installé dans le système. (Type pilote en mode noyau)
* ID d'événement de sécurité 4673 – Utilisation de privilège sensible ("Audit privilege use" doit être activé)
* ID d'événement 4611 – Un processus de connexion de confiance a été enregistré auprès de l'Autorité de sécurité locale ("Audit privilege use" doit être activé)
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* Cela détecte uniquement mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* Atténuation :
* Exécuter lsass.exe en tant que processus protégé, cela oblige un attaquant à charger un pilote en mode noyau
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* Vérifier après redémarrage : `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
