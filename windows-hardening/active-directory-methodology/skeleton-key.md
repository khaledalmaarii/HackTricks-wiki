# Skeleton Key

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Skeleton Key**

**De:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

Il existe plusieurs méthodes pour compromettre les comptes Active Directory que les attaquants peuvent utiliser pour élever les privilèges et créer une persistance une fois qu'ils se sont établis dans votre domaine. Le Skeleton Key est un malware particulièrement effrayant ciblant les domaines Active Directory pour rendre le détournement de compte alarmant facile. Ce malware **s'injecte dans LSASS et crée un mot de passe maître qui fonctionnera pour n'importe quel compte dans le domaine**. Les mots de passe existants continueront également à fonctionner, il est donc très difficile de savoir que cette attaque a eu lieu à moins de savoir quoi chercher.

Sans surprise, c'est l'une des nombreuses attaques qui est empaquetée et très facile à effectuer à l'aide de [Mimikatz](https://github.com/gentilkiwi/mimikatz). Voyons comment cela fonctionne.

### Exigences pour l'attaque Skeleton Key

Pour perpétrer cette attaque, **l'attaquant doit avoir des droits d'administrateur de domaine**. Cette attaque doit être **effectuée sur chaque contrôleur de domaine pour une compromission complète, mais même le ciblage d'un seul contrôleur de domaine peut être efficace**. **Redémarrer** un contrôleur de domaine **supprimera ce malware** et l'attaquant devra le redéployer.

### Réalisation de l'attaque Skeleton Key

L'attaque est très simple à effectuer. Il suffit de lancer la commande suivante **sur chaque contrôleur de domaine**: `misc::skeleton`. Après cela, vous pouvez vous authentifier en tant que n'importe quel utilisateur avec le mot de passe par défaut de Mimikatz.

![Injection d'une clé squelette à l'aide de misc::skeleton dans un contrôleur de domaine avec Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Voici une authentification pour un membre de l'administrateur de domaine utilisant la clé squelette comme mot de passe pour obtenir un accès administratif à un contrôleur de domaine :

![Utilisation de la clé squelette comme mot de passe avec la commande misc::skeleton pour obtenir un accès administratif à un contrôleur de domaine avec le mot de passe par défaut de Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Remarque : Si vous obtenez un message indiquant : "Erreur système 86 s'est produite. Le mot de passe réseau spécifié n'est pas correct", essayez simplement d'utiliser le format domaine\compte pour le nom d'utilisateur et cela devrait fonctionner.

![Utilisation du format domaine\compte pour le nom d'utilisateur si vous obtenez un message indiquant que l'erreur système 86 s'est produite. Le mot de passe réseau spécifié n'est pas correct](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

Si lsass était **déjà patché** avec skeleton, alors cette **erreur** apparaîtra :

![](<../../.gitbook/assets/image (160).png>)

### Atténuations

* Événements :
  * ID d'événement système 7045 - Un service a été installé dans le système. (Type de pilote de mode noyau)
  * ID d'événement de sécurité 4673 - Utilisation de privilèges sensibles ("Audit de l'utilisation des privilèges" doit être activé)
  * ID d'événement 4611 - Un processus d'ouverture de session de confiance a été enregistré auprès de l'autorité de sécurité locale ("Audit de l'utilisation des privilèges" doit être activé)
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* Cela ne détecte que mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* Atténuation :
  * Exécuter lsass.exe en tant que processus protégé, cela force un attaquant à charger un pilote de mode noyau
  * `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
  * Vérifier après le redémarrage : `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`processus protégé"}`_
