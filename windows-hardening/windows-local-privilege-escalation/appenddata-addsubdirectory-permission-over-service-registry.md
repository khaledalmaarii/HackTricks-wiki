<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


**Le message original est** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Résumé

Deux clés de registre ont été trouvées en écriture par l'utilisateur actuel :

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Il a été suggéré de vérifier les autorisations du service **RpcEptMapper** en utilisant l'interface graphique **regedit**, en particulier l'onglet **Autorisations efficaces** de la fenêtre **Paramètres de sécurité avancés**. Cette approche permet d'évaluer les autorisations accordées à des utilisateurs ou groupes spécifiques sans avoir besoin d'examiner chaque entrée de contrôle d'accès (ACE) individuellement.

Une capture d'écran montrait les autorisations attribuées à un utilisateur à faible privilège, parmi lesquelles la permission **Créer un sous-clé** était notable. Cette permission, également appelée **AppendData/AddSubdirectory**, correspondait aux résultats du script.

L'incapacité à modifier directement certaines valeurs, mais la capacité à créer de nouvelles sous-clés, a été notée. Un exemple mis en avant était une tentative de modifier la valeur **ImagePath**, qui a abouti à un message d'accès refusé.

Malgré ces limitations, un potentiel d'élévation de privilèges a été identifié grâce à la possibilité d'exploiter la sous-clé **Performance** au sein de la structure de registre du service **RpcEptMapper**, une sous-clé non présente par défaut. Cela pourrait permettre l'enregistrement de DLL et la surveillance des performances.

Une documentation sur la sous-clé **Performance** et son utilisation pour la surveillance des performances a été consultée, conduisant au développement d'une DLL de preuve de concept. Cette DLL, démontrant la mise en œuvre des fonctions **OpenPerfData**, **CollectPerfData** et **ClosePerfData**, a été testée via **rundll32**, confirmant son succès opérationnel.

L'objectif était de forcer le service **RPC Endpoint Mapper** à charger la DLL de Performance créée. Des observations ont révélé que l'exécution de requêtes de classe WMI liées aux données de performance via PowerShell entraînait la création d'un fichier journal, permettant l'exécution de code arbitraire sous le contexte **LOCAL SYSTEM**, accordant ainsi des privilèges élevés.

La persistance et les implications potentielles de cette vulnérabilité ont été soulignées, mettant en lumière sa pertinence pour les stratégies de post-exploitation, le mouvement latéral et l'évasion des systèmes antivirus/EDR.

Bien que la vulnérabilité ait été initialement divulguée involontairement via le script, il a été souligné que son exploitation est limitée aux anciennes versions de Windows (par exemple, **Windows 7 / Server 2008 R2**) et nécessite un accès local.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
