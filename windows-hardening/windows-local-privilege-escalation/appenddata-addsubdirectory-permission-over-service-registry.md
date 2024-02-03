<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


**Le post original est** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Résumé
La sortie du script indique que l'utilisateur actuel possède des permissions d'écriture sur deux clés de registre :

- `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
- `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Pour enquêter davantage sur les permissions du service RpcEptMapper, l'utilisateur mentionne l'utilisation de l'interface graphique regedit et souligne l'utilité de l'onglet Permissions effectives de la fenêtre Paramètres de sécurité avancés. Cet onglet permet aux utilisateurs de vérifier les permissions effectives accordées à un utilisateur ou groupe spécifique sans inspecter les ACE individuels.

La capture d'écran fournie affiche les permissions pour le compte lab-user à faibles privilèges. La plupart des permissions sont standard, telles que Query Value, mais une permission se démarque : Create Subkey. Le nom générique pour cette permission est AppendData/AddSubdirectory, ce qui correspond à ce qui a été rapporté par le script.

L'utilisateur explique ensuite que cela signifie qu'ils ne peuvent pas modifier certaines valeurs directement mais peuvent seulement créer de nouvelles sous-clés. Ils montrent un exemple où la tentative de modification de la valeur ImagePath aboutit à une erreur d'accès refusé.

Cependant, ils précisent que ce n'est pas un faux positif et qu'il y a ici une opportunité intéressante. Ils étudient la structure du registre Windows et découvrent une manière potentielle d'exploiter la sous-clé Performance, qui n'existe pas par défaut pour le service RpcEptMapper. Cette sous-clé pourrait potentiellement permettre l'enregistrement de DLL et la surveillance des performances, offrant une opportunité d'élévation de privilèges.

Ils mentionnent qu'ils ont trouvé de la documentation liée à la sous-clé Performance et comment l'utiliser pour la surveillance des performances. Cela les conduit à créer une DLL de preuve de concept et à montrer le code pour implémenter les fonctions requises : OpenPerfData, CollectPerfData, et ClosePerfData. Ils exportent également ces fonctions pour une utilisation externe.

L'utilisateur démontre le test de la DLL en utilisant rundll32 pour s'assurer qu'elle fonctionne comme prévu, en enregistrant avec succès des informations.

Ensuite, ils expliquent que le défi est de tromper le service RPC Endpoint Mapper pour qu'il charge leur DLL Performance. Ils mentionnent qu'ils ont observé la création de leur fichier log lors de l'interrogation des classes WMI liées aux données de performance dans PowerShell. Cela leur permet d'exécuter du code arbitraire dans le contexte du service WMI, qui s'exécute en tant que LOCAL SYSTEM. Cela leur fournit un accès inattendu et élevé.

En conclusion, l'utilisateur souligne la persistance inexpliquée de cette vulnérabilité et son impact potentiel, qui pourrait s'étendre à la post-exploitation, au mouvement latéral et à l'évasion d'antivirus/EDR.

Ils mentionnent également que bien qu'ils aient initialement rendu la vulnérabilité publique involontairement par le biais de leur script, son impact est limité aux versions non prises en charge de Windows (par exemple, Windows 7 / Server 2008 R2) avec un accès local.


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
