# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **Liste de contrôle d'accès (ACL)**

Une Liste de contrôle d'accès (ACL) se compose d'un ensemble ordonné d'entrées de contrôle d'accès (ACE) qui dictent les protections pour un objet et ses propriétés. En essence, une ACL définit quelles actions par quels principaux de sécurité (utilisateurs ou groupes) sont autorisées ou refusées sur un objet donné.

Il existe deux types d'ACL :

- **Liste de contrôle d'accès discrétionnaire (DACL) :** Spécifie quels utilisateurs et groupes ont ou n'ont pas accès à un objet.
- **Liste de contrôle d'accès système (SACL) :** Gère l'audit des tentatives d'accès à un objet.

Le processus d'accès à un fichier implique que le système vérifie le descripteur de sécurité de l'objet par rapport au jeton d'accès de l'utilisateur pour déterminer si l'accès doit être accordé et l'étendue de cet accès, en fonction des ACE.

### **Composants clés**

- **DACL :** Contient des ACE qui accordent ou refusent des autorisations d'accès aux utilisateurs et groupes pour un objet. C'est essentiellement la principale ACL qui dicte les droits d'accès.

- **SACL :** Utilisé pour l'audit de l'accès aux objets, où les ACE définissent les types d'accès à enregistrer dans le journal des événements de sécurité. Cela peut être inestimable pour détecter les tentatives d'accès non autorisées ou résoudre les problèmes d'accès.

### **Interaction du système avec les ACL**

Chaque session utilisateur est associée à un jeton d'accès contenant des informations de sécurité pertinentes pour cette session, y compris l'utilisateur, les identités de groupe et les privilèges. Ce jeton inclut également un SID de connexion qui identifie de manière unique la session.

L'Autorité de sécurité locale (LSASS) traite les demandes d'accès aux objets en examinant le DACL pour les ACE qui correspondent au principal de sécurité tentant d'accéder. L'accès est immédiatement accordé s'il n'y a pas d'ACE pertinents. Sinon, LSASS compare les ACE aux SID du principal de sécurité dans le jeton d'accès pour déterminer l'éligibilité à l'accès.

### **Processus résumé**

- **ACLs :** Définissent les autorisations d'accès via les DACL et les règles d'audit via les SACL.
- **Jeton d'accès :** Contient des informations sur l'utilisateur, le groupe et les privilèges pour une session.
- **Décision d'accès :** Faite en comparant les ACE DACL avec le jeton d'accès ; les SACL sont utilisés pour l'audit.

### ACEs

Il existe **trois principaux types d'entrées de contrôle d'accès (ACE)** :

- **ACE de refus d'accès :** Ce ACE refuse explicitement l'accès à un objet pour des utilisateurs ou groupes spécifiés (dans un DACL).
- **ACE d'autorisation d'accès :** Ce ACE accorde explicitement l'accès à un objet pour des utilisateurs ou groupes spécifiés (dans un DACL).
- **ACE d'audit système :** Positionné dans une Liste de contrôle d'accès système (SACL), ce ACE est responsable de la génération de journaux d'audit lors de tentatives d'accès à un objet par des utilisateurs ou groupes. Il documente si l'accès a été autorisé ou refusé et la nature de l'accès.

Chaque ACE a **quatre composants critiques** :

1. L'**Identifiant de sécurité (SID)** de l'utilisateur ou du groupe (ou leur nom principal dans une représentation graphique).
2. Un **drapeau** qui identifie le type d'ACE (accès refusé, autorisé ou audit système).
3. Des **drapeaux d'héritage** qui déterminent si les objets enfants peuvent hériter de l'ACE de leur parent.
4. Un **[masque d'accès](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, une valeur de 32 bits spécifiant les droits accordés à l'objet.

La détermination de l'accès est effectuée en examinant séquentiellement chaque ACE jusqu'à ce que :

- Un **ACE de refus d'accès** refuse explicitement les droits demandés à un bénéficiaire identifié dans le jeton d'accès.
- Les **ACE d'autorisation d'accès** accordent explicitement tous les droits demandés à un bénéficiaire dans le jeton d'accès.
- Après avoir vérifié tous les ACE, si un droit demandé n'a **pas été explicitement autorisé**, l'accès est implicitement **refusé**.

### Ordre des ACEs

La manière dont les **ACEs** (règles qui disent qui peut ou ne peut pas accéder à quelque chose) sont placés dans une liste appelée **DACL** est très importante. Cela est dû au fait que une fois que le système accorde ou refuse l'accès en fonction de ces règles, il cesse de regarder le reste.

Il y a une meilleure façon d'organiser ces ACEs, appelée **"ordre canonique"**. Cette méthode aide à s'assurer que tout fonctionne correctement et équitablement. Voici comment cela se passe pour les systèmes comme **Windows 2000** et **Windows Server 2003** :

- Tout d'abord, placez toutes les règles qui sont faites **spécifiquement pour cet élément** avant celles qui proviennent d'ailleurs, comme un dossier parent.
- Dans ces règles spécifiques, placez celles qui disent **"non" (refuser)** avant celles qui disent **"oui" (autoriser)**.
- Pour les règles qui proviennent d'ailleurs, commencez par celles de la **source la plus proche**, comme le parent, puis remontez à partir de là. Encore une fois, placez **"non"** avant **"oui"**.

Cette configuration aide de deux grandes manières :

* Elle garantit que si il y a un **"non"** spécifique, il est respecté, peu importe les autres règles **"oui"** qui sont là.
* Elle permet au propriétaire d'un élément d'avoir le **dernier mot** sur qui peut y accéder, avant que les règles des dossiers parents ou plus éloignés entrent en jeu.

En procédant de cette manière, le propriétaire d'un fichier ou dossier peut être très précis sur qui a accès, en s'assurant que les bonnes personnes peuvent accéder et que les mauvaises ne le peuvent pas.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Ainsi, cet **"ordre canonique"** vise à garantir que les règles d'accès sont claires et fonctionnent bien, en plaçant les règles spécifiques en premier et en organisant tout de manière intelligente.


<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemple GUI

**[Exemple d'ici](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Il s'agit de l'onglet de sécurité classique d'un dossier montrant l'ACL, le DACL et les ACEs :

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Si nous cliquons sur le **bouton Avancé**, nous aurons plus d'options comme l'héritage :

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Et si vous ajoutez ou modifiez un Principal de sécurité :

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Et enfin, nous avons le SACL dans l'onglet Audit :

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Explication du contrôle d'accès de manière simplifiée

Lors de la gestion de l'accès aux ressources, comme un dossier, nous utilisons des listes et des règles appelées Listes de contrôle d'accès (ACL) et Entrées de contrôle d'accès (ACE). Celles-ci définissent qui peut ou ne peut pas accéder à certaines données.

#### Refuser l'accès à un groupe spécifique

Imaginez que vous ayez un dossier nommé Coût, et que vous voulez que tout le monde y accède sauf une équipe marketing. En configurant correctement les règles, nous pouvons nous assurer que l'équipe marketing se voit explicitement refuser l'accès avant d'autoriser tout le monde. Cela se fait en plaçant la règle de refus d'accès à l'équipe marketing avant la règle qui autorise l'accès à tout le monde.

#### Autoriser l'accès à un membre spécifique d'un groupe refusé

Imaginons que Bob, le directeur marketing, ait besoin d'accéder au dossier Coût, même si l'équipe marketing ne devrait généralement pas y avoir accès. Nous pouvons ajouter une règle spécifique (ACE) pour Bob qui lui accorde l'accès, et la placer avant la règle qui refuse l'accès à l'équipe marketing. Ainsi, Bob obtient l'accès malgré la restriction générale de son équipe.

#### Compréhension des Entrées de contrôle d'accès

Les ACE sont les règles individuelles dans une ACL. Elles identifient les utilisateurs ou groupes, spécifient quel accès est autorisé ou refusé, et déterminent comment ces règles s'appliquent aux sous-éléments (héritage). Il existe deux principaux types d'ACE :

- **ACE génériques** : Ils s'appliquent largement, affectant soit tous les types d'objets, soit distinguant uniquement entre les conteneurs (comme les dossiers) et les non-conteneurs (comme les fichiers). Par exemple, une règle qui permet aux utilisateurs de voir le contenu d'un dossier mais pas d'accéder aux fichiers à l'intérieur.

- **ACE spécifiques à l'objet** : Ils offrent un contrôle plus précis, permettant de définir des règles pour des types d'objets spécifiques ou même des propriétés individuelles au sein d'un objet. Par exemple, dans un répertoire d'utilisateurs, une règle pourrait autoriser un utilisateur à mettre à jour son numéro de téléphone mais pas ses heures de connexion.

Chaque ACE contient des informations importantes comme à qui s'applique la règle (en utilisant un Identifiant de sécurité ou SID), ce que la règle autorise ou refuse (en utilisant un masque d'accès), et comment elle est héritée par d'autres objets.

#### Différences clés entre les types d'ACE

- Les **ACE génériques** conviennent aux scénarios simples de contrôle d'accès, où la même règle s'applique à tous les aspects d'un objet ou à tous les objets dans un conteneur.

- Les **ACE spécifiques à l'objet** sont utilisés pour des scénarios plus complexes, en particulier dans des environnements comme Active Directory, où vous pourriez avoir besoin de contrôler l'accès à des propriétés spécifiques d'un objet de manière différente.

En résumé, les ACL et les ACE aident à définir des contrôles d'accès précis, garantissant que seules les bonnes personnes ou groupes ont accès à des informations ou ressources sensibles, avec la possibilité d'adapter les droits d'accès jusqu'au niveau des propriétés individuelles ou des types d'objets.

### Mise en page de l'Entrée de contrôle d'accès

| Champ ACE | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Drapeau indiquant le type d'ACE. Windows 2000 et Windows Server 2003 prennent en charge six types d'ACE : Trois types d'ACE génériques attachés à tous les objets sécurisables. Trois types d'ACE spécifiques à l'objet qui peuvent se produire pour les objets Active Directory.                                                                                                                                                                                                                                                            |
| Drapeaux       | Ensemble de bits de contrôle d'héritage et d'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Taille        | Nombre d'octets de mémoire alloués pour l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Masque d'accès | Valeur de 32 bits dont les bits correspondent aux droits d'accès de l'objet. Les bits peuvent être activés ou désactivés, mais la signification du réglage dépend du type d'ACE. Par exemple, si le bit correspondant au droit de lire les autorisations est activé, et que le type d'ACE est Refuser, l'ACE refuse le droit de lire les autorisations de l'objet. Si le même bit est activé mais que le type d'ACE est Autoriser, l'ACE accorde le droit de lire les autorisations de l'objet. Plus de détails sur le Masque d'accès apparaissent dans le tableau suivant. |
| SID         | Identifie un utilisateur ou un groupe dont l'accès est contrôlé ou surveillé par cet ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Mise en page du Masque d'accès

| Bit (Plage) | Signification                            | Description/Exemple                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Droits d'accès spécifiques à l'objet      | Lire les données, Exécuter, Ajouter des données           |
| 16 - 22     | Droits d'accès standard             | Supprimer, Écrire ACL, Écrire le propriétaire            |
| 23          | Peut accéder à la liste de contrôle d'accès de sécurité            |                                           |
| 24 - 27     | Réservé                           |                                           |
| 28          | Générique TOUT (Lire, Écrire, Exécuter) | Tout en dessous                          |
| 29          | Exécution générique                    | Tout ce qui est nécessaire pour exécuter un programme |
| 30          | Écriture générique                      | Tout ce qui est nécessaire pour écrire dans un fichier   |
| 31          | Lecture générique                       | Tout ce qui est nécessaire pour lire un fichier       |
