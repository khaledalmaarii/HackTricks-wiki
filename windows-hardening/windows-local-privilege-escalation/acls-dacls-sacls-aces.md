# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) pour créer et **automatiser facilement des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## **Liste de Contrôle d'Accès (ACL)**

Une Liste de Contrôle d'Accès (ACL) se compose d'un ensemble ordonné d'Entrées de Contrôle d'Accès (ACE) qui dictent les protections pour un objet et ses propriétés. En essence, une ACL définit quelles actions par quels principaux de sécurité (utilisateurs ou groupes) sont autorisées ou refusées sur un objet donné.

Il existe deux types d'ACL :

* **Liste de Contrôle d'Accès Discrétionnaire (DACL) :** Spécifie quels utilisateurs et groupes ont ou n'ont pas accès à un objet.
* **Liste de Contrôle d'Accès Système (SACL) :** Régit l'audit des tentatives d'accès à un objet.

Le processus d'accès à un fichier implique que le système vérifie le descripteur de sécurité de l'objet par rapport au jeton d'accès de l'utilisateur pour déterminer si l'accès doit être accordé et l'étendue de cet accès, basé sur les ACE.

### **Composants Clés**

* **DACL :** Contient des ACE qui accordent ou refusent des permissions d'accès aux utilisateurs et groupes pour un objet. C'est essentiellement la principale ACL qui dicte les droits d'accès.
* **SACL :** Utilisé pour auditer l'accès aux objets, où les ACE définissent les types d'accès à enregistrer dans le Journal des Événements de Sécurité. Cela peut être inestimable pour détecter des tentatives d'accès non autorisées ou résoudre des problèmes d'accès.

### **Interaction du Système avec les ACL**

Chaque session utilisateur est associée à un jeton d'accès qui contient des informations de sécurité pertinentes pour cette session, y compris les identités d'utilisateur, de groupe et les privilèges. Ce jeton inclut également un SID de connexion qui identifie de manière unique la session.

L'Autorité de Sécurité Locale (LSASS) traite les demandes d'accès aux objets en examinant la DACL pour les ACE qui correspondent au principal de sécurité tentant d'accéder. L'accès est immédiatement accordé si aucune ACE pertinente n'est trouvée. Sinon, LSASS compare les ACE avec le SID du principal de sécurité dans le jeton d'accès pour déterminer l'éligibilité à l'accès.

### **Processus Résumé**

* **ACLs :** Définissent les permissions d'accès via les DACL et les règles d'audit via les SACL.
* **Jeton d'Accès :** Contient des informations sur l'utilisateur, le groupe et les privilèges pour une session.
* **Décision d'Accès :** Prise en comparant les ACE de la DACL avec le jeton d'accès ; les SACL sont utilisés pour l'audit.

### ACEs

Il existe **trois principaux types d'Entrées de Contrôle d'Accès (ACE)** :

* **ACE d'Accès Refusé :** Cette ACE refuse explicitement l'accès à un objet pour des utilisateurs ou groupes spécifiés (dans une DACL).
* **ACE d'Accès Autorisé :** Cette ACE accorde explicitement l'accès à un objet pour des utilisateurs ou groupes spécifiés (dans une DACL).
* **ACE d'Audit Système :** Positionnée dans une Liste de Contrôle d'Accès Système (SACL), cette ACE est responsable de la génération de journaux d'audit lors des tentatives d'accès à un objet par des utilisateurs ou groupes. Elle documente si l'accès a été autorisé ou refusé et la nature de l'accès.

Chaque ACE a **quatre composants critiques** :

1. Le **Identifiant de Sécurité (SID)** de l'utilisateur ou du groupe (ou leur nom principal dans une représentation graphique).
2. Un **drapeau** qui identifie le type d'ACE (accès refusé, autorisé ou audit système).
3. Des **drapeaux d'héritage** qui déterminent si les objets enfants peuvent hériter de l'ACE de leur parent.
4. Un [**masque d'accès**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), une valeur de 32 bits spécifiant les droits accordés à l'objet.

La détermination d'accès est effectuée en examinant séquentiellement chaque ACE jusqu'à ce que :

* Une **ACE d'Accès Refusé** refuse explicitement les droits demandés à un fiduciaire identifié dans le jeton d'accès.
* Des **ACE d'Accès Autorisé** accordent explicitement tous les droits demandés à un fiduciaire dans le jeton d'accès.
* Après avoir vérifié toutes les ACE, si un droit demandé n'a **pas été explicitement autorisé**, l'accès est implicitement **refusé**.

### Ordre des ACEs

La façon dont les **ACEs** (règles qui disent qui peut ou ne peut pas accéder à quelque chose) sont mises dans une liste appelée **DACL** est très importante. Cela est dû au fait qu'une fois que le système accorde ou refuse l'accès en fonction de ces règles, il cesse de regarder le reste.

Il existe une meilleure façon d'organiser ces ACE, et elle s'appelle **"ordre canonique."** Cette méthode aide à s'assurer que tout fonctionne de manière fluide et équitable. Voici comment cela se passe pour des systèmes comme **Windows 2000** et **Windows Server 2003** :

* D'abord, mettez toutes les règles qui sont faites **spécifiquement pour cet élément** avant celles qui viennent d'ailleurs, comme un dossier parent.
* Dans ces règles spécifiques, placez celles qui disent **"non" (refuser)** avant celles qui disent **"oui" (autoriser)**.
* Pour les règles qui viennent d'ailleurs, commencez par celles de la **source la plus proche**, comme le parent, puis revenez en arrière. Encore une fois, mettez **"non"** avant **"oui."**

Cette configuration aide de deux grandes manières :

* Elle s'assure que s'il y a un **"non"** spécifique, il est respecté, peu importe les autres règles **"oui"** qui existent.
* Elle permet au propriétaire d'un élément d'avoir le **dernier mot** sur qui peut entrer, avant que des règles provenant de dossiers parents ou plus éloignés ne prennent effet.

En procédant de cette manière, le propriétaire d'un fichier ou d'un dossier peut être très précis sur qui obtient l'accès, s'assurant que les bonnes personnes peuvent entrer et que les mauvaises ne le peuvent pas.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Ainsi, cet **"ordre canonique"** vise à garantir que les règles d'accès sont claires et fonctionnent bien, en plaçant les règles spécifiques en premier et en organisant le tout de manière intelligente.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemple GUI

[**Exemple d'ici**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Voici l'onglet de sécurité classique d'un dossier montrant l'ACL, DACL et ACEs :

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Si nous cliquons sur le **bouton Avancé**, nous obtiendrons plus d'options comme l'héritage :

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Et si vous ajoutez ou modifiez un Principal de Sécurité :

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Et enfin, nous avons le SACL dans l'onglet d'Audit :

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Expliquer le Contrôle d'Accès de Manière Simplifiée

Lors de la gestion de l'accès aux ressources, comme un dossier, nous utilisons des listes et des règles connues sous le nom de Listes de Contrôle d'Accès (ACL) et d'Entrées de Contrôle d'Accès (ACE). Celles-ci définissent qui peut ou ne peut pas accéder à certaines données.

#### Refuser l'Accès à un Groupe Spécifique

Imaginez que vous avez un dossier nommé Coût, et que vous souhaitez que tout le monde y accède sauf l'équipe marketing. En configurant correctement les règles, nous pouvons nous assurer que l'équipe marketing se voit explicitement refuser l'accès avant d'autoriser tout le monde d'autre. Cela se fait en plaçant la règle de refus d'accès à l'équipe marketing avant la règle qui autorise l'accès à tout le monde.

#### Autoriser l'Accès à un Membre Spécifique d'un Groupe Refusé

Disons que Bob, le directeur marketing, a besoin d'accéder au dossier Coût, même si l'équipe marketing ne devrait généralement pas avoir accès. Nous pouvons ajouter une règle spécifique (ACE) pour Bob qui lui accorde l'accès, et la placer avant la règle qui refuse l'accès à l'équipe marketing. De cette manière, Bob obtient l'accès malgré la restriction générale sur son équipe.

#### Comprendre les Entrées de Contrôle d'Accès

Les ACE sont les règles individuelles dans une ACL. Elles identifient les utilisateurs ou groupes, spécifient quel accès est autorisé ou refusé, et déterminent comment ces règles s'appliquent aux sous-éléments (héritage). Il existe deux principaux types d'ACE :

* **ACEs Génériques :** Celles-ci s'appliquent largement, affectant soit tous les types d'objets, soit ne distinguant qu'entre les conteneurs (comme les dossiers) et les non-conteneurs (comme les fichiers). Par exemple, une règle qui permet aux utilisateurs de voir le contenu d'un dossier mais pas d'accéder aux fichiers à l'intérieur.
* **ACEs Spécifiques à l'Objet :** Celles-ci fournissent un contrôle plus précis, permettant de définir des règles pour des types d'objets spécifiques ou même des propriétés individuelles au sein d'un objet. Par exemple, dans un annuaire d'utilisateurs, une règle pourrait permettre à un utilisateur de mettre à jour son numéro de téléphone mais pas ses heures de connexion.

Chaque ACE contient des informations importantes comme à qui la règle s'applique (en utilisant un Identifiant de Sécurité ou SID), ce que la règle autorise ou refuse (en utilisant un masque d'accès), et comment elle est héritée par d'autres objets.

#### Différences Clés Entre les Types d'ACE

* **ACEs Génériques** sont adaptées pour des scénarios de contrôle d'accès simples, où la même règle s'applique à tous les aspects d'un objet ou à tous les objets au sein d'un conteneur.
* **ACEs Spécifiques à l'Objet** sont utilisées pour des scénarios plus complexes, en particulier dans des environnements comme Active Directory, où vous pourriez avoir besoin de contrôler l'accès à des propriétés spécifiques d'un objet différemment.

En résumé, les ACL et les ACE aident à définir des contrôles d'accès précis, garantissant que seules les bonnes personnes ou groupes ont accès à des informations ou ressources sensibles, avec la capacité d'adapter les droits d'accès jusqu'au niveau des propriétés individuelles ou des types d'objets.

### Disposition de l'Entrée de Contrôle d'Accès

| Champ ACE   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Drapeau qui indique le type d'ACE. Windows 2000 et Windows Server 2003 prennent en charge six types d'ACE : Trois types d'ACE génériques qui sont attachés à tous les objets sécurisables. Trois types d'ACE spécifiques à l'objet qui peuvent se produire pour des objets Active Directory.                                                                                                                                                                                                                                                            |
| Drapeaux    | Ensemble de drapeaux binaires qui contrôlent l'héritage et l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Taille      | Nombre d'octets de mémoire qui sont alloués pour l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Masque d'accès | Valeur de 32 bits dont les bits correspondent aux droits d'accès pour l'objet. Les bits peuvent être activés ou désactivés, mais la signification du paramètre dépend du type d'ACE. Par exemple, si le bit qui correspond au droit de lire les permissions est activé, et que le type d'ACE est Refuser, l'ACE refuse le droit de lire les permissions de l'objet. Si le même bit est activé mais que le type d'ACE est Autoriser, l'ACE accorde le droit de lire les permissions de l'objet. Plus de détails sur le masque d'accès apparaissent dans le tableau suivant. |
| SID         | Identifie un utilisateur ou un groupe dont l'accès est contrôlé ou surveillé par cette ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Disposition du Masque d'Accès

| Bit (Plage) | Signification                            | Description/Exemple                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Droits d'Accès Spécifiques à l'Objet      | Lire des données, Exécuter, Ajouter des données           |
| 16 - 22     | Droits d'Accès Standards             | Supprimer, Écrire ACL, Écrire Propriétaire            |
| 23          | Peut accéder à l'ACL de sécurité            |                                           |
| 24 - 27     | Réservé                           |                                           |
| 28          | Générique TOUT (Lire, Écrire, Exécuter) | Tout en dessous                          |
| 29          | Générique Exécuter                    | Toutes les choses nécessaires pour exécuter un programme |
| 30          | Générique Écrire                      | Toutes les choses nécessaires pour écrire dans un fichier   |
| 31          | Générique Lire                       | Toutes les choses nécessaires pour lire un fichier       |

## Références

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) pour créer et **automatiser facilement des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
