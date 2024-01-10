# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** grâce aux outils communautaires **les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le groupe** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Liste de contrôle d'accès (ACL)**

Une **ACL est une liste ordonnée d'ACE** qui définissent les protections applicables à un objet et ses propriétés. Chaque **ACE** identifie un **principal de sécurité** et spécifie un **ensemble de droits d'accès** qui sont autorisés, refusés ou audités pour ce principal de sécurité.

Le descripteur de sécurité d'un objet peut contenir **deux ACLs** :

1. Un **DACL** qui **identifie** les **utilisateurs** et **groupes** qui sont **autorisés** ou **refusés** l'accès
2. Un **SACL** qui contrôle **comment** l'accès est **audité**

Lorsqu'un utilisateur tente d'accéder à un fichier, le système Windows exécute un AccessCheck et compare le descripteur de sécurité avec le jeton d'accès de l'utilisateur et évalue si l'utilisateur a le droit d'accès et quel type d'accès en fonction des ACE définis.

### **Liste de contrôle d'accès discrétionnaire (DACL)**

Un DACL (souvent mentionné comme l'ACL) identifie les utilisateurs et les groupes qui se voient attribuer ou refuser des permissions d'accès sur un objet. Il contient une liste d'ACE appariés (Compte + Droit d'accès) à l'objet sécurisable.

### **Liste de contrôle d'accès système (SACL)**

Les SACL permettent de surveiller l'accès aux objets sécurisés. Les ACE dans un SACL déterminent **quels types d'accès sont enregistrés dans le journal des événements de sécurité**. Avec des outils de surveillance, cela pourrait déclencher une alarme pour alerter les bonnes personnes si des utilisateurs malveillants tentent d'accéder à l'objet sécurisé, et en cas d'incident, nous pouvons utiliser les journaux pour retracer les étapes dans le temps. Enfin, vous pouvez activer la journalisation pour dépanner les problèmes d'accès.

## Comment le système utilise les ACLs

Chaque **utilisateur connecté** au système **possède un jeton d'accès avec des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **a une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (Identifiant de Sécurité) qui identifie la session de connexion actuelle.

Lorsqu'un thread tente d'accéder à un objet sécurisable, l'LSASS (Local Security Authority) accorde ou refuse l'accès. Pour ce faire, l'**LSASS recherche dans le DACL** (Liste de contrôle d'accès discrétionnaire) dans le flux de données SDS, à la recherche d'ACE qui s'appliquent au thread.

**Chaque ACE dans le DACL de l'objet** spécifie les droits d'accès qui sont autorisés ou refusés pour un principal de sécurité ou une session de connexion. Si le propriétaire de l'objet n'a créé aucun ACE dans le DACL pour cet objet, le système accorde immédiatement le droit d'accès.

Si l'LSASS trouve des ACE, il compare le SID du bénéficiaire dans chaque ACE aux SIDs des bénéficiaires identifiés dans le jeton d'accès du thread.

### ACEs

Il existe **`trois` types principaux d'ACE** qui peuvent être appliqués à tous les objets sécurisables dans AD :

| **ACE**                  | **Description**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ACE de refus d'accès`**  | Utilisé dans un DACL pour indiquer qu'un utilisateur ou un groupe se voit explicitement refuser l'accès à un objet                                                                                   |
| **`ACE d'autorisation d'accès`** | Utilisé dans un DACL pour indiquer qu'un utilisateur ou un groupe se voit explicitement accorder l'accès à un objet                                                                                  |
| **`ACE d'audit système`**   | Utilisé dans un SACL pour générer des journaux d'audit lorsqu'un utilisateur ou un groupe tente d'accéder à un objet. Il enregistre si l'accès a été accordé ou non et quel type d'accès a eu lieu |

Chaque ACE est composé des `quatre` composants suivants :

1. L'identifiant de sécurité (SID) de l'utilisateur/groupe qui a accès à l'objet (ou nom principal graphiquement)
2. Un drapeau indiquant le type d'ACE (refus d'accès, autorisation d'accès ou ACE d'audit système)
3. Un ensemble de drapeaux qui spécifient si les conteneurs/objets enfants peuvent hériter de l'entrée ACE donnée de l'objet principal ou parent
4. Un [masque d'accès](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) qui est une valeur de 32 bits qui définit les droits accordés à un objet

Le système examine chaque ACE séquentiellement jusqu'à ce que l'un des événements suivants se produise :

* **Un ACE de refus d'accès refus explicitement** l'un des droits d'accès demandés à l'un des bénéficiaires répertoriés dans le jeton d'accès du thread.
* **Un ou plusieurs ACE d'autorisation d'accès** pour les bénéficiaires répertoriés dans le jeton d'accès du thread accordent explicitement tous les droits d'accès demandés.
* Tous les ACE ont été vérifiés et il reste au moins **un droit d'accès demandé** qui n'a **pas été explicitement autorisé**, dans ce cas, l'accès est implicitement **refusé**.

### Ordre des ACE

Comme le **système arrête de vérifier les ACE lorsque l'accès demandé est explicitement accordé ou refusé**, l'ordre des ACE dans un DACL est important.

L'ordre préféré des ACE dans un DACL est appelé l'ordre "canonique". Pour Windows 2000 et Windows Server 2003, l'ordre canonique est le suivant :

1. Tous les ACE **explicites** sont placés dans un groupe **avant** tout ACE **hérité**.
2. Au sein du groupe d'**ACE explicites**, les ACE de **refus d'accès** sont placés **avant les ACE d'autorisation d'accès**.
3. Au sein du groupe **hérité**, les ACE qui sont hérités du **parent de l'objet enfant viennent en premier**, et **ensuite** les ACE hérités du **grand-parent**, **et ainsi** de suite dans l'arbre des objets. Après cela, les ACE de **refus d'accès** sont placés **avant les ACE d'autorisation d'accès**.

La figure suivante montre l'ordre canonique des ACE :

### Ordre canonique des ACE

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

L'ordre canonique garantit que les éléments suivants se produisent :

* Un ACE de **refus d'accès explicite est appliqué indépendamment de tout ACE d'autorisation d'accès explicite**. Cela signifie que le propriétaire de l'objet peut définir des permissions qui permettent l'accès à un groupe d'utilisateurs et refuser l'accès à un sous-ensemble de ce groupe.
* Tous les **ACE explicites sont traités avant tout ACE hérité**. Cela est conforme au concept de contrôle d'accès discrétionnaire : l'accès à un objet enfant (par exemple un fichier) est à la discrétion du propriétaire de l'enfant, et non du propriétaire de l'objet parent (par exemple un dossier). Le propriétaire d'un objet enfant peut définir des permissions directement sur l'enfant. Le résultat est que les effets des permissions héritées sont modifiés.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** grâce aux outils communautaires **les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemple GUI

Voici l'onglet de sécurité classique d'un dossier montrant l'ACL, le DACL et les ACEs :

![](../../.gitbook/assets/classicsectab.jpg)

Si nous cliquons sur le **bouton Avancé**, nous aurons plus d'options comme l'héritage :

![](../../.gitbook/assets/aceinheritance.jpg)

Et si vous ajoutez ou modifiez un Principal de Sécurité :

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

Et enfin, nous avons le SACL dans l'onglet Audit :

![](../../.gitbook/assets/audit-tab.jpg)

### Exemple : Accès refusé explicite à un groupe

Dans cet exemple, le groupe autorisé est Tout le monde et le groupe refusé est Marketing, un sous-ensemble de Tout le monde.

Vous souhaitez refuser l'accès au groupe Marketing à un dossier Coût. Si les ACEs du dossier Coût sont dans l'ordre canonique, l'ACE qui refuse l'accès à Marketing vient avant l'ACE qui autorise Tout le monde.

Lors d'une vérification d'accès, le système d'exploitation parcourt les ACE dans l'ordre dans lequel ils apparaissent dans le DACL de l'objet, de sorte que l'ACE de refus est traité avant l'ACE d'autorisation. En conséquence, les utilisateurs membres du groupe Marketing se voient refuser l'accès. Tous les autres ont accès à l'objet.

### Exemple : Explicite avant hérité

Dans cet exemple, le dossier Coût a un ACE héritable qui refuse l'accès au Marketing (l'objet parent). En d'autres termes, tous les utilisateurs membres (ou enfants) du groupe Marketing se voient refuser l'accès par héritage.

Vous souhaitez autoriser l'accès à Bob, qui est le directeur du Marketing. En tant que membre du groupe Marketing, Bob se voit refuser l'accès au dossier Coût par héritage. Le propriétaire de l'objet enfant (utilisateur Bob) définit un ACE explicite qui autorise l'accès au dossier Coût. Si les ACEs de l'objet enfant sont dans l'ordre canonique, l'ACE explicite qui autorise l'accès à Bob vient avant tout ACE hérité, y compris l'ACE hérité qui refuse l'accès au groupe Marketing.

Lors d'une vérification d'accès, le système d'exploitation atteint l'ACE qui autorise l'accès à Bob avant d'arriver à l'ACE qui refuse l'accès au groupe Marketing. En conséquence, Bob a accès à l'objet même s'il est membre du groupe Marketing. Les autres membres du groupe Marketing se voient refuser l'accès.

### Entrées de contrôle d'accès

Comme mentionné précédemment, une ACL (Liste de contrôle d'accès) est une liste ordonnée d'ACE (Entrées de contrôle d'accès). Chaque ACE contient les éléments suivants :

* Un SID (Identifiant de Sécurité) qui identifie un utilisateur ou un groupe particulier.
* Un masque d'accès qui spécifie les droits d'accès.
* Un ensemble de drapeaux qui déterminent si les objets enfants peuvent hériter de l'ACE.
* Un drapeau qui indique le type d'ACE.

Les ACEs sont fondamentalement similaires. Ce qui les distingue, c'est le degré de contrôle qu'ils offrent sur l'héritage et l'accès aux objets. Il existe deux types d'ACE :

* Type générique qui est attaché à tous les objets sécurisables.
* Type spécifique à l'objet qui ne peut se produire que dans les ACL pour les objets Active Directory.

### ACE générique

Un ACE générique offre un contrôle limité sur les types d'objets enfants qui peuvent les hériter. Essentiellement, ils ne peuvent distinguer qu'entre les conteneurs et les non-conteneurs.

Par exemple, le DACL (Liste de contrôle d'accès discrétionnaire) sur un objet Dossier dans NTFS peut inclure un ACE générique qui permet à un groupe d'utilisateurs de lister le contenu du dossier. Comme lister le contenu d'un dossier est une opération qui ne peut être effectuée que sur un objet Conteneur, l'ACE qui permet l'opération peut être marqué comme un CONTAINER_INHERIT_ACE. Seuls les objets Conteneur dans le dossier (c'est-à-dire, seulement d'autres objets Dossier) héritent de l'ACE. Les objets non-conteneur (c'est-à-dire, les objets Fichier) n'héritent pas de l'ACE de l'objet parent.

Un ACE générique s'applique à un objet entier. Si un ACE générique donne à un utilisateur particulier un accès en lecture, l'utilisateur peut lire toutes les informations associées à l'objet — à la fois les données et les propriétés. Ce n'est pas une limitation sérieuse pour la plupart des types d'objets. Les objets Fichier, par exemple, ont peu de propriétés, qui sont toutes utilisées pour décrire les caractéristiques de l'objet plutôt que pour stocker des informations. La plupart des informations dans un objet Fichier sont stockées sous forme de données d'objet ; par conséquent, il y a peu de besoin de contrôles séparés sur les propriétés d'un fichier.

### ACE spécifique à l'objet

Un ACE spécifique à l'objet offre un degré de contrôle plus élevé sur les types d'objets enfants qui peuvent les hériter.

Par exemple, le ACL d'un objet OU (Unité Organisationnelle) peut avoir un ACE spécifique à l'objet qui est marqué pour l'héritage uniquement par les objets Utilisateur. D'autres types d'objets, tels que les objets Ordinateur, n'hériteront pas de l'ACE.

Cette capacité est la raison pour laquelle les ACE spécifiques à l'objet sont appelés spécifiques à l'objet. Leur héritage peut être limité à des types spécifiques d'objets enfants.

Il existe des différences similaires dans la façon dont les deux catégories de types d'ACE contrôlent l'accès aux objets.

Un ACE spécifique à l'objet peut s'appliquer à n'importe quelle propriété individuelle d'un objet ou à un ensemble de propriétés pour cet objet. Ce type d'ACE est utilis
