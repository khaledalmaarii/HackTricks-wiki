# ACLs - DACLs/SACLs/ACEs

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Liste de contrôle d'accès (ACL)**

Une **ACL est une liste ordonnée d'ACE** qui définit les protections qui s'appliquent à un objet et à ses propriétés. Chaque **ACE** identifie un **principal de sécurité** et spécifie un **ensemble de droits d'accès** qui sont autorisés, refusés ou audités pour ce principal de sécurité.

Le descripteur de sécurité d'un objet peut contenir **deux ACL** :

1. Un **DACL** qui **identifie** les **utilisateurs** et les **groupes** qui sont **autorisés** ou **refusés** d'accès
2. Un **SACL** qui contrôle **comment** l'accès est **audité**

Lorsqu'un utilisateur tente d'accéder à un fichier, le système Windows exécute une vérification d'accès et compare le descripteur de sécurité avec le jeton d'accès de l'utilisateur et évalue si l'utilisateur est autorisé à accéder et quel type d'accès en fonction des ACE définis.

### **Liste de contrôle d'accès discrétionnaire (DACL)**

Un DACL (souvent mentionné comme ACL) identifie les utilisateurs et les groupes auxquels des autorisations d'accès sont attribuées ou refusées sur un objet. Il contient une liste de paires ACE (compte + droit d'accès) pour l'objet sécurisable.

### **Liste de contrôle d'accès système (SACL)**

Les SACL permettent de surveiller l'accès aux objets sécurisés. Les ACE dans un SACL déterminent **quels types d'accès sont enregistrés dans le journal des événements de sécurité**. Avec des outils de surveillance, cela peut déclencher une alarme auprès des bonnes personnes si des utilisateurs malveillants tentent d'accéder à l'objet sécurisé, et dans un scénario d'incident, nous pouvons utiliser les journaux pour retracer les étapes dans le temps. Enfin, vous pouvez activer la journalisation pour résoudre les problèmes d'accès.

## Comment le système utilise les ACL

Chaque **utilisateur connecté** au système **dispose d'un jeton d'accès avec des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **dispose d'une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (identificateur de sécurité) qui identifie la session de connexion actuelle.

Lorsqu'un thread tente d'accéder à un objet sécurisable, le LSASS (Autorité de sécurité locale) accorde ou refuse l'accès. Pour ce faire, le **LSASS recherche le DACL** (Liste de contrôle d'accès discrétionnaire) dans le flux de données SDS, à la recherche des ACE qui s'appliquent au thread.

**Chaque ACE dans le DACL de l'objet** spécifie les droits d'accès autorisés ou refusés pour un principal de sécurité ou une session de connexion. Si le propriétaire de l'objet n'a créé aucun ACE dans le DACL pour cet objet, le système accorde immédiatement l'accès.

Si le LSASS trouve des ACE, il compare l'identifiant SID du bénéficiaire dans chaque ACE aux SID des bénéficiaires identifiés dans le jeton d'accès du thread.

### ACEs

Il existe **`trois` types principaux d'ACE** qui peuvent être appliqués à tous les objets sécurisables dans AD :

| **ACE**                  | **Description**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ACE de refus d'accès`**  | Utilisé dans un DACL pour montrer qu'un utilisateur ou un groupe est explicitement refusé d'accéder à un objet                                                                                   |
| **`ACE d'autorisation d'accès`** | Utilisé dans un DACL pour montrer qu'un utilisateur ou un groupe est explicitement autorisé à accéder à un objet                                                                                  |
| **`ACE d'audit système`**   | Utilisé dans un SACL pour générer des journaux d'audit lorsqu'un utilisateur ou un groupe tente d'accéder à un objet. Il enregistre si l'accès a été accordé ou non et quel type d'accès a eu lieu |

Chaque ACE est composé des `quatre` composants suivants :

1. L'identificateur de sécurité (SID) de l'utilisateur/groupe qui a accès à l'objet (ou le nom du principal graphiquement)
2. Un indicateur indiquant le type d'ACE (ACE de refus d'accès, d'autorisation d'accès ou d'audit système)
3. Un ensemble d'indicateurs spécifiant si les conteneurs/objets enfants peuvent hériter de l'entrée ACE donnée à partir de l'objet principal ou parent
4. Un [masque d'accès](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) qui est une valeur de 32 bits qui définit les droits accordés à un objet

Le système examine chaque ACE séquentiellement jusqu'à ce que l'un des événements suivants se produise :

* **Un ACE de refus d'accès refuse explicitement** l'un des droits d'accès demandés à l'un des bénéficiaires répertoriés dans le jeton d'accès du thread.
* **Un ou plusieurs ACE d'autorisation d'accès** pour les bénéficiaires répertoriés dans le jeton d'accès du thread accordent explicitement tous les droits d'accès demandés.
* Tous les ACE ont été vérifiés et il y a encore au moins **un droit d'accès demandé** qui n'a **pas été explicitement autorisé**, auquel cas l'accès est implicitement **refusé**.
### Ordre des ACE

Parce que le **système arrête de vérifier les ACE lorsque l'accès demandé est explicitement accordé ou refusé**, l'ordre des ACE dans un DACL est important.

L'ordre préféré des ACE dans un DACL est appelé l'ordre "canonique". Pour Windows 2000 et Windows Server 2003, l'ordre canonique est le suivant :

1. Tous les ACE **explicites** sont placés dans un groupe **avant** tous les ACE **hérités**.
2. Au sein du groupe des ACE **explicites**, les ACE **d'accès refusé** sont placés **avant les ACE d'accès autorisé**.
3. Au sein du groupe **hérité**, les ACE hérités du **parent de l'objet enfant viennent en premier**, puis les ACE hérités du **grand-parent**, **et ainsi de suite** dans l'arborescence des objets. Ensuite, les ACE **d'accès refusé** sont placés **avant les ACE d'accès autorisé**.

La figure suivante montre l'ordre canonique des ACE :

### Ordre canonique des ACE

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

L'ordre canonique garantit que les actions suivantes se produisent :

* Un ACE **d'accès refusé explicite est appliqué indépendamment de tout ACE d'accès autorisé explicite**. Cela signifie que le propriétaire de l'objet peut définir des autorisations qui permettent l'accès à un groupe d'utilisateurs et refusent l'accès à un sous-ensemble de ce groupe.
* Tous les ACE **explicites sont traités avant tout ACE hérité**. Cela est conforme au concept de contrôle d'accès discrétionnaire : l'accès à un objet enfant (par exemple un fichier) est à la discrétion du propriétaire de l'enfant, et non du propriétaire de l'objet parent (par exemple un dossier). Le propriétaire d'un objet enfant peut définir des autorisations directement sur l'enfant. Le résultat est que les effets des autorisations héritées sont modifiés.



<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** avec les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemple graphique

Voici l'onglet de sécurité classique d'un dossier montrant le DACL, le DACL et les ACE :

![](../../.gitbook/assets/classicsectab.jpg)

Si nous cliquons sur le **bouton Avancé**, nous obtiendrons plus d'options comme l'héritage :

![](../../.gitbook/assets/aceinheritance.jpg)

Et si vous ajoutez ou modifiez un Principal de sécurité :

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

Et enfin, nous avons le SACL dans l'onglet Audit :

![](../../.gitbook/assets/audit-tab.jpg)

### Exemple : Accès refusé explicite à un groupe

Dans cet exemple, le groupe d'accès autorisé est Tout le monde et le groupe d'accès refusé est Marketing, un sous-ensemble de Tout le monde.

Vous souhaitez refuser l'accès au groupe Marketing à un dossier Coût. Si les ACE du dossier Coût sont dans l'ordre canonique, l'ACE qui refuse l'accès à Marketing vient avant l'ACE qui autorise Tout le monde.

Lors d'une vérification d'accès, le système d'exploitation parcourt les ACE dans l'ordre dans lequel ils apparaissent dans le DACL de l'objet, de sorte que l'ACE de refus est traité avant l'ACE d'autorisation. En conséquence, les utilisateurs membres du groupe Marketing se voient refuser l'accès. Tous les autres membres du groupe Tout le monde sont autorisés à accéder à l'objet.

### Exemple : Explicite avant hérité

Dans cet exemple, le dossier Coût a un ACE héritable qui refuse l'accès à Marketing (l'objet parent). En d'autres termes, tous les utilisateurs membres (ou enfants) du groupe Marketing se voient refuser l'accès par héritage.

Vous souhaitez autoriser l'accès à Bob, qui est le directeur du marketing. En tant que membre du groupe Marketing, Bob se voit refuser l'accès au dossier Coût par héritage. Le propriétaire de l'objet enfant (l'utilisateur Bob) définit un ACE explicite qui autorise l'accès au dossier Coût. Si les ACE de l'objet enfant sont dans l'ordre canonique, l'ACE explicite qui autorise l'accès à Bob vient avant tout ACE hérité, y compris l'ACE hérité qui refuse l'accès au groupe Marketing.

Lors d'une vérification d'accès, le système d'exploitation atteint l'ACE qui autorise l'accès à Bob avant d'atteindre l'ACE qui refuse l'accès au groupe Marketing. En conséquence, Bob est autorisé à accéder à l'objet même s'il est membre du groupe Marketing. Les autres membres du groupe Marketing se voient refuser l'accès.

### Entrées de contrôle d'accès

Comme indiqué précédemment, une ACL (Access Control List) est une liste ordonnée d'ACE (Access Control Entries). Chaque ACE contient les éléments suivants :

* Un SID (Security Identifier) qui identifie un utilisateur ou un groupe particulier.
* Un masque d'accès qui spécifie les droits d'accès.
* Un ensemble de drapeaux qui déterminent si les objets enfants peuvent hériter de l'ACE ou non.
* Un drapeau qui indique le type d'ACE.

Les ACE sont fondamentalement similaires. Ce qui les distingue, c'est le degré de contrôle qu'ils offrent sur l'héritage et l'accès aux objets. Il existe deux types d'ACE :

* Un type générique qui est attaché à tous les objets sécurisables.
* Un type spécifique à l'objet qui ne peut apparaître que dans les ACL des objets Active Directory.

### ACE générique

Un ACE générique offre un contrôle limité sur les types d'objets enfants qui peuvent hériter d'eux. Essentiellement, ils ne peuvent faire la distinction qu'entre les conteneurs et les non-conteneurs.

Par exemple, le DACL (Discretionary Access Control List) d'un objet Dossier dans NTFS peut inclure un ACE générique qui permet à un groupe d'utilisateurs de lister le contenu du dossier. Parce que la liste du contenu d'un dossier est une opération qui ne peut être effectuée que sur un objet Conteneur, l'ACE qui autorise l'opération peut être marqué comme un ACE CONTAINER\_INHERIT\_ACE. Seuls les objets Conteneur dans le dossier (c'est-à-dire d'autres objets Dossier) héritent de l'ACE. Les objets non-conteneurs (c'est-à-dire les objets Fichier) n'héritent pas de l'ACE de l'objet parent.

Un ACE générique s'applique à un objet entier. Si un ACE générique donne à un utilisateur particulier un accès en lecture, l'utilisateur peut lire toutes les informations associées à l'objet, à la fois les données et les propriétés. Cela n'est pas une limitation grave pour la plupart des types d'objets. Par exemple, les objets Fichier ont peu de propriétés, qui sont toutes utilisées pour décrire les caractéristiques de l'objet plutôt que pour stocker des informations. La plupart des informations dans un objet Fichier sont stockées sous forme de données d'objet ; par conséquent, il y a peu besoin de contrôles séparés sur les propriétés d'un fichier.

### ACE spécifique à l'objet

Un ACE spécifique à l'objet offre un degré de contrôle plus élevé sur les types d'objets enfants qui peuvent hériter d'eux.

Par exemple, la liste de contrôle d'accès (ACL) d'un objet OU (Unité d'organisation) peut avoir un ACE spécifique à l'objet qui est marqué pour être hérité uniquement par les objets Utilisateur. Les autres types d'objets, tels que les objets Ordinateur, n'hériteront pas de l'ACE.

C'est pourquoi les ACE spécifiques à l'objet sont appelés spécifiques à l'objet. Leur héritage peut être limité à des types spécifiques d'objets enfants.

Il existe des différences similaires dans la façon dont les deux catégories de types d'ACE contrôlent l'accès aux objets.

Un ACE spécifique à l'objet peut s'appliquer à une propriété individuelle d'un objet ou à un ensemble de propriétés pour cet objet. Ce type d'ACE est utilisé uniquement dans une ACL pour les objets Active Directory, qui, contrairement aux autres types d'objets, stockent la plupart de leurs informations dans des propriétés. Il est souvent souhaitable de placer des contrôles indépendants sur chaque propriété d'un objet Active Directory, et les ACE spécifiques à l'objet rendent cela possible.

Par exemple, lorsque vous définissez des autorisations pour un objet Utilisateur, vous pouvez utiliser un ACE spécifique à l'objet pour autoriser Principal Self (c'est-à-dire l'utilisateur) à écrire dans la propriété Phone-Home-Primary (homePhone), et vous pouvez utiliser d'autres ACE spécifiques à
### Structure de l'entrée de contrôle d'accès

| Champ ACE  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Indicateur du type d'ACE. Windows 2000 et Windows Server 2003 prennent en charge six types d'ACE : trois types d'ACE génériques attachés à tous les objets sécurisables et trois types d'ACE spécifiques à l'objet qui peuvent apparaître pour les objets Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Ensemble de drapeaux binaires qui contrôlent l'héritage et l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Taille        | Nombre d'octets de mémoire alloués pour l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Masque d'accès | Valeur de 32 bits dont les bits correspondent aux droits d'accès pour l'objet. Les bits peuvent être activés ou désactivés, mais leur signification dépend du type d'ACE. Par exemple, si le bit correspondant au droit de lire les autorisations est activé et que le type d'ACE est Refuser, l'ACE refuse le droit de lire les autorisations de l'objet. Si le même bit est activé mais que le type d'ACE est Autoriser, l'ACE accorde le droit de lire les autorisations de l'objet. Plus de détails sur le masque d'accès apparaissent dans le tableau suivant. |
| SID         | Identifie un utilisateur ou un groupe dont l'accès est contrôlé ou surveillé par cet ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Structure du masque d'accès

| Bit (Plage) | Signification                            | Description/Exemple                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Droits d'accès spécifiques à l'objet      | Lire les données, Exécuter, Ajouter des données           |
| 16 - 22     | Droits d'accès standard             | Supprimer, Écrire ACL, Écrire le propriétaire            |
| 23          | Peut accéder à la liste de contrôle d'accès de sécurité            |                                           |
| 24 - 27     | Réservé                           |                                           |
| 28          | Générique TOUT (Lire, Écrire, Exécuter) | Tout ce qui suit                          |
| 29          | Générique Exécuter                    | Tout ce qui est nécessaire pour exécuter un programme |
| 30          | Générique Écrire                      | Tout ce qui est nécessaire pour écrire dans un fichier   |
| 31          | Générique Lire                       | Tout ce qui est nécessaire pour lire un fichier       |

## Références

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au référentiel [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
