# ACLs - DACLs/SACLs/ACEs

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Liste de contrôle d'accès (ACL)**

Une **ACL est une liste ordonnée d'ACE** qui définit les protections qui s'appliquent à un objet et à ses propriétés. Chaque **ACE identifie un principal de sécurité** et spécifie un **ensemble de droits d'accès** qui sont autorisés, refusés ou audités pour ce principal de sécurité.

Le descripteur de sécurité d'un objet peut contenir **deux ACL** :

1. Un **DACL qui identifie les utilisateurs et les groupes** qui sont **autorisés** ou **refusés** d'accès
2. Un **SACL qui contrôle la façon dont** l'accès est **auditée**

Lorsqu'un utilisateur essaie d'accéder à un fichier, le système Windows exécute un AccessCheck et compare le descripteur de sécurité avec le jeton d'accès de l'utilisateur et évalue si l'utilisateur est autorisé à accéder et quel type d'accès en fonction des ACE définis.

### **Liste de contrôle d'accès discrétionnaire (DACL)**

Un DACL (souvent mentionné comme ACL) identifie les utilisateurs et les groupes auxquels des autorisations d'accès sont attribuées ou refusées sur un objet. Il contient une liste d'ACE appariés (compte + droit d'accès) à l'objet sécurisable.

### **Liste de contrôle d'accès système (SACL)**

Les SACL permettent de surveiller l'accès aux objets sécurisés. Les ACE dans un SACL déterminent **les types d'accès qui sont enregistrés dans le journal des événements de sécurité**. Avec des outils de surveillance, cela pourrait déclencher une alarme aux bonnes personnes si des utilisateurs malveillants tentent d'accéder à l'objet sécurisé, et dans un scénario d'incident, nous pouvons utiliser les journaux pour retracer les étapes en arrière dans le temps. Enfin, vous pouvez activer la journalisation pour résoudre les problèmes d'accès.

## Comment le système utilise les ACL

Chaque **utilisateur connecté** au système **possède un jeton d'accès avec des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **a une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (identificateur de sécurité) qui identifie la session de connexion actuelle.

Lorsqu'un thread essaie d'accéder à un objet sécurisable, le LSASS (Local Security Authority) accorde ou refuse l'accès. Pour ce faire, le **LSASS recherche le DACL** (Liste de contrôle d'accès discrét
### Entrées de contrôle d'accès

Comme indiqué précédemment, une ACL (Liste de contrôle d'accès) est une liste ordonnée d'ACE (Entrées de contrôle d'accès). Chaque ACE contient les éléments suivants :

* Un SID (Identificateur de sécurité) qui identifie un utilisateur ou un groupe particulier.
* Un masque d'accès qui spécifie les droits d'accès.
* Un ensemble de drapeaux qui déterminent si les objets enfants peuvent hériter de l'ACE ou non.
* Un drapeau qui indique le type d'ACE.

Les ACE sont fondamentalement similaires. Ce qui les distingue, c'est le degré de contrôle qu'ils offrent sur l'héritage et l'accès aux objets. Il existe deux types d'ACE :

* Type générique qui est attaché à tous les objets sécurisables.
* Type spécifique à l'objet qui ne peut apparaître que dans les ACL pour les objets Active Directory.

### ACE générique

Un ACE générique offre un contrôle limité sur les types d'objets enfants qui peuvent les hériter. Essentiellement, ils ne peuvent distinguer que les conteneurs et les non-conteneurs.

Par exemple, la DACL (Liste de contrôle d'accès discrétionnaire) sur un objet de dossier dans NTFS peut inclure un ACE générique qui permet à un groupe d'utilisateurs de lister le contenu du dossier. Comme la liste du contenu d'un dossier est une opération qui ne peut être effectuée que sur un objet conteneur, l'ACE qui permet l'opération peut être marqué comme un ACE hérité de CONTAINER. Seuls les objets conteneurs dans le dossier (c'est-à-dire les autres objets de dossier) héritent de l'ACE. Les objets non conteneurs (c'est-à-dire les objets de fichier) n'héritent pas de l'ACE de l'objet parent.

Un ACE générique s'applique à un objet entier. Si un ACE générique donne à un utilisateur particulier un accès en lecture, l'utilisateur peut lire toutes les informations associées à l'objet - à la fois les données et les propriétés. Ce n'est pas une limitation grave pour la plupart des types d'objets. Les objets de fichier, par exemple, ont peu de propriétés, qui sont toutes utilisées pour décrire les caractéristiques de l'objet plutôt que pour stocker des informations. La plupart des informations dans un objet de fichier sont stockées sous forme de données d'objet ; par conséquent, il y a peu besoin de contrôles séparés sur les propriétés d'un fichier.

### ACE spécifique à l'objet

Un ACE spécifique à l'objet offre un degré de contrôle supérieur sur les types d'objets enfants qui peuvent les hériter.

Par exemple, l'ACL d'un objet d'unité organisationnelle (OU) peut avoir un ACE spécifique à l'objet qui est marqué pour l'héritage uniquement par des objets utilisateur. D'autres types d'objets, tels que les objets d'ordinateur, n'hériteront pas de l'ACE.

C'est pourquoi les ACE spécifiques à l'objet sont appelés spécifiques à l'objet. Leur héritage peut être limité à des types spécifiques d'objets enfants.

Il existe des différences similaires dans la façon dont les deux catégories de types ACE contrôlent l'accès aux objets.

Un ACE spécifique à l'objet peut s'appliquer à n'importe quelle propriété individuelle d'un objet ou à un ensemble de propriétés pour cet objet. Ce type d'ACE est utilisé uniquement dans une ACL pour les objets Active Directory, qui, contrairement aux autres types d'objets, stockent la plupart de leurs informations dans des propriétés. Il est souvent souhaitable de placer des contrôles indépendants sur chaque propriété d'un objet Active Directory, et les ACE spécifiques à l'objet rendent cela possible.

Par exemple, lorsque vous définissez des autorisations pour un objet utilisateur, vous pouvez utiliser un ACE spécifique à l'objet pour permettre à Principal Self (c'est-à-dire l'utilisateur) d'avoir un accès en écriture à la propriété Phone-Home-Primary (homePhone), et vous pouvez utiliser d'autres ACE spécifiques à l'objet pour refuser à Principal Self l'accès à la propriété Logon-Hours (logonHours) et à d'autres propriétés qui définissent des restrictions sur le compte utilisateur.

Le tableau ci-dessous montre la disposition de chaque ACE.

### Disposition de l'entrée de contrôle d'accès

| Champ ACE  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type       | Drapeau qui indique le type d'ACE. Windows 2000 et Windows Server 2003 prennent en charge six types d'ACE : Trois types d'ACE génériques qui sont attachés à tous les objets sécurisables. Trois types d'ACE spécifiques à l'objet qui peuvent apparaître pour les objets Active Directory.                                                                                                                                                                                                                                                            |
| Drapeaux   | Ensemble de drapeaux qui contrôlent l'héritage et l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Taille     | Nombre d'octets de mémoire alloués pour l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Masque d'accès | Valeur de 32 bits dont les bits correspondent aux droits d'accès pour l'objet. Les bits peuvent être activés ou désactivés, mais la signification du paramètre dépend du type d'ACE. Par exemple, si le bit qui correspond au droit de lire les autorisations est activé, et que le type d'ACE est Refuser, l'ACE refuse le droit de lire les autorisations de l'objet. Si le même bit est activé mais que le type d'ACE est Autoriser, l'ACE accorde le droit de lire les autorisations de l'objet. Plus de détails sur le masque d'accès apparaissent dans le tableau suivant. |
| SID        | Identifie un utilisateur ou un groupe dont l'accès est contrôlé ou surveillé par cet ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Disposition du masque d'accès

| Bit (Plage) | Signification                            | Description/Exemple                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Droits d'accès spécifiques à l'objet      | Lire les données, Exécuter, Ajouter des données           |
| 16 - 22     | Droits d'accès standard             | Supprimer, Écrire ACL, Écrire le propriétaire            |
| 23          | Peut accéder à la liste de contrôle d'accès de sécurité            |                                           |
| 24 - 27     | Réservé                           |                                           |
| 28          | Générique TOUT (Lire, Écrire, Exécuter) | Tout en dessous                          |
| 29          | Générique Exécuter                    | Tout ce qui est nécessaire pour exécuter un programme |
| 30          | Générique Écrire                      | Tout ce qui est nécessaire pour écrire dans un fichier   |
| 31          | Générique Lire                       | Tout ce qui est nécessaire pour lire un fichier       |

## Références

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le
