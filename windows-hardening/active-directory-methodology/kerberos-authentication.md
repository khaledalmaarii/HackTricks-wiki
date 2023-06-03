# Authentification Kerberos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Ces informations ont été extraites de l'article :** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Kerberos (I) : Comment fonctionne Kerberos ? - Théorie

20 - MAR - 2019 - ELOY PÉREZ

L'objectif de cette série d'articles est de clarifier le fonctionnement de Kerberos, plutôt que de simplement présenter les attaques. En effet, il n'est pas toujours clair pourquoi certaines techniques fonctionnent ou non. Cette connaissance permet de savoir quand utiliser l'une de ces attaques lors d'un test de pénétration.

Par conséquent, après un long parcours de plongée dans la documentation et plusieurs articles sur le sujet, nous avons essayé de résumer dans cet article tous les détails importants que tout auditeur devrait connaître pour comprendre comment tirer parti du protocole Kerberos.

Dans ce premier article, seule la fonctionnalité de base sera discutée. Dans les articles suivants, nous verrons comment effectuer les attaques et comment fonctionnent les aspects les plus complexes, tels que la délégation.

Si vous avez des doutes sur le sujet qui ne sont pas bien expliqués, n'hésitez pas à laisser un commentaire ou une question à ce sujet. Maintenant, passons au sujet.

### Qu'est-ce que Kerberos ?

Tout d'abord, Kerberos est un protocole d'authentification, pas d'autorisation. En d'autres termes, il permet d'identifier chaque utilisateur, qui fournit un mot de passe secret, mais il ne valide pas à quelles ressources ou services cet utilisateur peut accéder.

Kerberos est utilisé dans Active Directory. Dans cette plateforme, Kerberos fournit des informations sur les privilèges de chaque utilisateur, mais il incombe à chaque service de déterminer si l'utilisateur a accès à ses ressources.

### Éléments de Kerberos

Dans cette section, plusieurs composants de l'environnement Kerberos seront étudiés.

**Couche de transport**

Kerberos utilise soit UDP soit TCP comme protocole de transport, qui envoie des données en clair. Pour cette raison, Kerberos est responsable de la fourniture de chiffrement.

Les ports utilisés par Kerberos sont UDP/88 et TCP/88, qui doivent être écoutés dans le KDC (expliqué dans la section suivante).

**Agents**

Plusieurs agents travaillent ensemble pour fournir l'authentification dans Kerberos. Ce sont les suivants :

* **Client ou utilisateur** qui veut accéder au service.
* **AP** (Application Server) qui offre le service requis par l'utilisateur.
* **KDC** (Key Distribution Center), le service principal de Kerberos, responsable de l'émission des tickets, installé sur le DC (Domain Controller). Il est soutenu par le **AS** (Authentication Service), qui émet les TGT.

**Clés de chiffrement**

Il existe plusieurs structures gérées par Kerberos, telles que les tickets. Beaucoup de ces structures sont chiffrées ou signées afin d'empêcher toute altération par des tiers. Ces clés sont les suivantes :

* **Clé KDC ou krbtgt** qui est dérivée du hachage NTLM du compte krbtgt.
* **Clé utilisateur** qui est dérivée du hachage NTLM de l'utilisateur.
* **Clé de service** qui est dérivée du hachage NTLM du propriétaire du service, qui peut être un compte utilisateur ou un compte d'ordinateur.
* **Clé de session** qui est négociée entre l'utilisateur et le KDC.
* **Clé de session de service** à utiliser entre l'utilisateur et le service.

**Tickets**

Les principales structures gérées par Kerberos sont les tickets. Ces tickets sont remis aux utilisateurs pour être utilisés par eux pour effectuer plusieurs actions dans le royaume Kerberos. Il y en a 2 types :

* Le **TGS** (Ticket Granting Service) est le ticket que l'utilisateur peut utiliser pour s'authentifier auprès d'un service. Il est chiffré avec la clé de service.
* Le **TGT** (Ticket Granting Ticket) est le ticket présenté au KDC pour demander des TGS. Il est chiffré avec la clé KDC.

**PAC**

Le **PAC** (Privilege Attribute Certificate) est une structure incluse dans presque tous les tickets. Cette structure contient les privilèges de l'utilisateur et est signée avec la clé KDC.

Il est possible pour les services de vérifier le PAC en communiquant avec le KDC, bien que cela n'arrive pas souvent. Néanmoins, la vérification du PAC consiste à vérifier uniquement sa signature, sans inspecter si les privilèges à l'intérieur du PAC sont corrects.

De plus, un client peut éviter l'inclusion du PAC à l'intérieur du ticket en le spécifiant dans le champ _KERB-PA-PAC-REQUEST_ de la demande de ticket.

**Messages**

Kerberos utilise différents types de messages. Les plus intéressants sont les suivants :

* **KRB\_AS\_REQ** : Utilisé pour demander le TGT à KDC.
* **KRB\_AS\_REP** : Utilisé pour remettre le TGT par KDC.
* **KRB\_TGS\_REQ** : Utilisé pour demander le TGS à KDC, en utilisant le TGT.
* **KRB\_TGS\_REP** : Utilisé pour remettre le TGS par KDC.
* **KRB\_AP\_REQ** : Utilisé pour authentifier un utilisateur auprès d'un service, en utilisant le TGS.
* **KRB\_AP\_REP** : (Optionnel) Utilisé par le service pour s'identifier auprès de l'utilisateur.
* **KRB\_ERROR** : Message pour communiquer les conditions d'erreur.

De plus, même s'il ne fait pas partie de Kerberos, mais de NRPC, l'AP pourrait éventuellement utiliser le message **KERB\_VERIFY\_PAC\_REQUEST** pour envoyer au KDC la signature de PAC, et vérifier si elle est correcte.

Ci-dessous est présenté un résumé de la séquence de messages pour effectuer l'authentification

![Résumé des messages Kerberos](<../../.gitbook/assets/image (174) (1).png>)

### Processus d'authentification

Dans cette section, la séquence de messages pour effectuer l'authentification sera étudiée, en partant d'un utilisateur sans tickets, jusqu'à être authentifié contre le service désiré.

**KRB\_AS\_REQ**

Tout d'abord, l'utilisateur doit obtenir un TGT du KDC. Pour ce faire, un KRB\_AS\_REQ doit être envoyé :

![Schéma de message KRB\_AS\_REQ](<../../.gitbook/assets/image (175) (1).png>)

_KRB\_AS\_REQ_ a, entre autres, les champs suivants :

* Un **horodatage**
* Un **Nonce** généré par l'utilisateur

Note : le timestamp chiffré n'est nécessaire que si l'utilisateur exige une pré-authentification, ce qui est courant, sauf si le drapeau [_DONT\_REQ\_PREAUTH_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro) est défini dans le compte utilisateur.

**KRB\_AS\_REP**

Après avoir reçu la demande, le KDC vérifie l'identité de l'utilisateur en déchiffrant le timestamp. Si le message est correct, il doit alors répondre avec un _KRB\_AS\_REP_ :

![Schéma de message KRB\_AS\_REP](<../../.gitbook/assets/image (176) (1).png>)

_KRB\_AS\_REP_ inclut les informations suivantes :

* **Nom d'utilisateur**
* **TGT**, qui inclut :
  * **Nom d'utilisateur**
  * **Clé de session**
  * **Date d'expiration** du TGT
  * **PAC** avec les privilèges de l'utilisateur, signé par le KDC
* Certaines **données chiffrées** avec la clé de l'utilisateur, qui incluent :
  * **Clé de session**
  * **Date d'expiration** du TGT
  * **Nonce** de l'utilisateur, pour éviter les attaques de rejeu

Une fois terminé, l'utilisateur a déjà le TGT, qui peut être utilisé pour demander des TGS, et ensuite accéder aux services.

**KRB\_TGS\_REQ**

Pour demander un TGS, un message _KRB\_TGS\_REQ_ doit être envoyé au KDC :

![Schéma de message KRB\_TGS\_REQ](<../../.gitbook/assets/image (177).png>)

_KRB\_TGS\_REQ_ inclut :

* **Données chiffrées** avec la clé de session :
  * **Nom d'utilisateur**
  * **Horodatage**
* **TGT**
* **SPN** du service demandé
* **Nonce** généré par l'utilisateur

**KRB\_TGS\_REP**

Après avoir reçu le message _KRB\_TGS\_REQ_, le KDC renvoie un TGS dans _KRB\_TGS\_REP_ :

![Schéma de message KRB\_TGS\_REP](<../../.gitbook/assets/image (178) (1).png>)

_KRB\_TGS\_REP_ inclut :

* **Nom d'utilisateur**
* **TGS**, qui contient :
  * **Clé de session du service**
  * **Nom d'utilisateur**
  * **Date d'expiration** du TGS
  * **PAC** avec les privilèges de l'utilisateur, signé par le KDC
* **Données chiffrées** avec la clé de session :
  * **Clé de session du service**
  * **Date d'expiration** du TGS
  * **Nonce** de l'utilisateur, pour éviter les attaques de rejeu

**KRB\_AP\_REQ**

Pour finir, si tout s'est bien passé, l'utilisateur dispose déjà d'un TGS valide pour interagir avec le service. Pour l'utiliser, l'utilisateur doit envoyer un message _KRB\_AP\_REQ_ à l'AP :

![Schéma de message KRB\_AP\_REQ](<../../.gitbook/assets/image (179) (1).png>)

_KRB\_AP\_REQ_ inclut :

* **TGS**
* **Données chiffrées** avec la clé de session du service :
  * **Nom d'utilisateur**
  * **Horodatage**, pour éviter les attaques de rejeu

Après cela, si les privilèges de l'utilisateur sont corrects, il peut accéder au service. Si c'est le cas, ce qui n'arrive pas habituellement, l'AP vérifiera le PAC contre le KDC. Et aussi, si une authentification mutuelle est nécessaire, il répondra à l'utilisateur avec un message _KRB\_AP\_REP_.

### Références

* Kerberos v5 RFC : [https://tools.ietf.org/html/rfc4120](https://tools.ietf.org/html/rfc4120)
* \[MS-KILE\] – Extension Kerberos : [https://msdn.microsoft.com/en-us/library/cc233855.aspx](https://msdn.microsoft.com/en-us/library/cc233855.aspx)
* \[MS-APDS\] – Support de domaine de protocole d'authentification : [https://msdn.microsoft.com/en-us/library/cc223948.aspx](https://msdn.microsoft.com/en-us/library/cc223948.aspx)
* Mimikatz et les attaques Kerberos Active Directory : [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
* Expliquez-moi comme si j'avais 5 ans : Kerberos : [https://www.roguelynn.com/words/explain-like-im-5-kerberos/](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* Kerberos & KRBTGT : [https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)
* Maîtriser la recherche d'indices et les enquêtes sur les réseaux Windows, 2e édition. Auteurs : S. Anson, S. Bunting, R. Johnson et S. Pearson. Édition Sibex.
* Active Directory, 5e édition. Auteurs : B. Desmond, J. Richards, R. Allen et A.G. Lowe-Norris
* Noms principaux de service : [https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/ms677949\(v=vs.85\).aspx)
* Niveaux fonctionnels de Active Directory : [https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0](https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0)
* OverPass The Hash – Blog Gentilkiwi : [https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash](https://
