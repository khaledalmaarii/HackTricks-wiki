# Attaque xpc\_connection\_get\_audit\_token sur macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Cette technique a été copiée depuis** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

## Informations de base sur les messages Mach

Si vous ne savez pas ce que sont les messages Mach, commencez par consulter cette page :

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Pour le moment, retenez que :
Les messages Mach sont envoyés via un _port Mach_, qui est un canal de communication à **un seul destinataire, plusieurs expéditeurs** intégré dans le noyau Mach. **Plusieurs processus peuvent envoyer des messages** à un port Mach, mais à tout moment, **un seul processus peut les lire**. Tout comme les descripteurs de fichiers et les sockets, les ports Mach sont alloués et gérés par le noyau et les processus ne voient qu'un entier, qu'ils peuvent utiliser pour indiquer au noyau lequel de leurs ports Mach ils veulent utiliser.

## Connexion XPC

Si vous ne savez pas comment établir une connexion XPC, consultez :

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Résumé de la vulnérabilité

Ce qui est intéressant à savoir, c'est que **l'abstraction XPC est une connexion un-à-un**, mais elle est basée sur une technologie qui **peut avoir plusieurs expéditeurs, donc** :

* Les ports Mach sont un destinataire unique, _**plusieurs expéditeurs**_.
* Le jeton d'audit d'une connexion XPC est le jeton d'audit **copié à partir du message le plus récemment reçu**.
* Obtenir le **jeton d'audit** d'une connexion XPC est essentiel pour de nombreux **contrôles de sécurité**.

Bien que la situation précédente semble prometteuse, il existe des scénarios où cela ne posera pas de problèmes :

* Les jetons d'audit sont souvent utilisés pour une vérification d'autorisation afin de décider d'accepter une connexion. Comme cela se fait à l'aide d'un message vers le port de service, il n'y a **pas encore de connexion établie**. Les messages supplémentaires sur ce port seront simplement traités comme des demandes de connexion supplémentaires. Par conséquent, **les vérifications avant d'accepter une connexion ne sont pas vulnérables** (cela signifie également que dans `-listener:shouldAcceptNewConnection:`, le jeton d'audit est sécurisé). Nous recherchons donc **des connexions XPC qui vérifient des actions spécifiques**.
* Les gestionnaires d'événements XPC sont traités de manière synchrone. Cela signifie que le gestionnaire d'événements pour un message doit être terminé avant de l'appeler pour le suivant, même sur des files d'attente de répartition concurrentes. Ainsi, à l'intérieur d'un **gestionnaire d'événements XPC, le jeton d'audit ne peut pas être écrasé** par d'autres messages normaux (non de réponse !).

Cela nous a donné l'idée de deux méthodes différentes pour que cela soit possible :

1. Variante 1 :
* L'**exploit** se connecte aux services **A** et **B**.
* Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service A que l'utilisateur ne peut pas appeler.
* Le service **A** appelle **`xpc_connection_get_audit_token`** tout en n'étant pas à l'intérieur du **gestionnaire d'événements** pour une connexion dans un **`dispatch_async`**.
* Ainsi, un **message différent** pourrait **écraser le jeton d'audit** car il est envoyé de manière asynchrone en dehors du gestionnaire d'événements.
* L'exploit transmet à **service B le droit d'envoyer à service A**.
* Ainsi, svc **B** enverra réellement les **messages** à service **A**.
* L'**exploit** essaie d'**appeler l'action privilégiée**. Dans un RC svc **A**, il **vérifie** l'autorisation de cette **action** tandis que **svc B a écrasé le jeton d'audit** (donnant à l'exploit l'accès pour appeler l'action privilégiée).
2. Variante 2 :
* Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service A que l'utilisateur ne peut pas appeler.
* L'exploit se connecte avec le **service A** qui envoie à l'exploit un **message en attendant une réponse** dans un **port de réponse** spécifique.
* L'exploit envoie au **service B** un message en passant **ce port de réponse**.
* Lorsque le service **B répond**, il envoie le message à service **A**, tandis que l'**exploit** envoie un autre **message à service A** en essayant d'**atteindre une fonctionnalité privilégiée** et en s'attendant à ce que la réponse de service B écrase le jeton d'audit au moment parfait (Condition de concurrence).
## Variante 1: appel à xpc\_connection\_get\_audit\_token en dehors d'un gestionnaire d'événements <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scénario :

* Deux services mach **A** et **B** auxquels nous pouvons tous deux nous connecter (en fonction du profil sandbox et des vérifications d'autorisation avant d'accepter la connexion).
* **A** doit effectuer une **vérification d'autorisation** pour une **action spécifique** que **B** peut passer (mais notre application ne peut pas).
* Par exemple, si B a des **droits**, ou s'exécute en tant que **root**, cela peut lui permettre de demander à A d'effectuer une action privilégiée.
* Pour cette vérification d'autorisation, **A obtient de manière asynchrone le jeton d'audit**, par exemple en appelant `xpc_connection_get_audit_token` depuis `dispatch_async`.

{% hint style="danger" %}
Dans ce cas, un attaquant pourrait déclencher une **condition de concurrence** en créant une **exploitation** qui **demande à A d'effectuer une action** plusieurs fois tout en faisant **envoyer des messages à A par B**. Lorsque la condition de concurrence est **réussie**, le **jeton d'audit** de **B** sera copié en mémoire **pendant que** la demande de notre **exploitation** est en cours de **traitement** par A, lui donnant ainsi **accès à l'action privilégiée que seul B pourrait demander**.
{% endhint %}

Cela s'est produit avec **A** en tant que `smd` et **B** en tant que `diagnosticd`. La fonction [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb peut être utilisée pour installer un nouvel outil auxiliaire privilégié (en tant que **root**). Si un **processus s'exécutant en tant que root contacte** **smd**, aucune autre vérification ne sera effectuée.

Par conséquent, le service **B** est **`diagnosticd`** car il s'exécute en tant que **root** et peut être utilisé pour **surveiller** un processus, donc une fois la surveillance commencée, il enverra **plusieurs messages par seconde**.

Pour effectuer l'attaque :

1. Nous établissons notre **connexion** à **`smd`** en suivant le protocole XPC normal.
2. Ensuite, nous établissons une **connexion** à **`diagnosticd`**, mais au lieu de générer deux nouveaux ports mach et de les envoyer, nous remplaçons le droit d'envoi du port client par une copie du **droit d'envoi que nous avons pour la connexion à `smd`**.
3. Cela signifie que nous pouvons envoyer des messages XPC à `diagnosticd`, mais que tous les **messages que `diagnosticd` envoie vont à `smd`**.
* Pour `smd`, nos messages et ceux de `diagnosticd` arrivent sur la même connexion.

<figure><img src="../../../../../../.gitbook/assets/image.png" alt="" width="563"><figcaption></figcaption></figure>

4. Nous demandons à **`diagnosticd`** de **commencer la surveillance** de notre (ou de tout autre) processus et nous **envoyons des messages de routine 1004 à `smd`** (pour installer un outil privilégié).
5. Cela crée une condition de concurrence qui doit atteindre une fenêtre très spécifique dans `handle_bless`. Nous devons obtenir l'appel à `xpc_connection_get_pid` pour renvoyer l'ID de notre propre processus, car l'outil auxiliaire privilégié se trouve dans notre bundle d'application. Cependant, l'appel à `xpc_connection_get_audit_token` à l'intérieur de la fonction `connection_is_authorized` doit utiliser le jeton d'audit de `diagnosticd`.

## Variante 2: transfert de réponse

Comme mentionné précédemment, le gestionnaire d'événements pour les connexions XPC n'est jamais exécuté plusieurs fois simultanément. Cependant, les **messages de réponse XPC sont traités différemment**. Deux fonctions existent pour envoyer un message qui attend une réponse :

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`, dans ce cas, le message XPC est reçu et analysé sur la file d'attente spécifiée.
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`, dans ce cas, le message XPC est reçu et analysé sur la file d'attente de répartition actuelle.

Par conséquent, les **paquets de réponse XPC peuvent être analysés pendant l'exécution d'un gestionnaire d'événements XPC**. Bien que `_xpc_connection_set_creds` utilise un verrouillage, cela empêche uniquement l'écrasement partiel du jeton d'audit, il ne verrouille pas l'objet de connexion entier, ce qui permet de **remplacer le jeton d'audit entre l'analyse** d'un paquet et l'exécution de son gestionnaire d'événements.

Pour ce scénario, nous aurions besoin de :

* Comme précédemment, deux services mach _A_ et _B_ auxquels nous pouvons tous deux nous connecter.
* Encore une fois, _A_ doit effectuer une vérification d'autorisation pour une action spécifique que _B_ peut passer (mais notre application ne peut pas).
* _A_ nous envoie un message qui attend une réponse.
* Nous pouvons envoyer un message à _B_ auquel il répondra.

Nous attendons qu'_A_ nous envoie un message qui attend une réponse (1), au lieu de répondre, nous prenons le port de réponse et l'utilisons pour un message que nous envoyons à _B_ (2). Ensuite, nous envoyons un message qui utilise l'action interdite et nous espérons qu'il arrive simultanément avec la réponse de _B_ (3).

<figure><img src="../../../../../../.gitbook/assets/image (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Problèmes de découverte

Nous avons passé beaucoup de temps à essayer de trouver d'autres instances, mais les conditions rendaient la recherche difficile, que ce soit de manière statique ou dynamique. Pour rechercher des appels asynchrones à `xpc_connection_get_audit_token`, nous avons utilisé Frida pour accrocher cette fonction afin de vérifier si la trace arrière inclut `_xpc_connection_mach_event` (ce qui signifie qu'elle n'est pas appelée à partir d'un gestionnaire d'événements). Mais cela ne trouve que les appels dans le processus auquel nous sommes actuellement accrochés et des actions qui sont activement utilisées. L'analyse de tous les services mach accessibles dans IDA/Ghidra était très chronophage, surtout lorsque les appels impliquaient le cache partagé dyld. Nous avons essayé de scripter cela pour rechercher les appels à `xpc_connection_get_audit_token` accessibles à partir d'un bloc soumis à l'aide de `dispatch_async`, mais l'analyse des blocs et des appels passant dans le cache partagé dyld rendait cela difficile aussi. Après avoir passé un certain temps sur cela, nous avons décidé qu'il serait préférable de soumettre ce que nous avions.
## La solution <a href="#la-solution" id="la-solution"></a>

Finalement, nous avons signalé le problème général et le problème spécifique dans `smd`. Apple l'a corrigé uniquement dans `smd` en remplaçant l'appel à `xpc_connection_get_audit_token` par `xpc_dictionary_get_audit_token`.

La fonction `xpc_dictionary_get_audit_token` copie le jeton d'audit du message mach sur lequel ce message XPC a été reçu, ce qui signifie qu'il n'est pas vulnérable. Cependant, tout comme `xpc_dictionary_get_audit_token`, cela ne fait pas partie de l'API publique. Pour l'API de niveau supérieur `NSXPCConnection`, aucune méthode claire n'existe pour obtenir le jeton d'audit du message actuel, car cela abstrait tous les messages en appels de méthode.

Il n'est pas clair pourquoi Apple n'a pas appliqué une correction plus générale, par exemple en supprimant les messages qui ne correspondent pas au jeton d'audit enregistré de la connexion. Il peut y avoir des scénarios où le jeton d'audit d'un processus change légitimement mais la connexion doit rester ouverte (par exemple, l'appel à `setuid` change le champ UID), mais des changements tels qu'un PID différent ou une version de PID différente sont peu probables.

Dans tous les cas, ce problème persiste toujours avec iOS 17 et macOS 14, donc si vous voulez le chercher, bonne chance!

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
