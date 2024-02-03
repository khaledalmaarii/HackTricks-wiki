# Attaque macOS xpc\_connection\_get\_audit\_token

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base sur les messages Mach

Si vous ne savez pas ce que sont les messages Mach, commencez par consulter cette page :

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Pour le moment, souvenez-vous que :
Les messages Mach sont envoyés via un _port mach_, qui est un canal de communication **à récepteur unique, à émetteurs multiples** intégré dans le noyau mach. **Plusieurs processus peuvent envoyer des messages** à un port mach, mais à tout moment **seul un processus peut en lire**. Tout comme les descripteurs de fichiers et les sockets, les ports mach sont alloués et gérés par le noyau et les processus ne voient qu'un entier, qu'ils peuvent utiliser pour indiquer au noyau lequel de leurs ports mach ils souhaitent utiliser.

## Connexion XPC

Si vous ne savez pas comment une connexion XPC est établie, consultez :

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Résumé de la vulnérabilité

Ce qui est intéressant pour vous de savoir, c'est que **l'abstraction XPC est une connexion un-à-un**, mais elle est basée sur une technologie qui **peut avoir plusieurs émetteurs, donc :**

* Les ports mach sont à récepteur unique, **à émetteurs multiples**.
* Le jeton d'audit d'une connexion XPC est le jeton d'audit **copié du message le plus récemment reçu**.
* Obtenir le **jeton d'audit** d'une connexion XPC est crucial pour de nombreux **contrôles de sécurité**.

Bien que la situation précédente semble prometteuse, il existe des scénarios où cela ne va pas poser de problèmes :

* Les jetons d'audit sont souvent utilisés pour un contrôle d'autorisation afin de décider d'accepter ou non une connexion. Comme cela se fait à l'aide d'un message vers le port de service, il n'y a **pas encore de connexion établie**. Plus de messages sur ce port seront simplement traités comme des demandes de connexion supplémentaires. Donc, tout **contrôle avant d'accepter une connexion n'est pas vulnérable** (cela signifie également que dans `-listener:shouldAcceptNewConnection:` le jeton d'audit est sûr). Nous recherchons donc **des connexions XPC qui vérifient des actions spécifiques**.
* Les gestionnaires d'événements XPC sont traités de manière synchrone. Cela signifie que le gestionnaire d'événements pour un message doit être complété avant de l'appeler pour le suivant, même sur des files d'attente de dispatch concurrentes. Donc, à l'intérieur d'un **gestionnaire d'événements XPC, le jeton d'audit ne peut pas être écrasé** par d'autres messages normaux (non-réponse !).

Cela nous a donné l'idée de deux méthodes différentes par lesquelles cela pourrait être possible :

1. Variante 1 :
* **L'exploit** **se connecte** au service **A** et au service **B**
* Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service A que l'utilisateur ne peut pas
* Le service **A** appelle **`xpc_connection_get_audit_token`** alors qu'il n'est _**pas**_ à l'intérieur du **gestionnaire d'événements** pour une connexion dans un **`dispatch_async`**.
* Ainsi, un **message différent** pourrait **écraser le jeton d'audit** car il est dispatché de manière asynchrone en dehors du gestionnaire d'événements.
* L'exploit passe au **service B le droit SEND au service A**.
* Ainsi, le svc **B** sera en fait **l'envoi** des **messages** au service **A**.
* **L'exploit** essaie d'**appeler** l'**action privilégiée**. Dans un RC svc **A** **vérifie** l'autorisation de cette **action** tandis que **svc B a écrasé le jeton d'audit** (donnant à l'exploit l'accès pour appeler l'action privilégiée).
2. Variante 2 :
* Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service A que l'utilisateur ne peut pas
* L'exploit se connecte avec **le service A** qui **envoie** à l'exploit un **message attendant une réponse** dans un port de **réponse** spécifique.
* L'exploit envoie **au service** B un message passant **ce port de réponse**.
* Lorsque le service **B répond**, il **envoie le message au service A**, **tandis que** l'**exploit** envoie un message différent **au service A** essayant d'**atteindre une fonctionnalité privilégiée** et s'attendant à ce que la réponse du service B écrase le jeton d'audit au moment parfait (Condition de Course).

## Variante 1 : appel de xpc\_connection\_get\_audit\_token en dehors d'un gestionnaire d'événements <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scénario :

* Deux services mach **`A`** et **`B`** auxquels nous pouvons tous deux nous connecter (selon le profil du bac à sable et les contrôles d'autorisation avant d'accepter la connexion).
* _**A**_ doit avoir un **contrôle d'autorisation** pour une action spécifique que **`B`** peut passer (mais pas notre application).
* Par exemple, si B a certains **droits** ou s'exécute en tant que **root**, cela pourrait lui permettre de demander à A d'effectuer une action privilégiée.
* Pour ce contrôle d'autorisation, **`A`** obtient le jeton d'audit de manière asynchrone, par exemple en appelant `xpc_connection_get_audit_token` à partir de **`dispatch_async`**.

{% hint style="danger" %}
Dans ce cas, un attaquant pourrait déclencher une **Condition de Course** en créant un **exploit** qui **demande à A d'effectuer une action** plusieurs fois tout en faisant **envoyer des messages à `A` par B**. Lorsque la RC est **réussie**, le **jeton d'audit** de **B** sera copié en mémoire **pendant** que la demande de notre **exploit** est **traitée** par A, lui donnant **accès à l'action privilégiée que seul B pouvait demander**.
{% endhint %}

Cela s'est produit avec **`A`** en tant que `smd` et **`B`** en tant que `diagnosticd`. La fonction [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb peut être utilisée pour installer un nouvel outil d'aide privilégié (en tant que **root**). Si un **processus s'exécutant en tant que root contacte** **smd**, aucun autre contrôle ne sera effectué.

Par conséquent, le service **B** est **`diagnosticd`** car il s'exécute en tant que **root** et peut être utilisé pour **surveiller** un processus, donc une fois la surveillance commencée, il **envoie plusieurs messages par seconde**.

Pour effectuer l'attaque :

1. Nous établissons notre **connexion** à **`smd`** en suivant le protocole XPC normal.
2. Ensuite, nous établissons une **connexion** à **`diagnosticd`**, mais au lieu de générer deux nouveaux ports mach et de les envoyer, nous remplaçons le droit d'envoi du port client par une copie du **droit d'envoi que nous avons pour la connexion à `smd`**.
3. Cela signifie que nous pouvons envoyer des messages XPC à `diagnosticd`, mais tout **message `diagnosticd` envoie va à `smd`**.
* Pour `smd`, les messages de nous et de `diagnosticd` semblent arriver sur la même connexion.

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. Nous demandons à **`diagnosticd`** de **commencer à surveiller** notre processus (ou tout processus actif) et nous **envoyons des messages de routine 1004 à `smd`** (pour installer un outil privilégié).
5. Cela crée une condition de course qui doit atteindre une fenêtre très spécifique dans `handle_bless`. Nous avons besoin que l'appel à `xpc_connection_get_pid` retourne le PID de notre propre processus, car l'outil d'aide privilégié est dans notre bundle d'application. Cependant, l'appel à `xpc_connection_get_audit_token` à l'intérieur de la fonction `connection_is_authorized` doit utiliser le jeton d'audit de `diganosticd`.

## Variante 2 : transfert de réponse

Comme mentionné précédemment, le gestionnaire d'événements pour une connexion XPC n'est jamais exécuté plusieurs fois de manière concurrente. Cependant, **les messages de réponse XPC sont traités différemment. Deux fonctions existent pour envoyer un message qui attend une réponse :

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`, dans ce cas, le message XPC est reçu et analysé sur la file d'attente spécifiée.
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`, dans ce cas, le message XPC est reçu et analysé sur la file d'attente de dispatch actuelle.

Par conséquent, **les paquets de réponse XPC peuvent être analysés alors qu'un gestionnaire d'événements XPC est en cours d'exécution**. Bien que `_xpc_connection_set_creds` utilise un verrouillage, cela ne prévient que l'écrasement partiel du jeton d'audit, cela ne verrouille pas l'ensemble de l'objet de connexion, rendant possible de **remplacer le jeton d'audit entre l'analyse** d'un paquet et l'exécution de son gestionnaire d'événements.

Pour ce scénario, nous aurions besoin :

* Comme avant, de deux services mach **`A`** et **`B`** auxquels nous pouvons tous deux nous connecter.
* Encore une fois, **`A`** doit avoir un contrôle d'autorisation pour une action spécifique que **`B`** peut passer (mais pas notre application).
* **`A`** nous envoie un message qui attend une réponse.
* Nous pouvons envoyer un message à **`B`** auquel il répondra.

Nous attendons que **`A`** nous envoie un message qui attend une réponse (1), au lieu de répondre, nous prenons le port de réponse et l'utilisons pour un message que nous envoyons à **`B`** (2). Ensuite, nous envoyons un message qui utilise l'action interdite et nous espérons qu'il arrive en même temps que la réponse de **`B`** (3).

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Problèmes de découverte

Nous avons passé beaucoup de temps à essayer de trouver d'autres instances, mais les conditions ont rendu la recherche difficile, soit statiquement, soit dynamiquement. Pour rechercher des appels asynchrones à `xpc_connection_get_audit_token`, nous avons utilisé Frida pour accrocher cette fonction afin de vérifier si la trace arrière inclut `_xpc_connection_mach_event` (ce qui signifie qu'elle n'est pas appelée à partir d'un gestionnaire d'événements). Mais cela ne trouve que des appels dans le processus que nous avons actuellement accroché et à partir des actions qui sont activement utilisées. Analyser tous les services mach accessibles dans IDA/Ghidra était très chronophage, surtout lorsque les appels impliquaient le cache partagé dyld. Nous avons essayé de scripter cela pour rechercher des appels à `xpc_connection_get_audit_token` accessibles à partir d'un bloc soumis en utilisant `dispatch_async`, mais l'analyse des blocs et des appels passant dans le cache partagé dyld a rendu cela difficile aussi. Après avoir passé un certain temps là-dessus, nous avons décidé qu'il serait mieux de soumettre ce que nous avions.

## La correction <a href="#the-fix" id="the-fix"></a>

En fin de compte, nous avons signalé le problème général et le problème spécifique dans `smd`. Apple l'a corrigé uniquement dans `smd` en remplaçant l'appel à `xpc_connection_get_audit_token` par `xpc_dictionary_get_audit_token`.

La fonction `xpc_dictionary_get_audit_token` copie le jeton d'audit du message mach sur lequel ce message XPC a été reçu, ce qui signifie qu'il n'est pas vulnérable. Cependant, tout comme `xpc_dictionary_get_audit_token`, cela ne fait pas partie de l'API publique. Pour l'API `NSXPCConnection` de niveau supérieur, aucune méthode claire n'existe pour obtenir le jeton d'audit du message actuel, car cela abstrait tous les messages en appels de méthode.

Il n'est pas clair pour nous pourquoi Apple n'a pas appliqué une correction plus générale, par exemple en supprimant les messages qui ne correspondent pas au jeton d'audit enregistré de la connexion. Il peut y avoir des scénarios où le jeton d'audit d'un processus change légitimement mais la connexion doit rester ouverte (par exemple, appeler `setuid` change le champ UID), mais des changements comme un PID différent ou une version de PID sont peu susceptibles d'être intentionnels.

Dans tous les cas, ce problème persiste avec iOS 17 et macOS 14, donc si vous voulez aller le chercher, bonne chance !

# Références
* Pour plus d'informations, consultez le post original : [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre
