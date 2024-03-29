# Attaque xpc\_connection\_get\_audit\_token

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

**Pour plus d'informations, consultez l'article original :** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Voici un résumé :

## Informations de base sur les messages Mach

Si vous ne savez pas ce que sont les messages Mach, commencez par consulter cette page :

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Pour l'instant, retenez que ([définition à partir d'ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :\
Les messages Mach sont envoyés sur un _port Mach_, qui est un canal de communication à **un seul destinataire, plusieurs expéditeurs** intégré dans le noyau Mach. **Plusieurs processus peuvent envoyer des messages** à un port Mach, mais à tout moment, **un seul processus peut les lire**. Tout comme les descripteurs de fichiers et les sockets, les ports Mach sont alloués et gérés par le noyau et les processus ne voient qu'un entier, qu'ils peuvent utiliser pour indiquer au noyau lequel de leurs ports Mach ils veulent utiliser.

## Connexion XPC

Si vous ne savez pas comment une connexion XPC est établie, consultez :

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Résumé de la vulnérabilité

Ce qui est intéressant à savoir, c'est que **l'abstraction XPC est une connexion un à un**, mais elle est basée sur une technologie qui **peut avoir plusieurs expéditeurs, donc :**

* Les ports Mach sont à un seul destinataire, **plusieurs expéditeurs**.
* Le jeton d'audit d'une connexion XPC est le jeton d'audit **copié du message le plus récemment reçu**.
* Obtenir le **jeton d'audit** d'une connexion XPC est crucial pour de nombreux **contrôles de sécurité**.

Bien que la situation précédente semble prometteuse, il existe des scénarios où cela ne posera pas de problèmes ([à partir d'ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :

* Les jetons d'audit sont souvent utilisés pour une vérification d'autorisation afin de décider d'accepter une connexion. Comme cela se fait en utilisant un message vers le port de service, il n'y a **pas encore de connexion établie**. Les messages supplémentaires sur ce port seront simplement traités comme des demandes de connexion supplémentaires. Ainsi, **les vérifications avant d'accepter une connexion ne sont pas vulnérables** (cela signifie également que dans `-listener:shouldAcceptNewConnection:`, le jeton d'audit est sécurisé). Nous recherchons donc **des connexions XPC qui vérifient des actions spécifiques**.
* Les gestionnaires d'événements XPC sont traités de manière synchrone. Cela signifie que le gestionnaire d'événements pour un message doit être terminé avant de l'appeler pour le suivant, même sur des files d'attente de répartition concurrentes. Ainsi, à l'intérieur d'un **gestionnaire d'événements XPC, le jeton d'audit ne peut pas être écrasé** par d'autres messages normaux (non de réponse !).

Deux méthodes différentes par lesquelles cela pourrait être exploité :

1. Variante 1 :
* L'**exploit** se connecte au service **A** et au service **B**.
* Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service **A** que l'utilisateur ne peut pas.
* Le service **A** appelle **`xpc_connection_get_audit_token`** tout en n'étant pas à l'intérieur du **gestionnaire d'événements** pour une connexion dans un **`dispatch_async`**.
* Ainsi, un **message différent** pourrait **écraser le jeton d'audit** car il est envoyé de manière asynchrone en dehors du gestionnaire d'événements.
* L'exploit transmet à **service B le droit d'ENVOI à service A**.
* Ainsi, svc **B** enverra effectivement les **messages** au service **A**.
* L'**exploit** tente d'**appeler** l'**action privilégiée**. Dans un RC, svc **A** **vérifie** l'autorisation de cette **action** tandis que **svc B a écrasé le jeton d'audit** (donnant à l'exploit l'accès pour appeler l'action privilégiée).
2. Variante 2 :
* Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service **A** que l'utilisateur ne peut pas.
* L'exploit se connecte avec le **service A** qui lui **envoie** un **message attendant une réponse** dans un **port de réponse** spécifique.
* L'exploit envoie au **service** B un message passant **ce port de réponse**.
* Lorsque le service **B répond**, il **envoie le message au service A**, **tandis que** l'**exploit** envoie un **message différent au service A** essayant d'**atteindre une fonctionnalité privilégiée** et s'attendant à ce que la réponse de service B écrase le jeton d'audit au moment parfait (Condition de Course).

## Variante 1 : appel de xpc\_connection\_get\_audit\_token en dehors d'un gestionnaire d'événements <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scénario :

* Deux services Mach **`A`** et **`B`** auxquels nous pouvons tous deux nous connecter (en fonction du profil de bac à sable et des vérifications d'autorisation avant d'accepter la connexion).
* _**A**_ doit avoir une **vérification d'autorisation** pour une action spécifique que **`B`** peut passer (mais notre application ne peut pas).
* Par exemple, si B a des **privilèges** ou s'exécute en tant que **root**, il pourrait lui permettre de demander à A d'effectuer une action privilégiée.
* Pour cette vérification d'autorisation, **`A`** obtient le jeton d'audit de manière asynchrone, par exemple en appelant `xpc_connection_get_audit_token` depuis **`dispatch_async`**.

{% hint style="danger" %}
Dans ce cas, un attaquant pourrait déclencher une **Condition de Course** en créant un **exploit** qui **demande à A d'effectuer une action** plusieurs fois tout en faisant **envoyer des messages à `A` par B**. Lorsque la CC est **réussie**, le **jeton d'audit** de **B** sera copié en mémoire **pendant que** la demande de notre **exploit** est en cours de **traitement** par A, lui donnant **accès à l'action privilégiée que seul B pourrait demander**.
{% endhint %}

Cela s'est produit avec **`A`** en tant que `smd` et **`B`** en tant que `diagnosticd`. La fonction [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb peut être utilisée pour installer un nouvel outil d'aide privilégié (en tant que **root**). Si un **processus s'exécutant en tant que root contacte** **smd**, aucune autre vérification ne sera effectuée.

Par conséquent, le service **B** est **`diagnosticd`** car il s'exécute en tant que **root** et peut être utilisé pour **surveiller** un processus, donc une fois la surveillance commencée, il **envoie plusieurs messages par seconde**.

Pour effectuer l'attaque :

1. Initier une **connexion** au service nommé `smd` en utilisant le protocole XPC standard.
2. Former une **connexion secondaire** à `diagnosticd`. Contrairement à la procédure normale, au lieu de créer et d'envoyer deux nouveaux ports Mach, le droit d'envoi du port client est remplacé par une copie du **droit d'envoi** associé à la connexion `smd`.
3. En conséquence, les messages XPC peuvent être envoyés à `diagnosticd`, mais les réponses de `diagnosticd` sont redirigées vers `smd`. Pour `smd`, il semble que les messages de l'utilisateur et de `diagnosticd` proviennent de la même connexion.

![Image illustrant le processus d'exploitation](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. La prochaine étape consiste à instruire `diagnosticd` d'initier la surveillance d'un processus choisi (potentiellement celui de l'utilisateur). Simultanément, une vague de messages 1004 de routine est envoyée à `smd`. L'intention ici est d'installer un outil avec des privilèges élevés.
5. Cette action déclenche une condition de course au sein de la fonction `handle_bless`. Le timing est crucial : l'appel de fonction `xpc_connection_get_pid` doit renvoyer le PID du processus de l'utilisateur (car l'outil privilégié réside dans le bundle d'application de l'utilisateur). Cependant, la fonction `xpc_connection_get_audit_token`, spécifiquement dans la sous-routine `connection_is_authorized`, doit faire référence au jeton d'audit appartenant à `diagnosticd`.

## Variante 2 : transfert de réponse

Dans un environnement XPC (Communication inter-processus), bien que les gestionnaires d'événements n'exécutent pas de manière concurrente, le traitement des messages de réponse a un comportement unique. Deux méthodes distinctes existent pour envoyer des messages qui attendent une réponse :

1. **`xpc_connection_send_message_with_reply`** : Ici, le message XPC est reçu et traité sur une file d'attente désignée.
2. **`xpc_connection_send_message_with_reply_sync`** : Au contraire, dans cette méthode, le message XPC est reçu et traité sur la file d'attente de dispatch actuelle.

Cette distinction est cruciale car elle permet la possibilité de **parser les paquets de réponse de manière concurrente avec l'exécution d'un gestionnaire d'événements XPC**. Notamment, bien que `_xpc_connection_set_creds` implémente un verrouillage pour protéger contre l'écrasement partiel du jeton d'audit, cette protection n'est pas étendue à l'objet de connexion entier. Par conséquent, cela crée une vulnérabilité où le jeton d'audit peut être remplacé pendant l'intervalle entre l'analyse d'un paquet et l'exécution de son gestionnaire d'événements.

Pour exploiter cette vulnérabilité, la configuration suivante est requise :

* Deux services mach, appelés **`A`** et **`B`**, qui peuvent tous deux établir une connexion.
* Le service **`A`** devrait inclure une vérification d'autorisation pour une action spécifique que seul **`B`** peut effectuer (l'application de l'utilisateur ne peut pas).
* Le service **`A`** devrait envoyer un message qui attend une réponse.
* L'utilisateur peut envoyer un message à **`B`** auquel il répondra.

Le processus d'exploitation implique les étapes suivantes :

1. Attendre que le service **`A`** envoie un message qui attend une réponse.
2. Au lieu de répondre directement à **`A`**, le port de réponse est détourné et utilisé pour envoyer un message au service **`B`**.
3. Ensuite, un message impliquant l'action interdite est envoyé, en s'attendant à ce qu'il soit traité de manière concurrente avec la réponse de **`B`**.

Ci-dessous se trouve une représentation visuelle du scénario d'attaque décrit :

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problèmes de découverte

* **Difficultés pour Localiser les Instances** : La recherche des instances d'utilisation de `xpc_connection_get_audit_token` était difficile, à la fois statiquement et dynamiquement.
* **Méthodologie** : Frida a été utilisé pour accrocher la fonction `xpc_connection_get_audit_token`, filtrant les appels ne provenant pas des gestionnaires d'événements. Cependant, cette méthode était limitée au processus accroché et nécessitait une utilisation active.
* **Outils d'Analyse** : Des outils comme IDA/Ghidra ont été utilisés pour examiner les services mach accessibles, mais le processus était long et compliqué par des appels impliquant le cache partagé dyld.
* **Limitations de Scripting** : Les tentatives de scripter l'analyse des appels à `xpc_connection_get_audit_token` à partir de blocs `dispatch_async` ont été entravées par des complexités dans l'analyse des blocs et les interactions avec le cache partagé dyld.

## La correction <a href="#the-fix" id="the-fix"></a>

* **Problèmes Signalés** : Un rapport a été soumis à Apple détaillant les problèmes généraux et spécifiques trouvés dans `smd`.
* **Réponse d'Apple** : Apple a résolu le problème dans `smd` en remplaçant `xpc_connection_get_audit_token` par `xpc_dictionary_get_audit_token`.
* **Nature de la Correction** : La fonction `xpc_dictionary_get_audit_token` est considérée comme sécurisée car elle récupère le jeton d'audit directement à partir du message mach lié au message XPC reçu. Cependant, elle ne fait pas partie de l'API publique, tout comme `xpc_connection_get_audit_token`.
* **Absence d'une Correction Plus Large** : Il n'est pas clair pourquoi Apple n'a pas mis en place une correction plus complète, comme le rejet des messages ne correspondant pas au jeton d'audit enregistré de la connexion. La possibilité de changements légitimes du jeton d'audit dans certains scénarios (par exemple, l'utilisation de `setuid`) pourrait être un facteur.
* **État Actuel** : Le problème persiste dans iOS 17 et macOS 14, posant un défi pour ceux cherchant à l'identifier et à le comprendre.
