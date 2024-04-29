# Abus de Processus macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de Base sur les Processus

Un processus est une instance d'un exécutable en cours d'exécution, cependant les processus n'exécutent pas de code, ce sont les threads qui le font. Par conséquent, **les processus ne sont que des conteneurs pour les threads en cours d'exécution** fournissant la mémoire, les descripteurs, les ports, les autorisations...

Traditionnellement, les processus étaient lancés à l'intérieur d'autres processus (à l'exception du PID 1) en appelant **`fork`** qui créait une copie exacte du processus actuel, puis le **processus enfant** appelait généralement **`execve`** pour charger le nouvel exécutable et l'exécuter. Ensuite, **`vfork`** a été introduit pour accélérer ce processus sans aucune copie de mémoire.\
Ensuite, **`posix_spawn`** a été introduit en combinant **`vfork`** et **`execve`** en un seul appel et en acceptant des indicateurs :

* `POSIX_SPAWN_RESETIDS` : Réinitialiser les identifiants effectifs aux identifiants réels
* `POSIX_SPAWN_SETPGROUP` : Définir l'affiliation au groupe de processus
* `POSUX_SPAWN_SETSIGDEF` : Définir le comportement par défaut des signaux
* `POSIX_SPAWN_SETSIGMASK` : Définir le masque de signal
* `POSIX_SPAWN_SETEXEC` : Exécuter dans le même processus (comme `execve` avec plus d'options)
* `POSIX_SPAWN_START_SUSPENDED` : Démarrer en mode suspendu
* `_POSIX_SPAWN_DISABLE_ASLR` : Démarrer sans ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR` : Utiliser l'allocateur Nano de libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC` : Autoriser `rwx` sur les segments de données
* `POSIX_SPAWN_CLOEXEC_DEFAULT` : Fermer toutes les descriptions de fichiers lors de l'exécution(2) par défaut
* `_POSIX_SPAWN_HIGH_BITS_ASLR` : Randomiser les bits élevés du décalage ASLR

De plus, `posix_spawn` permet de spécifier un tableau d'**`posix_spawnattr`** qui contrôle certains aspects du processus créé, et **`posix_spawn_file_actions`** pour modifier l'état des descripteurs.

Lorsqu'un processus meurt, il envoie le **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit obtenir cette valeur en appelant `wait4()` ou `waitid()` et tant que cela n'est pas fait, l'enfant reste dans un état zombie où il est toujours répertorié mais ne consomme pas de ressources.

### PIDs

Les PIDs, identifiants de processus, identifient un processus unique. Dans XNU, les **PIDs** sont sur **64 bits** augmentant de manière monotone et ne **rebouclent jamais** (pour éviter les abus).

### Groupes de Processus, Sessions & Coalitions

Les **processus** peuvent être regroupés pour faciliter leur gestion. Par exemple, les commandes dans un script shell seront dans le même groupe de processus, il est donc possible de les **signaler ensemble** en utilisant kill par exemple.\
Il est également possible de **regrouper des processus en sessions**. Lorsqu'un processus démarre une session (`setsid(2)`), les processus enfants sont placés dans la session, sauf s'ils démarrent leur propre session.

La coalition est une autre façon de regrouper des processus dans Darwin. Un processus rejoignant une coalition lui permet d'accéder à des ressources communes, de partager un registre ou de faire face à Jetsam. Les coalitions ont différents rôles : Leader, service XPC, Extension.

### Identifiants & Personae

Chaque processus détient des **identifiants** qui **définissent ses privilèges** dans le système. Chaque processus aura un `uid` principal et un `gid` principal (bien qu'il puisse appartenir à plusieurs groupes).\
Il est également possible de changer l'identifiant utilisateur et de groupe si le binaire a le bit `setuid/setgid`.\
Il existe plusieurs fonctions pour **définir de nouveaux uids/gids**.

L'appel système **`persona`** fournit un **ensemble alternatif** d'**identifiants**. Adopter une persona suppose son uid, gid et les appartenances aux groupes **en une seule fois**. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Informations de base sur les threads

1. **Threads POSIX (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d'une API de threading standard pour C/C++. L'implémentation des pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer des threads.
2. **Création de threads :** La fonction `pthread_create()` est utilisée pour créer de nouveaux threads. En interne, cette fonction appelle `bsdthread_create()`, qui est un appel système de plus bas niveau spécifique au noyau XNU (le noyau sur lequel macOS est basé). Cet appel système prend divers indicateurs dérivés de `pthread_attr` (attributs) qui spécifient le comportement du thread, y compris les politiques de planification et la taille de la pile.
* **Taille de pile par défaut :** La taille de pile par défaut pour les nouveaux threads est de 512 Ko, ce qui est suffisant pour des opérations typiques mais peut être ajusté via les attributs du thread si plus ou moins d'espace est nécessaire.
3. **Initialisation du thread :** La fonction `__pthread_init()` est cruciale lors de la configuration du thread, utilisant l'argument `env[]` pour analyser les variables d'environnement qui peuvent inclure des détails sur l'emplacement et la taille de la pile.

#### Terminaison des threads dans macOS

1. **Sortie des threads :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d'effectuer le nettoyage nécessaire et de permettre au thread d'envoyer une valeur de retour à tout thread rejoignant.
2. **Nettoyage du thread :** Lors de l'appel de `pthread_exit()`, la fonction `pthread_terminate()` est invoquée, qui gère la suppression de toutes les structures de thread associées. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication dans le noyau XNU) et appelle `bsdthread_terminate`, un appel système qui supprime les structures au niveau du noyau associées au thread.

#### Mécanismes de synchronisation

Pour gérer l'accès aux ressources partagées et éviter les conditions de concurrence, macOS fournit plusieurs primitives de synchronisation. Celles-ci sont essentielles dans les environnements multi-threading pour garantir l'intégrité des données et la stabilité du système :

1. **Mutex :**
* **Mutex standard (Signature : 0x4D555458) :** Mutex standard avec une empreinte mémoire de 60 octets (56 octets pour le mutex et 4 octets pour la signature).
* **Mutex rapide (Signature : 0x4d55545A) :** Similaire à un mutex standard mais optimisé pour des opérations plus rapides, également de taille 60 octets.
2. **Variables de condition :**
* Utilisées pour attendre que certaines conditions se produisent, avec une taille de 44 octets (40 octets plus une signature de 4 octets).
* **Attributs de variable de condition (Signature : 0x434e4441) :** Attributs de configuration pour les variables de condition, de taille 12 octets.
3. **Variable Once (Signature : 0x4f4e4345) :**
* Garantit qu'un morceau de code d'initialisation est exécuté une seule fois. Sa taille est de 12 octets.
4. **Verrous de lecture-écriture :**
* Permettent à plusieurs lecteurs ou à un seul écrivain à la fois, facilitant l'accès efficace aux données partagées.
* **Verrou de lecture-écriture (Signature : 0x52574c4b) :** Taille de 196 octets.
* **Attributs de verrou de lecture-écriture (Signature : 0x52574c41) :** Attributs pour les verrous de lecture-écriture, de taille 20 octets.

{% hint style="success" %}
Les 4 derniers octets de ces objets sont utilisés pour détecter les débordements.
{% endhint %}

### Variables locales au thread (TLV)

Les **Variables locales au thread (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables dans macOS) sont utilisées pour déclarer des variables spécifiques à **chaque thread** dans une application multi-threadée. Cela garantit que chaque thread a sa propre instance séparée d'une variable, offrant un moyen d'éviter les conflits et de maintenir l'intégrité des données sans avoir besoin de mécanismes de synchronisation explicites comme les mutex.

En C et dans les langages associés, vous pouvez déclarer une variable locale au thread en utilisant le mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ce extrait définit `tlv_var` comme une variable locale au thread. Chaque thread exécutant ce code aura sa propre `tlv_var`, et les modifications apportées par un thread à `tlv_var` n'affecteront pas `tlv_var` dans un autre thread.

Dans le binaire Mach-O, les données liées aux variables locales au thread sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : Cette section contient les métadonnées sur les variables locales au thread, comme leurs types et leur état d'initialisation.
- **`__DATA.__thread_bss`** : Cette section est utilisée pour les variables locales au thread qui ne sont pas explicitement initialisées. C'est une partie de la mémoire réservée pour des données initialisées à zéro.

Mach-O fournit également une API spécifique appelée **`tlv_atexit`** pour gérer les variables locales au thread lorsqu'un thread se termine. Cette API vous permet de **enregistrer des destructeurs** - des fonctions spéciales qui nettoient les données locales au thread lorsqu'un thread se termine.

### Priorités de thread

Comprendre les priorités de thread implique d'examiner comment le système d'exploitation décide quels threads exécuter et quand. Cette décision est influencée par le niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela est géré à l'aide de concepts tels que `nice`, `renice` et les classes de qualité de service (QoS).

#### Nice et Renice

1. **Nice :**
   - La valeur `nice` d'un processus est un nombre qui affecte sa priorité. Chaque processus a une valeur `nice` allant de -20 (la priorité la plus élevée) à 19 (la priorité la plus basse). La valeur `nice` par défaut lorsqu'un processus est créé est généralement 0.
   - Une valeur `nice` plus basse (plus proche de -20) rend un processus plus "égoïste", lui donnant plus de temps CPU par rapport à d'autres processus avec des valeurs `nice` plus élevées.
2. **Renice :**
   - `renice` est une commande utilisée pour changer la valeur `nice` d'un processus déjà en cours d'exécution. Cela peut être utilisé pour ajuster dynamiquement la priorité des processus, en augmentant ou en diminuant leur allocation de temps CPU en fonction des nouvelles valeurs `nice`.
   - Par exemple, si un processus a besoin de plus de ressources CPU temporairement, vous pouvez réduire sa valeur `nice` en utilisant `renice`.

#### Classes de qualité de service (QoS)

Les classes de QoS sont une approche plus moderne pour gérer les priorités de thread, en particulier dans des systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Les classes de QoS permettent aux développeurs de **catégoriser** le travail en différents niveaux en fonction de leur importance ou de leur urgence. macOS gère automatiquement la priorisation des threads en fonction de ces classes de QoS :

1. **Interaction Utilisateur :**
   - Cette classe est destinée aux tâches qui interagissent actuellement avec l'utilisateur ou nécessitent des résultats immédiats pour offrir une bonne expérience utilisateur. Ces tâches ont la priorité la plus élevée pour maintenir l'interface réactive (par exemple, animations ou gestion d'événements).
2. **Utilisateur Initié :**
   - Les tâches que l'utilisateur initie et qui nécessitent des résultats immédiats, comme l'ouverture d'un document ou le clic sur un bouton nécessitant des calculs. Ce sont des priorités élevées mais inférieures à l'interaction utilisateur.
3. **Utilitaire :**
   - Ces tâches sont de longue durée et montrent généralement un indicateur de progression (par exemple, téléchargement de fichiers, importation de données). Elles ont une priorité inférieure aux tâches initiées par l'utilisateur et n'ont pas besoin de se terminer immédiatement.
4. **Arrière-plan :**
   - Cette classe est destinée aux tâches qui fonctionnent en arrière-plan et ne sont pas visibles pour l'utilisateur. Il peut s'agir de tâches telles que l'indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus basse et un impact minimal sur les performances du système.

En utilisant les classes de QoS, les développeurs n'ont pas besoin de gérer les numéros de priorité exacts, mais plutôt de se concentrer sur la nature de la tâche, et le système optimise les ressources CPU en conséquence.

De plus, il existe différentes **politiques de planification de thread** qui permettent de spécifier un ensemble de paramètres de planification que le planificateur prendra en considération. Cela peut être fait en utilisant `thread_policy_[set/get]`. Cela peut être utile dans les attaques de conditions de concurrence.

## Abus de processus sur MacOS

MacOS, comme tout autre système d'exploitation, propose une variété de méthodes et de mécanismes pour que les **processus interagissent, communiquent et partagent des données**. Bien que ces techniques soient essentielles pour le bon fonctionnement du système, elles peuvent également être utilisées de manière abusive par des acteurs malveillants pour **effectuer des activités malveillantes**.

### Injection de bibliothèque

L'injection de bibliothèque est une technique dans laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus cible, fournissant à l'attaquant les mêmes autorisations et accès que le processus.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Accrochage de fonction

L'accrochage de fonction implique **d'intercepter les appels de fonction** ou les messages au sein d'un code logiciel. En accrochant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles, voire prendre le contrôle du flux d'exécution.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Communication inter-processus

La communication inter-processus (IPC) fait référence à différentes méthodes par lesquelles des processus distincts **partagent et échangent des données**. Bien que l'IPC soit fondamental pour de nombreuses applications légitimes, il peut également être utilisé de manière abusive pour contourner l'isolation des processus, divulguer des informations sensibles ou effectuer des actions non autorisées.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injection d'applications Electron

Les applications Electron exécutées avec des variables d'environnement spécifiques pourraient être vulnérables à l'injection de processus :

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Injection de Chromium

Il est possible d'utiliser les indicateurs `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **attaque de l'homme du navigateur** permettant de voler des frappes, du trafic, des cookies, d'injecter des scripts dans les pages... :

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Fichier NIB corrompu

Les fichiers NIB **définissent les éléments de l'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires** et **Gatekeeper n'empêche pas** l'exécution d'une application déjà exécutée si un **fichier NIB est modifié**. Par conséquent, ils pourraient être utilisés pour faire exécuter des programmes arbitraires des commandes arbitraires :

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Injection d'applications Java

Il est possible d'abuser de certaines capacités Java (comme la variable d'environnement **`_JAVA_OPTS`**) pour faire exécuter à une application Java du **code/commandes arbitraires**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Injection d'applications .Net

Il est possible d'injecter du code dans des applications .Net en **abusant de la fonctionnalité de débogage .Net** (non protégée par les protections macOS telles que le renforcement de l'exécution).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Injection Perl

Vérifiez les différentes options pour faire exécuter du code arbitraire par un script Perl dans :

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Injection Ruby

Il est également possible d'abuser des variables d'environnement Ruby pour faire exécuter des scripts arbitraires :

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}
### Injection Python

Si la variable d'environnement **`PYTHONINSPECT`** est définie, le processus python passera en mode CLI une fois terminé. Il est également possible d'utiliser **`PYTHONSTARTUP`** pour indiquer un script python à exécuter au début d'une session interactive.\
Cependant, notez que le script **`PYTHONSTARTUP`** ne sera pas exécuté lorsque **`PYTHONINSPECT`** crée la session interactive.

D'autres variables d'environnement telles que **`PYTHONPATH`** et **`PYTHONHOME`** pourraient également être utiles pour faire exécuter un code arbitraire par une commande python.

Notez que les exécutables compilés avec **`pyinstaller`** n'utiliseront pas ces variables d'environnement même s'ils sont exécutés à l'aide d'un python intégré.

{% hint style="danger" %}
Dans l'ensemble, je n'ai pas trouvé de moyen de faire exécuter un code arbitraire par python en abusant des variables d'environnement.\
Cependant, la plupart des gens installent python en utilisant **Hombrew**, qui installera python dans un **emplacement inscriptible** pour l'utilisateur administrateur par défaut. Vous pouvez le détourner avec quelque chose comme :
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Même **root** exécutera ce code lors de l'exécution de python.
{% endhint %}

## Détection

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) est une application open source qui peut **détecter et bloquer les actions d'injection de processus** :

* En utilisant les **Variables d'Environnement** : Il surveillera la présence de l'une des variables d'environnement suivantes : **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** et **`ELECTRON_RUN_AS_NODE`**
* En utilisant les appels **`task_for_pid`** : Pour trouver quand un processus veut obtenir le **port de tâche d'un autre** ce qui permet d'injecter du code dans le processus.
* **Paramètres des applications Electron** : Quelqu'un peut utiliser les arguments de ligne de commande **`--inspect`**, **`--inspect-brk`** et **`--remote-debugging-port`** pour démarrer une application Electron en mode débogage, et ainsi injecter du code dedans.
* En utilisant des **liens symboliques** ou des **liens physiques** : Typiquement, l'abus le plus courant est de **placer un lien avec nos privilèges utilisateur**, et **le pointer vers un emplacement de privilège supérieur**. La détection est très simple pour les liens physiques et symboliques. Si le processus créant le lien a un **niveau de privilège différent** du fichier cible, nous créons une **alerte**. Malheureusement, dans le cas des liens symboliques, le blocage n'est pas possible, car nous n'avons pas d'informations sur la destination du lien avant sa création. Il s'agit d'une limitation du framework EndpointSecuriy d'Apple.

### Appels effectués par d'autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) vous pouvez trouver comment il est possible d'utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d'autres **processus injectant du code dans un processus** et ensuite obtenir des informations sur cet autre processus.

Notez que pour appeler cette fonction, vous devez être **le même uid** que celui exécutant le processus ou **root** (et cela renvoie des informations sur le processus, pas un moyen d'injecter du code).

## Références

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
