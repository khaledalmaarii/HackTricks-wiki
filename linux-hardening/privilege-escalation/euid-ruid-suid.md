# euid, ruid, suid

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Variables d'Identification de l'Utilisateur

- **`ruid`**: L'**identifiant d'utilisateur réel** désigne l'utilisateur qui a lancé le processus.
- **`euid`**: Connu sous le nom d'**identifiant d'utilisateur effectif**, il représente l'identité de l'utilisateur utilisée par le système pour déterminer les privilèges du processus. Généralement, `euid` reflète `ruid`, sauf dans des cas comme l'exécution d'un binaire SetUID, où `euid` prend l'identité du propriétaire du fichier, accordant ainsi des autorisations opérationnelles spécifiques.
- **`suid`**: Cet **identifiant d'utilisateur sauvegardé** est essentiel lorsqu'un processus à haute privilège (fonctionnant généralement en tant que root) doit temporairement abandonner ses privilèges pour effectuer certaines tâches, pour ensuite retrouver son statut élevé initial.

#### Note Importante
Un processus n'opérant pas sous root ne peut modifier son `euid` que pour correspondre au `ruid`, `euid` ou `suid` actuel.

### Compréhension des Fonctions set*uid

- **`setuid`**: Contrairement aux hypothèses initiales, `setuid` modifie principalement `euid` plutôt que `ruid`. Spécifiquement, pour les processus privilégiés, il aligne `ruid`, `euid` et `suid` avec l'utilisateur spécifié, souvent root, solidifiant efficacement ces identifiants en raison de la substitution de `suid`. Des informations détaillées sont disponibles dans la [page de manuel de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** et **`setresuid`**: Ces fonctions permettent l'ajustement nuancé de `ruid`, `euid` et `suid`. Cependant, leurs capacités dépendent du niveau de privilège du processus. Pour les processus non root, les modifications sont limitées aux valeurs actuelles de `ruid`, `euid` et `suid`. En revanche, les processus root ou ceux avec la capacité `CAP_SETUID` peuvent attribuer des valeurs arbitraires à ces identifiants. Plus d'informations sont disponibles dans la [page de manuel de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) et la [page de manuel de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ces fonctionnalités sont conçues non pas comme un mécanisme de sécurité, mais pour faciliter le flux opérationnel prévu, comme lorsqu'un programme adopte l'identité d'un autre utilisateur en modifiant son identifiant d'utilisateur effectif.

Il est important de noter que, bien que `setuid` puisse être couramment utilisé pour l'élévation des privilèges vers root (car il aligne tous les identifiants sur root), différencier ces fonctions est crucial pour comprendre et manipuler les comportements des identifiants d'utilisateur dans divers scénarios.

### Mécanismes d'Exécution de Programmes sous Linux

#### **Appel Système `execve`**
- **Fonctionnalité**: `execve` lance un programme, déterminé par le premier argument. Il prend deux tableaux d'arguments, `argv` pour les arguments et `envp` pour l'environnement.
- **Comportement**: Il conserve l'espace mémoire de l'appelant mais rafraîchit la pile, le tas et les segments de données. Le code du programme est remplacé par le nouveau programme.
- **Préservation de l'Identifiant d'Utilisateur**:
- Les identifiants `ruid`, `euid` et les identifiants de groupe supplémentaires restent inchangés.
- `euid` peut subir des changements nuancés si le nouveau programme a le bit SetUID défini.
- `suid` est mis à jour à partir de `euid` après l'exécution.
- **Documentation**: Des informations détaillées sont disponibles sur la [page de manuel de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Fonction `system`**
- **Fonctionnalité**: Contrairement à `execve`, `system` crée un processus enfant en utilisant `fork` et exécute une commande dans ce processus enfant en utilisant `execl`.
- **Exécution de Commande**: Exécute la commande via `sh` avec `execl("/bin/sh", "sh", "-c", commande, (char *) NULL);`.
- **Comportement**: Comme `execl` est une forme de `execve`, il fonctionne de manière similaire mais dans le contexte d'un nouveau processus enfant.
- **Documentation**: Des informations supplémentaires peuvent être obtenues à partir de la [page de manuel de `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportement de `bash` et `sh` avec SUID**
- **`bash`**:
- Possède une option `-p` influençant la manière dont `euid` et `ruid` sont traités.
- Sans `-p`, `bash` définit `euid` sur `ruid` s'ils diffèrent initialement.
- Avec `-p`, l'`euid` initial est préservé.
- Plus de détails sont disponibles sur la [page de manuel de `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Ne possède pas de mécanisme similaire à `-p` dans `bash`.
- Le comportement concernant les identifiants d'utilisateur n'est pas explicitement mentionné, sauf sous l'option `-i`, mettant l'accent sur la préservation de l'égalité de `euid` et `ruid`.
- Des informations supplémentaires sont disponibles sur la [page de manuel de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ces mécanismes, distincts dans leur fonctionnement, offrent une gamme variée d'options pour exécuter et passer d'un programme à un autre, avec des nuances spécifiques dans la gestion et la préservation des identifiants d'utilisateur.

### Test des Comportements des Identifiants d'Utilisateur lors des Exécutions

Exemples tirés de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultez-le pour plus d'informations

#### Cas 1: Utilisation de `setuid` avec `system`

**Objectif**: Comprendre l'effet de `setuid` en combinaison avec `system` et `bash` en tant que `sh`.

**Code C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilation et autorisations :**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

* `ruid` et `euid` commencent respectivement à 99 (nobody) et 1000 (frank).
* `setuid` les aligne tous les deux sur 1000.
* `system` exécute `/bin/bash -c id` en raison du lien symbolique de sh vers bash.
* `bash`, sans `-p`, ajuste `euid` pour correspondre à `ruid`, ce qui fait que les deux valent 99 (nobody).

#### Cas 2 : Utilisation de setreuid avec system

**Code C** :
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilation et autorisations :**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

* `setreuid` définit à la fois ruid et euid sur 1000.
* `system` invoque bash, qui maintient les IDs utilisateur en raison de leur égalité, fonctionnant efficacement en tant que frank.

#### Cas 3 : Utilisation de setuid avec execve
Objectif : Explorer l'interaction entre setuid et execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

* `ruid` reste à 99, mais `euid` est défini à 1000, en accord avec l'effet de `setuid`.

**Exemple de code C 2 (Appel de Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

* Bien que `euid` soit défini à 1000 par `setuid`, `bash` réinitialise euid à `ruid` (99) en raison de l'absence de l'option `-p`.

**Exemple de code C 3 (Utilisation de bash -p) :**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Références
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
