# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Variables d'Identification Utilisateur

- **`ruid`** : L'**identifiant utilisateur réel** désigne l'utilisateur qui a initié le processus.
- **`euid`** : Connu sous le nom d'**identifiant utilisateur effectif**, il représente l'identité utilisateur utilisée par le système pour déterminer les privilèges du processus. Généralement, `euid` reflète `ruid`, sauf dans des cas comme l'exécution d'un binaire SetUID, où `euid` prend l'identité du propriétaire du fichier, accordant ainsi des permissions opérationnelles spécifiques.
- **`suid`** : Cet **identifiant utilisateur sauvegardé** est crucial lorsqu'un processus à privilèges élevés (généralement exécuté en tant que root) doit temporairement renoncer à ses privilèges pour effectuer certaines tâches, afin de réclamer plus tard son statut élevé initial.

#### Note Importante
Un processus n'opérant pas sous root ne peut modifier son `euid` que pour correspondre à l'actuel `ruid`, `euid`, ou `suid`.

### Comprendre les Fonctions set*uid

- **`setuid`** : Contrairement aux hypothèses initiales, `setuid` modifie principalement `euid` plutôt que `ruid`. Spécifiquement, pour les processus privilégiés, il aligne `ruid`, `euid`, et `suid` avec l'utilisateur spécifié, souvent root, solidifiant effectivement ces identifiants en raison de l'`suid` prédominant. Des détails approfondis peuvent être trouvés dans la [page man de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** et **`setresuid`** : Ces fonctions permettent un ajustement nuancé de `ruid`, `euid`, et `suid`. Cependant, leurs capacités dépendent du niveau de privilège du processus. Pour les processus non-root, les modifications sont limitées aux valeurs actuelles de `ruid`, `euid`, et `suid`. En revanche, les processus root ou ceux avec la capacité `CAP_SETUID` peuvent attribuer des valeurs arbitraires à ces identifiants. Plus d'informations peuvent être obtenues à partir de la [page man de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) et de la [page man de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ces fonctionnalités sont conçues non pas comme un mécanisme de sécurité, mais pour faciliter le flux opérationnel prévu, comme lorsqu'un programme adopte l'identité d'un autre utilisateur en modifiant son identifiant utilisateur effectif.

Notamment, alors que `setuid` pourrait être un choix courant pour l'élévation de privilège à root (puisqu'il aligne tous les identifiants sur root), il est crucial de différencier ces fonctions pour comprendre et manipuler les comportements des identifiants utilisateur dans divers scénarios.

### Mécanismes d'Exécution de Programmes sous Linux

#### **Appel Système `execve`**
- **Fonctionnalité** : `execve` lance un programme, déterminé par le premier argument. Il prend deux arguments de type tableau, `argv` pour les arguments et `envp` pour l'environnement.
- **Comportement** : Il conserve l'espace mémoire de l'appelant mais rafraîchit la pile, le tas et les segments de données. Le code du programme est remplacé par le nouveau programme.
- **Préservation des Identifiants Utilisateur** :
- `ruid`, `euid`, et les identifiants de groupe supplémentaires restent inchangés.
- `euid` peut subir des changements nuancés si le nouveau programme a le bit SetUID activé.
- `suid` est mis à jour à partir de `euid` après l'exécution.
- **Documentation** : Des informations détaillées peuvent être trouvées sur la [page man de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Fonction `system`**
- **Fonctionnalité** : Contrairement à `execve`, `system` crée un processus enfant en utilisant `fork` et exécute une commande dans ce processus enfant en utilisant `execl`.
- **Exécution de Commande** : Exécute la commande via `sh` avec `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportement** : Comme `execl` est une forme de `execve`, il fonctionne de manière similaire mais dans le contexte d'un nouveau processus enfant.
- **Documentation** : Des informations supplémentaires peuvent être obtenues à partir de la [page man de `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportement de `bash` et `sh` avec SUID**
- **`bash`** :
- Dispose d'une option `-p` influençant le traitement de `euid` et `ruid`.
- Sans `-p`, `bash` définit `euid` à `ruid` s'ils diffèrent initialement.
- Avec `-p`, l'`euid` initial est préservé.
- Plus de détails peuvent être trouvés sur la [page man de `bash`](https://linux.die.net/man/1/bash).
- **`sh`** :
- Ne possède pas de mécanisme similaire à `-p` dans `bash`.
- Le comportement concernant les identifiants utilisateur n'est pas explicitement mentionné, sauf sous l'option `-i`, soulignant la préservation de l'égalité entre `euid` et `ruid`.
- Des informations supplémentaires sont disponibles sur la [page man de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ces mécanismes, distincts dans leur fonctionnement, offrent une gamme polyvalente d'options pour l'exécution et la transition entre les programmes, avec des nuances spécifiques dans la gestion et la préservation des identifiants utilisateur.

### Tester les Comportements des Identifiants Utilisateur dans les Exécutions

Exemples pris de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultez-le pour plus d'informations

#### Cas 1 : Utilisation de `setuid` avec `system`

**Objectif** : Comprendre l'effet de `setuid` en combinaison avec `system` et `bash` en tant que `sh`.

**Code C** :
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
**Compilation et Permissions :**
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
* `setuid` aligne les deux à 1000.
* `system` exécute `/bin/bash -c id` à cause du lien symbolique de sh à bash.
* `bash`, sans `-p`, ajuste `euid` pour correspondre à `ruid`, résultant en les deux étant 99 (nobody).

#### Cas 2 : Utilisation de setreuid avec system

**Code C :**
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
**Compilation et Permissions :**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

* `setreuid` définit à la fois ruid et euid à 1000.
* `system` invoque bash, qui conserve les identifiants utilisateur en raison de leur égalité, fonctionnant effectivement comme frank.

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
**Analyse :**

* `ruid` reste à 99, mais l'euid est défini à 1000, conformément à l'effet de setuid.

**Exemple de code C 2 (Appel de Bash) :**
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

* Bien que `euid` soit défini à 1000 par `setuid`, `bash` réinitialise euid à `ruid` (99) en raison de l'absence de `-p`.

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
# Références
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
