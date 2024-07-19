# macOS Injection de Thread via le port de tâche

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Détournement de Thread

Initialement, la fonction **`task_threads()`** est invoquée sur le port de tâche pour obtenir une liste de threads de la tâche distante. Un thread est sélectionné pour le détournement. Cette approche diverge des méthodes d'injection de code conventionnelles, car la création d'un nouveau thread distant est interdite en raison de la nouvelle atténuation bloquant `thread_create_running()`.

Pour contrôler le thread, **`thread_suspend()`** est appelé, arrêtant son exécution.

Les seules opérations autorisées sur le thread distant impliquent **l'arrêt** et **le démarrage** de celui-ci, **la récupération** et **la modification** de ses valeurs de registre. Les appels de fonction distants sont initiés en définissant les registres `x0` à `x7` sur les **arguments**, configurant **`pc`** pour cibler la fonction souhaitée, et en activant le thread. S'assurer que le thread ne plante pas après le retour nécessite de détecter le retour.

Une stratégie consiste à **enregistrer un gestionnaire d'exception** pour le thread distant en utilisant `thread_set_exception_ports()`, en définissant le registre `lr` sur une adresse invalide avant l'appel de fonction. Cela déclenche une exception après l'exécution de la fonction, envoyant un message au port d'exception, permettant l'inspection de l'état du thread pour récupérer la valeur de retour. Alternativement, comme adopté de l'exploit triple\_fetch d'Ian Beer, `lr` est défini pour boucler indéfiniment. Les registres du thread sont ensuite continuellement surveillés jusqu'à ce que **`pc` pointe vers cette instruction**.

## 2. Ports Mach pour la communication

La phase suivante consiste à établir des ports Mach pour faciliter la communication avec le thread distant. Ces ports sont essentiels pour transférer des droits d'envoi et de réception arbitraires entre les tâches.

Pour une communication bidirectionnelle, deux droits de réception Mach sont créés : un dans la tâche locale et l'autre dans la tâche distante. Ensuite, un droit d'envoi pour chaque port est transféré à la tâche correspondante, permettant l'échange de messages.

En se concentrant sur le port local, le droit de réception est détenu par la tâche locale. Le port est créé avec `mach_port_allocate()`. Le défi réside dans le transfert d'un droit d'envoi vers ce port dans la tâche distante.

Une stratégie consiste à tirer parti de `thread_set_special_port()` pour placer un droit d'envoi vers le port local dans le `THREAD_KERNEL_PORT` du thread distant. Ensuite, le thread distant est instruit d'appeler `mach_thread_self()` pour récupérer le droit d'envoi.

Pour le port distant, le processus est essentiellement inversé. Le thread distant est dirigé pour générer un port Mach via `mach_reply_port()` (car `mach_port_allocate()` n'est pas adapté en raison de son mécanisme de retour). Une fois le port créé, `mach_port_insert_right()` est invoqué dans le thread distant pour établir un droit d'envoi. Ce droit est ensuite stocké dans le noyau en utilisant `thread_set_special_port()`. De retour dans la tâche locale, `thread_get_special_port()` est utilisé sur le thread distant pour acquérir un droit d'envoi vers le nouveau port Mach alloué dans la tâche distante.

L'achèvement de ces étapes aboutit à l'établissement de ports Mach, posant les bases d'une communication bidirectionnelle.

## 3. Primitives de lecture/écriture mémoire de base

Dans cette section, l'accent est mis sur l'utilisation de la primitive d'exécution pour établir des primitives de lecture et d'écriture mémoire de base. Ces étapes initiales sont cruciales pour obtenir plus de contrôle sur le processus distant, bien que les primitives à ce stade ne serviront pas à beaucoup de choses. Bientôt, elles seront mises à niveau vers des versions plus avancées.

### Lecture et écriture de mémoire en utilisant la primitive d'exécution

L'objectif est d'effectuer des lectures et des écritures de mémoire en utilisant des fonctions spécifiques. Pour lire la mémoire, des fonctions ressemblant à la structure suivante sont utilisées :
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Et pour écrire dans la mémoire, des fonctions similaires à cette structure sont utilisées :
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Ces fonctions correspondent aux instructions d'assemblage données :
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifier des Fonctions Appropriées

Un scan des bibliothèques courantes a révélé des candidats appropriés pour ces opérations :

1. **Lecture de la Mémoire :**
La fonction `property_getName()` de la [bibliothèque d'exécution Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) est identifiée comme une fonction appropriée pour lire la mémoire. La fonction est décrite ci-dessous :
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Cette fonction agit effectivement comme le `read_func` en retournant le premier champ de `objc_property_t`.

2. **Écriture en mémoire :**  
Trouver une fonction préconstruite pour écrire en mémoire est plus difficile. Cependant, la fonction `_xpc_int64_set_value()` de libxpc est un candidat approprié avec le désassemblage suivant :
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Pour effectuer une écriture 64 bits à une adresse spécifique, l'appel distant est structuré comme suit :
```c
_xpc_int64_set_value(address - 0x18, value)
```
Avec ces primitives établies, la scène est prête pour créer de la mémoire partagée, marquant une progression significative dans le contrôle du processus distant.

## 4. Configuration de la mémoire partagée

L'objectif est d'établir une mémoire partagée entre les tâches locales et distantes, simplifiant le transfert de données et facilitant l'appel de fonctions avec plusieurs arguments. L'approche consiste à tirer parti de `libxpc` et de son type d'objet `OS_xpc_shmem`, qui est construit sur des entrées de mémoire Mach.

### Aperçu du processus :

1. **Allocation de mémoire** :
- Allouer la mémoire pour le partage en utilisant `mach_vm_allocate()`.
- Utiliser `xpc_shmem_create()` pour créer un objet `OS_xpc_shmem` pour la région de mémoire allouée. Cette fonction gérera la création de l'entrée de mémoire Mach et stockera le droit d'envoi Mach à l'offset `0x18` de l'objet `OS_xpc_shmem`.

2. **Création de la mémoire partagée dans le processus distant** :
- Allouer de la mémoire pour l'objet `OS_xpc_shmem` dans le processus distant avec un appel distant à `malloc()`.
- Copier le contenu de l'objet local `OS_xpc_shmem` vers le processus distant. Cependant, cette copie initiale aura des noms d'entrées de mémoire Mach incorrects à l'offset `0x18`.

3. **Correction de l'entrée de mémoire Mach** :
- Utiliser la méthode `thread_set_special_port()` pour insérer un droit d'envoi pour l'entrée de mémoire Mach dans la tâche distante.
- Corriger le champ d'entrée de mémoire Mach à l'offset `0x18` en le remplaçant par le nom de l'entrée de mémoire distante.

4. **Finalisation de la configuration de la mémoire partagée** :
- Valider l'objet `OS_xpc_shmem` distant.
- Établir la cartographie de la mémoire partagée avec un appel distant à `xpc_shmem_remote()`.

En suivant ces étapes, la mémoire partagée entre les tâches locales et distantes sera efficacement configurée, permettant des transferts de données simples et l'exécution de fonctions nécessitant plusieurs arguments.

## Extraits de code supplémentaires

Pour l'allocation de mémoire et la création d'objets de mémoire partagée :
```c
mach_vm_allocate();
xpc_shmem_create();
```
Pour créer et corriger l'objet de mémoire partagée dans le processus distant :
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
N'oubliez pas de gérer correctement les détails des ports Mach et des noms d'entrée de mémoire pour garantir que la configuration de la mémoire partagée fonctionne correctement.

## 5. Obtenir un Contrôle Complet

Après avoir établi avec succès la mémoire partagée et acquis des capacités d'exécution arbitraire, nous avons essentiellement obtenu un contrôle total sur le processus cible. Les fonctionnalités clés permettant ce contrôle sont :

1. **Opérations de Mémoire Arbitraires** :
- Effectuer des lectures de mémoire arbitraires en invoquant `memcpy()` pour copier des données de la région partagée.
- Exécuter des écritures de mémoire arbitraires en utilisant `memcpy()` pour transférer des données vers la région partagée.

2. **Gestion des Appels de Fonction avec Plusieurs Arguments** :
- Pour les fonctions nécessitant plus de 8 arguments, disposer les arguments supplémentaires sur la pile conformément à la convention d'appel.

3. **Transfert de Port Mach** :
- Transférer des ports Mach entre les tâches via des messages Mach par le biais de ports préalablement établis.

4. **Transfert de Descripteurs de Fichier** :
- Transférer des descripteurs de fichier entre les processus en utilisant des fileports, une technique mise en avant par Ian Beer dans `triple_fetch`.

Ce contrôle complet est encapsulé dans la bibliothèque [threadexec](https://github.com/bazad/threadexec), fournissant une mise en œuvre détaillée et une API conviviale pour interagir avec le processus victime.

## Considérations Importantes :

- Assurez-vous d'utiliser correctement `memcpy()` pour les opérations de lecture/écriture en mémoire afin de maintenir la stabilité du système et l'intégrité des données.
- Lors du transfert de ports Mach ou de descripteurs de fichier, suivez les protocoles appropriés et gérez les ressources de manière responsable pour éviter les fuites ou les accès non intentionnels.

En respectant ces directives et en utilisant la bibliothèque `threadexec`, on peut gérer et interagir efficacement avec les processus à un niveau granulaire, obtenant ainsi un contrôle total sur le processus cible.

## Références
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
