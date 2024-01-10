# Sécurité Docker

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Sécurité de base du moteur Docker**

Le moteur Docker effectue le travail difficile de l'exécution et de la gestion des conteneurs. Le moteur Docker utilise des fonctionnalités du noyau Linux comme les **Namespaces** et les **Cgroups** pour fournir une **isolation** de base entre les conteneurs. Il utilise également des fonctionnalités comme la **réduction des capacités**, **Seccomp**, **SELinux/AppArmor pour obtenir une meilleure isolation**.

Enfin, un **plugin d'authentification** peut être utilisé pour **limiter les actions** que les utilisateurs peuvent effectuer.

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Accès sécurisé au moteur Docker**

Le client Docker peut accéder au moteur Docker **localement via un socket Unix ou à distance via un mécanisme http**. Pour l'utiliser à distance, il est nécessaire d'utiliser https et **TLS** afin que la confidentialité, l'intégrité et l'authentification puissent être assurées.

Par défaut, il écoute sur le socket Unix `unix:///var/`\
`run/docker.sock` et dans les distributions Ubuntu, les options de démarrage de Docker sont spécifiées dans `/etc/default/docker`. Pour permettre à l'API Docker et au client d'accéder au moteur Docker à distance, nous devons **exposer le démon Docker en utilisant un socket http**. Cela peut être fait en :
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Exposer le démon Docker en utilisant http n'est pas une bonne pratique et il est nécessaire de sécuriser la connexion en utilisant https. Il y a deux options : la première option est pour que **le client vérifie l'identité du serveur** et dans la seconde option **le client et le serveur vérifient mutuellement leur identité**. Les certificats établissent l'identité d'un serveur. Pour un exemple des deux options [**consultez cette page**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### **Sécurité des images de conteneurs**

Les images de conteneurs sont stockées soit dans un dépôt privé, soit dans un dépôt public. Voici les options que Docker propose pour le stockage des images de conteneurs :

* [Docker hub](https://hub.docker.com) – Il s'agit d'un service de registre public fourni par Docker.
* [Docker registry](https://github.com/%20docker/distribution) – Il s'agit d'un projet open source que les utilisateurs peuvent utiliser pour héberger leur propre registre.
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) – Il s'agit de l'implémentation commerciale par Docker du Docker registry et il offre une authentification utilisateur basée sur les rôles ainsi que l'intégration du service d'annuaire LDAP.

### Analyse d'images

Les conteneurs peuvent avoir des **vulnérabilités de sécurité** soit à cause de l'image de base, soit à cause du logiciel installé sur l'image de base. Docker travaille sur un projet appelé **Nautilus** qui effectue des analyses de sécurité des conteneurs et liste les vulnérabilités. Nautilus fonctionne en comparant chaque couche d'image de conteneur avec le dépôt de vulnérabilités pour identifier les failles de sécurité.

Pour plus [**d'informations, lisez ceci**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

La commande **`docker scan`** vous permet de scanner les images Docker existantes en utilisant le nom ou l'ID de l'image. Par exemple, exécutez la commande suivante pour scanner l'image hello-world :
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Signature des images Docker

Les images de conteneurs Docker peuvent être stockées dans un registre public ou privé. Il est nécessaire de **signer** les images de **Conteneur** pour pouvoir confirmer que les images n'ont pas été altérées. L'**éditeur** de contenu s'occupe de **signer** l'image de Conteneur et de la pousser dans le registre.\
Voici quelques détails sur la confiance de contenu Docker :

* La confiance de contenu Docker est une implémentation du [projet open source Notary](https://github.com/docker/notary). Le projet open source Notary est basé sur [le projet The Update Framework (TUF)](https://theupdateframework.github.io).
* La confiance de contenu **Docker est activée** avec `export DOCKER_CONTENT_TRUST=1`. À partir de la version 1.10 de Docker, la confiance de contenu **n'est pas activée par défaut**.
* **Lorsque** la confiance de contenu est **activée**, nous pouvons **tirer uniquement des images signées**. Lorsqu'une image est poussée, nous devons entrer une clé de balisage.
* Lorsque l'éditeur **pousse** l'image pour la **première** **fois** en utilisant docker push, il doit entrer une **phrase secrète** pour la **clé racine et la clé de balisage**. Les autres clés sont générées automatiquement.
* Docker a également ajouté le support pour les clés matérielles en utilisant Yubikey et les détails sont disponibles [ici](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).

Voici l'**erreur** que nous obtenons lorsque **la confiance de contenu est activée et que l'image n'est pas signée**.
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
La sortie suivante montre l'**image du conteneur poussée vers Docker hub avec la signature** activée. Comme ce n'est pas la première fois, l'utilisateur doit seulement entrer la phrase secrète pour la clé du dépôt.
```shell-session
$ docker push smakam/mybusybox:v2
The push refers to a repository [docker.io/smakam/mybusybox]
a7022f99b0cc: Layer already exists
5f70bf18a086: Layer already exists
9508eff2c687: Layer already exists
v2: digest: sha256:8509fa814029e1c1baf7696b36f0b273492b87f59554a33589e1bd6283557fc9 size: 2205
Signing and pushing trust metadata
Enter passphrase for repository key with ID 001986b (docker.io/smakam/mybusybox):
```
Il est nécessaire de stocker la clé root, la clé du dépôt ainsi que la phrase secrète dans un endroit sûr. La commande suivante peut être utilisée pour sauvegarder les clés privées :
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Lorsque j'ai changé d'hôte Docker, j'ai dû déplacer les clés racines et les clés de dépôt pour opérer depuis le nouvel hôte.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des flux de travail** alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Fonctionnalités de sécurité des conteneurs

<details>

<summary>Résumé des fonctionnalités de sécurité des conteneurs</summary>

**Namespaces**

Les namespaces sont utiles pour isoler un projet des autres, isolant les communications de processus, le réseau, les montages... C'est utile pour isoler le processus docker des autres processus (et même du dossier /proc) afin qu'il ne puisse pas s'échapper en abusant d'autres processus.

Il pourrait être possible de "s'échapper" ou plus exactement **créer de nouveaux namespaces** en utilisant le binaire **`unshare`** (qui utilise l'appel système **`unshare`**). Docker par défaut l'empêche, mais Kubernetes ne le fait pas (au moment de la rédaction de ce document).\
Cependant, cela est utile pour créer de nouveaux namespaces, mais **pas pour revenir aux namespaces par défaut de l'hôte** (à moins que vous n'ayez accès à certains `/proc` à l'intérieur des namespaces de l'hôte, où vous pourriez utiliser **`nsenter`** pour entrer dans les namespaces de l'hôte).

**CGroups**

Cela permet de limiter les ressources et n'affecte pas la sécurité de l'isolation du processus (sauf pour le `release_agent` qui pourrait être utilisé pour s'échapper).

**Suppression des capacités**

Je trouve que c'est l'une des fonctionnalités **les plus importantes** en ce qui concerne la sécurité de l'isolation des processus. C'est parce que sans les capacités, même si le processus s'exécute en tant que root **vous ne pourrez pas effectuer certaines actions privilégiées** (car l'appel système **`syscall`** renverra une erreur de permission parce que le processus n'a pas les capacités nécessaires).

Voici les **capacités restantes** après que le processus ait abandonné les autres :

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Il est activé par défaut dans Docker. Il aide à **limiter encore plus les appels systèmes** que le processus peut effectuer.\
Le **profil Seccomp par défaut de Docker** peut être trouvé ici : [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker dispose d'un modèle que vous pouvez activer : [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Cela permettra de réduire les capacités, les appels systèmes, l'accès aux fichiers et dossiers...

</details>

### Namespaces

Les **Namespaces** sont une fonctionnalité du noyau Linux qui **partitionne les ressources du noyau** de sorte qu'un ensemble de **processus** **voit** un ensemble de **ressources**, tandis qu'un **autre** ensemble de **processus** voit un **ensemble différent** de ressources. La fonctionnalité fonctionne en ayant le même espace de noms pour un ensemble de ressources et de processus, mais ces espaces de noms se réfèrent à des ressources distinctes. Les ressources peuvent exister dans plusieurs espaces.

Docker utilise les Namespaces du noyau Linux suivants pour réaliser l'isolation des conteneurs :

* espace de noms pid
* espace de noms de montage
* espace de noms réseau
* espace de noms ipc
* espace de noms UTS

Pour **plus d'informations sur les namespaces**, consultez la page suivante :

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La fonctionnalité du noyau Linux **cgroups** fournit la capacité de **restreindre des ressources telles que le cpu, la mémoire, les entrées/sorties, la bande passante réseau** parmi un ensemble de processus. Docker permet de créer des conteneurs en utilisant la fonctionnalité cgroup, ce qui permet de contrôler les ressources pour le conteneur spécifique.\
Voici un conteneur créé avec une mémoire utilisateur limitée à 500m, une mémoire noyau limitée à 50m, un partage de cpu à 512, un blkioweight à 400. Le partage de CPU est un ratio qui contrôle l'utilisation du CPU du conteneur. Il a une valeur par défaut de 1024 et varie entre 0 et 1024. Si trois conteneurs ont le même partage de CPU de 1024, chaque conteneur peut prendre jusqu'à 33 % du CPU en cas de contention de ressources CPU. blkio-weight est un ratio qui contrôle les entrées/sorties du conteneur. Il a une valeur par défaut de 500 et varie entre 10 et 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Pour obtenir le cgroup d'un conteneur, vous pouvez faire :
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Pour plus d'informations, consultez :

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacités

Les capacités permettent un **contrôle plus précis des capacités qui peuvent être autorisées** pour l'utilisateur root. Docker utilise la fonctionnalité de capacité du noyau Linux pour **limiter les opérations qui peuvent être effectuées à l'intérieur d'un Conteneur**, quel que soit le type d'utilisateur.

Lorsqu'un conteneur docker est exécuté, le **processus abandonne les capacités sensibles que le processus pourrait utiliser pour s'échapper de l'isolation**. Cela essaie d'assurer que le processus ne pourra pas effectuer d'actions sensibles et s'échapper :

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp dans Docker

Il s'agit d'une fonctionnalité de sécurité qui permet à Docker de **limiter les appels système** qui peuvent être utilisés à l'intérieur du conteneur :

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor dans Docker

**AppArmor** est une amélioration du noyau pour confiner les **conteneurs** à un ensemble **limité** de **ressources** avec des **profils par programme** :

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux dans Docker

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) est un **système d'étiquetage**. Chaque **processus** et chaque objet du **système de fichiers** a une **étiquette**. Les politiques SELinux définissent des règles sur ce qu'une **étiquette de processus est autorisée à faire avec toutes les autres étiquettes** sur le système.

Les moteurs de conteneurs lancent les **processus de conteneurs avec une seule étiquette SELinux confinée**, généralement `container_t`, puis définissent l'intérieur du conteneur pour être étiqueté `container_file_t`. Les règles de politique SELinux disent essentiellement que les processus **`container_t` ne peuvent lire/écrire/exécuter que des fichiers étiquetés `container_file_t`**.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Un plugin d'autorisation **approuve** ou **refuse** les **requêtes** au **démon** Docker en fonction à la fois du contexte d'**authentification** actuel et du contexte de **commande**. Le contexte d'**authentification** contient tous les **détails de l'utilisateur** et la **méthode d'authentification**. Le contexte de **commande** contient toutes les données de **requête pertinentes**.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS depuis un conteneur

Si vous ne limitez pas correctement les ressources qu'un conteneur peut utiliser, un conteneur compromis pourrait réaliser un DoS sur l'hôte où il s'exécute.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandwidth DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Drapeaux Docker intéressants

### drapeau --privileged

Dans la page suivante, vous pouvez apprendre **ce que le drapeau `--privileged` implique** :

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Si vous exécutez un conteneur où un attaquant parvient à obtenir un accès en tant qu'utilisateur à faibles privilèges. Si vous avez un **binaire suid mal configuré**, l'attaquant peut en abuser et **escalader les privilèges à l'intérieur** du conteneur. Ce qui peut lui permettre de s'en échapper.

Exécuter le conteneur avec l'option **`no-new-privileges`** activée va **empêcher ce type d'escalade de privilèges**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Autres
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Pour plus d'options **`--security-opt`**, consultez : [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Autres considérations de sécurité

### Gestion des secrets

Tout d'abord, **ne les mettez pas dans votre image !**

De plus, **n'utilisez pas de variables d'environnement** pour vos informations sensibles. Quiconque peut exécuter `docker inspect` ou `exec` dans le conteneur peut trouver votre secret.

Les volumes Docker sont préférables. Ils sont le moyen recommandé d'accéder à vos informations sensibles dans la documentation Docker. Vous pouvez **utiliser un volume comme système de fichiers temporaire en mémoire**. Les volumes éliminent le risque lié à `docker inspect` et aux journaux. Cependant, **les utilisateurs root pourraient toujours voir le secret, tout comme quiconque peut `exec` dans le conteneur**.

Mieux que les volumes, utilisez **Docker secrets**.

Si vous avez juste besoin du **secret dans votre image**, vous pouvez utiliser **BuildKit**. BuildKit réduit considérablement le temps de construction et offre d'autres fonctionnalités intéressantes, y compris le **support des secrets au moment de la construction**.

Il y a trois façons de spécifier le backend BuildKit pour que vous puissiez utiliser ses fonctionnalités dès maintenant :

1. Définissez-le comme une variable d'environnement avec `export DOCKER_BUILDKIT=1`.
2. Commencez votre commande `build` ou `run` avec `DOCKER_BUILDKIT=1`.
3. Activez BuildKit par défaut. Définissez la configuration dans /_etc/docker/daemon.json_ sur _true_ avec : `{ "features": { "buildkit": true } }`. Puis redémarrez Docker.
4. Ensuite, vous pouvez utiliser les secrets au moment de la construction avec l'option `--secret` comme ceci :
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Là où votre fichier spécifie vos secrets sous forme de paires clé-valeur.

Ces secrets sont exclus du cache de construction de l'image et de l'image finale.

Si vous avez besoin de votre **secret dans votre conteneur en cours d'exécution**, et pas seulement lors de la construction de votre image, utilisez **Docker Compose ou Kubernetes**.

Avec Docker Compose, ajoutez la paire clé-valeur des secrets à un service et spécifiez le fichier secret. Chapeau bas à la [réponse de Stack Exchange](https://serverfault.com/a/936262/535325) pour l'astuce sur les secrets Docker Compose dont l'exemple ci-dessous est adapté.

Exemple de `docker-compose.yml` avec secrets :
```yaml
version: "3.7"

services:

my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret

secrets:
my_secret:
file: ./my_secret_file.txt
```
```markdown
Ensuite, démarrez Compose comme d'habitude avec `docker-compose up --build my_service`.

Si vous utilisez [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/), il prend en charge les secrets. [Helm-Secrets](https://github.com/futuresimple/helm-secrets) peut aider à simplifier la gestion des secrets dans K8s. De plus, K8s dispose de contrôles d'accès basés sur les rôles (RBAC) - tout comme Docker Enterprise. RBAC rend la gestion des Secrets plus gérable et plus sécurisée pour les équipes.

### gVisor

**gVisor** est un noyau d'application, écrit en Go, qui implémente une grande partie de la surface du système Linux. Il comprend un runtime [Open Container Initiative (OCI)](https://www.opencontainers.org) appelé `runsc` qui fournit une **frontière d'isolation entre l'application et le noyau hôte**. Le runtime `runsc` s'intègre avec Docker et Kubernetes, ce qui simplifie l'exécution de conteneurs sandboxés.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** est une communauté open source qui travaille à construire un runtime de conteneurs sécurisé avec des machines virtuelles légères qui se comportent et fonctionnent comme des conteneurs, mais offrent une **isolation des charges de travail plus forte en utilisant la technologie de virtualisation matérielle** comme seconde couche de défense.

{% embed url="https://katacontainers.io/" %}

### Conseils Résumés

* **N'utilisez pas le drapeau `--privileged` ou ne montez pas un** [**socket Docker à l'intérieur du conteneur**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Le socket Docker permet de générer des conteneurs, c'est donc un moyen facile de prendre le contrôle total de l'hôte, par exemple, en exécutant un autre conteneur avec le drapeau `--privileged`.
* **Ne fonctionnez pas en tant que root à l'intérieur du conteneur. Utilisez un** [**autre utilisateur**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **et** [**espaces de noms d'utilisateur**](https://docs.docker.com/engine/security/userns-remap/)**.** Le root dans le conteneur est le même que sur l'hôte à moins d'être remappé avec des espaces de noms d'utilisateur. Il est seulement légèrement restreint par, principalement, les espaces de noms Linux, les capacités et les cgroups.
* [**Supprimez toutes les capacités**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) et activez uniquement celles qui sont requises** (`--cap-add=...`). Beaucoup de charges de travail n'ont besoin d'aucune capacité et en ajouter augmente la portée d'une attaque potentielle.
* [**Utilisez l'option de sécurité "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) pour empêcher les processus d'acquérir plus de privilèges, par exemple via des binaires suid.
* [**Limitez les ressources disponibles pour le conteneur**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Les limites de ressources peuvent protéger la machine contre les attaques par déni de service.
* **Ajustez** [**les profils seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** pour restreindre les actions et appels système disponibles pour le conteneur au minimum requis.
* **Utilisez** [**des images docker officielles**](https://docs.docker.com/docker-hub/official_images/) **et exigez des signatures** ou construisez les vôtres sur leur base. N'héritez pas ou n'utilisez pas d'images [compromises](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Stockez également les clés racines, les phrases secrètes dans un endroit sûr. Docker a des plans pour gérer les clés avec UCP.
* **Reconstruisez régulièrement** vos images pour **appliquer les correctifs de sécurité à l'hôte et aux images.**
* Gérez vos **secrets judicieusement** pour qu'il soit difficile à l'attaquant d'y accéder.
* Si vous **exposez le démon docker, utilisez HTTPS** avec authentification client et serveur.
* Dans votre Dockerfile, **préférez COPY au lieu de ADD**. ADD extrait automatiquement les fichiers compressés et peut copier des fichiers depuis des URL. COPY n'a pas ces capacités. Autant que possible, évitez d'utiliser ADD pour ne pas être vulnérable aux attaques via des URL distantes et des fichiers Zip.
* Ayez **des conteneurs séparés pour chaque micro-service**
* **N'intégrez pas ssh** à l'intérieur du conteneur, "docker exec" peut être utilisé pour se connecter au conteneur.
* Ayez des **images de conteneur plus petites**

## Évasion de Docker / Élévation de Privilèges

Si vous êtes **à l'intérieur d'un conteneur docker** ou si vous avez accès à un utilisateur dans le **groupe docker**, vous pourriez essayer de **vous échapper et d'augmenter vos privilèges** :

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Contournement du Plugin d'Authentification Docker

Si vous avez accès au socket docker ou à un utilisateur dans le **groupe docker mais que vos actions sont limitées par un plugin d'authentification docker**, vérifiez si vous pouvez **le contourner :**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Renforcement de Docker

* L'outil [**docker-bench-security**](https://github.com/docker/docker-bench-security) est un script qui vérifie des dizaines de bonnes pratiques courantes pour le déploiement de conteneurs Docker en production. Les tests sont tous automatisés et sont basés sur le [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Vous devez exécuter l'outil depuis l'hôte exécutant docker ou depuis un conteneur avec suffisamment de privilèges. Découvrez **comment l'exécuter dans le README :** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Références

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
