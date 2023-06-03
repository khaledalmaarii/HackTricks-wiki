# Sécurité Docker

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour créer facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Sécurité de base du moteur Docker**

Le moteur Docker effectue le gros du travail d'exécution et de gestion des conteneurs. Le moteur Docker utilise des fonctionnalités du noyau Linux telles que les **espaces de noms** et les **cgroups** pour fournir une **isolation de base** entre les conteneurs. Il utilise également des fonctionnalités telles que la **suppression des capacités**, **Seccomp**, **SELinux/AppArmor pour une meilleure isolation**.

Enfin, un **plugin d'authentification** peut être utilisé pour **limiter les actions** que les utilisateurs peuvent effectuer.

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Accès sécurisé au moteur Docker**

Le client Docker peut accéder au moteur Docker **localement en utilisant un socket Unix ou à distance en utilisant le mécanisme http**. Pour l'utiliser à distance, il est nécessaire d'utiliser https et **TLS** afin que la confidentialité, l'intégrité et l'authentification puissent être assurées.

Par défaut, il écoute sur le socket Unix `unix:///var/`\
`run/docker.sock` et dans les distributions Ubuntu, les options de démarrage de Docker sont spécifiées dans `/etc/default/docker`. Pour permettre à l'API et au client Docker d'accéder au moteur Docker à distance, nous devons **exposer le démon Docker en utilisant un socket http**. Cela peut être fait en :
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Exposer le démon Docker en utilisant http n'est pas une bonne pratique et il est nécessaire de sécuriser la connexion en utilisant https. Il existe deux options : la première option est pour que **le client vérifie l'identité du serveur** et la deuxième option est pour que **le client et le serveur se vérifient mutuellement leur identité**. Les certificats établissent l'identité d'un serveur. Pour un exemple des deux options, [**consultez cette page**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### **Sécurité de l'image du conteneur**

Les images de conteneurs sont stockées soit dans un référentiel privé, soit dans un référentiel public. Voici les options que Docker fournit pour stocker les images de conteneurs :

* [Docker hub](https://hub.docker.com) - Il s'agit d'un service de registre public fourni par Docker.
* [Docker registry](https://github.com/%20docker/distribution) - Il s'agit d'un projet open source que les utilisateurs peuvent utiliser pour héberger leur propre registre.
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) - Il s'agit de la mise en œuvre commerciale de Docker registry par Docker et il fournit une authentification des utilisateurs basée sur les rôles ainsi qu'une intégration de service de répertoire LDAP.

### Analyse d'image

Les conteneurs peuvent avoir des **vulnérabilités de sécurité** soit en raison de l'image de base, soit en raison du logiciel installé sur l'image de base. Docker travaille sur un projet appelé **Nautilus** qui effectue une analyse de sécurité des conteneurs et répertorie les vulnérabilités. Nautilus fonctionne en comparant chaque couche d'image de conteneur avec le référentiel de vulnérabilité pour identifier les failles de sécurité.

Pour plus d'**informations, lisez ceci** (https://docs.docker.com/engine/scan/).

#### Comment analyser les images <a href="#how-to-scan-images" id="how-to-scan-images"></a>

La commande `docker scan` vous permet d'analyser les images Docker existantes en utilisant le nom ou l'ID de l'image. Par exemple, exécutez la commande suivante pour analyser l'image hello-world :
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
### Signature de l'image Docker

Les images de conteneurs Docker peuvent être stockées dans un registre public ou privé. Il est nécessaire de **signer** les images de conteneurs pour pouvoir confirmer que les images n'ont pas été altérées. L'éditeur de contenu se charge de **signer** l'image de conteneur et de la pousser dans le registre.\
Voici quelques détails sur la confiance du contenu Docker :

* La confiance du contenu Docker est une implémentation du projet open source [Notary](https://github.com/docker/notary). Le projet open source Notary est basé sur le projet [The Update Framework (TUF)](https://theupdateframework.github.io).
* La confiance du contenu Docker est activée avec `export DOCKER_CONTENT_TRUST=1`. À partir de la version Docker 1.10, la confiance du contenu n'est **pas activée par défaut**.
* **Lorsque** la confiance du contenu est **activée**, nous ne pouvons **tirer que des images signées**. Lorsque l'image est poussée, nous devons entrer la clé de balisage.
* Lorsque l'éditeur **pousse** l'image pour la **première fois** en utilisant docker push, il est nécessaire d'entrer une **phrase secrète** pour la **clé racine et la clé de balisage**. Les autres clés sont générées automatiquement.
* Docker a également ajouté la prise en charge de clés matérielles en utilisant Yubikey et les détails sont disponibles [ici](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).

Voici l'**erreur** que nous obtenons lorsque la **confiance du contenu est activée et que l'image n'est pas signée**.
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
Le résultat suivant montre que l'image de conteneur est en cours de téléversement vers Docker Hub avec la signature activée. Comme ce n'est pas la première fois, l'utilisateur est invité à entrer uniquement la phrase secrète pour la clé de dépôt.
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
Il est nécessaire de stocker la clé racine, la clé de dépôt ainsi que la phrase secrète dans un endroit sûr. La commande suivante peut être utilisée pour sauvegarder les clés privées:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Lorsque j'ai changé d'hôte Docker, j'ai dû déplacer les clés racine et les clés de dépôt pour pouvoir opérer à partir du nouvel hôte.

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Fonctionnalités de sécurité des conteneurs

<details>

<summary>Résumé des fonctionnalités de sécurité des conteneurs</summary>

#### Namespaces

Les espaces de noms sont utiles pour isoler un projet des autres, en isolant les communications de processus, le réseau, les montages... Il est utile d'isoler le processus Docker des autres processus (et même du dossier /proc) afin qu'il ne puisse pas s'échapper en abusant d'autres processus.

Il pourrait être possible de "s'échapper" ou plus exactement **créer de nouveaux espaces de noms** en utilisant le binaire **`unshare`** (qui utilise l'appel système **`unshare`**). Docker l'empêche par défaut, mais Kubernetes ne le fait pas (au moment de la rédaction de ceci).\
De toute façon, cela est utile pour créer de nouveaux espaces de noms, mais **pas pour revenir aux espaces de noms par défaut de l'hôte** (à moins que vous n'ayez accès à certains `/proc` à l'intérieur des espaces de noms de l'hôte, où vous pourriez utiliser **`nsenter`** pour entrer dans les espaces de noms de l'hôte).

#### CGroups

Cela permet de limiter les ressources et n'affecte pas la sécurité de l'isolation du processus (sauf pour le `release_agent` qui pourrait être utilisé pour s'échapper).

#### Abandon des capacités

Je trouve que c'est l'une des fonctionnalités les plus importantes en ce qui concerne la sécurité de l'isolation des processus. Cela est dû au fait que sans les capacités, même si le processus s'exécute en tant que root, **vous ne pourrez pas effectuer certaines actions privilégiées** (car l'appel de **`syscall`** renverra une erreur de permission car le processus n'a pas les capacités nécessaires).

Voici les **capacités restantes** après que le processus a abandonné les autres :

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

#### Seccomp

Il est activé par défaut dans Docker. Il aide à **limiter encore plus les appels système** que le processus peut appeler.\
Le **profil Docker Seccomp par défaut** peut être trouvé dans [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

#### AppArmor

Docker a un modèle que vous pouvez activer: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Cela permettra de réduire les capacités, les appels système, l'accès aux fichiers et dossiers...

</details>

### Namespaces

**Les espaces de noms** sont une fonctionnalité du noyau Linux qui **partitionne les ressources du noyau** de sorte qu'un ensemble de **processus voit** un ensemble de **ressources** tandis qu'un autre ensemble de **processus** voit un **ensemble différent** de ressources. La fonctionnalité fonctionne en ayant le même espace de noms pour un ensemble de ressources et de processus, mais ces espaces de noms font référence à des ressources distinctes. Les ressources peuvent exister dans plusieurs espaces.

Docker utilise les espaces de noms du noyau Linux suivants pour atteindre l'isolation des conteneurs:

* espace de noms pid
* espace de noms de montage
* espace de noms réseau
* espace de noms ipc
* espace de noms UTS

Pour **plus d'informations sur les espaces de noms**, consultez la page suivante:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La fonctionnalité du noyau Linux **cgroups** fournit la capacité de **restreindre les ressources telles que le CPU, la mémoire, l'E / S, la bande passante réseau parmi** un ensemble de processus. Docker permet de créer des conteneurs en utilisant la fonctionnalité cgroup qui permet un contrôle des ressources pour le conteneur spécifique.\
Voici un conteneur créé avec une mémoire d'espace utilisateur limitée à 500 Mo, une mémoire de noyau limitée à 50 Mo, une part de CPU à 512, un poids de blkioweight à 400. La part de CPU est un ratio qui contrôle l'utilisation du CPU du conteneur. Il a une valeur par défaut de 1024 et une plage entre 0 et 1024. Si trois conteneurs ont la même part de CPU de 1024, chaque conteneur peut prendre jusqu'à 33% du CPU en cas de contention des ressources CPU. blkio-weight est un ratio qui contrôle l'E / S du conteneur. Il a une valeur par défaut de 500 et une plage entre 10 et 1000.
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

Les capacités permettent un **contrôle plus fin des capacités qui peuvent être autorisées** pour l'utilisateur root. Docker utilise la fonctionnalité de capacité du noyau Linux pour **limiter les opérations qui peuvent être effectuées à l'intérieur d'un conteneur** indépendamment du type d'utilisateur.

Lorsqu'un conteneur Docker est exécuté, le **processus abandonne les capacités sensibles que le processus pourrait utiliser pour s'échapper de l'isolation**. Cela tente d'assurer que le processus ne pourra pas effectuer d'actions sensibles et s'échapper :

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp dans Docker

Il s'agit d'une fonctionnalité de sécurité qui permet à Docker de **limiter les appels système** qui peuvent être utilisés à l'intérieur du conteneur :

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor dans Docker

**AppArmor** est une amélioration du noyau pour confiner les **conteneurs** à un **ensemble limité de ressources** avec des **profils par programme** :

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux dans Docker

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) est un **système d'étiquetage**. Chaque **processus** et chaque **objet de système de fichiers** a une **étiquette**. Les politiques SELinux définissent des règles sur ce qu'une **étiquette de processus est autorisée à faire avec toutes les autres étiquettes** sur le système.

Les moteurs de conteneurs lancent des **processus de conteneurs avec une seule étiquette SELinux confinée**, généralement `container_t`, puis définissent le conteneur à l'intérieur du conteneur pour être étiqueté `container_file_t`. Les règles de la politique SELinux disent essentiellement que les **processus `container_t` ne peuvent lire/écrire/exécuter que des fichiers étiquetés `container_file_t`**.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Un plugin d'autorisation **approuve** ou **refuse** les **demandes** au démon Docker en fonction du contexte **d'authentification** actuel et du contexte de **commande**. Le contexte d'**authentification** contient tous les **détails de l'utilisateur** et la **méthode d'authentification**. Le contexte de **commande** contient toutes les données de **demande** **pertinentes**.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Intéressants drapeaux Docker

### Drapeau --privileged

Sur la page suivante, vous pouvez apprendre **ce que signifie le drapeau `--privileged`** :

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Si vous exécutez un conteneur où un attaquant parvient à accéder en tant qu'utilisateur à faible privilège. Si vous avez un **binaire suid mal configuré**, l'attaquant peut l'exploiter et **escalader les privilèges à l'intérieur** du conteneur. Ce qui peut lui permettre de s'échapper.

L'exécution du conteneur avec l'option **`no-new-privileges`** activée **empêchera ce type d'escalade de privilèges**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Autre
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
Pour plus d'options **`--security-opt`**, consultez: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Autres considérations de sécurité

### Gestion des secrets

Tout d'abord, **ne les mettez pas à l'intérieur de votre image !**

De plus, **n'utilisez pas de variables d'environnement** pour vos informations sensibles. Toute personne qui peut exécuter `docker inspect` ou `exec` dans le conteneur peut trouver votre secret.

Les volumes Docker sont meilleurs. Ils sont la méthode recommandée pour accéder à vos informations sensibles dans la documentation Docker. Vous pouvez **utiliser un volume comme système de fichiers temporaire stocké en mémoire**. Les volumes éliminent le risque de `docker inspect` et de journalisation. Cependant, **les utilisateurs root pourraient toujours voir le secret, tout comme toute personne qui peut `exec` dans le conteneur**.

Mieux encore que les volumes, utilisez les secrets Docker.

Si vous avez juste besoin du **secret dans votre image**, vous pouvez utiliser **BuildKit**. BuildKit réduit considérablement le temps de construction et possède d'autres fonctionnalités intéressantes, notamment **la prise en charge des secrets au moment de la construction**.

Il existe trois façons de spécifier le backend BuildKit afin que vous puissiez utiliser ses fonctionnalités maintenant :

1. Définissez-le en tant que variable d'environnement avec `export DOCKER_BUILDKIT=1`.
2. Démarrez votre commande `build` ou `run` avec `DOCKER_BUILDKIT=1`.
3. Activez BuildKit par défaut. Définissez la configuration dans /_etc/docker/daemon.json_ sur _true_ avec : `{ "features": { "buildkit": true } }`. Puis redémarrez Docker.
4. Ensuite, vous pouvez utiliser des secrets au moment de la construction avec le drapeau `--secret` comme ceci:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Lorsque votre fichier spécifie vos secrets sous forme de paires clé-valeur.

Ces secrets sont exclus du cache de construction de l'image et de l'image finale.

Si vous avez besoin de votre **secret dans votre conteneur en cours d'exécution**, et pas seulement lors de la construction de votre image, utilisez **Docker Compose ou Kubernetes**.

Avec Docker Compose, ajoutez la paire clé-valeur des secrets à un service et spécifiez le fichier secret. Un grand merci à la réponse de [Stack Exchange](https://serverfault.com/a/936262/535325) pour le conseil sur les secrets de Docker Compose, dont l'exemple ci-dessous est adapté.

Exemple de docker-compose.yml avec des secrets:
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
Ensuite, lancez Compose comme d'habitude avec `docker-compose up --build my_service`.

Si vous utilisez [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/), il prend en charge les secrets. [Helm-Secrets](https://github.com/futuresimple/helm-secrets) peut aider à faciliter la gestion des secrets dans K8s. De plus, K8s dispose de contrôles d'accès basés sur les rôles (RBAC) - tout comme Docker Enterprise. RBAC rend la gestion des secrets plus facile et plus sécurisée pour les équipes.

### gVisor

**gVisor** est un noyau d'application, écrit en Go, qui implémente une partie substantielle de la surface du système Linux. Il inclut un runtime [Open Container Initiative (OCI)](https://www.opencontainers.org) appelé `runsc` qui fournit une **frontière d'isolation entre l'application et le noyau hôte**. Le runtime `runsc` s'intègre à Docker et Kubernetes, ce qui permet de lancer facilement des conteneurs sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** est une communauté open source qui travaille à la construction d'un runtime de conteneur sécurisé avec des machines virtuelles légères qui se comportent et fonctionnent comme des conteneurs, mais qui offrent une **isolation de charge de travail plus forte en utilisant la technologie de virtualisation matérielle** comme deuxième couche de défense.

{% embed url="https://katacontainers.io/" %}

### Conseils de résumé

* **Ne pas utiliser le drapeau `--privileged` ou monter un** [**socket Docker à l'intérieur du conteneur**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Le socket Docker permet de créer des conteneurs, il est donc facile de prendre le contrôle total de l'hôte, par exemple, en exécutant un autre conteneur avec le drapeau `--privileged`.
* Ne **pas exécuter en tant que root à l'intérieur du conteneur. Utilisez un** [**utilisateur différent**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **et des** [**espaces de noms utilisateur**](https://docs.docker.com/engine/security/userns-remap/)**.** Le root dans le conteneur est le même que sur l'hôte sauf s'il est remappé avec des espaces de noms utilisateur. Il est seulement légèrement restreint par, principalement, les espaces de noms Linux, les capacités et les cgroups.
* [**Abandonnez toutes les capacités**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) et n'activez que celles qui sont nécessaires** (`--cap-add=...`). Beaucoup de charges de travail n'ont pas besoin de capacités et leur ajout augmente la portée d'une attaque potentielle.
* [**Utilisez l'option de sécurité "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) pour empêcher les processus de gagner plus de privilèges, par exemple via des binaires suid.
* [**Limitez les ressources disponibles pour le conteneur**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Les limites de ressources peuvent protéger la machine contre les attaques de déni de service.
* **Ajustez les profils** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** pour restreindre les actions et les appels système disponibles pour le conteneur au minimum requis.
* **Utilisez des images Docker officielles** [**(https://docs.docker.com/docker-hub/official\_images/)**](https://docs.docker.com/docker-hub/official_images/) **et exigez des signatures** ou construisez les vôtres en fonction d'elles. N'héritez pas ou n'utilisez pas d'images [compromises](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Stockez également les clés racines, la phrase secrète dans un endroit sûr. Docker a prévu de gérer les clés avec UCP.
* **Reconstruisez régulièrement** vos images pour **appliquer les correctifs de sécurité à l'hôte et aux images.**
* Gérez vos **secrets avec sagesse** pour qu'il soit difficile pour l'attaquant de les accéder.
* Si vous **exposez le démon Docker, utilisez HTTPS** avec l'authentification client et serveur.
* Dans votre Dockerfile, **privilégiez COPY plutôt que ADD**. ADD extrait automatiquement les fichiers zippés et peut copier des fichiers à partir d'URL. COPY n'a pas ces capacités. Dans la mesure du possible, évitez d'utiliser ADD pour ne pas être vulnérable aux attaques via des URL distantes et des fichiers Zip.
* Avoir **des conteneurs séparés pour chaque micro-service**
* **Ne mettez pas ssh** à l'intérieur du conteneur, "docker exec" peut être utilisé pour ssh vers le conteneur.
* Avoir des images de conteneur **plus petites**

## Évasion de Docker / Élévation de privilèges

Si vous êtes **à l'intérieur d'un conteneur Docker** ou si vous avez accès à un utilisateur dans le **groupe docker**, vous pouvez essayer de **s'échapper et d'escalader les privilèges** :

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Contournement du plugin d'authentification Docker

Si vous avez accès au socket Docker ou si vous avez accès à un utilisateur dans le **groupe docker mais que vos actions sont limitées par un plugin d'authentification Docker**, vérifiez si vous pouvez **le contourner** :

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Durcissement de Docker

* L'outil [**docker-bench-security**](https://github.com/docker/docker-bench-security) est un script qui vérifie des dizaines de bonnes pratiques courantes pour le déploiement de conteneurs Docker en production. Les tests sont tous automatisés et sont basés sur le [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
  Vous
