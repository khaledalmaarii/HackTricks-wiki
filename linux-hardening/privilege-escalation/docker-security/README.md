# Sécurité Docker

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=docker-security) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-security" %}

## **Sécurité de base du moteur Docker**

Le moteur Docker utilise les **espaces de noms** et les **groupes de contrôle (Cgroups)** du noyau Linux pour isoler les conteneurs, offrant une couche de sécurité de base. Une protection supplémentaire est assurée par la **suppression des capacités (Capabilities dropping)**, **Seccomp**, et **SELinux/AppArmor**, renforçant l'isolation des conteneurs. Un **plugin d'authentification** peut restreindre davantage les actions des utilisateurs.

![Sécurité Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Accès sécurisé au moteur Docker

Le moteur Docker peut être accédé localement via un socket Unix ou à distance en utilisant HTTP. Pour un accès à distance, il est essentiel d'utiliser HTTPS et **TLS** pour garantir la confidentialité, l'intégrité et l'authentification.

Le moteur Docker écoute par défaut sur le socket Unix à `unix:///var/run/docker.sock`. Sur les systèmes Ubuntu, les options de démarrage de Docker sont définies dans `/etc/default/docker`. Pour permettre l'accès à distance à l'API et au client Docker, exposez le démon Docker sur un socket HTTP en ajoutant les paramètres suivants :
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Cependant, exposer le démon Docker via HTTP n'est pas recommandé en raison de problèmes de sécurité. Il est conseillé de sécuriser les connexions en utilisant HTTPS. Il existe deux approches principales pour sécuriser la connexion :

1. Le client vérifie l'identité du serveur.
2. Le client et le serveur s'authentifient mutuellement.

Des certificats sont utilisés pour confirmer l'identité d'un serveur. Pour des exemples détaillés des deux méthodes, consultez [**ce guide**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sécurité des images de conteneurs

Les images de conteneurs peuvent être stockées dans des référentiels privés ou publics. Docker propose plusieurs options de stockage pour les images de conteneurs :

* [**Docker Hub**](https://hub.docker.com) : Un service de registre public de Docker.
* [**Docker Registry**](https://github.com/docker/distribution) : Un projet open source permettant aux utilisateurs d'héberger leur propre registre.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry) : Offre commerciale de Docker, proposant une authentification des utilisateurs basée sur les rôles et une intégration avec les services d'annuaire LDAP.

### Analyse d'images

Les conteneurs peuvent présenter des **vulnérabilités de sécurité** soit en raison de l'image de base, soit en raison du logiciel installé par-dessus l'image de base. Docker travaille sur un projet appelé **Nautilus** qui effectue une analyse de sécurité des conteneurs et répertorie les vulnérabilités. Nautilus fonctionne en comparant chaque couche d'image de conteneur avec le référentiel de vulnérabilités pour identifier les failles de sécurité.

Pour plus d'**informations, lisez ceci**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

La commande **`docker scan`** vous permet de scanner les images Docker existantes en utilisant le nom ou l'ID de l'image. Par exemple, exécutez la commande suivante pour analyser l'image hello-world :
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
trivy -q -f json <container_name>:<tag>
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

La signature des images Docker garantit la sécurité et l'intégrité des images utilisées dans les conteneurs. Voici une explication condensée :

* **Docker Content Trust** utilise le projet Notary, basé sur The Update Framework (TUF), pour gérer la signature des images. Pour plus d'informations, consultez [Notary](https://github.com/docker/notary) et [TUF](https://theupdateframework.github.io).
* Pour activer la confiance du contenu Docker, définissez `export DOCKER_CONTENT_TRUST=1`. Cette fonctionnalité est désactivée par défaut dans Docker version 1.10 et ultérieure.
* Avec cette fonctionnalité activée, seules les images signées peuvent être téléchargées. Le premier envoi d'image nécessite de définir des phrases secrètes pour les clés racine et de balisage, Docker prenant également en charge Yubikey pour une sécurité renforcée. Plus de détails peuvent être trouvés [ici](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
* Tenter de télécharger une image non signée avec la confiance du contenu activée entraîne une erreur "No trust data for latest".
* Pour les envois d'images suivants le premier, Docker demande la phrase secrète de la clé du dépôt pour signer l'image.

Pour sauvegarder vos clés privées, utilisez la commande :
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Lorsque vous passez d'un hôte Docker à un autre, il est nécessaire de déplacer les clés root et de dépôt pour maintenir les opérations.

***

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=docker-security) pour construire facilement et **automatiser les workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-security" %}

## Fonctionnalités de sécurité des conteneurs

<details>

<summary>Résumé des fonctionnalités de sécurité des conteneurs</summary>

**Principales fonctionnalités d'isolation des processus**

Dans les environnements conteneurisés, isoler les projets et leurs processus est essentiel pour la sécurité et la gestion des ressources. Voici une explication simplifiée des concepts clés :

**Espaces de noms (Namespaces)**

* **Objectif** : Assurer l'isolation des ressources telles que les processus, le réseau et les systèmes de fichiers. En particulier dans Docker, les espaces de noms maintiennent les processus d'un conteneur séparés de l'hôte et des autres conteneurs.
* **Utilisation de `unshare`** : La commande `unshare` (ou l'appel système sous-jacent) est utilisée pour créer de nouveaux espaces de noms, offrant une couche supplémentaire d'isolation. Cependant, bien que Kubernetes ne bloque pas cela de manière inhérente, Docker le fait.
* **Limitation** : La création de nouveaux espaces de noms n'autorise pas un processus à revenir aux espaces de noms par défaut de l'hôte. Pour pénétrer dans les espaces de noms de l'hôte, on aurait généralement besoin d'accéder au répertoire `/proc` de l'hôte, en utilisant `nsenter` pour entrer.

**Groupes de contrôle (CGroups)**

* **Fonction** : Principalement utilisé pour allouer des ressources entre les processus.
* **Aspect de sécurité** : Les CGroups eux-mêmes ne fournissent pas de sécurité d'isolation, sauf pour la fonction `release_agent`, qui, si mal configurée, pourrait potentiellement être exploitée pour un accès non autorisé.

**Abandon de capacité (Capability Drop)**

* **Importance** : Il s'agit d'une fonctionnalité de sécurité cruciale pour l'isolation des processus.
* **Fonctionnalité** : Il restreint les actions qu'un processus root peut effectuer en abandonnant certaines capacités. Même si un processus s'exécute avec des privilèges root, le manque des capacités nécessaires l'empêche d'exécuter des actions privilégiées, car les appels système échoueront en raison d'autorisations insuffisantes.

Ce sont les **capacités restantes** après que le processus a abandonné les autres :

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Il est activé par défaut dans Docker. Il aide à **limiter encore plus les appels système** que le processus peut appeler.\
Le **profil Seccomp par défaut de Docker** peut être trouvé dans [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker a un modèle que vous pouvez activer : [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Cela permettra de réduire les capacités, les appels système, l'accès aux fichiers et dossiers...

</details>

### Espaces de noms

Les **espaces de noms** sont une fonctionnalité du noyau Linux qui **partitionne les ressources du noyau** de telle sorte qu'un ensemble de **processus** **voit** un ensemble de **ressources** tandis qu'un **autre** ensemble de **processus** voit un **ensemble différent** de ressources. La fonctionnalité fonctionne en ayant le même espace de noms pour un ensemble de ressources et de processus, mais ces espaces de noms font référence à des ressources distinctes. Les ressources peuvent exister dans plusieurs espaces.

Docker utilise les espaces de noms du noyau Linux suivants pour atteindre l'isolation des conteneurs :

* espace de noms pid
* espace de noms de montage
* espace de noms réseau
* espace de noms ipc
* espace de noms UTS

Pour **plus d'informations sur les espaces de noms**, consultez la page suivante :

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La fonctionnalité du noyau Linux **cgroups** fournit la capacité de **restreindre les ressources telles que le CPU, la mémoire, l'E/S, la bande passante réseau parmi** un ensemble de processus. Docker permet de créer des conteneurs en utilisant la fonctionnalité cgroup qui permet le contrôle des ressources pour le conteneur spécifique.\
Voici un conteneur créé avec une mémoire d'espace utilisateur limitée à 500m, une mémoire noyau limitée à 50m, une part de CPU à 512, un poids de blkioweight à 400. La part de CPU est un ratio qui contrôle l'utilisation du CPU du conteneur. Il a une valeur par défaut de 1024 et une plage entre 0 et 1024. Si trois conteneurs ont la même part de CPU de 1024, chaque conteneur peut utiliser jusqu'à 33% du CPU en cas de contention des ressources CPU. blkio-weight est un ratio qui contrôle l'E/S du conteneur. Il a une valeur par défaut de 500 et une plage entre 10 et 1000.
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

Les capacités permettent un **contrôle plus fin des capacités pouvant être autorisées** pour l'utilisateur root. Docker utilise la fonctionnalité de capacité du noyau Linux pour **limiter les opérations pouvant être effectuées à l'intérieur d'un conteneur** indépendamment du type d'utilisateur.

Lorsqu'un conteneur Docker est exécuté, le **processus abandonne les capacités sensibles que le processus pourrait utiliser pour s'échapper de l'isolation**. Cela vise à garantir que le processus ne pourra pas effectuer d'actions sensibles et s'échapper :

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp dans Docker

Il s'agit d'une fonctionnalité de sécurité qui permet à Docker de **limiter les appels système** pouvant être utilisés à l'intérieur du conteneur :

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor dans Docker

**AppArmor** est une amélioration du noyau pour confiner les **conteneurs** à un **ensemble limité de **ressources** avec des **profils par programme** :

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux dans Docker

* **Système d'étiquetage** : SELinux attribue une étiquette unique à chaque processus et objet du système de fichiers.
* **Application des politiques** : Il applique des politiques de sécurité définissant les actions qu'une étiquette de processus peut effectuer sur d'autres étiquettes dans le système.
* **Étiquettes de processus de conteneur** : Lorsque les moteurs de conteneurs lancent des processus de conteneurs, ils se voient généralement attribuer une étiquette SELinux confinée, couramment `container_t`.
* **Étiquetage des fichiers dans les conteneurs** : Les fichiers à l'intérieur du conteneur sont généralement étiquetés `container_file_t`.
* **Règles de politique** : La politique SELinux garantit principalement que les processus avec l'étiquette `container_t` ne peuvent interagir (lire, écrire, exécuter) qu'avec des fichiers étiquetés `container_file_t`.

Ce mécanisme garantit que même si un processus à l'intérieur d'un conteneur est compromis, il est confiné pour interagir uniquement avec des objets ayant les étiquettes correspondantes, limitant ainsi considérablement les dommages potentiels de telles compromissions.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Dans Docker, un plugin d'autorisation joue un rôle crucial en matière de sécurité en décidant d'autoriser ou de bloquer les demandes au démon Docker. Cette décision est prise en examinant deux contextes clés :

* **Contexte d'authentification** : Cela inclut des informations complètes sur l'utilisateur, telles que son identité et la manière dont il s'est authentifié.
* **Contexte de commande** : Il comprend toutes les données pertinentes liées à la demande effectuée.

Ces contextes aident à garantir que seules les demandes légitimes d'utilisateurs authentifiés sont traitées, renforçant ainsi la sécurité des opérations Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS à partir d'un conteneur

Si vous ne limitez pas correctement les ressources qu'un conteneur peut utiliser, un conteneur compromis pourrait provoquer un DoS sur l'hôte où il s'exécute.

* DoS CPU
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* **Bandwidth DoS**
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Drapeaux Docker intéressants

### Drapeau --privileged

Sur la page suivante, vous pouvez apprendre **ce que signifie le drapeau `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Si vous exécutez un conteneur où un attaquant parvient à accéder en tant qu'utilisateur à faibles privilèges. Si vous avez un **binaire suid mal configuré**, l'attaquant pourrait en abuser et **escalader les privilèges à l'intérieur** du conteneur. Ce qui pourrait lui permettre de s'en échapper.

Exécuter le conteneur avec l'option **`no-new-privileges`** activée **empêchera ce type d'escalade de privilèges**.
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
Pour plus d'options **`--security-opt`** consultez : [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Autres considérations en matière de sécurité

### Gestion des secrets : Meilleures pratiques

Il est crucial d'éviter d'intégrer directement des secrets dans les images Docker ou d'utiliser des variables d'environnement, car ces méthodes exposent vos informations sensibles à toute personne ayant accès au conteneur via des commandes telles que `docker inspect` ou `exec`.

Les **volumes Docker** sont une alternative plus sûre, recommandée pour accéder à des informations sensibles. Ils peuvent être utilisés comme un système de fichiers temporaire en mémoire, atténuant les risques associés à `docker inspect` et à la journalisation. Cependant, les utilisateurs root et ceux ayant un accès `exec` au conteneur pourraient toujours accéder aux secrets.

Les **secrets Docker** offrent une méthode encore plus sécurisée pour gérer des informations sensibles. Pour les cas nécessitant des secrets lors de la phase de construction de l'image, **BuildKit** présente une solution efficace avec la prise en charge des secrets au moment de la construction, améliorant la vitesse de construction et fournissant des fonctionnalités supplémentaires.

Pour tirer parti de BuildKit, il peut être activé de trois manières :

1. Via une variable d'environnement : `export DOCKER_BUILDKIT=1`
2. En préfixant les commandes : `DOCKER_BUILDKIT=1 docker build .`
3. En l'activant par défaut dans la configuration Docker : `{ "features": { "buildkit": true } }`, suivi d'un redémarrage de Docker.

BuildKit permet l'utilisation de secrets au moment de la construction avec l'option `--secret`, garantissant que ces secrets ne sont pas inclus dans le cache de construction de l'image ou dans l'image finale, en utilisant une commande comme :
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Pour les secrets nécessaires dans un conteneur en cours d'exécution, **Docker Compose et Kubernetes** offrent des solutions robustes. Docker Compose utilise une clé `secrets` dans la définition du service pour spécifier les fichiers secrets, comme le montre un exemple de `docker-compose.yml` :
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
Cette configuration permet l'utilisation de secrets lors du démarrage des services avec Docker Compose.

Dans les environnements Kubernetes, les secrets sont nativement pris en charge et peuvent être gérés plus avant avec des outils comme [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Les contrôles d'accès basés sur les rôles (RBAC) de Kubernetes renforcent la sécurité de la gestion des secrets, de manière similaire à Docker Enterprise.

### gVisor

**gVisor** est un noyau d'application, écrit en Go, qui implémente une partie substantielle de la surface du système Linux. Il inclut un runtime de l'**Open Container Initiative (OCI)** appelé `runsc` qui fournit une **frontière d'isolation entre l'application et le noyau hôte**. Le runtime `runsc` s'intègre avec Docker et Kubernetes, facilitant l'exécution de conteneurs sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** est une communauté open source travaillant à construire un runtime de conteneur sécurisé avec des machines virtuelles légères qui se comportent et fonctionnent comme des conteneurs, mais offrent une **isolation de charge de travail plus forte en utilisant la virtualisation matérielle** comme une deuxième couche de défense.

{% embed url="https://katacontainers.io/" %}

### Conseils Résumés

* **Ne pas utiliser le drapeau `--privileged` ou monter un** [**socket Docker à l'intérieur du conteneur**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Le socket Docker permet de lancer des conteneurs, c'est donc un moyen facile de prendre le contrôle total de l'hôte, par exemple, en exécutant un autre conteneur avec le drapeau `--privileged`.
* Ne **pas exécuter en tant que root à l'intérieur du conteneur. Utiliser un** [**utilisateur différent**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **et des** [**espaces de noms utilisateur**](https://docs.docker.com/engine/security/userns-remap/)**.** Le root dans le conteneur est le même que sur l'hôte sauf s'il est remappé avec des espaces de noms utilisateur. Il est seulement légèrement restreint par, principalement, les espaces de noms Linux, les capacités et les cgroups.
* [**Abandonner toutes les capacités**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) et activer uniquement celles qui sont nécessaires** (`--cap-add=...`). Beaucoup de charges de travail n'ont pas besoin de capacités et les ajouter augmente la portée d'une attaque potentielle.
* [**Utiliser l'option de sécurité “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) pour empêcher les processus de gagner plus de privilèges, par exemple via des binaires suid.
* [**Limitez les ressources disponibles pour le conteneur**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Les limites de ressources peuvent protéger la machine contre les attaques de déni de service.
* **Ajuster les profils** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** pour restreindre les actions et les appels système disponibles pour le conteneur au minimum requis.
* **Utiliser des** [**images Docker officielles**](https://docs.docker.com/docker-hub/official\_images/) **et exiger des signatures** ou construire les vôtres basées sur elles. Ne pas hériter ou utiliser des images [compromises](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Stocker également les clés racine, les phrases secrètes dans un endroit sûr. Docker a des plans pour gérer les clés avec UCP.
* **Reconstruire régulièrement** vos images pour **appliquer les correctifs de sécurité à l'hôte et aux images.**
* Gérez vos **secrets de manière avisée** pour qu'il soit difficile pour l'attaquant d'y accéder.
* Si vous **exposez le démon Docker, utilisez HTTPS** avec une authentification client et serveur.
* Dans votre Dockerfile, **privilégiez COPY à la place de ADD**. ADD extrait automatiquement les fichiers zippés et peut copier des fichiers à partir d'URL. COPY n'a pas ces capacités. Dans la mesure du possible, évitez d'utiliser ADD pour ne pas être vulnérable aux attaques via des URL distantes et des fichiers Zip.
* Avoir des **conteneurs séparés pour chaque micro-service**
* **Ne pas mettre ssh** à l'intérieur du conteneur, “docker exec” peut être utilisé pour ssh vers le conteneur.
* Avoir des **images de conteneurs plus petites**

## Évasion / Élévation de privilèges Docker

Si vous êtes **à l'intérieur d'un conteneur Docker** ou avez accès à un utilisateur dans le **groupe docker**, vous pourriez essayer de **vous échapper et d'escalader les privilèges**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Contournement du Plugin d'Authentification Docker

Si vous avez accès au socket Docker ou avez accès à un utilisateur dans le **groupe docker mais que vos actions sont limitées par un plugin d'authentification Docker**, vérifiez si vous pouvez le **contourner:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Durcissement de Docker

* L'outil [**docker-bench-security**](https://github.com/docker/docker-bench-security) est un script qui vérifie des dizaines de bonnes pratiques courantes autour du déploiement de conteneurs Docker en production. Les tests sont tous automatisés et sont basés sur le [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Vous devez exécuter l'outil à partir de l'hôte exécutant Docker ou d'un conteneur avec suffisamment de privilèges. Découvrez **comment l'exécuter dans le README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Références

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins\_authorization](https://docs.docker.com/engine/extend/plugins\_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=docker-security) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-security" %}

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
