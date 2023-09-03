# Sécurité Docker

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des flux de travail** avec les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


## **Sécurité de base du moteur Docker**

Le moteur Docker effectue le gros du travail d'exécution et de gestion des conteneurs. Le moteur Docker utilise des fonctionnalités du noyau Linux telles que les **espaces de noms** et les **groupes de contrôle** pour fournir une **isolation de base** entre les conteneurs. Il utilise également des fonctionnalités telles que la **réduction des capacités**, **Seccomp**, **SELinux/AppArmor pour une meilleure isolation**.

Enfin, un **plugin d'authentification** peut être utilisé pour **limiter les actions** que les utilisateurs peuvent effectuer.

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Accès sécurisé au moteur Docker**

Le client Docker peut accéder au moteur Docker **en local en utilisant un socket Unix ou à distance en utilisant le mécanisme http**. Pour l'utiliser à distance, il est nécessaire d'utiliser https et **TLS** afin de garantir la confidentialité, l'intégrité et l'authentification.

Par défaut, il écoute sur le socket Unix `unix:///var/`\
`run/docker.sock` et dans les distributions Ubuntu, les options de démarrage de Docker sont spécifiées dans `/etc/default/docker`. Pour permettre à l'API Docker et au client d'accéder au moteur Docker à distance, nous devons **exposer le démon Docker en utilisant un socket http**. Cela peut être fait en :
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Exposer le démon Docker en utilisant http n'est pas une bonne pratique et il est nécessaire de sécuriser la connexion en utilisant https. Il existe deux options : la première option est pour **le client de vérifier l'identité du serveur** et la deuxième option est que **le client et le serveur se vérifient mutuellement**. Les certificats établissent l'identité d'un serveur. Pour un exemple des deux options, [**consultez cette page**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### **Sécurité des images de conteneurs**

Les images de conteneurs sont stockées soit dans un référentiel privé, soit dans un référentiel public. Voici les options que Docker propose pour stocker les images de conteneurs :

* [Docker hub](https://hub.docker.com) - Il s'agit d'un service de registre public fourni par Docker.
* [Docker registry](https://github.com/%20docker/distribution) - Il s'agit d'un projet open source que les utilisateurs peuvent utiliser pour héberger leur propre registre.
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) - Il s'agit de la mise en œuvre commerciale de Docker du registre Docker et il offre une authentification des utilisateurs basée sur les rôles ainsi qu'une intégration avec le service d'annuaire LDAP.

### Analyse des images

Les conteneurs peuvent présenter des **vulnérabilités de sécurité** soit en raison de l'image de base, soit en raison des logiciels installés par-dessus l'image de base. Docker travaille sur un projet appelé **Nautilus** qui effectue une analyse de sécurité des conteneurs et répertorie les vulnérabilités. Nautilus fonctionne en comparant chaque couche d'image de conteneur avec un référentiel de vulnérabilités pour identifier les failles de sécurité.

Pour plus d'**informations, lisez ceci** (https://docs.docker.com/engine/scan/).

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

Les images de conteneurs Docker peuvent être stockées soit dans un registre public, soit dans un registre privé. Il est nécessaire de **signer** les images de conteneurs afin de pouvoir confirmer qu'elles n'ont pas été altérées. L'éditeur de contenu se charge de **signer** l'image du conteneur et de la pousser dans le registre.\
Voici quelques détails sur la confiance du contenu Docker :

- La confiance du contenu Docker est une implémentation du projet open source [Notary](https://github.com/docker/notary). Le projet open source Notary est basé sur le projet [The Update Framework (TUF)](https://theupdateframework.github.io).
- La confiance du contenu Docker est activée avec `export DOCKER_CONTENT_TRUST=1`. À partir de la version 1.10 de Docker, la confiance du contenu n'est **pas activée par défaut**.
- Lorsque la confiance du contenu est activée, nous ne pouvons **tirer que des images signées**. Lorsque l'image est poussée, nous devons entrer une clé de balisage.
- Lorsque l'éditeur pousse l'image pour la **première fois** en utilisant `docker push`, il est nécessaire d'entrer une **phrase secrète** pour la **clé racine et la clé de balisage**. Les autres clés sont générées automatiquement.
- Docker a également ajouté la prise en charge de clés matérielles en utilisant Yubikey et les détails sont disponibles [ici](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).

Voici l'**erreur** que nous obtenons lorsque la **confiance du contenu est activée et que l'image n'est pas signée**.
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
Le résultat suivant montre que l'image du conteneur est en cours de téléversement vers Docker Hub avec la signature activée. Comme ce n'est pas la première fois, l'utilisateur est invité à entrer uniquement la phrase secrète pour la clé du référentiel.
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
Lorsque j'ai changé d'hôte Docker, j'ai dû déplacer les clés root et les clés de dépôt pour pouvoir opérer à partir du nouvel hôte.

***

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Fonctionnalités de sécurité des conteneurs

<details>

<summary>Résumé des fonctionnalités de sécurité des conteneurs</summary>

**Namespaces**

Les namespaces sont utiles pour isoler un projet des autres, en isolant les communications entre les processus, le réseau, les montages... C'est utile pour isoler le processus Docker des autres processus (et même du dossier /proc) afin qu'il ne puisse pas s'échapper en abusant d'autres processus.

Il serait possible de "s'échapper" ou plus précisément **créer de nouveaux namespaces** en utilisant l'exécutable **`unshare`** (qui utilise l'appel système **`unshare`**). Docker l'empêche par défaut, mais Kubernetes ne le fait pas (au moment de la rédaction de ceci).\
Quoi qu'il en soit, cela est utile pour créer de nouveaux namespaces, mais **pas pour revenir aux namespaces par défaut de l'hôte** (à moins d'avoir accès à certains `/proc` à l'intérieur des namespaces de l'hôte, où vous pourriez utiliser **`nsenter`** pour entrer dans les namespaces de l'hôte).

**CGroups**

Cela permet de limiter les ressources et n'affecte pas la sécurité de l'isolation du processus (à l'exception de `release_agent` qui pourrait être utilisé pour s'échapper).

**Abandon des capacités**

Je trouve que c'est l'une des fonctionnalités les plus importantes en ce qui concerne la sécurité de l'isolation des processus. Cela est dû au fait que sans les capacités, même si le processus s'exécute en tant que root, **vous ne pourrez pas effectuer certaines actions privilégiées** (car l'appel **`syscall`** renverra une erreur de permission car le processus n'a pas les capacités nécessaires).

Voici les **capacités restantes** après que le processus a abandonné les autres :

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Il est activé par défaut dans Docker. Il aide à **limiter encore plus les appels système** que le processus peut effectuer.\
Le **profil Seccomp par défaut de Docker** peut être trouvé à l'adresse [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker dispose d'un modèle que vous pouvez activer : [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Cela permettra de réduire les capacités, les appels système, l'accès aux fichiers et aux dossiers...

</details>

### Namespaces

Les **espaces de noms** sont une fonctionnalité du noyau Linux qui **partitionne les ressources du noyau** de telle sorte qu'un ensemble de **processus** voit un ensemble de **ressources** tandis qu'un autre ensemble de **processus** voit un **ensemble différent** de ressources. La fonctionnalité fonctionne en ayant le même espace de noms pour un ensemble de ressources et de processus, mais ces espaces de noms font référence à des ressources distinctes. Les ressources peuvent exister dans plusieurs espaces.

Docker utilise les espaces de noms du noyau Linux suivants pour assurer l'isolation des conteneurs :

* espace de noms pid
* espace de noms mount
* espace de noms réseau
* espace de noms ipc
* espace de noms UTS

Pour **plus d'informations sur les espaces de noms**, consultez la page suivante :

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La fonctionnalité du noyau Linux appelée **cgroups** permet de **restreindre les ressources telles que le CPU, la mémoire, l'E/S, la bande passante réseau** pour un ensemble de processus. Docker permet de créer des conteneurs en utilisant la fonctionnalité cgroups, ce qui permet de contrôler les ressources spécifiques du conteneur.\
Voici un exemple de création d'un conteneur avec une limite de mémoire de 500 Mo pour l'espace utilisateur, une limite de mémoire du noyau de 50 Mo, une part de CPU de 512 et un poids de blkioweight de 400. La part de CPU est un ratio qui contrôle l'utilisation du CPU par le conteneur. Sa valeur par défaut est de 1024 et sa plage va de 0 à 1024. Si trois conteneurs ont la même part de CPU de 1024, chaque conteneur peut utiliser jusqu'à 33% du CPU en cas de conflit de ressources CPU. Le poids de blkioweight est un ratio qui contrôle l'E/S du conteneur. Sa valeur par défaut est de 500 et sa plage va de 10 à 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Pour obtenir le cgroup d'un conteneur, vous pouvez faire :
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Pour plus d'informations, consultez:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacités

Les capacités permettent un **contrôle plus précis des capacités autorisées** pour l'utilisateur root. Docker utilise la fonctionnalité de capacité du noyau Linux pour **limiter les opérations pouvant être effectuées à l'intérieur d'un conteneur**, indépendamment du type d'utilisateur.

Lorsqu'un conteneur Docker est exécuté, le **processus abandonne les capacités sensibles que le processus pourrait utiliser pour échapper à l'isolation**. Cela vise à garantir que le processus ne pourra pas effectuer d'actions sensibles et s'échapper :

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp dans Docker

Il s'agit d'une fonctionnalité de sécurité qui permet à Docker de **limiter les appels système** pouvant être utilisés à l'intérieur du conteneur :

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor dans Docker

**AppArmor** est une amélioration du noyau permettant de confiner les **conteneurs** à un **ensemble limité de ressources** avec des **profils par programme** :

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux dans Docker

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) est un **système d'étiquetage**. Chaque **processus** et chaque **objet de système de fichiers** possède une **étiquette**. Les politiques SELinux définissent des règles sur ce qu'une **étiquette de processus est autorisée à faire avec toutes les autres étiquettes** du système.

Les moteurs de conteneur lancent des **processus de conteneur avec une seule étiquette SELinux confinée**, généralement `container_t`, puis définissent le conteneur à l'intérieur du conteneur avec l'étiquette `container_file_t`. Les règles de la politique SELinux disent essentiellement que les **processus `container_t` ne peuvent lire/écrire/exécuter que des fichiers étiquetés `container_file_t`**.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Un plugin d'autorisation **approuve** ou **refuse** les **demandes** au démon Docker en fonction du **contexte d'authentification** actuel et du **contexte de commande**. Le **contexte d'authentification** contient tous les **détails de l'utilisateur** et la **méthode d'authentification**. Le **contexte de commande** contient toutes les **données de demande** pertinentes.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS à partir d'un conteneur

Si vous ne limitez pas correctement les ressources qu'un conteneur peut utiliser, un conteneur compromis pourrait provoquer un déni de service (DoS) sur l'hôte où il s'exécute.

* DoS du CPU
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bande passante DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Intéressants drapeaux Docker

### Drapeau --privileged

Sur la page suivante, vous pouvez apprendre **ce que signifie le drapeau `--privileged`**:

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

---

##### Docker Security

##### Sécurité de Docker

---

##### Docker Privilege Escalation

##### Élévation de privilèges Docker

---

##### Docker is a popular containerization platform that allows you to package an application and its dependencies into a standardized unit called a container. Containers are isolated from each other and from the underlying host system, providing a lightweight and portable way to run applications.

##### Docker est une plateforme de conteneurisation populaire qui vous permet de regrouper une application et ses dépendances dans une unité standardisée appelée conteneur. Les conteneurs sont isolés les uns des autres et du système hôte sous-jacent, offrant ainsi un moyen léger et portable d'exécuter des applications.

---

##### Docker Security Best Practices

##### Meilleures pratiques de sécurité Docker

---

##### Docker provides several security features and best practices that can be implemented to harden the security of your Docker environment. Some of these best practices include:

##### Docker propose plusieurs fonctionnalités de sécurité et meilleures pratiques qui peuvent être mises en œuvre pour renforcer la sécurité de votre environnement Docker. Certaines de ces meilleures pratiques comprennent :

---

##### 1. Use Official Images

##### 1. Utiliser des images officielles

---

##### Always use official Docker images from trusted sources. Official images are maintained by the Docker community and are regularly updated with security patches. Avoid using images from untrusted sources, as they may contain vulnerabilities or malicious code.

##### Utilisez toujours des images Docker officielles provenant de sources fiables. Les images officielles sont maintenues par la communauté Docker et sont régulièrement mises à jour avec des correctifs de sécurité. Évitez d'utiliser des images provenant de sources non fiables, car elles peuvent contenir des vulnérabilités ou du code malveillant.

---

##### 2. Enable Content Trust

##### 2. Activer la confiance du contenu

---

##### Enable Docker Content Trust to ensure the integrity and authenticity of Docker images. Content Trust uses digital signatures to verify the publisher of an image and ensure that it has not been tampered with. This helps prevent the use of malicious or compromised images.

##### Activez la confiance du contenu Docker pour garantir l'intégrité et l'authenticité des images Docker. La confiance du contenu utilise des signatures numériques pour vérifier l'éditeur d'une image et s'assurer qu'elle n'a pas été altérée. Cela permet d'éviter l'utilisation d'images malveillantes ou compromises.

---

##### 3. Limit Container Capabilities

##### 3. Limiter les capacités du conteneur

---

##### Limit the capabilities of Docker containers to reduce the potential impact of a container breakout. By default, Docker containers have a wide range of capabilities, which can be restricted using the `--cap-drop` and `--cap-add` flags when running containers.

##### Limitez les capacités des conteneurs Docker pour réduire l'impact potentiel d'une évasion de conteneur. Par défaut, les conteneurs Docker ont un large éventail de capacités, qui peuvent être restreintes à l'aide des indicateurs `--cap-drop` et `--cap-add` lors de l'exécution des conteneurs.

---

##### 4. Use User Namespaces

##### 4. Utiliser des espaces de noms utilisateur

---

##### Enable user namespaces to provide additional isolation between the host system and Docker containers. User namespaces map the container's user and group IDs to different IDs on the host system, preventing container processes from accessing host resources.

##### Activez les espaces de noms utilisateur pour fournir une isolation supplémentaire entre le système hôte et les conteneurs Docker. Les espaces de noms utilisateur associent les ID utilisateur et de groupe du conteneur à des ID différents sur le système hôte, empêchant les processus du conteneur d'accéder aux ressources de l'hôte.

---

##### 5. Implement Network Segmentation

##### 5. Mettre en œuvre la segmentation réseau

---

##### Implement network segmentation to isolate Docker containers from each other and from the host system. Use Docker's built-in networking features, such as creating custom networks and using network policies, to control the flow of network traffic between containers.

##### Mettez en œuvre la segmentation réseau pour isoler les conteneurs Docker les uns des autres et du système hôte. Utilisez les fonctionnalités de mise en réseau intégrées de Docker, telles que la création de réseaux personnalisés et l'utilisation de stratégies de réseau, pour contrôler le flux du trafic réseau entre les conteneurs.

---

##### 6. Monitor Container Activity

##### 6. Surveiller l'activité des conteneurs

---

##### Regularly monitor the activity of Docker containers to detect any suspicious or unauthorized behavior. Use Docker's logging and monitoring features, as well as third-party tools, to collect and analyze container logs and metrics.

##### Surveillez régulièrement l'activité des conteneurs Docker pour détecter tout comportement suspect ou non autorisé. Utilisez les fonctionnalités de journalisation et de surveillance de Docker, ainsi que des outils tiers, pour collecter et analyser les journaux et les métriques des conteneurs.

---

##### 7. Keep Docker Up to Date

##### 7. Maintenir Docker à jour

---

##### Regularly update Docker to ensure that you have the latest security patches and bug fixes. Subscribe to Docker's security announcements and follow best practices for updating Docker and its dependencies.

##### Mettez régulièrement à jour Docker pour vous assurer que vous disposez des derniers correctifs de sécurité et correctifs de bogues. Abonnez-vous aux annonces de sécurité de Docker et suivez les meilleures pratiques pour mettre à jour Docker et ses dépendances.

---

##### Conclusion

##### Conclusion

---

##### Implementing these Docker security best practices can help protect your Docker environment from potential security vulnerabilities and attacks. By following these guidelines, you can ensure that your Docker containers are running securely and that your applications and data are protected.

##### La mise en œuvre de ces meilleures pratiques de sécurité Docker peut aider à protéger votre environnement Docker contre les vulnérabilités et les attaques potentielles. En suivant ces lignes directrices, vous pouvez vous assurer que vos conteneurs Docker fonctionnent de manière sécurisée et que vos applications et vos données sont protégées.
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

## Autres considérations de sécurité

### Gestion des secrets

Tout d'abord, **ne les mettez pas à l'intérieur de votre image !**

De plus, **n'utilisez pas de variables d'environnement** pour vos informations sensibles. Toute personne qui peut exécuter `docker inspect` ou `exec` dans le conteneur peut trouver votre secret.

Les volumes Docker sont meilleurs. Ils sont la méthode recommandée pour accéder à vos informations sensibles dans la documentation Docker. Vous pouvez **utiliser un volume comme système de fichiers temporaire stocké en mémoire**. Les volumes éliminent le risque de `docker inspect` et de journalisation. Cependant, **les utilisateurs root pourraient toujours voir le secret, tout comme toute personne pouvant `exec` dans le conteneur**.

Encore **mieux que les volumes, utilisez les secrets Docker**.

Si vous avez juste besoin du **secret dans votre image**, vous pouvez utiliser **BuildKit**. BuildKit réduit considérablement le temps de construction et offre d'autres fonctionnalités intéressantes, notamment **la prise en charge des secrets au moment de la construction**.

Il existe trois façons de spécifier le backend BuildKit afin de pouvoir utiliser ses fonctionnalités dès maintenant :

1. Définissez-le en tant que variable d'environnement avec `export DOCKER_BUILDKIT=1`.
2. Démarrez votre commande `build` ou `run` avec `DOCKER_BUILDKIT=1`.
3. Activez BuildKit par défaut. Définissez la configuration dans /_etc/docker/daemon.json_ sur _true_ avec : `{ "features": { "buildkit": true } }`. Ensuite, redémarrez Docker.
4. Ensuite, vous pouvez utiliser des secrets au moment de la construction avec le drapeau `--secret` comme ceci :
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Lorsque votre fichier spécifie vos secrets sous forme de paires clé-valeur.

Ces secrets sont exclus du cache de construction de l'image et de l'image finale.

Si vous avez besoin de votre **secret dans votre conteneur en cours d'exécution**, et pas seulement lors de la construction de votre image, utilisez **Docker Compose ou Kubernetes**.

Avec Docker Compose, ajoutez la paire clé-valeur des secrets à un service et spécifiez le fichier secret. Un grand merci à [la réponse de Stack Exchange](https://serverfault.com/a/936262/535325) pour le conseil sur les secrets de Docker Compose, dont l'exemple ci-dessous est adapté.

Exemple de `docker-compose.yml` avec des secrets :
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
Ensuite, démarrez Compose comme d'habitude avec `docker-compose up --build my_service`.

Si vous utilisez [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/), il prend en charge les secrets. [Helm-Secrets](https://github.com/futuresimple/helm-secrets) peut faciliter la gestion des secrets dans K8s. De plus, K8s dispose de contrôles d'accès basés sur les rôles (RBAC), tout comme Docker Enterprise. RBAC facilite la gestion et la sécurisation de l'accès aux secrets pour les équipes.

### gVisor

**gVisor** est un noyau d'application, écrit en Go, qui implémente une partie importante de la surface du système Linux. Il comprend un runtime [Open Container Initiative (OCI)](https://www.opencontainers.org) appelé `runsc` qui fournit une **frontière d'isolation entre l'application et le noyau hôte**. Le runtime `runsc` s'intègre à Docker et Kubernetes, ce qui permet d'exécuter facilement des conteneurs sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** est une communauté open source qui travaille à la création d'un runtime de conteneur sécurisé avec des machines virtuelles légères qui offrent des performances et une isolation des charges de travail plus solides en utilisant la virtualisation matérielle comme deuxième couche de défense.

{% embed url="https://katacontainers.io/" %}

### Conseils récapitulatifs

* **N'utilisez pas le drapeau `--privileged` ou montez un** [**socket Docker à l'intérieur du conteneur**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Le socket Docker permet de créer des conteneurs, il est donc facile de prendre le contrôle total de l'hôte, par exemple en exécutant un autre conteneur avec le drapeau `--privileged`.
* **N'exécutez pas en tant que root à l'intérieur du conteneur. Utilisez un** [**utilisateur différent**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **et des** [**espaces de noms utilisateur**](https://docs.docker.com/engine/security/userns-remap/)**.** Le compte root dans le conteneur est le même que sur l'hôte, sauf s'il est remappé avec des espaces de noms utilisateur. Il est seulement légèrement restreint par les espaces de noms Linux, les capacités et les cgroups.
* [**Supprimez toutes les capacités**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) et n'activez que celles qui sont nécessaires** (`--cap-add=...`). De nombreuses charges de travail n'ont pas besoin de capacités et leur ajout élargit la portée d'une attaque potentielle.
* [**Utilisez l'option de sécurité "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) pour empêcher les processus d'obtenir plus de privilèges, par exemple via des binaires suid.
* [**Limitez les ressources disponibles pour le conteneur**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Les limites des ressources peuvent protéger la machine contre les attaques de déni de service.
* **Ajustez les profils** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** pour restreindre les actions et les appels système disponibles pour le conteneur au strict minimum requis.
* **Utilisez des images Docker officielles** [**https://docs.docker.com/docker-hub/official\_images/**](https://docs.docker.com/docker-hub/official\_images/) **et exigez des signatures** ou créez vos propres images basées sur celles-ci. N'héritez pas ou n'utilisez pas d'images [compromises](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Stockez également les clés racines et les phrases secrètes dans un endroit sûr. Docker prévoit de gérer les clés avec UCP.
* **Reconstruisez régulièrement** vos images pour **appliquer les correctifs de sécurité sur l'hôte et les images**.
* Gérez vos **secrets avec prudence** afin qu'il soit difficile pour un attaquant de les accéder.
* Si vous **exposez le démon Docker, utilisez HTTPS** avec une authentification client et serveur.
* Dans votre Dockerfile, **privilégiez COPY plutôt que ADD**. ADD extrait automatiquement les fichiers compressés et peut copier des fichiers à partir d'URL. COPY n'a pas ces fonctionnalités. Dans la mesure du possible, évitez d'utiliser ADD pour ne pas être vulnérable aux attaques via des URL distantes et des fichiers Zip.
* Utilisez des **conteneurs séparés pour chaque micro-service**.
* **Ne mettez pas SSH** à l'intérieur du conteneur, "docker exec" peut être utilisé pour se connecter en SSH au conteneur.
* Utilisez des **images de conteneur plus petites**.

## Évasion de Docker / Élévation de privilèges

Si vous êtes **à l'intérieur d'un conteneur Docker** ou si vous avez accès à un utilisateur du **groupe docker**, vous pouvez essayer de **vous échapper et d'escalader les privilèges** :

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Contournement du plugin d'authentification Docker

Si vous avez accès au socket Docker ou si vous avez accès à un utilisateur du **groupe docker mais que vos actions sont limitées par un plugin d'authentification Docker**, vérifiez si vous pouvez **le contourner** :

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Durcissement de Docker

* L'outil [**docker-bench-security**](https://github.com/docker/docker-bench-security) est un script qui vérifie des dizaines de bonnes pratiques courantes pour le déploiement de conteneurs Docker en production. Les tests sont tous automatisés et sont basés sur le [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Vous devez exécuter l'outil à partir de l'hôte exécutant Docker ou à partir d'un conteneur disposant des privilèges suffisants. Découvrez **comment l'exécuter dans le README** : [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.
Obtenez un accès dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
