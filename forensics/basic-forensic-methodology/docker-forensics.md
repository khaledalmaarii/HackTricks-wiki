# Docker Forensics

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Modification de conteneur

Il y a des soupçons qu'un conteneur docker a été compromis :
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Vous pouvez facilement **trouver les modifications apportées à ce conteneur par rapport à l'image** avec :
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Dans la commande précédente, **C** signifie **Changé** et **A,** **Ajouté**.\
Si vous découvrez qu'un fichier intéressant comme `/etc/shadow` a été modifié, vous pouvez le télécharger depuis le conteneur pour vérifier une activité malveillante avec :
```bash
docker cp wordpress:/etc/shadow.
```
Vous pouvez également **le comparer avec l'original** en exécutant un nouveau conteneur et en extrayant le fichier de celui-ci :
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si vous découvrez qu'**un fichier suspect a été ajouté**, vous pouvez accéder au conteneur et le vérifier :
```bash
docker exec -it wordpress bash
```
## Modifications des images

Lorsque vous recevez une image docker exportée (probablement au format `.tar`), vous pouvez utiliser [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) pour **extraire un résumé des modifications** :
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ensuite, vous pouvez **décompresser** l'image et **accéder aux blobs** pour rechercher des fichiers suspects que vous auriez trouvés dans l'historique des modifications :
```bash
tar -xf image.tar
```
### Analyse de base

Vous pouvez obtenir des **informations de base** de l'image en exécutant :
```bash
docker inspect <image>
```
Vous pouvez également obtenir un résumé de l'**historique des modifications** avec :
```bash
docker history --no-trunc <image>
```
Vous pouvez également générer un **dockerfile à partir d'une image** avec :
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Pour trouver les fichiers ajoutés/modifiés dans les images docker, vous pouvez également utiliser l'outil [**dive**](https://github.com/wagoodman/dive) (téléchargez-le depuis les [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) :
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Cela vous permet de **naviguer à travers les différents blobs des images docker** et de vérifier quels fichiers ont été modifiés/ajoutés. **Rouge** signifie ajouté et **jaune** signifie modifié. Utilisez **tab** pour passer à l'autre vue et **espace** pour réduire/ouvrir les dossiers.

Avec die, vous ne pourrez pas accéder au contenu des différentes étapes de l'image. Pour ce faire, vous devrez **décompresser chaque couche et y accéder**.\
Vous pouvez décompresser toutes les couches d'une image depuis le répertoire où l'image a été décompressée en exécutant :
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Identifiants depuis la mémoire

Notez que lorsque vous exécutez un conteneur docker à l'intérieur d'un hôte, **vous pouvez voir les processus s'exécutant dans le conteneur depuis l'hôte** en exécutant simplement `ps -ef`.

Par conséquent (en tant que root), vous pouvez **dumper la mémoire des processus** depuis l'hôte et rechercher des **identifiants** tout [**comme dans l'exemple suivant**](../../linux-hardening/privilege-escalation/#process-memory).

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
