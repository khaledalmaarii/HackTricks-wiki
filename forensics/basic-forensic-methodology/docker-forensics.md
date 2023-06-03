## Forensique Docker

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Modification de conteneur

Il y a des soupçons qu'un conteneur Docker a été compromis :
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Vous pouvez facilement **trouver les modifications apportées à ce conteneur par rapport à l'image** avec:
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
Dans la commande précédente, **C** signifie **Changé** et **A**, **Ajouté**.\
Si vous trouvez qu'un fichier intéressant comme `/etc/shadow` a été modifié, vous pouvez le télécharger depuis le conteneur pour vérifier s'il y a une activité malveillante avec:
```bash
docker cp wordpress:/etc/shadow.
```
Vous pouvez également **le comparer avec l'original** en exécutant un nouveau conteneur et en extrayant le fichier à partir de celui-ci :
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si vous constatez qu'un **fichier suspect a été ajouté**, vous pouvez accéder au conteneur et le vérifier :
```bash
docker exec -it wordpress bash
```
## Modifications d'images

Lorsque vous recevez une image Docker exportée (probablement au format `.tar`), vous pouvez utiliser [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) pour **extraire un résumé des modifications** :
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ensuite, vous pouvez **décompresser** l'image et **accéder aux blobs** pour rechercher des fichiers suspects que vous avez peut-être trouvés dans l'historique des modifications :
```bash
tar -xf image.tar
```
### Analyse de base

Vous pouvez obtenir des **informations de base** à partir de l'image en cours d'exécution :
```bash
docker inspect <image> 
```
Vous pouvez également obtenir un résumé de **l'historique des modifications** avec:
```bash
docker history --no-trunc <image>
```
Vous pouvez également générer un **dockerfile à partir d'une image** avec:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Pour trouver les fichiers ajoutés/modifiés dans les images Docker, vous pouvez également utiliser l'utilitaire [**dive**](https://github.com/wagoodman/dive) (téléchargez-le depuis les [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) :
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Cela vous permet de **naviguer à travers les différents blobs des images Docker** et de vérifier quels fichiers ont été modifiés/ajoutés. Le **rouge** signifie ajouté et le **jaune** signifie modifié. Utilisez la touche **tabulation** pour passer à l'autre vue et **espace** pour réduire/ouvrir les dossiers.

Avec `die`, vous ne pourrez pas accéder au contenu des différentes étapes de l'image. Pour ce faire, vous devrez **décompresser chaque couche et y accéder**.\
Vous pouvez décompresser toutes les couches d'une image depuis le répertoire où l'image a été décompressée en exécutant:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Identifiants à partir de la mémoire

Notez que lorsque vous exécutez un conteneur Docker à l'intérieur d'un hôte, **vous pouvez voir les processus s'exécutant sur le conteneur depuis l'hôte** en exécutant simplement `ps -ef`.

Par conséquent (en tant que root), vous pouvez **extraire la mémoire des processus** depuis l'hôte et rechercher des **identifiants** tout comme [**dans l'exemple suivant**](../../linux-hardening/privilege-escalation/#process-memory).
