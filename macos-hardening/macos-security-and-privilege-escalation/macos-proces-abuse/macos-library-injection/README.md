# Injection de bibliothèque macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
Le code de **dyld est open source** et peut être trouvé dans [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et peut être téléchargé sous forme de tar en utilisant une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> Ceci est une liste de bibliothèques dynamiques séparées par des deux-points à charger avant celles spécifiées dans le programme. Cela vous permet de tester de nouveaux modules de bibliothèques partagées dynamiques existantes utilisées dans des images de l'espace de noms plat en chargeant une bibliothèque partagée dynamique temporaire avec seulement les nouveaux modules. Notez que cela n'a aucun effet sur les images construites avec un espace de noms à deux niveaux utilisant une bibliothèque partagée dynamique, à moins que DYLD\_FORCE\_FLAT\_NAMESPACE ne soit également utilisé.

C'est comme le [**LD\_PRELOAD sur Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload).

Cette technique peut également être **utilisée comme technique ASEP** car chaque application installée a un fichier plist appelé "Info.plist" qui permet **d'assigner des variables d'environnement** en utilisant une clé appelée `LSEnvironmental`.

{% hint style="info" %}
Depuis 2012, **Apple a considérablement réduit la puissance** de **`DYLD_INSERT_LIBRARIES`**.

Allez dans le code et **vérifiez `src/dyld.cpp`**. Dans la fonction **`pruneEnvironmentVariables`**, vous pouvez voir que les variables **`DYLD_*`** sont supprimées.

Dans la fonction **`processRestricted`**, la raison de la restriction est définie. En vérifiant ce code, vous pouvez voir que les raisons sont les suivantes :

* Le binaire est `setuid/setgid`
* Existence de la section `__RESTRICT/__restrict` dans le binaire macho.
* Le logiciel a des attributs (runtime renforcé) sans l'attribut [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) ou [`com.apple.security.cs.disable-library-validation`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).
* Vérifiez les **attributs** d'un binaire avec : `codesign -dv --entitlements :- </path/to/bin>`
* Si la bibliothèque est signée avec un certificat différent du binaire
* Si la bibliothèque et le binaire sont signés avec le même certificat, cela contournera les restrictions précédentes
* Les programmes avec les attributs **`system.install.apple-software`** et **`system.install.apple-software.standar-user`** peuvent **installer des logiciels** signés par Apple sans demander à l'utilisateur un mot de passe (élévation de privilèges)

Dans les versions plus récentes, vous pouvez trouver cette logique dans la deuxième partie de la fonction **`configureProcessRestrictions`**. Cependant, ce qui est exécuté dans les versions plus récentes, ce sont les **vérifications initiales de la fonction** (vous pouvez supprimer les ifs liés à iOS ou à la simulation car ils ne seront pas utilisés dans macOS.
{% endhint %}

Vous pouvez vérifier si un binaire a **un runtime renforcé** avec `codesign --display --verbose <bin>` en vérifiant le drapeau runtime dans **`CodeDirectory`** comme : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Trouvez un exemple de (dé)tournement de cette technique et vérifiez les restrictions dans :

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Détournement de Dylib

{% hint style="danger" %}
N'oubliez pas que les **restrictions précédentes s'appliquent également** pour effectuer des attaques de détournement de Dylib.
{% endhint %}

Comme sous Windows, sous MacOS, vous pouvez également **détourner les dylibs** pour faire exécuter du **code arbitraire** par des **applications**.\
Cependant, la façon dont les applications **MacOS** chargent les bibliothèques est **plus restreinte** que sous Windows. Cela implique que les développeurs de logiciels malveillants peuvent toujours utiliser cette technique pour **se camoufler**, mais la probabilité de pouvoir **abuser de cela pour escalader les privilèges est beaucoup plus faible**.

Tout d'abord, il est **plus courant** de trouver que les **binaires MacOS indiquent le chemin complet** des bibliothèques à charger. Et deuxièmement, **MacOS ne recherche jamais** dans les dossiers du **$PATH** les bibliothèques.

La **partie principale** du **code** liée à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`** dans `ImageLoader.cpp`.

Il existe **4 commandes d'en-tête différentes** qu'un binaire macho peut utiliser pour charger des bibliothèques :

* La commande **`LC_LOAD_DYLIB`** est la commande courante pour charger une dylib.
* La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si la dylib n'est pas trouvée, l'exécution se poursuit sans aucune erreur.
* La commande **`LC_REEXPORT_DYLIB`** permet de faire proxy (ou réexporter) les symboles d'une bibliothèque différente.
* La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux bibliothèques dépendent l'une de l'autre (on parle de _dépendance ascendante_).

Cependant, il existe **2 types de détournement de dylib** :
* **Bibliothèques liées faibles manquantes**: Cela signifie que l'application essaiera de charger une bibliothèque qui n'existe pas configurée avec **LC\_LOAD\_WEAK\_DYLIB**. Ensuite, **si un attaquant place un dylib là où il est attendu, il sera chargé**.
* Le fait que le lien soit "faible" signifie que l'application continuera de s'exécuter même si la bibliothèque n'est pas trouvée.
* Le **code associé** à cela se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, où `lib->required` est seulement `false` lorsque `LC_LOAD_WEAK_DYLIB` est vrai.
* **Trouver des bibliothèques liées faibles** dans les binaires avec (vous avez ensuite un exemple de création de bibliothèques de détournement) :
* ```bash
otool -l </chemin/vers/binaire> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Configuré avec @rpath**: Les binaires Mach-O peuvent avoir les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, des **bibliothèques** vont être **chargées** à partir de **différents répertoires**.
* **`LC_RPATH`** contient les chemins de certains dossiers utilisés pour charger les bibliothèques par le binaire.
* **`LC_LOAD_DYLIB`** contient le chemin des bibliothèques spécifiques à charger. Ces chemins peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs dans **`LC_RPATH`**. Si plusieurs chemins sont présents dans **`LC_RPATH`**, chacun sera utilisé pour rechercher la bibliothèque à charger. Exemple :
* Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`. Les deux dossiers seront utilisés pour charger `library.dylib`**.** Si la bibliothèque n'existe pas dans `[...]/v1/`, un attaquant pourrait la placer là pour détourner le chargement de la bibliothèque dans `[...]/v2/` car l'ordre des chemins dans **`LC_LOAD_DYLIB`** est suivi.
* **Trouver les chemins rpath et les bibliothèques** dans les binaires avec : `otool -l </chemin/vers/binaire> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`** : Est le **chemin** vers le répertoire contenant le **fichier exécutable principal**.

**`@loader_path`** : Est le **chemin** vers le **répertoire** contenant le **binaire Mach-O** qui contient la commande de chargement.

* Lorsqu'il est utilisé dans un exécutable, **`@loader_path`** est effectivement le **même** que **`@executable_path`**.
* Lorsqu'il est utilisé dans une **dylib**, **`@loader_path`** donne le **chemin** vers la **dylib**.
{% endhint %}

La façon de **escalader les privilèges** en abusant de cette fonctionnalité serait dans le cas rare où une **application** exécutée **par** **root** recherche une **bibliothèque dans un dossier où l'attaquant a des permissions d'écriture**.

{% hint style="success" %}
Un bon **scanner** pour trouver des **bibliothèques manquantes** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou une [**version CLI**](https://github.com/pandazheng/DylibHijack).\
Un bon **rapport avec des détails techniques** sur cette technique peut être trouvé [**ici**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Exemple**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

D'après **`man dlopen`** :

* Lorsque le chemin **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit simplement d'un nom de feuille), **dlopen() effectuera une recherche**. Si **`$DYLD_LIBRARY_PATH`** était défini au lancement, dyld cherchera d'abord dans ce répertoire. Ensuite, si le fichier mach-o appelant ou l'exécutable principal spécifie un **`LC_RPATH`**, alors dyld cherchera dans ces répertoires. Ensuite, si le processus est **non restreint**, dyld recherchera dans le **répertoire de travail actuel**. Enfin, pour les anciens binaires, dyld essaiera quelques solutions de repli. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans ces répertoires, sinon, dyld cherchera dans **`/usr/local/lib/`** (si le processus est non restreint), puis dans **`/usr/lib/`** (ces informations ont été extraites de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (si non restreint)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si non restreint)
6. `/usr/lib/`

{% hint style="danger" %}
S'il n'y a pas de slash dans le nom, il y aurait 2 façons de faire un détournement :

* Si un **`LC_RPATH`** est **modifiable** (mais la signature est vérifiée, donc pour cela, vous avez également besoin que le binaire soit non restreint)
* Si le binaire est **non restreint** et qu'il est ensuite possible de charger quelque chose depuis le CWD (ou en abusant des variables d'environnement mentionnées)
{% endhint %}

* Lorsque le chemin **ressemble à un chemin de framework** (par exemple `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** était défini au lancement, dyld cherchera d'abord dans ce répertoire pour le **chemin partiel du framework** (par exemple `foo.framework/foo`). Ensuite, dyld essaiera le **chemin fourni tel quel** (en utilisant le répertoire de travail actuel pour les chemins relatifs). Enfin, pour les anciens binaires, dyld essaiera quelques solutions de repli. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** était défini au lancement, dyld recherchera dans ces répertoires. Sinon, il recherchera dans **`/Library/Frameworks`** (sur macOS si le processus est non restreint), puis dans **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si non restreint)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si non restreint)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
S'il s'agit d'un chemin de framework, la façon de le détourner serait :

* Si le processus est **non restreint**, en abusant du **chemin relatif depuis le CWD** et des variables d'environnement mentionnées (même si cela n'est pas précisé dans la documentation, si le processus est restreint, les variables d'environnement DYLD\_\* sont supprimées)
{% endhint %}

* Lorsque le chemin **contient un slash mais n'est pas un chemin de framework** (c'est-à-dire un chemin complet ou un chemin partiel vers une dylib), dlopen() recherche d'abord (si défini) dans **`$DYLD_LIBRARY_PATH`** (avec la partie feuille du chemin). Ensuite, dyld **essaie le chemin fourni** (en utilisant le répertoire de travail actuel pour les chemins relatifs (mais uniquement pour les processus non restreints)). Enfin, pour les anciens binaires, dyld essaiera des solutions de repli. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** était défini au lancement, dyld recherchera dans ces répertoires, sinon, dyld cherchera dans **`/usr/local/lib/`** (si le processus est non restreint), puis dans **`/usr/lib/`
2. chemin fourni (utilisation du répertoire de travail actuel pour les chemins relatifs si non restreint)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (si non restreint)
5. `/usr/lib/`

{% hint style="danger" %}
Si les barres obliques sont présentes dans le nom et qu'il ne s'agit pas d'un framework, la façon de le pirater serait la suivante :

* Si le binaire est **non restreint**, il est possible de charger quelque chose à partir du CWD ou de `/usr/local/lib` (ou en abusant l'une des variables d'environnement mentionnées)
{% endhint %}

{% hint style="info" %}
Remarque : Il n'y a **aucun** fichier de configuration pour **contrôler la recherche de dlopen**.

Remarque : Si l'exécutable principal est un binaire **set\[ug]id ou signé avec des entitlements**, alors **toutes les variables d'environnement sont ignorées**, et seul un chemin complet peut être utilisé ([vérifier les restrictions de DYLD\_INSERT\_LIBRARIES](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) pour plus d'informations détaillées)

Remarque : Les plates-formes Apple utilisent des fichiers "universels" pour combiner les bibliothèques 32 bits et 64 bits. Cela signifie qu'il n'y a **pas de chemins de recherche séparés pour les bibliothèques 32 bits et 64 bits**.

Remarque : Sur les plates-formes Apple, la plupart des dylibs du système sont **combinées dans le cache dyld** et n'existent pas sur le disque. Par conséquent, l'appel à **`stat()`** pour pré-vérifier si une dylib du système existe **ne fonctionnera pas**. Cependant, **`dlopen_preflight()`** utilise les mêmes étapes que **`dlopen()`** pour trouver un fichier mach-o compatible.
{% endhint %}

**Vérifier les chemins**

Vérifions toutes les options avec le code suivant :
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Si vous le compilez et l'exécutez, vous pouvez voir **où chaque bibliothèque a été recherchée sans succès**. De plus, vous pouvez **filtrer les journaux du système de fichiers** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Élaguer les variables d'environnement `DYLD_*` et `LD_LIBRARY_PATH`

Dans le fichier `dyld-dyld-832.7.1/src/dyld2.cpp`, il est possible de trouver la fonction **`pruneEnvironmentVariables`**, qui supprimera toute variable d'environnement qui **commence par `DYLD_`** et **`LD_LIBRARY_PATH=`**.

Elle définira également spécifiquement les variables d'environnement **`DYLD_FALLBACK_FRAMEWORK_PATH`** et **`DYLD_FALLBACK_LIBRARY_PATH`** à **null** pour les binaires **suid** et **sgid**.

Cette fonction est appelée depuis la fonction **`_main`** du même fichier lorsqu'on cible OSX de la manière suivante:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
et ces indicateurs booléens sont définis dans le même fichier dans le code :
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Ce qui signifie essentiellement que si le binaire est **suid** ou **sgid**, ou s'il a un segment **RESTRICT** dans les en-têtes ou s'il a été signé avec le drapeau **CS\_RESTRICT**, alors **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** est vrai et les variables d'environnement sont élaguées.

Notez que si CS\_REQUIRE\_LV est vrai, alors les variables ne seront pas élaguées mais la validation de la bibliothèque vérifiera qu'elles utilisent le même certificat que le binaire d'origine.

## Vérifier les restrictions

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Section `__RESTRICT` avec le segment `__restrict`

Le segment `__restrict` est une section spéciale dans les binaires macOS qui est utilisée pour restreindre l'accès à certaines fonctionnalités sensibles du système d'exploitation. Cette section est conçue pour empêcher les processus non autorisés d'interférer avec des bibliothèques système critiques.

Lorsqu'un binaire est compilé avec le flag `-fno-strict-aliasing`, le compilateur ajoute automatiquement le segment `__restrict` au binaire. Ce segment contient des informations sur les restrictions d'accès pour les bibliothèques système.

L'objectif principal de la section `__RESTRICT` est de renforcer la sécurité en empêchant les attaquants d'injecter du code malveillant dans les bibliothèques système. Cela réduit considérablement les risques de compromission du système et de privilège d'escalade.

Il est important de noter que la section `__RESTRICT` n'est pas une mesure de sécurité absolue. Les attaquants expérimentés peuvent toujours trouver des moyens de contourner ces restrictions. Cependant, l'utilisation de cette section renforce la sécurité globale du système et rend l'exploitation plus difficile pour les attaquants.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime sécurisé

Créez un nouveau certificat dans le trousseau d'accès et utilisez-le pour signer le binaire :

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Notez que même s'il existe des binaires signés avec le drapeau **`0x0(none)`**, ils peuvent obtenir dynamiquement le drapeau **`CS_RESTRICT`** lorsqu'ils sont exécutés et donc cette technique ne fonctionnera pas sur eux.

Vous pouvez vérifier si un processus a ce drapeau avec (obtenez [**csops ici**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
et vérifiez ensuite si le drapeau 0x800 est activé.
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
