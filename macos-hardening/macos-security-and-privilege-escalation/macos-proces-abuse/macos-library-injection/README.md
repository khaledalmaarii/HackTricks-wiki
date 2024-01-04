# Injection de bibliothèque macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
Le code de **dyld est open source** et peut être trouvé sur [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) et peut être téléchargé en tar en utilisant une **URL telle que** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> Il s'agit d'une **liste séparée par des deux-points de bibliothèques dynamiques** à **charger avant celles spécifiées dans le programme**. Cela vous permet de tester de nouveaux modules de bibliothèques partagées dynamiques existantes qui sont utilisées dans des images à espace de noms plat en chargeant une bibliothèque partagée dynamique temporaire avec juste les nouveaux modules. Notez que cela n'a aucun effet sur les images construites avec un espace de noms à deux niveaux utilisant une bibliothèque partagée dynamique à moins que DYLD\_FORCE\_FLAT\_NAMESPACE soit également utilisé.

C'est comme le [**LD\_PRELOAD sur Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload).

Cette technique peut également être **utilisée comme une technique ASEP** car chaque application installée a un fichier plist appelé "Info.plist" qui permet **d'assigner des variables d'environnement** en utilisant une clé appelée `LSEnvironmental`.

{% hint style="info" %}
Depuis 2012, **Apple a considérablement réduit la puissance** de **`DYLD_INSERT_LIBRARIES`**.

Allez dans le code et **vérifiez `src/dyld.cpp`**. Dans la fonction **`pruneEnvironmentVariables`**, vous pouvez voir que les variables **`DYLD_*`** sont supprimées.

Dans la fonction **`processRestricted`**, la raison de la restriction est établie. En vérifiant ce code, vous pouvez voir que les raisons sont :

* Le binaire est `setuid/setgid`
* Existence d'une section `__RESTRICT/__restrict` dans le binaire macho.
* Le logiciel a des droits (runtime renforcé) sans le droit [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Vérifiez les **droits** d'un binaire avec : `codesign -dv --entitlements :- </path/to/bin>`

Dans des versions plus récentes, vous pouvez trouver cette logique dans la seconde partie de la fonction **`configureProcessRestrictions`.** Cependant, ce qui est exécuté dans les versions plus récentes sont les **vérifications initiales de la fonction** (vous pouvez supprimer les if liés à iOS ou à la simulation car ceux-ci ne seront pas utilisés dans macOS.
{% endhint %}

### Validation de la bibliothèque

Même si le binaire permet d'utiliser la variable d'environnement **`DYLD_INSERT_LIBRARIES`**, si le binaire vérifie la signature de la bibliothèque à charger, il ne chargera pas une bibliothèque personnalisée.

Pour charger une bibliothèque personnalisée, le binaire doit avoir **l'un des droits suivants** :

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou le binaire **ne devrait pas** avoir le **drapeau runtime renforcé** ou le **drapeau de validation de la bibliothèque**.

Vous pouvez vérifier si un binaire a **runtime renforcé** avec `codesign --display --verbose <bin>` en vérifiant le drapeau runtime dans **`CodeDirectory`** comme : **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Vous pouvez également charger une bibliothèque si elle est **signée avec le même certificat que le binaire**.

Trouvez un exemple sur comment (ab)user de cela et vérifiez les restrictions dans :

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Détournement de Dylib

{% hint style="danger" %}
Rappelez-vous que les **restrictions de validation de bibliothèque précédentes s'appliquent également** pour effectuer des attaques de détournement de Dylib.
{% endhint %}

Comme sous Windows, sous MacOS, vous pouvez également **détourner des dylibs** pour faire **exécuter du code arbitraire** par des **applications**.\
Cependant, la manière dont les applications **MacOS** **chargent** les bibliothèques est **plus restreinte** que sous Windows. Cela implique que les développeurs de **malware** peuvent toujours utiliser cette technique pour la **discrétion**, mais la probabilité de pouvoir **abuser de cela pour élever les privilèges est beaucoup plus faible**.

Tout d'abord, il est **plus courant** de trouver que les binaires **MacOS indiquent le chemin complet** vers les bibliothèques à charger. Et deuxièmement, **MacOS ne recherche jamais** dans les dossiers du **$PATH** pour les bibliothèques.

La **partie principale** du **code** lié à cette fonctionnalité se trouve dans **`ImageLoader::recursiveLoadLibraries`** dans `ImageLoader.cpp`.

Il existe **4 commandes d'en-tête différentes** qu'un binaire macho peut utiliser pour charger des bibliothèques :

* La commande **`LC_LOAD_DYLIB`** est la commande commune pour charger une dylib.
* La commande **`LC_LOAD_WEAK_DYLIB`** fonctionne comme la précédente, mais si la dylib n'est pas trouvée, l'exécution continue sans erreur.
* La commande **`LC_REEXPORT_DYLIB`** elle proxy (ou réexporte) les symboles d'une bibliothèque différente.
* La commande **`LC_LOAD_UPWARD_DYLIB`** est utilisée lorsque deux bibliothèques dépendent l'une de l'autre (ceci est appelé une _dépendance ascendante_).

Cependant, il existe **2 types de détournement de dylib** :

* **Bibliothèques liées faibles manquantes** : Cela signifie que l'application essaiera de charger une bibliothèque qui n'existe pas configurée avec **LC\_LOAD\_WEAK\_DYLIB**. Ensuite, **si un attaquant place une dylib là où elle est attendue, elle sera chargée**.
* Le fait que le lien soit "faible" signifie que l'application continuera de fonctionner même si la bibliothèque n'est pas trouvée.
* Le **code lié** à cela se trouve dans la fonction `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp` où `lib->required` n'est `false` que lorsque `LC_LOAD_WEAK_DYLIB` est vrai.
* **Trouvez des bibliothèques liées faibles** dans les binaires avec (vous avez plus tard un exemple de comment créer des bibliothèques de détournement) :
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Configuré avec @rpath** : Les binaires Mach-O peuvent avoir les commandes **`LC_RPATH`** et **`LC_LOAD_DYLIB`**. En fonction des **valeurs** de ces commandes, les **bibliothèques** seront **chargées** à partir de **différents répertoires**.
* **`LC_RPATH`** contient les chemins de certains dossiers utilisés pour charger des bibliothèques par le binaire.
* **`LC_LOAD_DYLIB`** contient le chemin vers des bibliothèques spécifiques à charger. Ces chemins peuvent contenir **`@rpath`**, qui sera **remplacé** par les valeurs dans **`LC_RPATH`**. Si plusieurs chemins sont présents dans **`LC_RPATH`**, chacun sera utilisé pour rechercher la bibliothèque à charger. Exemple :
* Si **`LC_LOAD_DYLIB`** contient `@rpath/library.dylib` et **`LC_RPATH`** contient `/application/app.app/Contents/Framework/v1/` et `/application/app.app/Contents/Framework/v2/`. Les deux dossiers seront utilisés pour charger `library.dylib`**.** Si la bibliothèque n'existe pas dans `[...]/v1/` et qu'un attaquant la place là, il pourrait détourner le chargement de la bibliothèque dans `[...]/v2/` car l'ordre des chemins dans **`LC_LOAD_DYLIB`** est suivi.
* **Trouvez les chemins rpath et les bibliothèques** dans les binaires avec : `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`** : Est le **chemin** vers le répertoire contenant le **fichier exécutable principal**.

**`@loader_path`** : Est le **chemin** vers le **répertoire** contenant le **binaire Mach-O** qui contient la commande de chargement.

* Lorsqu'il est utilisé dans un exécutable, **`@loader_path`** est effectivement le **même** que **`@executable_path`**.
* Lorsqu'il est utilisé dans une **dylib**, **`@loader_path`** donne le **chemin** vers la **dylib**.
{% endhint %}

La manière d'**élever les privilèges** en abusant de cette fonctionnalité serait dans le cas rare où une **application** exécutée **par** **root** est **à la recherche** d'une **bibliothèque dans un dossier où l'attaquant a des permissions d'écriture.**

{% hint style="success" %}
Un bon **scanner** pour trouver des **bibliothèques manquantes** dans les applications est [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou une [**version CLI**](https://github.com/pandazheng/DylibHijack).\
Un bon **rapport avec des détails techniques** sur cette technique peut être trouvé [**ici**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Exemple**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Détournement de Dlopen

{% hint style="danger" %}
Rappelez-vous que les **restrictions de validation de bibliothèque précédentes s'appliquent également** pour effectuer des attaques de détournement de Dlopen.
{% endhint %}

Depuis **`man dlopen`** :

* Lorsque le chemin **ne contient pas de caractère slash** (c'est-à-dire qu'il s'agit juste d'un nom de feuille), **dlopen() effectuera une recherche**. Si **`$DYLD_LIBRARY_PATH`** a été défini au lancement, dyld cherchera d'abord dans **ce répertoire**. Ensuite, si le fichier mach-o appelant ou l'exécutable principal spécifient un **`LC_RPATH`**, alors dyld cherchera dans **ces répertoires**. Ensuite, si le processus est **non restreint**, dyld cherchera dans le **répertoire de travail actuel**. Enfin, pour les anciens binaires, dyld essaiera quelques solutions de repli. Si **`$DYLD_FALLBACK_LIBRARY_PATH`** a été défini au lancement, dyld cherchera dans **ces répertoires**, sinon, dyld cherchera dans **`/usr/local/lib/`** (si le processus est non restreint), puis dans **`/usr/lib/`** (cette information a été prise de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(si non restreint)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (si non restreint)
6. `/usr/lib/`

{% hint style="danger" %}
Si aucun slash dans le nom, il y aurait 2 façons de faire un détournement :

* Si un **`LC_RPATH`** est **modifiable** (mais la signature est vérifiée, donc pour cela vous avez également besoin que le binaire soit non restreint)
* Si le binaire est **non restreint** et qu'il est alors possible de charger quelque chose depuis le CWD (ou en abusant de l'une des variables d'environnement mentionnées)
{% endhint %}

* Lorsque le chemin **ressemble à un chemin de framework** (par exemple, `/stuff/foo.framework/foo`), si **`$DYLD_FRAMEWORK_PATH`** a été défini au lancement, dyld cherchera d'abord dans ce répertoire pour le **chemin partiel du framework** (par exemple, `foo.framework/foo`). Ensuite, dyld essaiera le **chemin fourni tel quel** (en utilisant le répertoire de travail actuel pour les chemins relatifs). Enfin, pour les anciens binaires, dyld essaiera quelques solutions de repli. Si **`$DYLD_FALLBACK_FRAMEWORK_PATH`** a été défini au lancement, dyld cherchera dans ces répertoires. Sinon, il cherchera dans **`/Library/Frameworks`** (sur macOS si le processus est non restreint), puis dans **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. chemin fourni (en utilisant le répertoire de travail actuel pour les chemins relatifs si non restreint)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (si non restreint)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Si un chemin de framework, la manière de le détourner serait :

* Si le processus est **non restreint**, en abusant du **chemin relatif depuis le CWD** les variables d'environnement mentionnées (même si ce n'est pas dit dans les documents si le processus est restreint les variables d'environnement DYLD\_\* sont supprimées)
{% endhint %}

* Lorsque le chemin **contient un slash mais n'est pas un chemin de framework** (c'est-à-dire un chemin complet ou un chemin partiel vers une dylib), dlopen() regarde d'abord dans (si défini) **`$DYLD_LIBRARY_PATH`** (avec la partie feuille du chemin). Ensuite, dyld **essaie le chemin fourni** (en utilisant le répertoire de travail actuel pour les chemins relatifs (mais seulement pour
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
Si vous compilez et exécutez, vous pouvez voir **où chaque bibliothèque a été recherchée sans succès**. Vous pourriez également **filtrer les journaux FS** :
```bash
sudo fs_usage | grep "dlopentest"
```
## Détournement de chemin relatif

Si un **binaire/application privilégié** (comme un SUID ou un binaire avec des droits étendus) **charge une bibliothèque avec un chemin relatif** (par exemple en utilisant `@executable_path` ou `@loader_path`) et a la **Validation de bibliothèque désactivée**, il pourrait être possible de déplacer le binaire vers un emplacement où l'attaquant pourrait **modifier la bibliothèque chargée par le chemin relatif**, et l'exploiter pour injecter du code dans le processus.

## Élaguer les variables d'environnement `DYLD_*` et `LD_LIBRARY_PATH`

Dans le fichier `dyld-dyld-832.7.1/src/dyld2.cpp`, il est possible de trouver la fonction **`pruneEnvironmentVariables`**, qui supprimera toute variable d'environnement qui **commence par `DYLD_`** et **`LD_LIBRARY_PATH=`**.

Elle définira également à **null** spécifiquement les variables d'environnement **`DYLD_FALLBACK_FRAMEWORK_PATH`** et **`DYLD_FALLBACK_LIBRARY_PATH`** pour les binaires **suid** et **sgid**.

Cette fonction est appelée depuis la fonction **`_main`** du même fichier si ciblant OSX comme ceci :
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
Ce qui signifie essentiellement que si le binaire est **suid** ou **sgid**, ou possède un segment **RESTRICT** dans les en-têtes ou a été signé avec le drapeau **CS_RESTRICT**, alors **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** est vrai et les variables d'environnement sont élaguées.

Notez que si CS_REQUIRE_LV est vrai, alors les variables ne seront pas élaguées mais la validation de la bibliothèque vérifiera qu'elles utilisent le même certificat que le binaire original.

## Vérifier les Restrictions

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
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Exécution renforcée

Créez un nouveau certificat dans le Trousseau et utilisez-le pour signer le binaire :

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
Notez que même si certains binaires sont signés avec les drapeaux **`0x0(aucun)`**, ils peuvent obtenir dynamiquement le drapeau **`CS_RESTRICT`** lors de l'exécution et donc cette technique ne fonctionnera pas sur eux.

Vous pouvez vérifier si un processus a ce drapeau avec (obtenez [**csops ici**](https://github.com/axelexic/CSOps)) :&#x20;
```bash
csops -status <pid>
```
et vérifiez ensuite si le drapeau 0x800 est activé.
{% endhint %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
