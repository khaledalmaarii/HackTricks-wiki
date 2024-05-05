# macOS IOKit

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

L'IO Kit est un **cadre de pilote de périphérique** orienté objet open source dans le noyau XNU, gère les **pilotes de périphériques chargés dynamiquement**. Il permet d'ajouter du code modulaire au noyau à la volée, prenant en charge du matériel divers.

Les pilotes IOKit **exportent essentiellement des fonctions du noyau**. Les types de paramètres de ces fonctions sont **prédéfinis** et vérifiés. De plus, tout comme XPC, IOKit est juste une autre couche au **dessus des messages Mach**.

Le code **noyau IOKit XNU** est open source par Apple sur [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). De plus, les composants IOKit de l'espace utilisateur sont également open source sur [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Cependant, **aucun pilote IOKit** n'est open source. De toute façon, de temps en temps, une version d'un pilote peut être publiée avec des symboles qui facilitent le débogage. Consultez comment **obtenir les extensions de pilote à partir du micrologiciel ici**](./#ipsw)**.

Il est écrit en **C++**. Vous pouvez obtenir des symboles C++ démanglés avec :
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Les fonctions exposées par IOKit pourraient effectuer des vérifications de sécurité supplémentaires lorsqu'un client tente d'appeler une fonction, mais notez que les applications sont généralement limitées par le bac à sable quant aux fonctions IOKit avec lesquelles elles peuvent interagir.
{% endhint %}

## Pilotes

Sur macOS, ils se trouvent dans :

- **`/System/Library/Extensions`**
- Fichiers KEXT intégrés au système d'exploitation OS X.
- **`/Library/Extensions`**
- Fichiers KEXT installés par des logiciels tiers

Sur iOS, ils se trouvent dans :

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Jusqu'au numéro 9, les pilotes répertoriés sont **chargés à l'adresse 0**. Cela signifie que ce ne sont pas de vrais pilotes mais **font partie du noyau et ne peuvent pas être déchargés**.

Pour trouver des extensions spécifiques, vous pouvez utiliser :
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Pour charger et décharger des extensions de noyau, faites :
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Le **IORegistry** est une partie cruciale du framework IOKit dans macOS et iOS qui sert de base de données pour représenter la configuration matérielle et l'état du système. C'est une **collection hiérarchique d'objets qui représentent tout le matériel et les pilotes** chargés sur le système, ainsi que leurs relations mutuelles.

Vous pouvez obtenir l'IORegistry en utilisant la commande **`ioreg`** pour l'inspecter depuis la console (particulièrement utile pour iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Vous pouvez télécharger **`IORegistryExplorer`** depuis les **Outils Additionnels Xcode** sur [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) et inspecter le **IORegistry macOS** à travers une interface **graphique**.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Dans IORegistryExplorer, les "planes" sont utilisés pour organiser et afficher les relations entre différents objets dans l'IORegistry. Chaque plane représente un type spécifique de relation ou une vue particulière de la configuration matérielle et des pilotes du système. Voici quelques-uns des planes courants que vous pourriez rencontrer dans IORegistryExplorer :

1. **Plane IOService** : Il s'agit du plane le plus général, affichant les objets de service qui représentent les pilotes et les nœuds (canaux de communication entre les pilotes). Il montre les relations fournisseur-client entre ces objets.
2. **Plane IODeviceTree** : Ce plane représente les connexions physiques entre les appareils tels qu'ils sont attachés au système. Il est souvent utilisé pour visualiser la hiérarchie des appareils connectés via des bus comme USB ou PCI.
3. **Plane IOPower** : Affiche les objets et leurs relations en termes de gestion de l'alimentation. Il peut montrer quels objets affectent l'état d'alimentation des autres, utile pour le débogage des problèmes liés à l'alimentation.
4. **Plane IOUSB** : Spécifiquement axé sur les appareils USB et leurs relations, montrant la hiérarchie des concentrateurs USB et des appareils connectés.
5. **Plane IOAudio** : Ce plane est pour représenter les appareils audio et leurs relations au sein du système.
6. ...

## Exemple de Code de Communication du Pilote

Le code suivant se connecte au service IOKit `"VotreNomDeServiceIci"` et appelle la fonction à l'intérieur du sélecteur 0. Pour cela :

* il appelle d'abord **`IOServiceMatching`** et **`IOServiceGetMatchingServices`** pour obtenir le service.
* Il établit ensuite une connexion en appelant **`IOServiceOpen`**.
* Et enfin, il appelle une fonction avec **`IOConnectCallScalarMethod`** en indiquant le sélecteur 0 (le sélecteur est le numéro attribué à la fonction que vous souhaitez appeler).
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
Il existe **d'autres** fonctions qui peuvent être utilisées pour appeler des fonctions IOKit en dehors de **`IOConnectCallScalarMethod`** comme **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Inversion du point d'entrée du pilote

Vous pourriez les obtenir par exemple à partir d'une [**image du micrologiciel (ipsw)**](./#ipsw). Ensuite, chargez-la dans votre décompilateur préféré.

Vous pourriez commencer à décompiler la fonction **`externalMethod`** car c'est la fonction du pilote qui recevra l'appel et appellera la fonction correcte :

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

Cet appel horrible démêlé signifie :

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Notez comment dans la définition précédente le paramètre **`self`** est manquant, la bonne définition serait :

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

En fait, vous pouvez trouver la définition réelle dans [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Avec ces informations, vous pouvez réécrire Ctrl+Right -> `Modifier la signature de la fonction` et définir les types connus :

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Le nouveau code décomplié ressemblera à ceci :

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Pour l'étape suivante, nous devons avoir défini la structure **`IOExternalMethodDispatch2022`**. C'est open source sur [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), vous pouvez le définir :

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Maintenant, en suivant `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, vous pouvez voir beaucoup de données :

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Changez le type de données en **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

après le changement :

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Et comme nous le savons maintenant, nous avons un **tableau de 7 éléments** (vérifiez le code décomplié final), cliquez pour créer un tableau de 7 éléments :

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Une fois le tableau créé, vous pouvez voir toutes les fonctions exportées :

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Si vous vous souvenez, pour **appeler** une fonction **exportée** depuis l'espace utilisateur, nous n'avons pas besoin d'appeler le nom de la fonction, mais le **numéro de sélecteur**. Ici, vous pouvez voir que le sélecteur **0** est la fonction **`initializeDecoder`**, le sélecteur **1** est **`startDecoder`**, le sélecteur **2** **`initializeEncoder`**...
{% endhint %}
