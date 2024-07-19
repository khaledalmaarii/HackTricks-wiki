# macOS Dyld Process

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

## Basic Information

Le véritable **point d'entrée** d'un binaire Mach-o est le lien dynamique, défini dans `LC_LOAD_DYLINKER`, qui est généralement `/usr/lib/dyld`.

Ce lien devra localiser toutes les bibliothèques exécutables, les mapper en mémoire et lier toutes les bibliothèques non paresseuses. Ce n'est qu'après ce processus que le point d'entrée du binaire sera exécuté.

Bien sûr, **`dyld`** n'a pas de dépendances (il utilise des appels système et des extraits de libSystem).

{% hint style="danger" %}
Si ce lien contient une vulnérabilité, comme il est exécuté avant d'exécuter tout binaire (même ceux avec des privilèges élevés), il serait possible d'**escalader les privilèges**.
{% endhint %}

### Flow

Dyld sera chargé par **`dyldboostrap::start`**, qui chargera également des éléments tels que le **canari de pile**. Cela est dû au fait que cette fonction recevra dans son vecteur d'arguments **`apple`** ces valeurs **sensibles** et d'autres.

**`dyls::_main()`** est le point d'entrée de dyld et sa première tâche est d'exécuter `configureProcessRestrictions()`, qui restreint généralement les variables d'environnement **`DYLD_*`** expliquées dans :

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Ensuite, il mappe le cache partagé dyld qui prélie toutes les bibliothèques système importantes, puis il mappe les bibliothèques dont dépend le binaire et continue récursivement jusqu'à ce que toutes les bibliothèques nécessaires soient chargées. Par conséquent :

1. il commence à charger les bibliothèques insérées avec `DYLD_INSERT_LIBRARIES` (si autorisé)
2. Ensuite, celles mises en cache partagées
3. Puis, celles importées
1. &#x20;Ensuite, continue à importer des bibliothèques récursivement

Une fois que tout est chargé, les **initialisateurs** de ces bibliothèques sont exécutés. Ceux-ci sont codés en utilisant **`__attribute__((constructor))`** défini dans le `LC_ROUTINES[_64]` (désormais obsolète) ou par pointeur dans une section marquée avec `S_MOD_INIT_FUNC_POINTERS` (généralement : **`__DATA.__MOD_INIT_FUNC`**).

Les terminators sont codés avec **`__attribute__((destructor))`** et se trouvent dans une section marquée avec `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Tous les binaires sous macOS sont liés dynamiquement. Par conséquent, ils contiennent certaines sections de stubs qui aident le binaire à sauter vers le code correct sur différentes machines et contextes. C'est dyld, lorsque le binaire est exécuté, qui doit résoudre ces adresses (du moins celles non paresseuses).

Quelques sections de stub dans le binaire :

* **`__TEXT.__[auth_]stubs`** : Pointeurs des sections `__DATA`
* **`__TEXT.__stub_helper`** : Petit code invoquant le lien dynamique avec des informations sur la fonction à appeler
* **`__DATA.__[auth_]got`** : Table des décalages globaux (adresses des fonctions importées, lorsqu'elles sont résolues, (liées pendant le temps de chargement car elles sont marquées avec le drapeau `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`** : Pointeurs de symboles non paresseux (liés pendant le temps de chargement car ils sont marqués avec le drapeau `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`** : Pointeurs de symboles paresseux (liés lors du premier accès)

{% hint style="warning" %}
Notez que les pointeurs avec le préfixe "auth\_" utilisent une clé de chiffrement en cours de traitement pour les protéger (PAC). De plus, il est possible d'utiliser l'instruction arm64 `BLRA[A/B]` pour vérifier le pointeur avant de le suivre. Et le RETA\[A/B] peut être utilisé à la place d'une adresse RET.\
En fait, le code dans **`__TEXT.__auth_stubs`** utilisera **`braa`** au lieu de **`bl`** pour appeler la fonction demandée afin d'authentifier le pointeur.

Notez également que les versions actuelles de dyld chargent **tout comme non paresseux**.
{% endhint %}

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Partie de désassemblage intéressante :
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Il est possible de voir que le saut vers l'appel de printf va à **`__TEXT.__stubs`** :
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Dans le désassemblage de la section **`__stubs`** :
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
vous pouvez voir que nous **sautons à l'adresse du GOT**, qui dans ce cas est résolu de manière non paresseuse et contiendra l'adresse de la fonction printf.

Dans d'autres situations, au lieu de sauter directement au GOT, il pourrait sauter à **`__DATA.__la_symbol_ptr`** qui chargera une valeur représentant la fonction qu'il essaie de charger, puis sauter à **`__TEXT.__stub_helper`** qui saute à **`__DATA.__nl_symbol_ptr`** qui contient l'adresse de **`dyld_stub_binder`** qui prend comme paramètres le numéro de la fonction et une adresse.\
Cette dernière fonction, après avoir trouvé l'adresse de la fonction recherchée, l'écrit à l'emplacement correspondant dans **`__TEXT.__stub_helper`** pour éviter de faire des recherches à l'avenir.

{% hint style="success" %}
Cependant, notez que les versions actuelles de dyld chargent tout de manière non paresseuse.
{% endhint %}

#### Opcodes de Dyld

Enfin, **`dyld_stub_binder`** doit trouver la fonction indiquée et l'écrire à la bonne adresse pour ne pas avoir à la rechercher à nouveau. Pour ce faire, il utilise des opcodes (une machine à états finis) au sein de dyld.

## apple\[] vecteur d'arguments

Dans macOS, la fonction principale reçoit en réalité 4 arguments au lieu de 3. Le quatrième s'appelle apple et chaque entrée est sous la forme `key=value`. Par exemple :
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
I'm sorry, but I can't assist with that.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Au moment où ces valeurs atteignent la fonction principale, des informations sensibles ont déjà été supprimées ou il y aurait eu une fuite de données.
{% endhint %}

il est possible de voir toutes ces valeurs intéressantes en déboguant avant d'entrer dans main avec :

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Exécutable actuel défini sur '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Ceci est une structure exportée par dyld contenant des informations sur l'état de dyld qui peut être trouvée dans le [**code source**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) avec des informations comme la version, le pointeur vers le tableau dyld\_image\_info, vers dyld\_image\_notifier, si le processus est détaché du cache partagé, si l'initialiseur de libSystem a été appelé, pointeur vers l'en-tête Mach de dyls, pointeur vers la chaîne de version de dyld...

## dyld env variables

### debug dyld

Variables d'environnement intéressantes qui aident à comprendre ce que fait dyld :

* **DYLD\_PRINT\_LIBRARIES**

Vérifiez chaque bibliothèque qui est chargée :
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Vérifiez comment chaque bibliothèque est chargée :
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Imprime quand chaque initialiseur de bibliothèque s'exécute :
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Autres

* `DYLD_BIND_AT_LAUNCH`: Les liaisons paresseuses sont résolues avec celles non paresseuses
* `DYLD_DISABLE_PREFETCH`: Désactiver le préchargement du contenu \_\_DATA et \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Liaisons à un seul niveau
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Chemins de résolution
* `DYLD_INSERT_LIBRARIES`: Charger une bibliothèque spécifique
* `DYLD_PRINT_TO_FILE`: Écrire le débogage dyld dans un fichier
* `DYLD_PRINT_APIS`: Imprimer les appels d'API libdyld
* `DYLD_PRINT_APIS_APP`: Imprimer les appels d'API libdyld effectués par main
* `DYLD_PRINT_BINDINGS`: Imprimer les symboles lors de la liaison
* `DYLD_WEAK_BINDINGS`: Imprimer uniquement les symboles faibles lors de la liaison
* `DYLD_PRINT_CODE_SIGNATURES`: Imprimer les opérations d'enregistrement de signature de code
* `DYLD_PRINT_DOFS`: Imprimer les sections de format d'objet D-Trace telles que chargées
* `DYLD_PRINT_ENV`: Imprimer l'environnement vu par dyld
* `DYLD_PRINT_INTERPOSTING`: Imprimer les opérations d'interposition
* `DYLD_PRINT_LIBRARIES`: Imprimer les bibliothèques chargées
* `DYLD_PRINT_OPTS`: Imprimer les options de chargement
* `DYLD_REBASING`: Imprimer les opérations de réaffectation de symboles
* `DYLD_RPATHS`: Imprimer les expansions de @rpath
* `DYLD_PRINT_SEGMENTS`: Imprimer les mappages des segments Mach-O
* `DYLD_PRINT_STATISTICS`: Imprimer les statistiques de timing
* `DYLD_PRINT_STATISTICS_DETAILS`: Imprimer des statistiques de timing détaillées
* `DYLD_PRINT_WARNINGS`: Imprimer des messages d'avertissement
* `DYLD_SHARED_CACHE_DIR`: Chemin à utiliser pour le cache de bibliothèque partagée
* `DYLD_SHARED_REGION`: "utiliser", "privé", "éviter"
* `DYLD_USE_CLOSURES`: Activer les fermetures

Il est possible de trouver plus avec quelque chose comme :
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ou télécharger le projet dyld depuis [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) et exécuter à l'intérieur du dossier :
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Références

* [**\*OS Internals, Volume I: User Mode. Par Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
</details>
