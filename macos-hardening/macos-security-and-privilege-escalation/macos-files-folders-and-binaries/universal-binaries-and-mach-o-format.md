# macOS Binaires universels et format Mach-O

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

Ces binaires suivent la structure **Mach-O** qui est essentiellement composée de :

* En-tête
* Commandes de chargement
* Données

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## En-tête Fat

Recherchez le fichier avec : `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* nombre de structures qui suivent */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* spécificateur de CPU (int) */
cpu_subtype_t	cpusubtype;	/* spécificateur de machine (int) */
uint32_t	offset;		/* décalage de fichier vers ce fichier objet */
uint32_t	size;		/* taille de ce fichier objet */
uint32_t	align;		/* alignement en puissance de 2 */
};
</code></pre>

L'en-tête contient les octets **magic** suivis du **nombre** d'**architectures** contenues dans le fichier (`nfat_arch`) et chaque architecture aura une structure `fat_arch`.

Vérifiez-le avec :

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O binaire universel avec 2 architectures : [x86_64:Exécutable 64 bits Mach-O x86_64] [arm64e:Exécutable 64 bits Mach-O arm64e]
/bin/ls (pour l'architecture x86_64) : Exécutable 64 bits Mach-O x86_64
/bin/ls (pour l'architecture arm64e) : Exécutable 64 bits Mach-O arm64e

% otool -f -v /bin/ls
En-têtes Fat
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

ou en utilisant l'outil [Mach-O View](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Comme vous pouvez le penser, un binaire universel compilé pour 2 architectures **double la taille** de celui compilé pour seulement 1 architecture.

## En-tête Mach-O

L'en-tête contient des informations de base sur le fichier, telles que les octets magiques pour l'identifier comme un fichier Mach-O et des informations sur l'architecture cible. Vous pouvez le trouver dans : `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Types de fichiers Mach-O

Il existe différents types de fichiers, vous pouvez les trouver définis dans le [**code source par exemple ici**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Les plus importants sont :

* `MH_OBJECT` : Fichier objet relocatable (produits intermédiaires de la compilation, pas encore des exécutables).
* `MH_EXECUTE` : Fichiers exécutables.
* `MH_FVMLIB` : Fichier de bibliothèque VM fixe.
* `MH_CORE` : Dumps de code
* `MH_PRELOAD` : Fichier exécutable préchargé (plus pris en charge dans XNU)
* `MH_DYLIB` : Bibliothèques dynamiques
* `MH_DYLINKER` : Lien dynamique
* `MH_BUNDLE` : Fichiers "Plugin". Générés en utilisant -bundle dans gcc et chargés explicitement par `NSBundle` ou `dlopen`.
* `MH_DYSM` : Fichier compagnon `.dSym` (fichier avec des symboles pour le débogage).
* `MH_KEXT_BUNDLE` : Extensions du noyau.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou en utilisant [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Drapeaux Mach-O**

Le code source définit également plusieurs drapeaux utiles pour le chargement des bibliothèques :

* `MH_NOUNDEFS` : Pas de références non définies (entièrement liées)
* `MH_DYLDLINK` : Liaison Dyld
* `MH_PREBOUND` : Références dynamiques préliées.
* `MH_SPLIT_SEGS` : Fichier divise les segments r/o et r/w.
* `MH_WEAK_DEFINES` : Binaire a des symboles faiblement définis
* `MH_BINDS_TO_WEAK` : Binaire utilise des symboles faibles
* `MH_ALLOW_STACK_EXECUTION` : Rendre la pile exécutable
* `MH_NO_REEXPORTED_DYLIBS` : Bibliothèque sans commandes LC\_REEXPORT
* `MH_PIE` : Exécutable à position indépendante
* `MH_HAS_TLV_DESCRIPTORS` : Il y a une section avec des variables locales de thread
* `MH_NO_HEAP_EXECUTION` : Aucune exécution pour les pages de tas/données
* `MH_HAS_OBJC` : Le binaire a des sections oBject-C
* `MH_SIM_SUPPORT` : Support du simulateur
* `MH_DYLIB_IN_CACHE` : Utilisé sur les dylibs/frameworks dans le cache de bibliothèque partagée.

## **Commandes de chargement Mach-O**

La **disposition du fichier en mémoire** est spécifiée ici, détaillant l'emplacement de la **table des symboles**, le contexte du thread principal au démarrage de l'exécution, et les **bibliothèques partagées** requises. Des instructions sont fournies au chargeur dynamique **(dyld)** sur le processus de chargement du binaire en mémoire.

Il utilise la structure **load\_command**, définie dans le fichier **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Il existe environ **50 types de commandes de chargement** différents que le système gère différemment. Les plus courants sont : `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` et `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Essentiellement, ce type de commande de chargement définit **comment charger les segments \_\_TEXT** (code exécutable) **et \_\_DATA** (données du processus) **selon les décalages indiqués dans la section Data** lorsque le binaire est exécuté.
{% endhint %}

Ces commandes **définissent des segments** qui sont **cartographiés** dans l'**espace mémoire virtuel** d'un processus lors de son exécution.

Il existe **différents types** de segments, tels que le segment **\_\_TEXT**, qui contient le code exécutable d'un programme, et le segment **\_\_DATA**, qui contient les données utilisées par le processus. Ces **segments sont situés dans la section des données** du fichier Mach-O.

**Chaque segment** peut être **divisé en plusieurs sections**. La **structure de la commande de chargement** contient des **informations** sur **ces sections** dans le segment respectif.

Dans l'en-tête, vous trouvez d'abord l'**en-tête du segment** :

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* pour les architectures 64 bits */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* inclut la taille des structures section_64 */
char		segname[16];	/* nom du segment */
uint64_t	vmaddr;		/* adresse mémoire de ce segment */
uint64_t	vmsize;		/* taille mémoire de ce segment */
uint64_t	fileoff;	/* décalage du fichier de ce segment */
uint64_t	filesize;	/* quantité à mapper depuis le fichier */
int32_t		maxprot;	/* protection VM maximale */
int32_t		initprot;	/* protection VM initiale */
<strong>	uint32_t	nsects;		/* nombre de sections dans le segment */
</strong>	uint32_t	flags;		/* drapeaux */
};
</code></pre>

Exemple d'en-tête de segment :

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Cet en-tête définit le **nombre de sections dont les en-têtes apparaissent après** lui :
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
Exemple de **en-tête de section** :

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Si vous **ajoutez** le **décalage de section** (0x37DC) + le **décalage** où **l'architecture commence**, dans ce cas `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Il est également possible d'obtenir des **informations d'en-tête** à partir de la **ligne de commande** avec :
```bash
otool -lv /bin/ls
```
Les segments communs chargés par cette commande :

* **`__PAGEZERO` :** Il indique au noyau de **mapper** l'**adresse zéro** de sorte qu'elle **ne puisse pas être lue, écrite ou exécutée**. Les variables maxprot et minprot dans la structure sont définies à zéro pour indiquer qu'il n'y a **aucun droit de lecture-écriture-exécution sur cette page**.
* Cette allocation est importante pour **atténuer les vulnérabilités de déréférencement de pointeur NULL**. Cela est dû au fait que XNU impose une page zéro stricte qui garantit que la première page (seulement la première) de la mémoire est inaccessible (sauf en i386). Un binaire pourrait satisfaire ces exigences en créant un petit \_\_PAGEZERO (en utilisant `-pagezero_size`) pour couvrir les premiers 4 ko et en ayant le reste de la mémoire 32 bits accessible à la fois en mode utilisateur et en mode noyau.
* **`__TEXT` :** Contient du **code exécutable** avec des autorisations de **lecture** et d'**exécution** (non inscriptible)**.** Sections courantes de ce segment :
  * `__text` : Code binaire compilé
  * `__const` : Données constantes (lecture seule)
  * `__[c/u/os_log]string` : Constantes de chaînes C, Unicode ou de journaux os
  * `__stubs` et `__stubs_helper` : Impliqués lors du processus de chargement de bibliothèque dynamique
  * `__unwind_info` : Données de déroulement de pile.
* Notez que tout ce contenu est signé mais également marqué comme exécutable (créant plus d'options pour l'exploitation de sections qui n'ont pas nécessairement besoin de ce privilège, comme les sections dédiées aux chaînes).
* **`__DATA` :** Contient des données **lisibles** et **inscriptibles** (non exécutables)**.**
  * `__got` : Table des décalages globaux
  * `__nl_symbol_ptr` : Pointeur de symbole non paresseux (lié au chargement)
  * `__la_symbol_ptr` : Pointeur de symbole paresseux (lié à l'utilisation)
  * `__const` : Devrait être des données en lecture seule (pas vraiment)
  * `__cfstring` : Chaînes CoreFoundation
  * `__data` : Variables globales (qui ont été initialisées)
  * `__bss` : Variables statiques (qui n'ont pas été initialisées)
  * `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc) : Informations utilisées par le runtime Objective-C
* **`__DATA_CONST` :** \_\_DATA.\_\_const n'est pas garanti d'être constant (autorisations d'écriture), pas plus que les autres pointeurs et la GOT. Cette section rend `__const`, certains initialiseurs et la table GOT (une fois résolue) **en lecture seule** en utilisant `mprotect`.
* **`__LINKEDIT` :** Contient des informations pour le chargeur (dyld) telles que les entrées de table de symboles, de chaînes et de réadressage. C'est un conteneur générique pour les contenus qui ne sont ni dans `__TEXT` ni dans `__DATA` et son contenu est décrit dans d'autres commandes de chargement.
* Informations dyld : Rebase, opcodes de liaison non paresseux/paresseux/faibles et infos d'exportation
* Début des fonctions : Table des adresses de début des fonctions
* Données dans le code : Îlots de données dans \_\_text
* Table des symboles : Symboles dans le binaire
* Table des symboles indirects : Symboles de pointeur/stub
* Table des chaînes
* Signature de code
* **`__OBJC` :** Contient des informations utilisées par le runtime Objective-C. Bien que ces informations puissent également être trouvées dans le segment \_\_DATA, dans diverses sections \_\_objc\_\*.
* **`__RESTRICT` :** Un segment sans contenu avec une seule section appelée **`__restrict`** (également vide) qui garantit qu'en exécutant le binaire, il ignorera les variables d'environnement DYLD.

Comme il a été possible de le voir dans le code, **les segments prennent également en charge des indicateurs** (bien qu'ils ne soient pas beaucoup utilisés) :

* `SG_HIGHVM` : Core uniquement (non utilisé)
* `SG_FVMLIB` : Non utilisé
* `SG_NORELOC` : Le segment n'a pas de réadressage
* `SG_PROTECTED_VERSION_1` : Chiffrement. Utilisé par exemple par Finder pour chiffrer le segment de texte `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contient le point d'entrée dans l'attribut **entryoff**. Au moment du chargement, **dyld** ajoute simplement cette valeur à la **base du binaire en mémoire**, puis **saute** vers cette instruction pour démarrer l'exécution du code du binaire.

**`LC_UNIXTHREAD`** contient les valeurs que les registres doivent avoir au démarrage du thread principal. Cela a déjà été obsolète mais **`dyld`** l'utilise toujours. Il est possible de voir les valeurs des registres définies par ceci avec :
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

Contient des informations sur la **signature de code du fichier Mach-O**. Il ne contient qu'un **décalage** qui **pointe** vers le **blob de signature**. Cela se trouve généralement à la toute fin du fichier.\
Cependant, vous pouvez trouver des informations sur cette section dans [**cet article de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) et ce [**gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Prise en charge du chiffrement binaire. Cependant, bien sûr, si un attaquant parvient à compromettre le processus, il pourra extraire la mémoire non chiffrée.

### **`LC_LOAD_DYLINKER`**

Contient le **chemin de l'exécutable du chargeur dynamique** qui mappe les bibliothèques partagées dans l'espace d'adressage du processus. La **valeur est toujours définie sur `/usr/lib/dyld`**. Il est important de noter que sous macOS, le mappage des dylib se fait en **mode utilisateur**, et non en mode noyau.

### **`LC_IDENT`**

Obsolète mais lorsqu'il est configuré pour générer des vidages en cas de panique, un vidage de base Mach-O est créé et la version du noyau est définie dans la commande `LC_IDENT`.

### **`LC_UUID`**

UUID aléatoire. Il n'est pas directement utile mais XNU le met en cache avec le reste des informations du processus. Il peut être utilisé dans les rapports de plantage.

### **`LC_DYLD_ENVIRONMENT`**

Permet d'indiquer des variables d'environnement à dyld avant l'exécution du processus. Cela peut être très dangereux car cela peut permettre d'exécuter du code arbitraire à l'intérieur du processus, donc cette commande de chargement n'est utilisée que dans dyld construit avec `#define SUPPORT_LC_DYLD_ENVIRONMENT` et restreint davantage le traitement uniquement aux variables de la forme `DYLD_..._PATH` spécifiant les chemins de chargement.

### **`LC_LOAD_DYLIB`**

Cette commande de chargement décrit une **dépendance de bibliothèque dynamique** qui **indique** au **chargeur** (dyld) de **charger et lier ladite bibliothèque**. Il y a une commande de chargement `LC_LOAD_DYLIB` **pour chaque bibliothèque** requise par le binaire Mach-O.

* Cette commande de chargement est une structure de type **`dylib_command`** (qui contient une structure dylib, décrivant la bibliothèque dynamique dépendante réelle):
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![](<../../../.gitbook/assets/image (486).png>)

Vous pouvez également obtenir ces informations depuis l'interface de ligne de commande avec :
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Certains bibliothèques potentiellement liées aux logiciels malveillants sont :

* **DiskArbitration** : Surveillance des lecteurs USB
* **AVFoundation** : Capture audio et vidéo
* **CoreWLAN** : Balayages Wifi.

{% hint style="info" %}
Un binaire Mach-O peut contenir un ou **plusieurs** **constructeurs**, qui seront **exécutés** **avant** l'adresse spécifiée dans **LC\_MAIN**.\
Les décalages de tous les constructeurs sont conservés dans la section **\_\_mod\_init\_func** du segment **\_\_DATA\_CONST**.
{% endhint %}

## **Données Mach-O**

Au cœur du fichier se trouve la région des données, composée de plusieurs segments tels que définis dans la région des commandes de chargement. **Une variété de sections de données peut être contenue dans chaque segment**, chaque section **contenant du code ou des données** spécifiques à un type.

{% hint style="success" %}
Les données sont essentiellement la partie contenant toutes les **informations** chargées par les commandes de chargement **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Cela inclut :

* **Table des fonctions** : Qui contient des informations sur les fonctions du programme.
* **Table des symboles** : Qui contient des informations sur les fonctions externes utilisées par le binaire
* Il pourrait également contenir des noms de fonctions internes, des noms de variables et plus encore.

Pour vérifier, vous pouvez utiliser l'outil [**Mach-O View**](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou depuis la ligne de commande :
```bash
size -m /bin/ls
```
## Sections Communes d'Objective-C

Dans le segment `__TEXT` (r-x) :

- `__objc_classname` : Noms de classe (chaînes de caractères)
- `__objc_methname` : Noms de méthode (chaînes de caractères)
- `__objc_methtype` : Types de méthode (chaînes de caractères)

Dans le segment `__DATA` (rw-) :

- `__objc_classlist` : Pointeurs vers toutes les classes Objective-C
- `__objc_nlclslist` : Pointeurs vers les classes Objective-C non paresseuses
- `__objc_catlist` : Pointeur vers les catégories
- `__objc_nlcatlist` : Pointeur vers les catégories non paresseuses
- `__objc_protolist` : Liste de protocoles
- `__objc_const` : Données constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
