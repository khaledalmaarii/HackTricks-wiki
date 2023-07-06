# macOS Binaires universels et format Mach-O

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

Ces binaires suivent la structure **Mach-O** qui est essentiellement composée de :

* En-tête
* Commandes de chargement
* Données

![](<../../../.gitbook/assets/image (559).png>)

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
uint32_t	offset;		/* décalage du fichier vers ce fichier objet */
uint32_t	size;		/* taille de ce fichier objet */
uint32_t	align;		/* alignement en puissance de 2 */
};
</code></pre>

L'en-tête contient les octets **magic** suivis du **nombre** d'**architectures** que le fichier **contient** (`nfat_arch`) et chaque architecture aura une structure `fat_arch`.

Vérifiez-le avec :

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O binaire universel avec 2 architectures : [x86_64: exécutable 64 bits Mach-O x86_64] [arm64e: exécutable 64 bits Mach-O arm64e]
/bin/ls (pour l'architecture x86_64) : exécutable 64 bits Mach-O x86_64
/bin/ls (pour l'architecture arm64e) : exécutable 64 bits Mach-O arm64e

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

<figure><img src="../../../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

Comme vous pouvez le penser, un binaire universel compilé pour 2 architectures **double la taille** de celui compilé pour une seule architecture.

## **En-tête Mach-O**

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
**Types de fichiers**:

* MH\_EXECUTE (0x2): Exécutable Mach-O standard
* MH\_DYLIB (0x6): Une bibliothèque dynamique Mach-O (c'est-à-dire .dylib)
* MH\_BUNDLE (0x8): Un bundle Mach-O (c'est-à-dire .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou en utilisant [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Commandes de chargement Mach-O**

Cela spécifie la **structure du fichier en mémoire**. Il contient l'**emplacement de la table des symboles**, le contexte du thread principal au début de l'exécution et les **bibliothèques partagées** requises.\
Les commandes indiquent essentiellement au chargeur dynamique **(dyld) comment charger le binaire en mémoire**.

Toutes les commandes de chargement commencent par une structure **load\_command**, définie dans le fichier **`loader.h`** mentionné précédemment:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Il existe environ **50 types différents de commandes de chargement** que le système traite différemment. Les plus courantes sont : `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` et `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Essentiellement, ce type de commande de chargement définit **comment charger les sections** qui sont stockées dans DATA lorsque le binaire est exécuté.
{% endhint %}

Ces commandes **définissent des segments** qui sont **mappés** dans l'espace **mémoire virtuelle** d'un processus lorsqu'il est exécuté.

Il existe **différents types** de segments, tels que le segment **\_\_TEXT**, qui contient le code exécutable d'un programme, et le segment **\_\_DATA**, qui contient les données utilisées par le processus. Ces **segments sont situés dans la section des données** du fichier Mach-O.

**Chaque segment** peut être **divisé** en plusieurs **sections**. La structure de la commande de chargement contient des **informations** sur **ces sections** dans le segment correspondant.

Dans l'en-tête, vous trouverez d'abord l'**en-tête du segment** :

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
</strong>	uint32_t	flags;		/* indicateurs */
};
</code></pre>

Exemple d'en-tête de segment :

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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
Exemple d'**en-tête de section** :

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Si vous **ajoutez** le **décalage de section** (0x37DC) + le **décalage** où **l'architecture commence**, dans ce cas `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Il est également possible d'obtenir des **informations d'en-tête** depuis la **ligne de commande** avec :
```bash
otool -lv /bin/ls
```
Segments communs chargés par cette commande :

* **`__PAGEZERO`** : Il indique au noyau de **mapper** l'**adresse zéro** de sorte qu'elle **ne puisse pas être lue, écrite ou exécutée**. Les variables maxprot et minprot dans la structure sont définies à zéro pour indiquer qu'il n'y a **aucun droit de lecture-écriture-exécution sur cette page**.
* Cette allocation est importante pour **atténuer les vulnérabilités de référence de pointeur NULL**.
* **`__TEXT`** : Contient du **code exécutable** et des **données en lecture seule**. Sections courantes de ce segment :
* `__text` : Code binaire compilé
* `__const` : Données constantes
* `__cstring` : Constantes de chaîne
* `__stubs` et `__stubs_helper` : Impliqués lors du processus de chargement de bibliothèque dynamique
* **`__DATA`** : Contient des données **modifiables**.
* `__data` : Variables globales (qui ont été initialisées)
* `__bss` : Variables statiques (qui n'ont pas été initialisées)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc) : Informations utilisées par le runtime Objective-C
* **`__LINKEDIT`** : Contient des informations pour le lien (dyld) telles que "symbole, chaîne et entrées de table de relocation".
* **`__OBJC`** : Contient des informations utilisées par le runtime Objective-C. Bien que ces informations puissent également être trouvées dans le segment \_\_DATA, dans diverses sections \_\_objc\_\*.

### **`LC_MAIN`**

Contient le point d'entrée dans l'attribut **entryoff**. Au moment du chargement, **dyld** ajoute simplement cette valeur à la **base du binaire en mémoire**, puis **saute** vers cette instruction pour démarrer l'exécution du code du binaire.

### **LC\_CODE\_SIGNATURE**

Contient des informations sur la **signature de code du fichier Mach-O**. Il contient uniquement un **décalage** qui **pointe** vers le **blob de signature**. Cela se trouve généralement à la toute fin du fichier.\
Cependant, vous pouvez trouver des informations sur cette section dans [**cet article de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) et ce [**gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Contient le **chemin vers l'exécutable du lien dynamique** qui mappe les bibliothèques partagées dans l'espace d'adressage du processus. La **valeur est toujours définie sur `/usr/lib/dyld`**. Il est important de noter que dans macOS, le mappage dylib se fait en **mode utilisateur**, et non en mode noyau.

### **`LC_LOAD_DYLIB`**

Cette commande de chargement décrit une **dépendance de bibliothèque dynamique** qui **instructe** le **chargeur** (dyld) à **charger et lier cette bibliothèque**. Il y a une commande de chargement LC\_LOAD\_DYLIB **pour chaque bibliothèque** requise par le binaire Mach-O.

* Cette commande de chargement est une structure de type **`dylib_command`** (qui contient une structure dylib, décrivant la bibliothèque dynamique dépendante réelle) :
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
![](<../../../.gitbook/assets/image (558).png>)

Vous pouvez également obtenir ces informations depuis la ligne de commande avec :
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Certaines bibliothèques potentiellement liées aux logiciels malveillants sont :

* **DiskArbitration** : Surveillance des lecteurs USB
* **AVFoundation** : Capture audio et vidéo
* **CoreWLAN** : Analyse des réseaux Wifi.

{% hint style="info" %}
Un binaire Mach-O peut contenir un ou **plusieurs** **constructeurs**, qui seront **exécutés** **avant** l'adresse spécifiée dans **LC\_MAIN**.\
Les offsets de tous les constructeurs sont stockés dans la section **\_\_mod\_init\_func** du segment **\_\_DATA\_CONST**.
{% endhint %}

## **Données Mach-O**

Le cœur du fichier est la région finale, les données, qui se composent de plusieurs segments tels qu'ils sont disposés dans la région des commandes de chargement. **Chaque segment peut contenir plusieurs sections de données**. Chacune de ces sections **contient du code ou des données** d'un type particulier.

{% hint style="success" %}
Les données sont essentiellement la partie contenant toutes les informations chargées par les commandes de chargement LC\_SEGMENTS\_64.
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

Cela inclut :

* **Table des fonctions** : qui contient des informations sur les fonctions du programme.
* **Table des symboles** : qui contient des informations sur les fonctions externes utilisées par le binaire.
* Elle peut également contenir des fonctions internes, des noms de variables, etc.

Pour vérifier cela, vous pouvez utiliser l'outil [**Mach-O View**](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Ou depuis la ligne de commande :
```bash
size -m /bin/ls
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
