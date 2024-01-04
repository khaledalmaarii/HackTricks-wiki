# Binaires universels macOS & Format Mach-O

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

Ces binaires suivent la **structure Mach-O** qui est composée essentiellement de :

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
<strong>	uint32_t	magic;		/* FAT_MAGIC ou FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* nombre de structures qui suivent */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* spécificateur de CPU (int) */
cpu_subtype_t	cpusubtype;	/* spécificateur de machine (int) */
uint32_t	offset;		/* décalage dans le fichier vers ce fichier objet */
uint32_t	size;		/* taille de ce fichier objet */
uint32_t	align;		/* alignement en puissance de 2 */
};
</code></pre>

L'en-tête contient les octets **magic** suivis du **nombre** d'**architectures** que le fichier **contient** (`nfat_arch`) et chaque architecture aura une structure `fat_arch`.

Vérifiez-le avec :

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: binaire universel Mach-O avec 2 architectures : [x86_64 : exécutable Mach-O 64 bits x86_64] [arm64e : exécutable Mach-O 64 bits arm64e]
/bin/ls (pour l'architecture x86_64) :	exécutable Mach-O 64 bits x86_64
/bin/ls (pour l'architecture arm64e) :	exécutable Mach-O 64 bits arm64e

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

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Comme vous pouvez le penser, un binaire universel compilé pour 2 architectures **double généralement la taille** d'un compilé pour juste 1 arch.

## En-tête **Mach-O**

L'en-tête contient des informations de base sur le fichier, telles que les octets magiques pour l'identifier en tant que fichier Mach-O et des informations sur l'architecture cible. Vous pouvez le trouver dans : `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Types de fichiers** :

* MH\_EXECUTE (0x2) : Exécutable Mach-O standard
* MH\_DYLIB (0x6) : Bibliothèque liée dynamiquement Mach-O (par exemple, .dylib)
* MH\_BUNDLE (0x8) : Bundle Mach-O (par exemple, .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou en utilisant [Mach-O View](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Commandes de chargement Mach-O**

Cela spécifie **la disposition du fichier en mémoire**. Il contient **l'emplacement de la table des symboles**, le contexte du thread principal au début de l'exécution, et quelles **bibliothèques partagées** sont requises.
Les commandes instruisent essentiellement le chargeur dynamique **(dyld) sur la manière de charger le binaire en mémoire**.

Toutes les commandes de chargement commencent par une structure **load\_command**, définie dans le **`loader.h`** mentionné précédemment :
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Il existe environ **50 types différents de commandes de chargement** que le système gère différemment. Les plus courantes sont : `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` et `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
En gros, ce type de commande de chargement définit **comment charger les segments \_\_TEXT** (code exécutable) **et \_\_DATA** (données pour le processus) selon les **décalages indiqués dans la section des données** lorsque le binaire est exécuté.
{% endhint %}

Ces commandes **définissent des segments** qui sont **cartographiés** dans l'**espace mémoire virtuel** d'un processus lorsqu'il est exécuté.

Il existe **différents types** de segments, tels que le segment **\_\_TEXT**, qui contient le code exécutable d'un programme, et le segment **\_\_DATA**, qui contient les données utilisées par le processus. Ces **segments sont situés dans la section des données** du fichier Mach-O.

**Chaque segment** peut être encore **divisé** en plusieurs **sections**. La **structure de commande de chargement** contient des **informations** sur **ces sections** au sein du segment respectif.

Dans l'en-tête, vous trouvez d'abord l'**en-tête de segment** :

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* pour les architectures 64 bits */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* inclut la taille des structures section_64 */
char		segname[16];	/* nom du segment */
uint64_t	vmaddr;		/* adresse mémoire de ce segment */
uint64_t	vmsize;		/* taille mémoire de ce segment */
uint64_t	fileoff;	/* décalage du fichier de ce segment */
uint64_t	filesize;	/* quantité à mapper depuis le fichier */
int32_t		maxprot;	/* protection maximale de la VM */
int32_t		initprot;	/* protection initiale de la VM */
<strong>	uint32_t	nsects;		/* nombre de sections dans le segment */
</strong>	uint32_t	flags;		/* drapeaux */
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
Exemple de **titre de section** :

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Si vous **ajoutez** le **décalage de section** (0x37DC) + le **décalage** où l'**architecture commence**, dans ce cas `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Il est également possible d'obtenir des **informations d'en-tête** depuis la **ligne de commande** avec :
```bash
otool -lv /bin/ls
```
Segments courants chargés par cette cmd :

* **`__PAGEZERO` :** Il indique au noyau de **mapper** l'**adresse zéro** de sorte qu'elle **ne puisse être lue, écrite ou exécutée**. Les variables maxprot et minprot dans la structure sont définies à zéro pour indiquer qu'il n'y a **aucun droit de lecture-écriture-exécution sur cette page**.
* Cette allocation est importante pour **atténuer les vulnérabilités de déréférencement de pointeur NULL**.
* **`__TEXT` :** Contient du **code exécutable** avec des permissions de **lecture** et **d'exécution** (non modifiable)**.** Sections courantes de ce segment :
* `__text` : Code binaire compilé
* `__const` : Données constantes
* `__cstring` : Constantes de chaînes de caractères
* `__stubs` et `__stubs_helper` : Impliqués pendant le processus de chargement de la bibliothèque dynamique
* **`__DATA` :** Contient des données qui sont **lisibles** et **modifiables** (non exécutables)**.**
* `__data` : Variables globales (qui ont été initialisées)
* `__bss` : Variables statiques (qui n'ont pas été initialisées)
* `__objc_*` (__objc_classlist, __objc_protolist, etc) : Informations utilisées par le runtime Objective-C
* **`__LINKEDIT` :** Contient des informations pour l'éditeur de liens (dyld) telles que "les entrées de tableaux de symboles, de chaînes et de relocalisation."
* **`__OBJC` :** Contient des informations utilisées par le runtime Objective-C. Bien que ces informations puissent également se trouver dans le segment __DATA, dans diverses sections __objc_*.

### **`LC_MAIN`**

Contient le point d'entrée dans l'**attribut entryoff.** Au moment du chargement, **dyld** ajoute simplement cette valeur à la **base (en mémoire) du binaire**, puis **saute** à cette instruction pour commencer l'exécution du code du binaire.

### **LC_CODE_SIGNATURE**

Contient des informations sur la **signature de code du fichier Mach-O**. Il contient uniquement un **décalage** qui **pointe** vers le **blob de signature**. Cela se trouve généralement à la toute fin du fichier.
Cependant, vous pouvez trouver des informations sur cette section dans [**ce billet de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) et ce [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC_LOAD_DYLINKER**

Contient le **chemin vers l'exécutable du lieur dynamique** qui mappe les bibliothèques partagées dans l'espace d'adressage du processus. La **valeur est toujours définie sur `/usr/lib/dyld`**. Il est important de noter que sous macOS, le mappage de dylib se fait en **mode utilisateur**, et non en mode noyau.

### **`LC_LOAD_DYLIB`**

Cette commande de chargement décrit une dépendance de **bibliothèque dynamique** qui **instruit** le **chargeur** (dyld) de **charger et lier ladite bibliothèque**. Il y a une commande de chargement LC_LOAD_DYLIB **pour chaque bibliothèque** dont le binaire Mach-O a besoin.

* Cette commande de chargement est une structure de type **`dylib_command`** (qui contient une struct dylib, décrivant la bibliothèque dynamique dépendante réelle) :
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
```markdown
Vous pouvez également obtenir ces informations depuis le cli avec :
```
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Certaines bibliothèques potentiellement liées à des malwares sont :

* **DiskArbitration** : Surveillance des clés USB
* **AVFoundation** : Capture audio et vidéo
* **CoreWLAN** : Scans Wifi.

{% hint style="info" %}
Un binaire Mach-O peut contenir un ou **plusieurs** **constructeurs**, qui seront **exécutés** **avant** l'adresse spécifiée dans **LC\_MAIN**.
Les décalages de tous les constructeurs se trouvent dans la section **\_\_mod\_init\_func** du segment **\_\_DATA\_CONST**.
{% endhint %}

## **Données Mach-O**

Le cœur du fichier est la région finale, les données, qui se compose de plusieurs segments tels qu'organisés dans la région des commandes de chargement. **Chaque segment peut contenir un certain nombre de sections de données**. Chacune de ces sections **contient du code ou des données** d'un type particulier.

{% hint style="success" %}
Les données sont essentiellement la partie contenant toutes les **informations** qui sont chargées par les commandes de chargement **LC\_SEGMENTS\_64**
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

Cela inclut :

* **Table des fonctions** : Qui contient des informations sur les fonctions du programme.
* **Table des symboles** : Qui contient des informations sur la fonction externe utilisée par le binaire
* Elle pourrait également contenir des noms de fonctions internes, de variables et plus encore.

Pour le vérifier, vous pourriez utiliser l'outil [**Mach-O View**](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Ou depuis le cli :
```bash
size -m /bin/ls
```
<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
