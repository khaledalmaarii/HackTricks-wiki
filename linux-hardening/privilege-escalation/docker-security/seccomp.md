# Seccomp

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine çıkarın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

**Seccomp**, Linux çekirdeğinin bir güvenlik özelliğidir ve **sistem çağrılarını filtrelemek** için tasarlanmıştır. Bu, işlemleri sınırlı bir sistem çağrısı kümesine (`exit()`, `sigreturn()`, `read()` ve `write()`) kısıtlar. Bir işlem başka bir şey çağırmaya çalışırsa, çekirdek tarafından SIGKILL veya SIGSYS kullanılarak sonlandırılır. Bu mekanizma kaynakları sanallaştırmaz, ancak işlemi onlardan izole eder.

Seccomp'i etkinleştirmenin iki yolu vardır: `prctl(2)` sistem çağrısıyla `PR_SET_SECCOMP` kullanarak veya Linux çekirdekleri 3.17 ve üstü için `seccomp(2)` sistem çağrısıyla. Seccomp'i etkinleştirmenin eski yöntemi, `/proc/self/seccomp`'a yazarak seccomp'i etkinleştirmekti, ancak bu yöntem `prctl()` lehine kullanımdan kaldırılmıştır.

Bir geliştirme olan **seccomp-bpf**, özelleştirilebilir bir politika ile sistem çağrılarını filtreleme yeteneği ekler ve Berkeley Packet Filter (BPF) kurallarını kullanır. Bu uzantı, OpenSSH, vsftpd ve Chrome OS ve Linux üzerindeki Chrome/Chromium tarayıcıları gibi yazılımlar tarafından kullanılır ve eski desteklenmeyen systrace için esnek ve verimli sistem çağrısı filtreleme sağlar.

### **Orijinal/Katı Mod**

Bu modda Seccomp, yalnızca `exit()`, `sigreturn()`, `read()` ve `write()` sistem çağrılarına izin verir. Başka bir sistem çağrısı yapılırsa, işlem SIGKILL kullanılarak sonlandırılır.

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
{% endcode %}

### Seccomp-bpf

Bu mod, Berkeley Packet Filter kuralları kullanılarak uygulanan yapılandırılabilir bir politika ile sistem çağrılarının filtrelenmesine izin verir.

{% code title="seccomp_bpf.c" %}
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
{% endcode %}

## Docker'da Seccomp

**Seccomp-bpf**, **Docker** tarafından desteklenir ve konteynerlerden gelen **sistem çağrılarını** kısıtlamak için kullanılır, böylece yüzey alanı azaltılır. **Varsayılan olarak engellenen sistem çağrılarını** [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) adresinde bulabilirsiniz ve **varsayılan seccomp profili** burada bulunabilir: [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Farklı bir seccomp politikasıyla bir docker konteyneri çalıştırabilirsiniz:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Örneğin, `uname` gibi bazı **sistem çağrılarının** bir konteyner tarafından **yürütülmesini yasaklamak** istiyorsanız, varsayılan profil dosyasını [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) adresinden indirebilir ve sadece listeden `uname` dizesini **kaldırabilirsiniz**.\
Bir **docker konteyneri içinde bazı ikili dosyaların çalışmadığından** emin olmak isterseniz, strace kullanarak ikili dosyanın kullandığı sistem çağrılarını listelemek ve ardından bunları yasaklamak mümkündür.\
Aşağıdaki örnekte, `uname`'in sistem çağrıları keşfedilir:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Eğer sadece bir uygulama başlatmak için Docker kullanıyorsanız, onu `strace` ile **profilleyebilir** ve sadece ihtiyaç duyduğu sistem çağrılarını **izin verebilirsiniz**.
{% endhint %}

### Örnek Seccomp politikası

[Örnek buradan alınmıştır](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Seccomp özelliğini göstermek için, aşağıdaki gibi "chmod" sistem çağrısını devre dışı bırakan bir Seccomp profil oluşturalım.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Yukarıdaki profilde, varsayılan eylemi "izin ver" olarak ayarladık ve "chmod"u devre dışı bırakmak için bir kara liste oluşturduk. Daha güvenli olmak için, varsayılan eylemi "düşür" olarak ayarlayabilir ve sistem çağrılarını seçici olarak etkinleştirmek için bir beyaz liste oluşturabiliriz.\
Aşağıdaki çıktı, seccomp profilde devre dışı bırakıldığı için "chmod" çağrısının hata döndürdüğünü göstermektedir.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Aşağıdaki çıktı, profilin görüntülendiği "docker inspect" komutunu göstermektedir:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Docker'da Devre Dışı Bırakma

Bayrakla birlikte bir konteyner başlatın: **`--security-opt seccomp=unconfined`**

Kubernetes 1.19'dan itibaren, **seccomp varsayılan olarak tüm Pod'lar için etkinleştirilmiştir**. Bununla birlikte, Pod'lara uygulanan varsayılan seccomp profili, konteyner çalışma zamanı tarafından sağlanan "**RuntimeDefault**" profili olup (örneğin Docker, containerd), "RuntimeDefault" profili, çoğu sistem çağrısına izin verirken, konteynerler için tehlikeli veya genellikle gereksiz olarak kabul edilen birkaç sistem çağrısını engeller.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
