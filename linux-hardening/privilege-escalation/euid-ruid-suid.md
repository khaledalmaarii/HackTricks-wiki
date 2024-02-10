# euid, ruid, suid

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) sahip olun
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>

### Kullanıcı Kimlik Değişkenleri

- **`ruid`**: **Gerçek kullanıcı kimliği** işlemi başlatan kullanıcıyı belirtir.
- **`euid`**: **Etkili kullanıcı kimliği** olarak bilinen, sistem tarafından işlem ayrıcalıklarını belirlemek için kullanılan kullanıcı kimliğini temsil eder. Genellikle, `euid` SetUID ikili yürütmesi gibi durumlar dışında, `euid` dosya sahibinin kimliğini alır ve belirli işletimsel izinler sağlar.
- **`suid`**: Bu **kaydedilmiş kullanıcı kimliği**, geçici olarak ayrıcalıklarını bırakması gereken yüksek ayrıcalıklı bir işlem (genellikle root olarak çalışan) için önemlidir, ancak daha sonra başlangıçta yükseltilmiş durumunu geri alır.

#### Önemli Not
Kök altında çalışmayan bir işlem, yalnızca `euid`'yi mevcut `ruid`, `euid` veya `suid` ile eşleştirebilir.

### set*uid Fonksiyonlarının Anlaşılması

- **`setuid`**: İlk varsayımların aksine, `setuid` öncelikle `ruid`'yi değiştirir, `euid`'yi değil. Özellikle ayrıcalıklı işlemler için, belirtilen kullanıcıyla (`root` gibi) `ruid`, `euid` ve `suid`'yi hizalar, bu nedenle bu kimlikleri geçersiz kılarak etkinleştirir. Ayrıntılı bilgilere [setuid man sayfasında](https://man7.org/linux/man-pages/man2/setuid.2.html) ulaşılabilir.
- **`setreuid`** ve **`setresuid`**: Bu fonksiyonlar, `ruid`, `euid` ve `suid`'yi ince ayar yapmanıza olanak tanır. Ancak, yetki düzeyine bağlı olarak yetenekleri sınırlıdır. Kök olmayan işlemler için değişiklikler, `ruid`, `euid` ve `suid`'nin mevcut değerleriyle sınırlıdır. Buna karşılık, kök işlemleri veya `CAP_SETUID` yeteneğine sahip olanlar bu kimliklere keyfi değerler atayabilir. Daha fazla bilgi, [setresuid man sayfasında](https://man7.org/linux/man-pages/man2/setresuid.2.html) ve [setreuid man sayfasında](https://man7.org/linux/man-pages/man2/setreuid.2.html) bulunabilir.

Bu işlevler, bir güvenlik mekanizması olarak değil, bir programın etkin kullanıcı kimliğini değiştirerek başka bir kullanıcının kimliğini benimsemesini kolaylaştırmak için tasarlanmıştır.

Özellikle, `setuid`, kök ayrıcalığına yükseltme için yaygın bir seçenek olabilir (çünkü tüm kimlikleri köke hizalar), ancak bu işlevler arasındaki farkı ayırt etmek, farklı senaryolarda kullanıcı kimliği davranışlarını anlamak ve manipüle etmek için önemlidir.

### Linux'ta Program Yürütme Mekanizmaları

#### **`execve` Sistem Çağrısı**
- **İşlevsellik**: `execve`, ilk argüman tarafından belirlenen bir programı başlatır. İki dizi argüman alır, argümanlar için `argv` ve çevre için `envp`.
- **Davranış**: Çağıranın bellek alanını korur, ancak yığın, heap ve veri segmentlerini yeniler. Programın kodu, yeni program tarafından değiştirilir.
- **Kullanıcı Kimliği Koruma**:
- `ruid`, `euid` ve ek grup kimlikleri değiştirilmez.
- Yeni programın SetUID bitine sahip olması durumunda, `euid`'de ince değişiklikler olabilir.
- `suid`, yürütmeden sonra `euid`'den güncellenir.
- **Belgeleme**: Ayrıntılı bilgilere [`execve` man sayfasında](https://man7.org/linux/man-pages/man2/execve.2.html) ulaşılabilir.

#### **`system` İşlevi**
- **İşlevsellik**: `execve`'den farklı olarak, `system` bir çocuk işlem oluşturur ve bu çocuk işlemde `fork` kullanarak bir komutu yürütür.
- **Komut Yürütme**: Komutu `sh` ile `execl("/bin/sh", "sh", "-c", komut, (char *) NULL);` kullanarak yürütür.
- **Davranış**: `execl`, `execve`'nin bir formu olduğu için benzer şekilde çalışır, ancak yeni bir çocuk işlem bağlamında çalışır.
- **Belgeleme**: Daha fazla bilgi [`system` man sayfasında](https://man7.org/linux/man-pages/man3/system.3.html) bulunabilir.

#### **SUID ile `bash` ve `sh` Davranışı**
- **`bash`**:
- `euid` ve `ruid`'nin nasıl işlendiğini etkileyen `-p` seçeneğine sahiptir.
- `-p` olmadan, `bash`, başlangıçta farklılarsa `euid`'yi `ruid`'ye ayarlar.
- `-p` ile, başlangıçtaki `euid` korunur.
- Daha fazla ayrıntı [`bash` man sayfasında](https://linux.die.net/man/1/bash) bulunabilir.
- **`sh`**:
- `bash`'deki `-p` ile benzer bir mekanizmaya sahip değildir.
- Kullanıcı kimlikleriyle ilgili davranış açıkça belirtilmemiştir, `-i` seçeneği altında `euid` ve `ruid`'nin eşitliğinin korunmasına vurgu yapılır.
- Ek bilgiler [`sh` man sayfasında](https://man7.org/linux/man-pages/man1/sh.1p.html) bulunabilir.

Bu işlemler, işleyişlerinde farklılık gösteren, programların yürütülmesi ve geçiş yapılması için çeşitli seçenekler sunan ve kullanıcı kimliklerinin nasıl yönetildiği ve korunduğu konusunda belirli nüanslara sahip olan mekanizmalardır.

### Yürütme Sırasında Kullanıcı Kimliği Davranışlarını Test Etme

Daha fazla bilgi için https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail adresinden alınan örnekleri kontrol edin

#### Durum 1: `setuid` ile `system` kullanımı

**Amaç**: `setuid`'in `system` ve `bash` olarak `sh` ile birlikte kullanımının etkisini anlamak.

**C Kodu**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Derleme ve İzinler:**


When a program is compiled, it is assigned certain permissions based on the user who compiled it. These permissions determine the level of access the program has to system resources. There are three types of permissions that can be assigned to a program: the effective user ID (euid), the real user ID (ruid), and the saved user ID (suid).


Bir program derlendiğinde, derleyen kullanıcıya bağlı olarak belirli izinler atanır. Bu izinler, programın sistem kaynaklarına erişim düzeyini belirler. Bir programa atanan üç tür izin vardır: etkili kullanıcı kimliği (euid), gerçek kullanıcı kimliği (ruid) ve kaydedilmiş kullanıcı kimliği (suid).


The euid is the user ID that the program will use when accessing system resources. It is set to the ruid by default, but it can be changed using the setuid() system call. This allows a program to temporarily elevate its privileges to perform certain tasks that require higher permissions.


Euid, programın sistem kaynaklarına erişirken kullanacağı kullanıcı kimliğidir. Varsayılan olarak ruid'ye ayarlanır, ancak setuid() sistem çağrısı kullanılarak değiştirilebilir. Bu, bir programın geçici olarak ayrıcalıklarını yükseltmesine ve daha yüksek izinlere ihtiyaç duyan belirli görevleri gerçekleştirmesine olanak tanır.


The ruid is the user ID of the user who executed the program. It remains constant throughout the execution of the program and is used for permission checks.


Ruid, programı çalıştıran kullanıcının kullanıcı kimliğidir. Programın yürütülmesi boyunca sabit kalır ve izin kontrolleri için kullanılır.


The suid is the user ID that the program will use when it is executed with elevated privileges. It is set to the euid by default, but it can be changed using the setuid() system call. This allows a program to permanently elevate its privileges, even when executed by a different user.


Suid, programın yükseltilmiş ayrıcalıklarla çalıştırıldığında kullanacağı kullanıcı kimliğidir. Varsayılan olarak euid'ye ayarlanır, ancak setuid() sistem çağrısı kullanılarak değiştirilebilir. Bu, bir programın ayrıcalıklarını kalıcı olarak yükseltmesine olanak tanır, hatta farklı bir kullanıcı tarafından çalıştırıldığında bile.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `ruid` ve `euid` başlangıçta sırasıyla 99 (nobody) ve 1000 (frank) olarak başlar.
* `setuid` her ikisini de 1000'e ayarlar.
* `system`, sh'den bash'e olan sembolik bağlantı nedeniyle `/bin/bash -c id` komutunu çalıştırır.
* `-p` olmadan `bash`, `euid`'yi `ruid` ile eşleştirmek için ayarlar ve sonuç olarak her ikisi de 99 (nobody) olur.

#### Durum 2: setreuid ile system Kullanımı

**C Kodu**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Derleme ve İzinler:**


When a program is compiled, it is assigned certain permissions based on the user who compiled it. These permissions determine the level of access the program has to system resources. There are three types of permissions that can be assigned to a program: the effective user ID (euid), the real user ID (ruid), and the saved user ID (suid).


Bir program derlendiğinde, derleyen kullanıcıya bağlı olarak belirli izinler atanır. Bu izinler, programın sistem kaynaklarına erişim düzeyini belirler. Bir programa atanan üç tür izin vardır: etkili kullanıcı kimliği (euid), gerçek kullanıcı kimliği (ruid) ve kaydedilmiş kullanıcı kimliği (suid).


The euid is the user ID that the program will use when accessing system resources. It is set to the ruid by default, but it can be changed using the setuid() system call. This allows a program to temporarily elevate its privileges to perform certain tasks that require higher permissions.


Euid, programın sistem kaynaklarına erişirken kullanacağı kullanıcı kimliğidir. Varsayılan olarak ruid olarak ayarlanır, ancak setuid() sistem çağrısı kullanılarak değiştirilebilir. Bu, bir programın geçici olarak ayrıcalıklarını yükseltmesine ve daha yüksek izinlere ihtiyaç duyan belirli görevleri gerçekleştirmesine olanak tanır.


The ruid is the user ID of the user who executed the program. It remains constant throughout the execution of the program and is used for permission checks.


Ruid, programı çalıştıran kullanıcının kullanıcı kimliğidir. Programın yürütülmesi boyunca sabit kalır ve izin kontrolleri için kullanılır.


The suid is the user ID that the program will use when it is executed with elevated privileges. It is set to the euid by default, but it can also be changed using the setuid() system call. This allows a program to permanently run with elevated privileges, even if it is executed by a user with lower permissions.


Suid, programın yükseltilmiş ayrıcalıklarla çalıştırıldığında kullanacağı kullanıcı kimliğidir. Varsayılan olarak euid olarak ayarlanır, ancak setuid() sistem çağrısı kullanılarak da değiştirilebilir. Bu, bir programın, daha düşük izinlere sahip bir kullanıcı tarafından çalıştırılsa bile kalıcı olarak yükseltilmiş ayrıcalıklarla çalışmasına olanak tanır.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `setreuid`, ruid ve euid'yi 1000 olarak ayarlar.
* `system`, eşitlikleri nedeniyle kullanıcı kimliklerini koruyan bash'i çağırır ve etkili bir şekilde frank olarak çalışır.

#### Durum 3: execve ile setuid kullanma
Amaç: setuid ve execve arasındaki etkileşimi keşfetmek.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `ruid` 99 olarak kalırken, euid 1000 olarak ayarlanır, setuid'in etkisiyle uyumludur.

**C Kodu Örneği 2 (Bash Çağırma):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `euid` 1000'e `setuid` tarafından ayarlanmasına rağmen, `-p` olmaması nedeniyle `bash`, `ruid` (99) olarak `euid`'yi sıfırlar.

**C Kodu Örneği 3 (bash -p Kullanarak):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referanslar
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamınızı görmek ister misiniz**? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>
