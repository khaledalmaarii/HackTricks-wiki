# AppArmor

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** katkıda bulunun.

</details>

## Temel Bilgiler

AppArmor, kullanıcılar yerine programlara doğrudan erişim kontrol özelliklerini bağlayarak, zorunlu erişim kontrolünü (MAC) etkin bir şekilde uygulayan, programlara sunulan kaynakları kısıtlamak için tasarlanmış bir **çekirdek geliştirmesidir**. Bu sistem, genellikle önyükleme sırasında, profilleri çekirdeğe yükleyerek çalışır ve bu profiller, bir programın erişebileceği kaynakları, ağ bağlantıları, ham soket erişimi ve dosya izinleri gibi belirler.

AppArmor profilleri için iki işletim modu vardır:

- **Uygulama Modu**: Bu mod, profil içinde tanımlanan politikaları etkin bir şekilde uygular, bu politikalara aykırı olan eylemleri engeller ve syslog veya auditd gibi sistemler aracılığıyla bunları ihlal etmeye yönelik girişimleri kaydeder.
- **Şikayet Modu**: Uygulama modunun aksine, şikayet modu, profilin politikalarına aykırı olan eylemleri engellemez. Bunun yerine, bu girişimleri kısıtlamaları uygulamadan politika ihlalleri olarak kaydeder.

### AppArmor'ın Bileşenleri

- **Çekirdek Modülü**: Politikaların uygulanmasından sorumludur.
- **Politikalar**: Program davranışı ve kaynak erişimi için kuralları ve kısıtlamaları belirtir.
- **Ayrıştırıcı**: Politikaları çekirdeğe yükler, uygulama veya raporlama için.
- **Araçlar**: AppArmor ile etkileşimde bulunmak ve yönetmek için kullanıcı modu programlarıdır.

### Profil Yolu

AppArmor profilleri genellikle _**/etc/apparmor.d/**_ dizininde kaydedilir. `sudo aa-status` komutunu kullanarak, bazı profillerle kısıtlanan ikili dosyaları listeleyebilirsiniz. Listelenen her ikili dosyanın yolundaki "/" karakterini bir nokta ile değiştirirseniz, bahsedilen klasördeki apparmor profilinin adını elde edersiniz.

Örneğin, _/usr/bin/man_ için bir **apparmor** profili, _/etc/apparmor.d/usr.bin.man_ konumunda bulunur.

### Komutlar
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Profil Oluşturma

* Etkilenen yürütülebilir dosyayı belirtmek için **mutlak yol ve joker karakterleri** (dosya eşleştirmesi için) kullanılabilir.
* **Dosyalar** üzerinde yürütülecek işlemleri belirtmek için aşağıdaki **erişim kontrolleri** kullanılabilir:
* **r** (okuma)
* **w** (yazma)
* **m** (belleğe haritalama, yürütülebilir olarak)
* **k** (dosya kilitleme)
* **l** (sabit bağlantı oluşturma)
* **ix** (yeni programın politikayı devralarak başka bir programı yürütmesi için)
* **Px** (ortamı temizledikten sonra başka bir profil altında yürütme)
* **Cx** (ortamı temizledikten sonra bir alt profil altında yürütme)
* **Ux** (ortamı temizledikten sonra sınırsız olarak yürütme)
* **Profillerde değişkenler** tanımlanabilir ve profilden dışarıdan manipüle edilebilir. Örneğin: @{PROC} ve @{HOME} (profil dosyasına #include \<tunables/global> ekleyin)
* **İzin verme kuralları, izin verme kurallarını geçersiz kılmak için kullanılabilir**.

### aa-genprof

Profil oluşturmaya kolayca başlamak için apparmor size yardımcı olabilir. **Apparmor, bir ikili tarafından gerçekleştirilen eylemleri incelemesini ve ardından hangi eylemleri izin vermek veya reddetmek istediğinizi belirlemenizi sağlayabilir**.\
Sadece şunu çalıştırmanız yeterlidir:
```bash
sudo aa-genprof /path/to/binary
```
Ardından, farklı bir konsolda, genellikle ikili dosyanın gerçekleştireceği tüm eylemleri gerçekleştirin:
```bash
/path/to/binary -a dosomething
```
Ardından, ilk konsolda "**s**" tuşuna basın ve kaydedilen eylemlerde yoksaymak, izin vermek veya başka bir şey yapmak istediğinizi belirtin. İşiniz bittiğinde "**f**" tuşuna basın ve yeni profil _/etc/apparmor.d/path.to.binary_ dizininde oluşturulacaktır.

{% hint style="info" %}
Yukarı/aşağı ok tuşlarını kullanarak izin vermek/engellemek/istenen seçeneği seçebilirsiniz.
{% endhint %}

### aa-easyprof

Ayrıca, bir ikili dosyanın apparmor profilinin bir şablonunu da oluşturabilirsiniz:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Varsayılan olarak, oluşturulan bir profilde hiçbir şey izin verilmez, bu yüzden her şey reddedilir. Örneğin, `/etc/passwd r,` gibi satırlar eklemek için `/etc/passwd` dosyasını okumaya izin vermek için eklemeler yapmanız gerekecektir.
{% endhint %}

Yeni profili ardından **zorlayabilirsiniz**.
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Günlüklerden bir profil değiştirme

Aşağıdaki araç, günlükleri okuyacak ve kullanıcıya tespit edilen yasaklanmış eylemlerin bazılarını izin vermek isteyip istemediğini soracaktır:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Ok tuşları kullanarak neyi izin vermek/engellemek/neyi yapmak istediğinizi seçebilirsiniz.
{% endhint %}

### Bir Profili Yönetmek

```bash
# Create a new profile
sudo aa-genprof /path/to/binary

# Load a profile
sudo apparmor_parser -r -W /etc/apparmor.d/profile

# Unload a profile
sudo apparmor_parser -R /etc/apparmor.d/profile

# Disable a profile
sudo ln -s /etc/apparmor.d/profile /etc/apparmor.d/disable/

# Enable a profile
sudo ln -s /etc/apparmor.d/profile /etc/apparmor.d/enable/

# Check the status of a profile
sudo apparmor_status
```

### Profile Syntax

Profiles are written in a specific syntax. Here is an example of a simple profile:

```bash
#include <tunables/global>

/usr/bin/myapp {
  # Deny access to all files
  deny /**,

  # Allow read access to /etc/passwd
  /etc/passwd r,

  # Allow write access to /tmp
  /tmp w,

  # Allow execute access to /usr/bin/myapp
  /usr/bin/myapp x,
}
```

In this example, the profile denies access to all files except for `/etc/passwd`, `/tmp`, and `/usr/bin/myapp`. The `r`, `w`, and `x` indicate read, write, and execute permissions, respectively.

### Profile Inheritance

Profiles can also inherit from other profiles. This allows for the reuse of common rules and simplifies profile management. Here is an example of a profile that inherits from another profile:

```bash
#include <tunables/global>

/usr/bin/myapp {
  # Inherit from the base profile
  profile /usr/bin/myapp flags=(attach_disconnected,mediate_deleted) {
    # Additional rules specific to /usr/bin/myapp
    /var/log/myapp.log w,
  }
}
```

In this example, the profile for `/usr/bin/myapp` inherits from the base profile and adds an additional rule for write access to `/var/log/myapp.log`.

### Conclusion

AppArmor provides a powerful and flexible way to enforce security policies on Linux systems. By creating and managing profiles, you can control the access and permissions of individual applications, reducing the risk of privilege escalation and unauthorized access.
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Günlükler

**`service_bin`** adlı yürütülebilir dosyanın _/var/log/audit/audit.log_ dosyasındaki **AUDIT** ve **DENIED** günlüklerinin örneği:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Bu bilgilere şu şekilde de ulaşabilirsiniz:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Docker'da Apparmor

Docker'ın varsayılan olarak yüklenen **docker-profile** profiline dikkat edin:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Varsayılan olarak **Apparmor docker-default profili**, [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) adresinden oluşturulur.

**docker-default profil Özeti**:

* Tüm **ağ erişimine** izin verilir.
* **Hiçbir yetenek** tanımlanmamıştır (Ancak, bazı yetenekler temel kuralların içe aktarılmasıyla gelecektir, örneğin #include \<abstractions/base> )
* **/proc** dosyalarına yazma izni **verilmemiştir**
* Diğer **alt dizinler**/**dosyalar** /**proc** ve /**sys** dizinlerinde okuma/yazma/kilit/ilişkilendirme/çalıştırma erişimi **reddedilmiştir**
* **Mount** izni **verilmemiştir**
* **Ptrace**, yalnızca aynı apparmor profiliyle sınırlanmış bir işlemde çalıştırılabilir

Bir docker konteyneri çalıştırdığınızda aşağıdaki çıktıyı görmelisiniz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
**Not:** Apparmor, varsayılan olarak konteynere verilen yetenek ayrıcalıklarını bile engelleyecektir. Örneğin, SYS_ADMIN yeteneği verilse bile, /proc içine yazma iznini engelleyebilecektir çünkü varsayılan olarak docker apparmor profili bu erişimi reddeder:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Apparmor kısıtlamalarını atlamak için **apparmor'u devre dışı bırakmanız** gerekmektedir:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Not: Varsayılan olarak **AppArmor**, SYS\_ADMIN yeteneğiyle bile içeriden klasörleri bağlamayı **yasaklar**.

Not: Docker konteynerine **yetenekler** ekleyebilir/çıkarabilirsiniz (bu, **AppArmor** ve **Seccomp** gibi koruma yöntemleri tarafından hala kısıtlanır):

* `--cap-add=SYS_ADMIN` SYS\_ADMIN yeteneği verir
* `--cap-add=ALL` tüm yetenekleri verir
* `--cap-drop=ALL --cap-add=SYS_PTRACE` tüm yetenekleri kaldırır ve sadece `SYS_PTRACE` yeteneğini verir

{% hint style="info" %}
Genellikle, bir **docker** konteyneri **içinde** bir **ayrıcalıklı yetenek** olduğunu **fark ettiğinizde** ancak **saldırının bazı kısımlarının çalışmadığını** görürseniz, bunun nedeni docker **apparmor'ın bunu engellemesidir**.
{% endhint %}

### Örnek

([**buradan**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/) alınan örnek)

AppArmor işlevselliğini göstermek için aşağıdaki satırı içeren yeni bir Docker profilü "mydocker" oluşturdum:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Profil'i etkinleştirmek için aşağıdaki adımları izlememiz gerekmektedir:
```
sudo apparmor_parser -r -W mydocker
```
Profilleri listelemek için aşağıdaki komutu kullanabiliriz. Aşağıdaki komut, yeni AppArmor profilimi listeliyor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Aşağıda gösterildiği gibi, "AppArmor" profilinin "/etc/" dizinine yazma erişimini engellediği için "AppArmor" profili değiştirilmeye çalışıldığında hata alırız.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Bir konteynerin hangi **apparmor profili çalıştırdığını** bulmak için şunu kullanabilirsiniz:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Ardından, aşağıdaki satırı çalıştırarak **kullanılan kesin profilin bulunmasını** sağlayabilirsiniz:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Eğer apparmor docker profilini değiştirip yeniden yükleyebilirseniz, sınırlamaları kaldırabilir ve onları "atlayabilirsiniz".

### AppArmor Docker Atlatma2

AppArmor, yol tabanlıdır, bu da demektir ki **`/proc`** gibi bir dizin içindeki dosyaları koruyor olsa bile, **konteynerin nasıl çalıştırılacağını yapılandırabilirseniz**, ana bilgisayarın proc dizinini **`/host/proc`** içine bağlayabilir ve bu şekilde AppArmor tarafından korunmaz.

### AppArmor Shebang Atlatma

[**Bu hata**](https://bugs.launchpad.net/apparmor/+bug/1911431)da, belirli kaynaklarla perl'in çalışmasını engellemenize rağmen, sadece bir kabuk betiği oluşturup ilk satırda **`#!/usr/bin/perl`** belirtirseniz ve dosyayı doğrudan çalıştırırsanız, istediğinizi çalıştırabilirsiniz. Örneğin:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
