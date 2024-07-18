# AppArmor

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek HackTricks** ve **HackTricks Cloud** github depolarına katkıda bulunun.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Temel Bilgiler

AppArmor, **programlara program profilleri aracılığıyla sunulan kaynakları kısıtlamayı amaçlayan bir çekirdek geliştirmesidir**, erişim kontrol özelliklerini doğrudan kullanıcılara değil programlara bağlayarak Zorunlu Erişim Kontrolü (MAC) uygulamaktadır. Bu sistem, genellikle önyükleme sırasında, profilleri çekirdeğe yükleyerek çalışır ve bu profiller bir programın erişebileceği kaynakları belirler, örneğin ağ bağlantıları, ham soket erişimi ve dosya izinleri gibi.

AppArmor profilleri için iki işletim modu bulunmaktadır:

* **Uygulama Modu**: Bu mod, profilde tanımlanan politikaları aktif olarak uygular, bu politikalara aykırı hareketleri engeller ve syslog veya auditd gibi sistemler aracılığıyla bunları ihlal etmeye yönelik girişimleri kaydeder.
* **Şikayet Modu**: Uygulama modunun aksine, şikayet modu, profilin politikalarına aykırı hareketleri engellemez. Bunun yerine, bu girişimleri kısıtlamaları uygulamadan politika ihlalleri olarak kaydeder.

### AppArmor'ın Bileşenleri

* **Çekirdek Modülü**: Politikaların uygulanmasından sorumludur.
* **Politikalar**: Program davranışı ve kaynak erişimi için kuralları ve kısıtlamaları belirtir.
* **Ayrıştırıcı**: Politikaları çekirdeğe yükler ve uygular veya raporlar.
* **Araçlar**: AppArmor ile etkileşimde bulunmak ve yönetmek için bir arayüz sağlayan kullanıcı modu programlarıdır.

### Profil Yolu

Apparmor profilleri genellikle _**/etc/apparmor.d/**_ dizininde saklanır.\
`sudo aa-status` komutu ile bazı profiller tarafından kısıtlanan ikili dosyaları listeleyebilirsiniz. Listelenen her ikili dosyanın yolundaki "/" karakterini bir noktaya değiştirirseniz, bahsedilen klasördeki apparmor profilinin adını elde edersiniz.

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
## Profil oluşturma

* Etkilenen yürütülebilir dosyayı belirtmek için **mutlak yol ve joker karakterleri** (dosya eşleştirmesi için) kullanılabilir.
* **Dosyalar** üzerinde yürütülecek erişimi belirtmek için aşağıdaki **erişim kontrolleri** kullanılabilir:
* **r** (okuma)
* **w** (yazma)
* **m** (bellek haritası olarak yürütme)
* **k** (dosya kilitleme)
* **l** (sert bağlantı oluşturma)
* **ix** (yeni programın politikayı devralarak başka bir programı yürütmesi için)
* **Px** (ortamı temizledikten sonra başka bir profil altında yürütme)
* **Cx** (ortamı temizledikten sonra başka bir alt profil altında yürütme)
* **Ux** (ortamı temizledikten sonra kısıtlanmamış olarak yürütme)
* **Değişkenler** profillerde tanımlanabilir ve profilden dışarıdan manipüle edilebilir. Örneğin: @{PROC} ve @{HOME} (profil dosyasına #include \<tunables/global> ekleyin)
* **İzin verme kurallarını geçersiz kılmak için reddetme kuralları desteklenir**.

### aa-genprof

Profil oluşturmaya kolayca başlamak için apparmor size yardımcı olabilir. **Bir yürütülebilir tarafından gerçekleştirilen eylemleri incelemesine ve ardından hangi eylemleri izin vermek veya reddetmek istediğinize karar vermenize olanak tanır**.\
Sadece şunu çalıştırmanız yeterlidir:
```bash
sudo aa-genprof /path/to/binary
```
Ardından, farklı bir konsolda genellikle ikili dosyanın gerçekleştireceği tüm eylemleri gerçekleştirin:
```bash
/path/to/binary -a dosomething
```
Ardından, ilk konsolda "**s**" tuşuna basın ve kaydedilen eylemlerde ihmal etmek, izin vermek veya ne yapmak istediğinizi belirtin. İşlemi tamamladığınızda "**f**" tuşuna basın ve yeni profil _/etc/apparmor.d/path.to.binary_ dizininde oluşturulacaktır.

{% hint style="info" %}
Yön tuşları kullanarak izin vermek/engellemek/ne yapmak istediğinizi seçebilirsiniz.
{% endhint %}

### aa-easyprof

Ayrıca, bir uygulamanın apparmor profil şablonunu oluşturabilirsiniz:
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

Yeni profilinizi ardından şu şekilde **zorlayabilirsiniz**:
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Günlüklerden bir profil değiştirme

Aşağıdaki araç, günlükleri okuyacak ve kullanıcıya tespit edilen bazı yasaklanmış eylemlerin izin verilip verilmediğini sormak için soracak:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Ok tuşları kullanarak neyi izin vermek/engellemek/neyi yapmak istediğinizi seçebilirsiniz
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

**`service_bin`** yürütülebilir dosyasının _/var/log/audit/audit.log_ dosyasındaki **AUDIT** ve **DENIED** günlüklerinden bir örnek:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Ayrıca bu bilgilere şu şekilde de ulaşabilirsiniz:
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
Varsayılan olarak **Apparmor docker-default profil**i [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) adresinden oluşturulur.

**docker-default profil Özeti**:

- Tüm **ağa erişim**
- **Yetenek** tanımlanmamıştır (Ancak, bazı yetenekler temel kural dosyalarını içererek gelecektir, yani #include \<abstractions/base>)
- Herhangi bir **/proc** dosyasına **yazma izni yok**
- Diğer /**proc** ve /**sys** alt dizinleri/**dosyaları** okuma/yazma/kilitleme/bağlantı/çalıştırma erişimine **izin verilmez**
- **Bağlama** izni **yok**
- **Ptrace** yalnızca **aynı apparmor profil**i tarafından sınırlanmış bir işlemde çalıştırılabilir

Bir **docker konteyneri çalıştırdıktan** sonra aşağıdaki çıktıyı görmelisiniz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Dikkat edin ki **apparmor, varsayılan olarak konteynıra verilen yetenek ayrıcalıklarını bile engelleyecektir**. Örneğin, **SYS_ADMIN yeteneği verilmiş olsa bile /proc içine yazma iznini engelleyebilecektir** çünkü varsayılan olarak docker apparmor profili bu erişimi reddeder:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Apparmor kısıtlamalarını atlamak için **apparmor'u devre dışı bırakmanız** gerekmektedir:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Varsayılan olarak **AppArmor'ın**, **konteynerin içinden klasör bağlamasını yasaklayacağını** unutmayın, hatta SYS_ADMIN yeteneği ile bile.

Docker konteynerine **yetenekler ekleyebilir/çıkarabilirsiniz** (bu hala **AppArmor** ve **Seccomp** gibi koruma yöntemleri tarafından kısıtlanacaktır):

* `--cap-add=SYS_ADMIN` `SYS_ADMIN` yeteneği verir
* `--cap-add=ALL` tüm yetenekleri verir
* `--cap-drop=ALL --cap-add=SYS_PTRACE` tüm yetenekleri kaldırır ve sadece `SYS_PTRACE` yeteneğini verir

{% hint style="info" %}
Genellikle, bir **docker** konteyneri **içinde** bir **açık yeteneğin** bulunduğunu **fark ettiğinizde** ve **saldırının bazı kısımlarının çalışmadığını gördüğünüzde**, bunun nedeni docker **apparmor'ın bunu engelliyor olması** olacaktır.
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
Aşağıda gösterildiği gibi, "AppArmor" profili "/etc/" dizinine yazma erişimini engellediği için "/etc/" dizinini değiştirmeye çalıştığımızda hata alırız.
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
Ardından, kullanılan tam profil **bulmak için aşağıdaki komutu çalıştırabilirsiniz**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Eğer **apparmor docker profilini değiştirebilir ve yeniden yükleyebilirseniz** tuhaf bir durumda. Kısıtlamaları kaldırabilir ve onları "atlayabilirsiniz".

### AppArmor Docker Atlatma2

**AppArmor yol tabanlıdır**, bu da demektir ki eğer **`/proc`** gibi bir dizin içindeki dosyaları koruyorsa bile, **konteynerin nasıl çalıştırılacağını yapılandırabilirseniz**, ana bilgisayarın proc dizinini **`/host/proc`** içine bağlayabilir ve bu artık AppArmor tarafından korunmaz.

### AppArmor Shebang Atlatma

Bu [**bu hata**](https://bugs.launchpad.net/apparmor/+bug/1911431)da, **belirli kaynaklarla perl'in çalışmasını engelliyorsanız bile**, sadece bir kabuk betiği oluşturursanız ve ilk satırda **`#!/usr/bin/perl`** belirtirseniz ve dosyayı doğrudan **çalıştırırsanız**, istediğinizi çalıştırabilirsiniz. Örn.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize** edilip edilmediğini kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
