# AppArmor

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Temel Bilgiler

AppArmor, **programlara program başına profiller aracılığıyla mevcut kaynakları kısıtlamak için tasarlanmış bir çekirdek geliştirmesidir**, erişim kontrol özelliklerini doğrudan kullanıcılara değil, programlara bağlayarak Zorunlu Erişim Kontrolü (MAC) uygulamaktadır. Bu sistem, **profilleri çekirdeğe yükleyerek** çalışır, genellikle önyükleme sırasında, ve bu profiller bir programın erişebileceği kaynakları, örneğin ağ bağlantıları, ham soket erişimi ve dosya izinleri gibi, belirler.

AppArmor profilleri için iki çalışma modu vardır:

* **Zorunlu Mod**: Bu mod, profil içinde tanımlanan politikaları aktif olarak uygular, bu politikaları ihlal eden eylemleri engeller ve bunları syslog veya auditd gibi sistemler aracılığıyla kaydeder.
* **Şikayet Modu**: Zorunlu modun aksine, şikayet modu profilin politikalarına aykırı olan eylemleri engellemez. Bunun yerine, bu girişimleri politika ihlalleri olarak kaydeder, ancak kısıtlamaları uygulamaz.

### AppArmor Bileşenleri

* **Çekirdek Modülü**: Politikaların uygulanmasından sorumludur.
* **Politikalar**: Program davranışı ve kaynak erişimi için kuralları ve kısıtlamaları belirtir.
* **Ayrıştırıcı**: Politikaları uygulama veya raporlama için çekirdeğe yükler.
* **Araçlar**: AppArmor ile etkileşimde bulunmak ve yönetmek için bir arayüz sağlayan kullanıcı modu programlarıdır.

### Profillerin Yolu

AppArmor profilleri genellikle _**/etc/apparmor.d/**_ dizininde saklanır.\
`sudo aa-status` komutunu kullanarak bazı profiller tarafından kısıtlanan ikili dosyaları listeleyebilirsiniz. Listelenen her ikili dosyanın yolundaki "/" karakterini bir nokta ile değiştirdiğinizde, belirtilen klasördeki apparmor profilinin adını elde edersiniz.

Örneğin, _/usr/bin/man_ için bir **apparmor** profili _/etc/apparmor.d/usr.bin.man_ konumunda bulunacaktır.

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

* Etkilenen çalıştırılabilir dosyayı belirtmek için, **mutlak yollar ve joker karakterler** (dosya globbing için) dosyaları belirtmekte kullanılabilir.
* İkili dosyanın **dosyalar** üzerindeki erişimini belirtmek için aşağıdaki **erişim kontrolleri** kullanılabilir:
* **r** (okuma)
* **w** (yazma)
* **m** (bellek haritası olarak çalıştırılabilir)
* **k** (dosya kilitleme)
* **l** (sert bağlantılar oluşturma)
* **ix** (yeni programın miras aldığı politika ile başka bir programı çalıştırmak için)
* **Px** (ortamı temizledikten sonra başka bir profil altında çalıştırmak için)
* **Cx** (ortamı temizledikten sonra bir çocuk profil altında çalıştırmak için)
* **Ux** (ortamı temizledikten sonra kısıtlanmamış olarak çalıştırmak için)
* **Değişkenler** profillerde tanımlanabilir ve profil dışından manipüle edilebilir. Örneğin: @{PROC} ve @{HOME} (profil dosyasına #include \<tunables/global> ekleyin)
* **İzin verme kurallarını geçersiz kılmak için yasaklama kuralları desteklenmektedir**.

### aa-genprof

Profil oluşturmaya başlamak için apparmor size yardımcı olabilir. **Apparmor'un bir ikilinin gerçekleştirdiği eylemleri incelemesi ve ardından hangi eylemleri izin vermek veya yasaklamak istediğinize karar vermenize olanak tanıması mümkündür**.\
Sadece şunu çalıştırmanız yeterlidir:
```bash
sudo aa-genprof /path/to/binary
```
Sonra, farklı bir konsolda ikili dosyanın genellikle gerçekleştireceği tüm eylemleri gerçekleştirin:
```bash
/path/to/binary -a dosomething
```
Sonra, ilk konsolda "**s**" tuşuna basın ve ardından kaydedilen eylemlerde neyi yok saymak, neyi izin vermek veya ne yapmak istediğinizi belirtin. İşlemi bitirdiğinizde "**f**" tuşuna basın ve yeni profil _/etc/apparmor.d/path.to.binary_ içinde oluşturulacaktır.

{% hint style="info" %}
Ok tuşlarını kullanarak neyi izin vermek/yasaklamak/neyse seçebilirsiniz.
{% endhint %}

### aa-easyprof

Bir ikili dosyanın apparmor profilinin bir şablonunu da oluşturabilirsiniz:
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
Varsayılan olarak oluşturulan bir profilde hiçbir şeye izin verilmediğini unutmayın, bu nedenle her şey reddedilir. Örneğin, `/etc/passwd` dosyasının okunmasına izin vermek için `/etc/passwd r,` gibi satırlar eklemeniz gerekecek.
{% endhint %}

Daha sonra yeni profili **uygulayabilirsiniz**.
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Loglardan bir profili değiştirme

Aşağıdaki araç, logları okuyacak ve kullanıcıya tespit edilen bazı yasaklı eylemleri izin verip vermek istemediğini soracaktır:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Ok tuşlarını kullanarak neyi izin vermek/engellemek/başka bir şey yapmak istediğinizi seçebilirsiniz.
{% endhint %}

### Bir Profili Yönetmek
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Örnek **AUDIT** ve **DENIED** logları _/var/log/audit/audit.log_ dosyasından **`service_bin`** yürütülebilir dosyası için:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Bu bilgiyi şu şekilde de alabilirsiniz:
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

**docker-profile** profilinin varsayılan olarak nasıl yüklendiğine dikkat edin:
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
Varsayılan olarak **Apparmor docker-default profili** [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) adresinden oluşturulur.

**docker-default profili Özeti**:

* Tüm **ağ** erişimi
* **Hiçbir yetenek** tanımlanmamıştır (Ancak, bazı yetenekler temel temel kuralları içermekten gelecektir, yani #include \<abstractions/base>)
* Herhangi bir **/proc** dosyasına **yazma** **izin verilmez**
* Diğer **alt dizinler**/**dosyalar** için /**proc** ve /**sys** okuma/yazma/kilit/link/çalıştırma erişimi **reddedilir**
* **Mount** **izin verilmez**
* **Ptrace** yalnızca **aynı apparmor profili** tarafından kısıtlanmış bir süreçte çalıştırılabilir

Bir **docker konteyneri çalıştırdığınızda** aşağıdaki çıktıyı görmelisiniz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Not edin ki **apparmor, varsayılan olarak konteynere verilen yetenek ayrıcalıklarını bile engelleyecektir**. Örneğin, **SYS\_ADMIN yeteneği verilse bile /proc içine yazma iznini engelleyebilecektir** çünkü varsayılan olarak docker apparmor profili bu erişimi reddeder:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
AppArmor kısıtlamalarını aşmak için **apparmor'ı devre dışı bırakmalısınız**:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Not edin ki varsayılan olarak **AppArmor**, **SYS\_ADMIN** yetkisi ile bile konteynerin içinden klasörleri **monte etmesini** **yasaklayacaktır**.

Not edin ki docker konteynerine **yetkiler** **ekleyebilir/çıkarabilirsiniz** (bu hala **AppArmor** ve **Seccomp** gibi koruma yöntemleri tarafından kısıtlanacaktır):

* `--cap-add=SYS_ADMIN` `SYS_ADMIN` yetkisini ver
* `--cap-add=ALL` tüm yetkileri ver
* `--cap-drop=ALL --cap-add=SYS_PTRACE` tüm yetkileri kaldır ve sadece `SYS_PTRACE` ver

{% hint style="info" %}
Genellikle, bir **docker** konteynerinin içinde **yetkili bir yetki** bulduğunuzda **ama** **sömürü** kısmının **çalışmadığını** **bulursanız**, bu docker'ın **apparmor'unun bunu engelliyor olmasından** kaynaklanacaktır.
{% endhint %}

### Örnek

(Örnek [**buradan**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/) alınmıştır)

AppArmor işlevselliğini göstermek için, aşağıdaki satırı ekleyerek “mydocker” adında yeni bir Docker profili oluşturdum:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Profili etkinleştirmek için aşağıdakileri yapmamız gerekiyor:
```
sudo apparmor_parser -r -W mydocker
```
Profilleri listelemek için aşağıdaki komutu verebiliriz. Aşağıdaki komut, benim yeni AppArmor profilimi listelemektedir.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Aşağıda gösterildiği gibi, “/etc/” dizinini değiştirmeye çalıştığımızda hata alıyoruz çünkü AppArmor profili “/etc” dizinine yazma erişimini engelliyor.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Bir konteynerin hangi **apparmor profilinin çalıştığını** bulmak için:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Sonra, **kullanılan tam profili bulmak için** aşağıdaki satırı çalıştırabilirsiniz:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In the weird case you can **apparmor docker profilini değiştirebilir ve yeniden yükleyebilirsiniz.** Kısıtlamaları kaldırabilir ve "bypass" edebilirsiniz.

### AppArmor Docker Bypass2

**AppArmor yol tabanlıdır**, bu, **`/proc`** gibi bir dizin içindeki dosyaları **koruyor** olsa bile, eğer **konteynerin nasıl çalıştırılacağını yapılandırabiliyorsanız**, ana bilgisayarın proc dizinini **`/host/proc`** içine **mount** edebilir ve artık **AppArmor tarafından korunmayacaktır**.

### AppArmor Shebang Bypass

[**bu hata**](https://bugs.launchpad.net/apparmor/+bug/1911431) ile, **belirli kaynaklarla perl'in çalıştırılmasını engelliyorsanız bile**, eğer sadece ilk satırda **`#!/usr/bin/perl`** belirten bir shell script oluşturursanız ve dosyayı doğrudan **çalıştırırsanız**, istediğiniz her şeyi çalıştırabileceğinizi görebilirsiniz. Örnek:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
