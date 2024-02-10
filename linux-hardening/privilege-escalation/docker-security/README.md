# Docker Güvenliği

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **Trickest** kullanarak kolayca iş akışları oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Temel Docker Engine Güvenliği**

**Docker motoru**, konteynerleri izole etmek için Linux çekirdeğinin **Namespaces** ve **Cgroups**'ını kullanır ve temel bir güvenlik katmanı sunar. Ek koruma, **Yeteneklerin düşürülmesi**, **Seccomp** ve **SELinux/AppArmor** ile konteyner izolasyonunu artırır. Bir **auth eklentisi**, kullanıcı eylemlerini daha da kısıtlayabilir.

![Docker Güvenliği](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker Engine'e Güvenli Erişim

Docker motoruna yerel olarak Unix soketi üzerinden veya uzaktan HTTP kullanarak erişilebilir. Uzaktan erişim için, gizlilik, bütünlük ve kimlik doğrulama sağlamak için HTTPS ve **TLS** kullanmak önemlidir.

Docker motoru, varsayılan olarak Unix soketinde `unix:///var/run/docker.sock` üzerinde dinler. Ubuntu sistemlerinde, Docker'ın başlatma seçenekleri `/etc/default/docker` dosyasında tanımlanır. Docker API ve istemciye uzaktan erişimi etkinleştirmek için aşağıdaki ayarları ekleyerek Docker daemonunu bir HTTP soketi üzerinde açığa çıkarın:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Ancak, Docker daemon'ını HTTP üzerinden açmak güvenlik endişeleri nedeniyle önerilmez. Bağlantıları HTTPS kullanarak güvence altına almak tavsiye edilir. Bağlantıyı güvence altına almanın iki temel yaklaşımı vardır:
1. İstemci, sunucunun kimliğini doğrular.
2. İstemci ve sunucu, birbirlerinin kimliklerini karşılıklı olarak doğrular.

Sertifikalar, bir sunucunun kimliğini doğrulamak için kullanılır. Her iki yöntemin detaylı örnekleri için [**bu kılavuza**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/) başvurun.

### Konteyner Görüntülerinin Güvenliği

Konteyner görüntüleri, özel veya genel depolama alanlarında saklanabilir. Docker, konteyner görüntüleri için birkaç depolama seçeneği sunar:

* **[Docker Hub](https://hub.docker.com)**: Docker'ın genel kayıt defteri hizmeti.
* **[Docker Registry](https://github.com/docker/distribution)**: Kullanıcıların kendi kayıt defterlerini barındırmasına izin veren açık kaynaklı bir proje.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Docker'ın ticari kayıt defteri hizmeti, rol tabanlı kullanıcı kimlik doğrulama ve LDAP dizin hizmetleriyle entegrasyon özelliklerine sahiptir.

### Görüntü Tarama

Konteynerler, temel görüntü veya temel görüntü üzerine kurulan yazılım nedeniyle **güvenlik açıklarına** sahip olabilir. Docker, konteynerlerin güvenlik taramasını yapabilen ve güvenlik açıklarını listeleyen **Nautilus** adlı bir proje üzerinde çalışmaktadır. Nautilus, her konteyner görüntü katmanını güvenlik açığı deposuyla karşılaştırarak güvenlik açıklarını belirler.

Daha fazla [**bilgi için burayı okuyun**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

**`docker scan`** komutu, görüntü adını veya kimliğini kullanarak mevcut Docker görüntülerini taramanıza olanak sağlar. Örneğin, hello-world görüntüsünü taramak için aşağıdaki komutu çalıştırın:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker İmaj İmzalama

Docker imaj imzalama, konteynerlerde kullanılan imajların güvenliğini ve bütünlüğünü sağlar. İşte özetlenmiş bir açıklama:

- **Docker İçerik Güveni**, imaj imzalama işlemini yönetmek için The Update Framework (TUF) üzerine kurulu Notary projesini kullanır. Daha fazla bilgi için [Notary](https://github.com/docker/notary) ve [TUF](https://theupdateframework.github.io) sayfalarına bakabilirsiniz.
- Docker içerik güvenini etkinleştirmek için `export DOCKER_CONTENT_TRUST=1` komutunu kullanın. Bu özellik, Docker 1.10 ve sonraki sürümlerde varsayılan olarak kapalıdır.
- Bu özellik etkinleştirildiğinde, yalnızca imzalı imajlar indirilebilir. İlk imaj gönderimi için, Docker ayrıca artırılmış güvenlik için Yubikey'i de destekleyerek kök ve etiketleme anahtarları için parolaların ayarlanmasını gerektirir. Daha fazla ayrıntıya [buradan](https://blog.docker.com/2015/11/docker-content-trust-yubikey/) ulaşabilirsiniz.
- İçerik güveni etkinleştirilmiş bir imzasız imajı çekmeye çalışmak, "No trust data for latest" hatasına neden olur.
- İlk gönderimden sonra imaj gönderirken, Docker imajı imzalamak için depo anahtarının parolasını ister.

Özel anahtarlarınızı yedeklemek için aşağıdaki komutu kullanın:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Docker ana bilgisayardan geçiş yaparken, işlemleri sürdürebilmek için kök ve depo anahtarlarını taşımak gereklidir.


***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **otomatik iş akışları** oluşturabilir ve otomatikleştirebilirsiniz.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Konteyner Güvenlik Özellikleri

<details>

<summary>Konteyner Güvenlik Özelliklerinin Özeti</summary>

### Ana İşlem Yalıtım Özellikleri

Konteynerleştirilmiş ortamlarda, projelerin ve işlemlerinin yalıtılması güvenlik ve kaynak yönetimi için önemlidir. İşte temel kavramların basitleştirilmiş bir açıklaması:

#### **İsim Alanları (Namespaces)**
- **Amaç**: İşlemler, ağ ve dosya sistemleri gibi kaynakların yalıtılmasını sağlamak. Özellikle Docker'da, isim alanları bir konteynerin işlemlerini ana bilgisayardan ve diğer konteynerlerden ayırır.
- **`unshare` Komutunun Kullanımı**: Yeni bir isim alanı oluşturmak için `unshare` komutu (veya altta yatan sistem çağrısı) kullanılır ve ek bir yalıtım katmanı sağlar. Bununla birlikte, Kubernetes bunu doğal olarak engellemezken, Docker engeller.
- **Sınırlama**: Yeni bir isim alanı oluşturmak, bir işlemin ana bilgisayarın varsayılan isim alanlarına geri dönmesine izin vermez. Ana bilgisayarın isim alanlarına nüfuz etmek için genellikle ana bilgisayarın `/proc` dizinine erişim gereklidir ve giriş için `nsenter` kullanılır.

#### **Kontrol Grupları (CGroups)**
- **İşlev**: Öncelikle işlemler arasında kaynak tahsis etmek için kullanılır.
- **Güvenlik Yönü**: CGroups, kendileri başlı başına bir yalıtım güvenliği sunmazlar, ancak yanlış yapılandırılmışsa `release_agent` özelliği yetkisiz erişim için istismar edilebilir.

#### **Yetenek Düşürme (Capability Drop)**
- **Önemi**: İşlem yalıtımı için önemli bir güvenlik özelliğidir.
- **İşlevsellik**: Belirli yetenekleri düşürerek kök işlemin gerçekleştirebileceği eylemleri sınırlar. Bir işlem kök ayrıcalıklarıyla çalışsa bile, gerekli yeteneklere sahip olmaması nedeniyle ayrıcalıklı eylemleri gerçekleştiremez, çünkü sistem çağrıları yetersiz izinler nedeniyle başarısız olur.

Bu, işlem diğerlerini düşürdükten sonra **kalan yeteneklerdir**:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Docker'da varsayılan olarak etkinleştirilmiştir. Bu, işlemin çağırabileceği sistem çağrılarını daha da sınırlamaya yardımcı olur.\
**Varsayılan Docker Seccomp profili**, [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) adresinde bulunabilir.

**AppArmor**

Docker'ın etkinleştirebileceğiniz bir şablonu vardır: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Bu, yetenekleri, sistem çağrılarını, dosya ve klasörlere erişimi azaltmanıza olanak sağlar...

</details>

### Namespaces

**Namespaces**, Linux çekirdeğinin bir özelliğidir ve bir dizi **işlem**, bir dizi **kaynağı** görürken **başka** bir dizi **işlem** farklı bir dizi kaynak görür şeklinde çekirdek kaynaklarını **bölümlendirir**. Bu özellik, bir dizi kaynak ve işlem için aynı ad alanına sahip olmakla birlikte, bu ad alanlarının farklı kaynaklara işaret etmesiyle çalışır. Kaynaklar birden çok alanda bulunabilir.

Docker, Konteyner izolasyonunu sağlamak için aşağıdaki Linux çekirdek Ad Alanlarını kullanır:

* pid ad alanı
* mount ad alanı
* network ad alanı
* ipc ad alanı
* UTS ad alanı

**Ad alanları hakkında daha fazla bilgi** için aşağıdaki sayfaya bakın:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux çekirdek özelliği olan **cgroups**, bir dizi işlem arasında cpu, bellek, io, ağ bant genişliği gibi kaynakları **sınırlama** yeteneği sağlar. Docker, belirli bir Konteyner için kaynak kontrolüne izin veren cgroup özelliğini kullanarak Konteynerler oluşturmanıza izin verir.\
Aşağıdaki örnekte, kullanıcı alanı belleği 500m, çekirdek belleği 50m, cpu payı 512, blkioweight 400 ile sınırlı bir Konteyner oluşturulmuştur. CPU payı, Konteyner'in CPU kullanımını kontrol eden bir orandır. Varsayılan değeri 1024'tür ve 0 ile 1024 arasında bir aralığa sahiptir. Eğer üç Konteynerin aynı CPU payı 1024 ise, CPU kaynak çekişmesi durumunda her Konteyner CPU'nun %33'ünü alabilir. blkio-weight, Konteyner'in IO'sunu kontrol eden bir orandır. Varsayılan değeri 500'dür ve 10 ile 1000 arasında bir aralığa sahiptir.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Bir konteynerin cgroup'una erişmek için şunu yapabilirsiniz:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Daha fazla bilgi için şu adrese bakın:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Yetenekler

Yetenekler, kök kullanıcı için **izin verilebilecek yeteneklerin daha ince kontrolünü sağlar**. Docker, kullanıcı türünden bağımsız olarak **bir Konteyner içinde yapılabilen işlemleri sınırlamak** için Linux çekirdeği yetenek özelliğini kullanır.

Bir docker konteyneri çalıştırıldığında, **işlem, izolasyondan kaçınmak için kullanabileceği hassas yetenekleri bırakır**. Bu, işlemin hassas eylemleri gerçekleştiremeyeceğini ve kaçamayacağını sağlamaya çalışır:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker'da Seccomp

Bu, Docker'ın konteyner içinde kullanılabilecek **sistem çağrılarını sınırlamasına** izin veren bir güvenlik özelliğidir:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker'da AppArmor

**AppArmor**, **konteynerleri** bir **sınırlı** **kaynak kümesine** ve **program bazlı profillere** kısıtlamak için bir çekirdek geliştirmesidir:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker'da SELinux

- **Etiketleme Sistemi**: SELinux, her işlem ve dosya sistemi nesnesine benzersiz bir etiket atar.
- **Politika Uygulaması**: İşlem etiketinin sistem içindeki diğer etiketler üzerinde hangi eylemleri gerçekleştirebileceğini tanımlayan güvenlik politikalarını uygular.
- **Konteyner İşlem Etiketleri**: Konteyner motorları konteyner işlemlerini başlattığında genellikle sınırlı bir SELinux etiketi olan `container_t` atanır.
- **Konteyner İçindeki Dosya Etiketleme**: Konteyner içindeki dosyalar genellikle `container_file_t` olarak etiketlenir.
- **Politika Kuralları**: SELinux politikası, `container_t` etiketine sahip işlemlerin yalnızca `container_file_t` olarak etiketlenmiş dosyalarla etkileşimde bulunabileceğini (okuma, yazma, çalıştırma) sağlar.

Bu mekanizma, bir konteynerin içindeki bir işlem bile ele geçirilse bile, ilgili etiketlere sahip nesnelerle sınırlı kalmasını sağlar ve böyle bir saldırının potansiyel zararını önemli ölçüde sınırlar.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Docker'da, bir yetkilendirme eklentisi, Docker daemonuna yapılan istekleri izin vermek veya engellemek için güvenlik açısından önemli bir rol oynar. Bu karar, iki temel bağlamı inceleyerek verilir:

- **Kimlik Doğrulama Bağlamı**: Bu, kullanıcı hakkında kapsamlı bilgileri içerir, örneğin kim oldukları ve nasıl kimlik doğruladıkları.
- **Komut Bağlamı**: Bu, yapılan isteğe ilişkin tüm ilgili verileri içerir.

Bu bağlamlar, yalnızca kimlik doğrulaması yapılmış kullanıcılardan gelen meşru isteklerin işlenmesini sağlayarak Docker işlemlerinin güvenliğini artırır.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Bir konteynerden DoS saldırısı

Bir konteynerin kullanabileceği kaynakları düzgün bir şekilde sınırlamazsanız, ele geçirilmiş bir konteyner, çalıştığı ana bilgisayarı DoS edebilir.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandwidth DoS

Bandwidth DoS (Hiz Kısıtlama Hizmet Reddi) saldırısı, bir hedefin ağ bağlantısını aşırı miktarda veri trafiğiyle doldurarak hizmetlerini kullanılamaz hale getirmeyi amaçlayan bir saldırı türüdür. Bu saldırı, hedefin ağ kaynaklarını tüketerek ağ performansını düşürebilir veya tamamen durdurabilir.

Bu saldırı türü, genellikle bir botnet veya dağıtılmış bir ağ kullanılarak gerçekleştirilir. Saldırganlar, hedefin ağ bağlantısına büyük miktarda veri trafiği göndererek ağ kaynaklarını tüketirler. Bu, hedefin ağ altyapısının kapasitesini aşmasına ve hizmetlerin kullanılamaz hale gelmesine neden olur.

Bandwidth DoS saldırılarına karşı korunmak için ağ güvenliği önlemleri almak önemlidir. Bu önlemler arasında güvenlik duvarları, ağ trafiği izleme ve filtreleme, saldırı tespit sistemleri ve yük dengeleme gibi teknolojiler kullanılabilir. Ayrıca, ağ kaynaklarının düzgün bir şekilde yapılandırılması ve güncel tutulması da saldırı riskini azaltmaya yardımcı olabilir.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## İlginç Docker Bayrakları

### --privileged bayrağı

Aşağıdaki sayfada **`--privileged` bayrağının ne anlama geldiğini** öğrenebilirsiniz:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Eğer düşük ayrıcalıklı bir kullanıcı olarak erişim sağlayan bir saldırganın çalıştırdığı bir konteyneriniz varsa ve **hatalı yapılandırılmış bir suid ikili**ye sahipseniz, saldırgan bunu istismar edebilir ve konteyner içindeki ayrıcalıkları **yükseltebilir**. Bu da ona kaçmasına izin verebilir.

Konteyneri **`no-new-privileges`** seçeneği etkinleştirilmiş olarak çalıştırmak, bu tür bir ayrıcalık yükselmesini **önleyecektir**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Diğer

Docker, birçok güvenlik önlemi içerir, ancak doğru yapılandırma ve güvenlik önlemleri alınmadığında hala riskler içerebilir. Aşağıda, Docker konteynerlerinin güvenliğini artırmak için bazı önemli adımlar bulunmaktadır:

- **Güncel Kalın**: Docker'ı ve kullanılan tüm bileşenleri güncel tutun. Güncellemeler, güvenlik açıklarını düzeltmek ve yeni güvenlik özelliklerini sağlamak için önemlidir.
- **Güvenli İmajlar Kullanın**: Güvenilir ve güncel imajlar kullanın. İmajlar, güvenlik açıkları içerebilir, bu nedenle güvenilir kaynaklardan indirildiğinden emin olun.
- **Kısıtlı İzinler**: Konteynerlerin çalışma zamanı izinlerini kısıtlayın. İhtiyaç duyulmayan izinleri devre dışı bırakarak saldırı yüzeyini azaltabilirsiniz.
- **Ağ Güvenliği**: Konteynerler arasında ağ izolasyonu sağlayın ve gereksiz ağ bağlantılarını kapatın. Ayrıca, güvenli ağ politikaları ve güvenlik duvarları kullanarak ağ trafiğini kontrol altında tutun.
- **Güvenli Depolama**: Hassas verileri güvenli bir şekilde depolayın ve şifreleme kullanın. Verilerin güvenliğini sağlamak için güvenli depolama çözümleri kullanın.
- **Güvenli Kimlik Doğrulama**: Güçlü kimlik doğrulama yöntemleri kullanarak konteynerlere erişimi sınırlayın. Parola politikaları ve çok faktörlü kimlik doğrulama gibi güvenlik önlemleri uygulayın.
- **Günlükleme ve İzleme**: Konteyner faaliyetlerini günlükleyin ve izleyin. Anormal faaliyetleri tespit etmek ve saldırıları önlemek için günlükleri düzenli olarak kontrol edin.
- **Güvenlik Denetimleri**: Düzenli olarak güvenlik denetimleri yapın ve zayıf noktaları tespit edin. Zayıf noktaları düzeltmek ve güvenlik önlemlerini güncellemek için düzenli olarak denetimler yapın.

Bu adımları takip ederek, Docker konteynerlerinin güvenliğini artırabilir ve potansiyel saldırılara karşı daha iyi korunabilirsiniz.
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Daha fazla **`--security-opt`** seçeneği için şu adrese bakın: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Diğer Güvenlik Düşünceleri

### Gizli Bilgileri Yönetme: En İyi Uygulamalar

Docker görüntülerine gizli bilgileri doğrudan yerleştirmek veya çevre değişkenlerini kullanmak, `docker inspect` veya `exec` gibi komutlarla konteynere erişimi olan herkese hassas bilgilerinizi açığa çıkarır, bu nedenle bu yöntemlerden kaçınmak son derece önemlidir.

**Docker volumleri**, hassas bilgilere erişmek için önerilen daha güvenli bir alternatiftir. Bunlar, `docker inspect` ve günlükleme ile ilişkili riskleri azaltarak geçici bir dosya sistemi olarak bellekte kullanılabilir. Bununla birlikte, kök kullanıcılar ve konteynere `exec` erişimi olanlar hala gizli bilgilere erişebilir.

**Docker secrets**, hassas bilgileri işleme konusunda daha da güvenli bir yöntem sunar. Görüntü oluşturma aşamasında gizli bilgilere ihtiyaç duyulan durumlar için, **BuildKit** ek özellikler sunarak oluşturma hızını artıran ve build-time secrets'ı destekleyen verimli bir çözüm sunar.

BuildKit'i kullanmak için üç farklı yol vardır:

1. Bir çevre değişkeni aracılığıyla: `export DOCKER_BUILDKIT=1`
2. Komutlara önek ekleyerek: `DOCKER_BUILDKIT=1 docker build .`
3. Docker yapılandırmasında varsayılan olarak etkinleştirerek: `{ "features": { "buildkit": true } }` ve ardından Docker'ı yeniden başlatarak.

BuildKit, `--secret` seçeneğiyle build-time secrets'ın görüntü oluşturma önbelleğine veya nihai görüntüye dahil edilmediğini sağlar. Bu seçenek, aşağıdaki gibi bir komut kullanılarak kullanılabilir:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Çalışan bir konteyner için gerekli olan sırlar için **Docker Compose ve Kubernetes**, sağlam çözümler sunar. Docker Compose, gizli dosyaları belirtmek için hizmet tanımında `secrets` anahtarını kullanır. İşte bir `docker-compose.yml` örneğinde gösterildiği gibi:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Bu yapılandırma, Docker Compose ile hizmetleri başlatırken secrets kullanımına izin verir.

Kubernetes ortamlarında, secrets doğal olarak desteklenir ve [Helm-Secrets](https://github.com/futuresimple/helm-secrets) gibi araçlarla daha fazla yönetilebilir. Kubernetes'in Rol Tabanlı Erişim Kontrolleri (RBAC), Docker Enterprise ile benzer şekilde secret yönetimi güvenliğini artırır.

### gVisor

**gVisor**, Go dilinde yazılmış bir uygulama çekirdeğidir ve Linux sistemi yüzeyinin önemli bir bölümünü uygular. **Uygulama ve ana çekirdek arasında bir izolasyon sınırı** sağlayan bir [Open Container Initiative (OCI)](https://www.opencontainers.org) çalışma zamanı olan `runsc`'yi içerir. `runsc` çalışma zamanı, Docker ve Kubernetes ile entegre olup, sandboxed konteynerlerin çalıştırılmasını kolaylaştırır.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**, hafif sanal makineler kullanarak daha güçlü iş yükü izolasyonu sağlayan, ancak konteynerler gibi hissedip performans gösteren güvenli bir konteyner çalışma zamanı oluşturmak için çalışan açık kaynak bir topluluktur.

{% embed url="https://katacontainers.io/" %}

### Özet İpuçları

* **`--privileged` bayrağını kullanmayın veya konteynerin içine bir** [**Docker soketi bağlamayın**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Docker soketi, konteynerlerin başlatılmasına izin verir, bu nedenle başka bir konteyneri `--privileged` bayrağıyla çalıştırarak ana bilgisayarı tam kontrol altına almak kolaydır.
* Konteynerin içinde **root olarak çalıştırmayın.** [**Farklı bir kullanıcı**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **ve** [**kullanıcı ad alanları**](https://docs.docker.com/engine/security/userns-remap/)** kullanın.** Konteynerdeki root, kullanıcı ad alanlarıyla yeniden eşlenmediği sürece ana bilgisayardaki root ile aynıdır. Yalnızca Linux ad alanları, yetenekler ve cgroups tarafından hafifçe kısıtlanır.
* [**Tüm yetenekleri bırakın**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) ve yalnızca gerekenleri etkinleştirin** (`--cap-add=...`). Birçok iş yükü hiçbir yetenek gerektirmez ve bunları eklemek, potansiyel bir saldırının kapsamını artırır.
* [**"no-new-privileges" güvenlik seçeneğini kullanın**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/), örneğin suid ikili dosyalar aracılığıyla daha fazla yetki elde etmeyi önlemek için. 
* Konteynere sağlanan **kaynakları sınırlayın**. Kaynak sınırları, hizmet reddi saldırılarına karşı makineyi koruyabilir.
* **seccomp**'u, **AppArmor**'ı (veya SELinux'i) **ayarlayarak** konteyner için kullanılabilir eylem ve sistem çağrılarını minimuma indirin.
* [**Resmi Docker görüntülerini kullanın**](https://docs.docker.com/docker-hub/official\_images/) **ve imzaları gerektirin** veya bunlara dayalı olarak kendi görüntülerinizi oluşturun. Kalıtım almayın veya [arka kapısı olan](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) görüntüler kullanmayın. Ayrıca, kök anahtarları ve parolayı güvenli bir yerde saklayın. Docker, UCP ile anahtarları yönetme planlarına sahiptir.
* Görüntülerinizi düzenli olarak yeniden oluşturarak, ana bilgisayara ve görüntülere güvenlik yamalarını uygulayın.
* Secrets'ları akıllıca yönetin, saldırganın bunlara erişmesini zorlaştırın.
* Docker daemon'ı açığa çıkarıyorsanız, HTTPS kullanarak istemci ve sunucu kimlik doğrulaması yapın.
* Dockerfile'ınızda, **ADD yerine COPY'yi tercih edin**. ADD otomatik olarak sıkıştırılmış dosyaları çıkarır ve dosyaları URL'lerden kopyalayabilir. COPY bu yeteneklere sahip değildir. Mümkün olduğunca ADD kullanmaktan kaçının, böylece uzaktan URL'ler ve Zip dosyaları aracılığıyla yapılan saldırılara karşı savunmasız olmazsınız.
* Her mikro hizmet için **ayrı konteynerler** kullanın.
* Konteynerin içine **ssh koymayın**, "docker exec" komutu Konteynere ssh yapmak için kullanılabilir.
* Daha **küçük** konteyner **görüntüleri** kullanın.

## Docker Breakout / Privilege Escalation

Eğer bir **docker konteynerinin içindeyseniz** veya **docker grubunda bir kullanıcıya erişiminiz varsa**, kaçma ve ayrıcalıkları yükseltmeyi deneyebilirsiniz:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker Authentication Plugin Bypass

Eğer docker soketine erişiminiz varsa veya **docker grubunda bir kullanıcıya erişiminiz var, ancak docker kimlik doğrulama eklentisi tarafından sınırlanıyorsanız**, onu atlayıp atlayamayacağınızı kontrol edin:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Docker'ı Güvenceye Alma

* [**docker-bench-security**](https://github.com/docker/docker-bench-security) aracı, Docker konteynerlerini üretim ortamında dağıtma konusunda onlarca yaygın en iyi uygulamayı kontrol eden bir betiktir. Testlerin hepsi otomatiktir ve [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/) temel alınarak yapılmıştır.\
Araç, Docker'ı çalıştıran ana bilgisayardan veya yeterli ayrıcalıklara sahip bir konteynerden çalıştırmanız gerekmektedir. README'de nasıl çalıştırılacağını bulun: [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referanslar

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/115148705198608793
HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te reklamını görmek veya HackTricks'i PDF olarak indirmek isterseniz, [ABONELİK PLANLARI](https://github.com/sponsors/carlospolop)'na göz atın!
* [Resmi PEASS & HackTricks ürünlerini](https://peass.creator-spring.com) edinin.
* [The PEASS Ailesi](https://opensea.io/collection/the-peass-family)ni keşfedin, özel [NFT'lerimiz](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* 💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) takip edin.
* Hacking hilelerinizi paylaşarak PR'lar göndererek [HackTricks](https://github.com/carlospolop/hacktricks) ve [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
