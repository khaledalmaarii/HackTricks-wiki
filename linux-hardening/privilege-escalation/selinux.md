<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Konteynerlerde SELinux

[Kırmızı şapkalı belgelerden giriş ve örnek](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux), bir **etiketleme** **sistemidir**. Her **işlem** ve her **dosya** sistemi nesnesi bir **etikete** sahiptir. SELinux politikaları, bir **işlem etiketinin sistemdeki diğer tüm etiketlerle ne yapabileceğine dair kuralları** tanımlar.

Konteyner motorları, genellikle `container_t` olarak etiketlenen **tek bir sınırlı SELinux etiketiyle** konteyner işlemlerini başlatır ve ardından konteyneri içindeki konteyneri `container_file_t` olarak etiketler. SELinux politika kuralları temel olarak **`container_t` işlemlerinin yalnızca `container_file_t` olarak etiketlenmiş dosyaları okuyabileceğini/yazabileceğini/çalıştırabileceğini** söyler. Bir konteyner işlemi konteynerden kaçar ve ana makinedeki içeriğe yazmaya çalışırsa, Linux çekirdeği erişimi reddeder ve yalnızca konteyner işleminin `container_file_t` olarak etiketlenmiş içeriğe yazmasına izin verir.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux Kullanıcıları

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları bulunmaktadır. SELinux kullanıcıları, bir SELinux politikasının bir parçasıdır. Her Linux kullanıcısı, politikanın bir parçası olarak bir SELinux kullanıcısına eşlenir. Bu, Linux kullanıcılarının SELinux kullanıcıları üzerinde uygulanan kısıtlamaları ve güvenlik kurallarını ve mekanizmalarını devralmasını sağlar.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
