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
{% endhint %}


# Konteynerlerde SELinux

[Redhat belgelerinden giriş ve örnek](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) bir **etiketleme** **sistemidir**. Her **işlem** ve her **dosya** sistemi nesnesinin bir **etiketi** vardır. SELinux politikaları, bir **işlem etiketinin sistemdeki diğer etiketlerle ne yapabileceğine dair kurallar tanımlar.

Konteyner motorları, **konteyner işlemlerini tek bir sınırlı SELinux etiketiyle** başlatır, genellikle `container_t`, ve ardından konteynerin içindeki dosyaların `container_file_t` olarak etiketlenmesini sağlar. SELinux politika kuralları, **`container_t` işlemlerinin yalnızca `container_file_t` olarak etiketlenmiş dosyaları okuyup/yazabileceğini/çalıştırabileceğini** söyler. Eğer bir konteyner işlemi konteynerden kaçarak ana makinedeki içeriğe yazmaya çalışırsa, Linux çekirdeği erişimi reddeder ve yalnızca konteyner işleminin `container_file_t` olarak etiketlenmiş içeriğe yazmasına izin verir.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux Kullanıcıları

Normal Linux kullanıcılarının yanı sıra SELinux kullanıcıları da vardır. SELinux kullanıcıları, bir SELinux politikasının parçasıdır. Her Linux kullanıcısı, politikanın bir parçası olarak bir SELinux kullanıcısına eşlenir. Bu, Linux kullanıcılarının SELinux kullanıcılarına uygulanan kısıtlamaları ve güvenlik kurallarını ve mekanizmalarını miras almasını sağlar.
