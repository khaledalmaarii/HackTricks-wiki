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


# 컨테이너의 SELinux

[레드햇 문서의 소개 및 예제](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)는 **레이블링** **시스템**입니다. 모든 **프로세스**와 모든 **파일** 시스템 객체는 **레이블**을 가지고 있습니다. SELinux 정책은 **프로세스 레이블이 시스템의 다른 모든 레이블과 함께 무엇을 할 수 있는지에 대한 규칙을 정의**합니다.

컨테이너 엔진은 **단일 제한된 SELinux 레이블**로 **컨테이너 프로세스**를 시작하며, 일반적으로 `container_t`를 사용하고, 그 후 컨테이너 내부의 컨테이너를 `container_file_t`로 레이블을 설정합니다. SELinux 정책 규칙은 기본적으로 **`container_t` 프로세스가 `container_file_t`로 레이블이 지정된 파일만 읽고/쓰고/실행할 수 있다고 말합니다**. 만약 컨테이너 프로세스가 컨테이너를 탈출하고 호스트의 콘텐츠에 쓰려고 시도하면, 리눅스 커널은 접근을 거부하고 컨테이너 프로세스가 `container_file_t`로 레이블이 지정된 콘텐츠에만 쓸 수 있도록 허용합니다.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux 사용자

정상적인 Linux 사용자 외에도 SELinux 사용자가 있습니다. SELinux 사용자는 SELinux 정책의 일부입니다. 각 Linux 사용자는 정책의 일환으로 SELinux 사용자에 매핑됩니다. 이를 통해 Linux 사용자는 SELinux 사용자에게 부여된 제한 및 보안 규칙과 메커니즘을 상속받을 수 있습니다.

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
</details>
{% endhint %}
