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


# コンテナにおけるSELinux

[Redhatのドキュメントからの紹介と例](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)は**ラベリング** **システム**です。すべての**プロセス**とすべての**ファイル**システムオブジェクトには**ラベル**があります。SELinuxポリシーは、**プロセスラベルがシステム上の他のすべてのラベルに対して何をすることが許可されているか**に関するルールを定義します。

コンテナエンジンは、通常`container_t`という単一の制限されたSELinuxラベルで**コンテナプロセスを起動**し、その後、コンテナ内のコンテナを`container_file_t`というラベルに設定します。SELinuxポリシールールは基本的に、**`container_t`プロセスは`container_file_t`というラベルが付けられたファイルをのみ読み書き/実行できる**と言っています。コンテナプロセスがコンテナから脱出し、ホスト上のコンテンツに書き込もうとすると、Linuxカーネルはアクセスを拒否し、コンテナプロセスが`container_file_t`というラベルが付けられたコンテンツにのみ書き込むことを許可します。
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinuxユーザー

通常のLinuxユーザーに加えて、SELinuxユーザーも存在します。SELinuxユーザーはSELinuxポリシーの一部です。各Linuxユーザーはポリシーの一部としてSELinuxユーザーにマッピングされます。これにより、LinuxユーザーはSELinuxユーザーに課せられた制限やセキュリティルール、メカニズムを継承することができます。

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
