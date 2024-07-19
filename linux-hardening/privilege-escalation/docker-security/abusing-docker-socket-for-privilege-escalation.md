# Dockerソケットを悪用した特権昇格

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してハッキングトリックを共有してください。**

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Dockerソケットに**アクセス**できる場合があり、それを使用して**特権を昇格**させたい場合があります。いくつかのアクションは非常に疑わしい可能性があるため、避けたい場合があります。ここでは、特権を昇格させるのに役立つさまざまなフラグを見つけることができます。

### マウントを介して

ルートとして実行されているコンテナ内で**ファイルシステム**の異なる部分を**マウント**し、それに**アクセス**できます。\
マウントを悪用してコンテナ内で特権を昇格させることもできます。

* **`-v /:/host`** -> ホストのファイルシステムをコンテナにマウントし、**ホストのファイルシステムを読み取る**ことができます。
* **ホストにいるように感じたいが、コンテナにいる場合**は、次のフラグを使用して他の防御メカニズムを無効にできます:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> これは前の方法に似ていますが、ここでは**デバイスディスクをマウント**しています。次に、コンテナ内で`mount /dev/sda1 /mnt`を実行すると、**/mnt**で**ホストのファイルシステムにアクセス**できます。
* ホストで`fdisk -l`を実行して、マウントする`</dev/sda1>`デバイスを見つけます。
* **`-v /tmp:/host`** -> 何らかの理由で**ホストから特定のディレクトリのみをマウント**でき、ホスト内にアクセスできる場合は、それをマウントし、マウントされたディレクトリに**suid**を持つ**`/bin/bash`**を作成して、**ホストから実行してrootに昇格**できます。

{% hint style="info" %}
おそらく`/tmp`フォルダをマウントできないかもしれませんが、**異なる書き込み可能なフォルダ**をマウントできる場合があります。書き込み可能なディレクトリを見つけるには、`find / -writable -type d 2>/dev/null`を使用します。

**Linuxマシンのすべてのディレクトリがsuidビットをサポートするわけではありません!** suidビットをサポートするディレクトリを確認するには、`mount | grep -v "nosuid"`を実行します。たとえば、通常`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、および`/var/lib/lxcfs`はsuidビットをサポートしていません。

また、**`/etc`**や**設定ファイルを含む他のフォルダ**を**マウント**できる場合、コンテナ内でrootとしてそれらを変更し、**ホストで悪用して特権を昇格**させることができます（たとえば、`/etc/shadow`を変更する）。
{% endhint %}

### コンテナからの脱出

* **`--privileged`** -> このフラグを使用すると、[コンテナからのすべての隔離を削除します](docker-privileged.md#what-affects)。特権コンテナからrootとして脱出するための技術を確認してください。[特権コンテナからの脱出](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)。
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [能力を悪用して昇格するために](../linux-capabilities.md)、**その能力をコンテナに付与し、エクスプロイトが機能するのを妨げる可能性のある他の保護方法を無効にします。**

### Curl

このページでは、dockerフラグを使用して特権を昇格させる方法について説明しました。**curl**コマンドを使用してこれらの方法を悪用する方法を見つけることができます。

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してハッキングトリックを共有してください。**

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
