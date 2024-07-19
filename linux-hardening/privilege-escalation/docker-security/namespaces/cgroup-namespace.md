# CGroup Namespace

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

## 基本情報

cgroup名前空間は、**名前空間内で実行されているプロセスのためのcgroup階層の隔離を提供するLinuxカーネルの機能**です。cgroupsは、**制御グループ**の略で、プロセスを階層的なグループに整理し、CPU、メモリ、I/Oなどの**システムリソースの制限を管理および強制する**ためのカーネル機能です。

cgroup名前空間は、以前に議論した他の名前空間タイプ（PID、マウント、ネットワークなど）とは異なる独立した名前空間タイプではありませんが、名前空間の隔離の概念に関連しています。**Cgroup名前空間はcgroup階層のビューを仮想化**し、cgroup名前空間内で実行されているプロセスは、ホストや他の名前空間で実行されているプロセスとは異なる階層のビューを持ちます。

### 仕組み:

1. 新しいcgroup名前空間が作成されると、**それは作成プロセスのcgroupに基づいたcgroup階層のビューから始まります**。これは、新しいcgroup名前空間内で実行されるプロセスが、作成プロセスのcgroupに根ざしたcgroupサブツリーに制限された、全体のcgroup階層のサブセットのみを表示することを意味します。
2. cgroup名前空間内のプロセスは、**自分のcgroupを階層のルートとして見る**ことになります。これは、名前空間内のプロセスの視点から、自分のcgroupがルートとして表示され、他のサブツリーの外にあるcgroupを見ることもアクセスすることもできないことを意味します。
3. cgroup名前空間はリソースの隔離を直接提供するわけではありません; **それはcgroup階層のビューの隔離のみを提供します**。**リソースの制御と隔離は、cgroup**サブシステム（例：cpu、メモリなど）自体によって依然として強制されます。

CGroupsに関する詳細情報は、以下を確認してください:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムを `--mount-proc` パラメータを使用してマウントすることで、新しいマウント名前空間がその名前空間に特有のプロセス情報の**正確で隔離されたビュー**を持つことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てできません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) 名前空間を処理する方法のためにエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**：
- Linux カーネルはプロセスが `unshare` システムコールを使用して新しい名前空間を作成することを許可します。しかし、新しい PID 名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間に存在します。
- 新しい名前空間内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1 は孤児プロセスを引き取る特別な役割を持っています。Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**：
- 新しい名前空間内の PID 1 の終了は `PIDNS_HASH_ADDING` フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てできません」というエラーが発生します。

3. **解決策**：
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションは、`unshare` が新しい PID 名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に収容され、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### すべてのCGroup名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### CGroup ネームスペースに入る
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
また、**ルートでない限り他のプロセスネームスペースに入ることはできません**。そして、**ディスクリプタ**がそれを指していない限り（例えば`/proc/self/ns/cgroup`）、他のネームスペースに**入ることはできません**。

## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
