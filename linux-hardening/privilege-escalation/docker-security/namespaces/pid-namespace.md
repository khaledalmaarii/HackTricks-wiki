# PID Namespace

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

## 基本情報

PID（プロセス識別子）名前空間は、Linuxカーネルの機能であり、プロセスの隔離を提供します。これにより、一群のプロセスが他の名前空間のPIDとは別に独自の一意のPIDセットを持つことができます。これは、プロセスの隔離がセキュリティとリソース管理に不可欠なコンテナ化に特に役立ちます。

新しいPID名前空間が作成されると、その名前空間内の最初のプロセスにはPID 1が割り当てられます。このプロセスは新しい名前空間の「init」プロセスとなり、その名前空間内の他のプロセスを管理する責任を負います。名前空間内で作成される各後続プロセスは、その名前空間内で一意のPIDを持ち、これらのPIDは他の名前空間のPIDとは独立しています。

PID名前空間内のプロセスの視点から見ると、同じ名前空間内の他のプロセスのみを見ることができます。他の名前空間のプロセスを認識せず、従来のプロセス管理ツール（例：`kill`、`wait`など）を使用して相互作用することはできません。これにより、プロセスが互いに干渉するのを防ぐための隔離レベルが提供されます。

### 仕組み：

1. 新しいプロセスが作成されると（例：`clone()`システムコールを使用して）、そのプロセスは新しいまたは既存のPID名前空間に割り当てられます。**新しい名前空間が作成されると、そのプロセスはその名前空間の「init」プロセスになります**。
2. **カーネルは新しい名前空間内のPIDと親名前空間内の対応するPIDとの間のマッピングを維持します**（つまり、新しい名前空間が作成された親名前空間）。このマッピングは、**カーネルが必要に応じてPIDを変換できるようにします**。たとえば、異なる名前空間のプロセス間で信号を送信する際などです。
3. **PID名前空間内のプロセスは、同じ名前空間内の他のプロセスのみを見ることができ、相互作用できます**。他の名前空間のプロセスを認識せず、そのPIDは自分の名前空間内で一意です。
4. **PID名前空間が破棄されると**（例：名前空間の「init」プロセスが終了すると）、**その名前空間内のすべてのプロセスが終了します**。これにより、名前空間に関連するすべてのリソースが適切にクリーンアップされます。

## ラボ：

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

`unshare`を`-f`オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。以下に重要な詳細と解決策を示します。

1. **問題の説明**:
- Linuxカーネルは、プロセスが`unshare`システムコールを使用して新しい名前空間を作成することを許可します。しかし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入ることはなく、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`unshare`と同じプロセスで`/bin/bash`が開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間に存在します。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他にプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1は孤児プロセスを引き取る特別な役割を持っています。Linuxカーネルはその名前空間でのPID割り当てを無効にします。

2. **結果**:
- 新しい名前空間内のPID 1の終了は、`PIDNS_HASH_ADDING`フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てることに失敗し、「Cannot allocate memory」エラーが発生します。

3. **解決策**:
- この問題は、`unshare`に`-f`オプションを使用することで解決できます。このオプションにより、`unshare`は新しいPID名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しい名前空間内でPID 1になります。これにより、`/bin/bash`とその子プロセスはこの新しい名前空間内に安全に収容され、PID 1の早期終了を防ぎ、正常なPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確保することで、新しいPID名前空間が正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

新しいインスタンスの`/proc`ファイルシステムをマウントすることで、`--mount-proc`パラメータを使用すると、新しいマウント名前空間がその名前空間に特有の**プロセス情報の正確で孤立したビューを持つ**ことが保証されます。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### すべてのPID名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

初期（デフォルト）PID名前空間からのrootユーザーは、新しいPID名前空間内のプロセスを含むすべてのプロセスを見ることができるため、すべてのPID名前空間を見ることができます。

### PID名前空間内に入る
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
PID名前空間にデフォルトの名前空間から入ると、すべてのプロセスを見ることができます。そして、そのPID nsのプロセスはPID nsの新しいbashを見ることができます。

また、**あなたがrootでない限り、他のプロセスのPID名前空間に入ることはできません**。そして、**それに指し示すディスクリプタなしに他の名前空間に** **入ることはできません**（例えば、`/proc/self/ns/pid`のように）。

## References
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
</details>
{% endhint %}
