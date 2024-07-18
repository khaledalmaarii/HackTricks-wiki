# CGroups

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して**ハッキングトリックを共有**してください。

</details>
{% endhint %}

## 基本情報

**Linux Control Groups**、または**cgroups**は、Linuxカーネルの機能であり、CPU、メモリ、ディスクI/Oなどのシステムリソースの割り当て、制限、優先順位付けをプロセスグループ間で可能にします。これらは、プロセスコレクションのリソース使用量を**管理および分離**するメカニズムを提供し、リソース制限、ワークロードの分離、異なるプロセスグループ間でのリソースの優先順位付けなどの目的に役立ちます。

**cgroupsには2つのバージョン**があります: バージョン1とバージョン2。両方をシステムで同時に使用できます。主な違いは、**cgroupsバージョン2**が**階層的なツリー構造**を導入し、プロセスグループ間でより微妙で詳細なリソース分配を可能にする点です。さらに、バージョン2には次のようなさまざまな改善点があります:

新しい階層構造の導入に加えて、cgroupsバージョン2には**他のいくつかの変更と改善**が導入されており、**新しいリソースコントローラ**のサポート、レガシーアプリケーションへのより良いサポート、およびパフォーマンスの向上が含まれています。

全体として、cgroups **バージョン2は、バージョン1よりも多くの機能と優れたパフォーマンス**を提供しますが、後者は、古いシステムとの互換性が懸念される場合には引き続き使用される可能性があります。

任意のプロセスのv1およびv2 cgroupsをリストするには、そのcgroupファイルを/proc/\<pid>で見ることができます。次のコマンドでシェルのcgroupsを確認できます:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
### cgroupsの表示

ファイルシステムは通常、**cgroups**にアクセスするために使用され、従来はカーネルとのやり取りにUnixシステムコールインターフェースが使用されていました。シェルのcgroup構成を調査するには、**/proc/self/cgroup**ファイルを調べる必要があります。これにより、シェルのcgroupが明らかになります。次に、**/sys/fs/cgroup**（または**`/sys/fs/cgroup/unified`**）ディレクトリに移動し、cgroupの名前を共有するディレクトリを見つけることで、cgroupに関連するさまざまな設定やリソース使用情報を観察できます。

![Cgroup Filesystem](<../../../.gitbook/assets/image (1128).png>)

cgroupsの主要なインターフェースファイルは**cgroup**で接頭辞が付けられています。標準のcatなどのコマンドで表示できる**cgroup.procs**ファイルには、cgroup内のプロセスがリストされています。別のファイルである**cgroup.threads**にはスレッド情報が含まれています。

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

シェルを管理するcgroupsには通常、メモリ使用量とプロセス数を規制する2つのコントローラが含まれています。コントローラとやり取りするには、コントローラの接頭辞を持つファイルを参照する必要があります。たとえば、**pids.current**は、cgroup内のスレッド数を確認するために参照されます。

![Cgroup Memory](<../../../.gitbook/assets/image (677).png>)

値に**max**が示されている場合、cgroupに特定の制限がないことを示します。ただし、cgroupsの階層構造のため、ディレクトリ階層の下位レベルのcgroupによって制限が課される場合があります。

### cgroupsの操作と作成

プロセスは、**そのプロセスID（PID）を`cgroup.procs`ファイルに書き込むこと**でcgroupsに割り当てられます。これにはroot権限が必要です。たとえば、プロセスを追加するには：
```bash
echo [pid] > cgroup.procs
```
同様に、**PID制限を設定するなど、cgroup属性を変更**するには、関連するファイルに希望する値を書き込むことで行われます。cgroupに最大3,000個のPIDを設定するには：
```bash
echo 3000 > pids.max
```
**新しいcgroupsを作成する**には、cgroup階層内に新しいサブディレクトリを作成する必要があります。これにより、カーネルが自動的に必要なインターフェースファイルを生成します。アクティブなプロセスがないcgroupsは`rmdir`で削除できますが、次の制約に注意してください：

- **プロセスはリーフcgroupsにのみ配置できます**（つまり、階層内で最も入れ子になっています）。
- **親に存在しないコントローラを持つcgroupはできません**。
- **子cgroupsのコントローラは`cgroup.subtree_control`ファイルで明示的に宣言する必要があります**。たとえば、子cgroupでCPUおよびPIDコントローラを有効にするには：
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**ルートcgroup**はこれらのルールの例外であり、直接プロセス配置を許可します。これは、プロセスをsystemdの管理から削除するために使用できます。

cgroup内での**CPU使用率の監視**は、`cpu.stat`ファイルを介して可能であり、消費された合計CPU時間を表示し、サービスのサブプロセス全体での使用状況を追跡するのに役立ちます：

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>cpu.statファイルに表示されるCPU使用率統計</p></figcaption></figure>

## 参考文献

* **書籍: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**
