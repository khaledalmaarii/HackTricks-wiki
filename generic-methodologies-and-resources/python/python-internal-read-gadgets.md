# Python 内部读取小工具

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

不同的漏洞，如 [**Python 格式化字符串**](bypass-python-sandboxes/#python-format-string) 或 [**类污染**](class-pollution-pythons-prototype-pollution.md)，可能允许您 **读取 Python 内部数据但不允许您执行代码**。因此，渗透测试人员将需要充分利用这些读取权限来 **获取敏感权限并升级漏洞**。

### Flask - 读取密钥

Flask 应用程序的主页可能会有 **`app`** 全局对象，这个 **密钥是在这里配置的**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，只需使用任何小工具即可**访问全局对象**，具体方法请参见[**绕过Python沙箱页面**](bypass-python-sandboxes/)。

如果**漏洞存在于不同的Python文件中**，你需要一个小工具来遍历文件以访问主文件，以**访问全局对象`app.secret_key`**，更改Flask密钥，并能够[**通过知道这个密钥来提升权限**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

像这样的有效载荷[来自这篇文章](https://ctftime.org/writeup/36082)：

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

使用此有效载荷来**更改 `app.secret_key`**（在你的应用中可能有不同的名称），以便能够签署新的、权限更高的flask cookies。

### Werkzeug - machine\_id 和 node uuid

[**使用这篇文章中的有效载荷**](https://vozec.fr/writeups/tweedle-dum-dee/)，你将能够访问**machine\_id** 和 **uuid** 节点，这些是你需要[**生成 Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md)的**主要秘密**，如果**调试模式启用**，你可以使用它来访问 `/console` 中的python控制台：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
请注意，您可以通过在网页上生成一些**错误**来获取**服务器本地路径到 `app.py`**，这将**给您显示路径**。
{% endhint %}

如果漏洞存在于不同的python文件中，请检查之前的Flask技巧以从主python文件访问对象。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
