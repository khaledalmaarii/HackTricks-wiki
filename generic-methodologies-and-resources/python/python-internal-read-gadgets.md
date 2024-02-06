# Python内部读取工具

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>

## 基本信息

不同的漏洞，如[**Python格式字符串**](bypass-python-sandboxes/#python-format-string)或[**类污染**](class-pollution-pythons-prototype-pollution.md)可能会允许您**读取Python内部数据，但不允许您执行代码**。因此，渗透测试人员需要充分利用这些读取权限来**获取敏感权限并升级漏洞**。

### Flask - 读取密钥

Flask应用程序的主页可能会有**`app`**全局对象，其中配置了**密钥**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，可以使用任何小工具来从[绕过Python沙盒页面](bypass-python-sandboxes/)访问全局对象来访问该对象。

在**漏洞存在于不同的Python文件中**的情况下，您需要一个小工具来遍历文件以找到主文件，以访问全局对象`app.secret_key`，从而更改Flask密钥并能够[**利用此密钥升级权限**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

像这样的有效负载[来自此解决方案](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

使用此有效负载来**更改 `app.secret_key`**（您的应用程序中的名称可能不同），以便能够签署新的和更多特权的 flask cookies。

### Werkzeug - machine\_id 和 node uuid

[**使用此 writeup 中的有效负载**](https://vozec.fr/writeups/tweedle-dum-dee/)，您将能够访问 **machine\_id** 和 **uuid** 节点，这是您需要的**主要秘密**，以便[**生成 Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) ，您可以使用它来访问 `/console` 中的 python 控制台，如果**启用了调试模式**：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
请注意，您可以通过在网页中生成一些错误来获取`app.py`的**服务器本地路径**，这将**提供给您路径**。
{% endhint %}

如果漏洞存在于不同的Python文件中，请检查之前的Flask技巧，以访问主Python文件中的对象。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
