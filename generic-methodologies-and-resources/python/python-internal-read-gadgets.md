# Python内部读取工具

{% hint style="success" %}
学习并练习AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}

## 基本信息

不同的漏洞，如[**Python格式字符串**](bypass-python-sandboxes/#python-format-string)或[**类污染**](class-pollution-pythons-prototype-pollution.md)可能允许您**读取Python内部数据，但不允许您执行代码**。因此，渗透测试人员需要充分利用这些读取权限来**获取敏感权限并升级漏洞**。

### Flask - 读取密钥

Flask应用程序的主页可能有**`app`**全局对象，其中配置了**密钥**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，可以使用任何小工具来从[Bypass Python sandboxes page](bypass-python-sandboxes/)访问全局对象。

在**漏洞存在于不同的Python文件中**的情况下，您需要一个小工具来遍历文件以找到主文件，以访问全局对象`app.secret_key`，从而更改Flask密钥并能够[**利用此密钥升级权限**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

像这样的有效负载[来自这篇解密文章](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

使用此有效负载来**更改 `app.secret_key`**（您的应用程序中的名称可能不同），以便能够签署新的和更多特权的 flask cookies。

### Werkzeug - machine\_id 和 node uuid

[**使用此 writeup 中的有效负载**](https://vozec.fr/writeups/tweedle-dum-dee/)，您将能够访问 **machine\_id** 和 **uuid** 节点，这是您需要的**主要秘密**，以便[**生成 Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md)，您可以使用它来访问 `/console` 中的 python 控制台，如果**启用了调试模式**：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
请注意，您可以通过在网页中生成一些错误来获取`app.py`的**服务器本地路径**，这将**提供给您路径**。
{% endhint %}

如果漏洞存在于不同的Python文件中，请检查以前的Flask技巧，以访问主Python文件中的对象。

{% hint style="success" %}
学习并实践AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并实践GCP Hacking：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}
