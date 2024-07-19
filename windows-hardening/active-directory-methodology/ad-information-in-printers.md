{% hint style="success" %}
学习与实践 AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}


互联网上有几个博客**强调了将打印机配置为使用默认/弱**登录凭据的 LDAP 的危险。\
这是因为攻击者可能会**欺骗打印机向一个恶意的 LDAP 服务器进行身份验证**（通常一个 `nc -vv -l -p 444` 就足够了），并捕获打印机的**明文凭据**。

此外，一些打印机将包含**带有用户名的日志**，甚至可能能够**从域控制器下载所有用户名**。

所有这些**敏感信息**和普遍的**安全缺失**使得打印机对攻击者非常有吸引力。

关于该主题的一些博客：

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## 打印机配置
- **位置**: LDAP 服务器列表位于: `Network > LDAP Setting > Setting Up LDAP`。
- **行为**: 界面允许在不重新输入凭据的情况下修改 LDAP 服务器，旨在方便用户，但带来安全风险。
- **利用**: 利用涉及将 LDAP 服务器地址重定向到受控机器，并利用“测试连接”功能捕获凭据。

## 捕获凭据

**有关更详细的步骤，请参阅原始 [来源](https://grimhacker.com/2018/03/09/just-a-printer/)。**

### 方法 1: Netcat 监听器
一个简单的 netcat 监听器可能就足够了:
```bash
sudo nc -k -v -l -p 386
```
然而，这种方法的成功率有所不同。

### 方法 2：完整的 LDAP 服务器与 Slapd
一种更可靠的方法是设置一个完整的 LDAP 服务器，因为打印机在尝试凭证绑定之前会执行空绑定，然后进行查询。

1. **LDAP 服务器设置**：该指南遵循 [此来源](https://www.server-world.info/en/note?os=Fedora_26&p=openldap) 的步骤。
2. **关键步骤**：
- 安装 OpenLDAP。
- 配置管理员密码。
- 导入基本架构。
- 在 LDAP 数据库上设置域名。
- 配置 LDAP TLS。
3. **LDAP 服务执行**：设置完成后，可以使用以下命令运行 LDAP 服务：
```bash
slapd -d 2
```
## 参考文献
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
