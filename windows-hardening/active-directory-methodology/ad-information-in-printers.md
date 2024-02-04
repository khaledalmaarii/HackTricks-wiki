<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


互联网上有几篇博客**强调将打印机配置为使用默认/弱LDAP登录凭据的危险性**。\
这是因为攻击者可能会**欺骗打印机对抗一个虚假的LDAP服务器**（通常`nc -vv -l -p 444`就足够了），并捕获打印机**明文凭据**。

此外，一些打印机将包含**用户名日志**，甚至可能能够**从域控制器下载所有用户名**。

所有这些**敏感信息**和常见的**安全缺陷**使得打印机对攻击者非常有吸引力。

一些关于这个主题的博客：

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## 打印机配置
- **位置**：LDAP服务器列表位于：`网络 > LDAP设置 > 设置LDAP`。
- **行为**：该界面允许修改LDAP服务器而无需重新输入凭据，旨在方便用户使用，但存在安全风险。
- **利用**：利用涉及将LDAP服务器地址重定向到受控机器，并利用“测试连接”功能来捕获凭据。

## 捕获凭据

### 方法1：Netcat监听器
一个简单的netcat监听器可能就足够了：
```bash
sudo nc -k -v -l -p 386
```
### 方法2：具有Slapd的完整LDAP服务器

更可靠的方法涉及设置完整的LDAP服务器，因为打印机在尝试凭据绑定之前执行空绑定后跟查询。

1. **LDAP服务器设置**：该指南遵循来自[此来源](https://www.server-world.info/en/note?os=Fedora_26&p=openldap)的步骤。
2. **关键步骤**：
   - 安装OpenLDAP。
   - 配置管理员密码。
   - 导入基本模式。
   - 在LDAP DB上设置域名。
   - 配置LDAP TLS。
3. **LDAP服务执行**：设置完成后，可以使用以下命令运行LDAP服务：
   ```
   slapd -d 2
   ```

**有关更详细的步骤，请参考原始[来源](https://grimhacker.com/2018/03/09/just-a-printer/)。**

# 参考资料
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
