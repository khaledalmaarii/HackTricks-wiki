<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


对于钓鱼评估，有时完全**克隆一个网站**可能会很有用。

请注意，您还可以向克隆的网站添加一些有效负载，例如BeEF钩子来"控制"用户的选项卡。

有不同的工具可用于此目的：

## wget
```text
wget -mk -nH
```
## goclone

### Description

goclone is a command-line tool that allows you to clone a website by creating an exact replica of it. This can be useful for various purposes, including phishing attacks, social engineering, or testing the security of a website.

### Installation

To install goclone, follow these steps:

1. Download the latest release of goclone from the official GitHub repository.
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted goclone.
4. Run the following command to make goclone executable:

```bash
chmod +x goclone
```

5. Add the goclone executable to your system's PATH variable to make it accessible from anywhere.

### Usage

To clone a website using goclone, use the following command:

```bash
goclone clone <URL> <output_directory>
```

Replace `<URL>` with the URL of the website you want to clone, and `<output_directory>` with the directory where you want to save the cloned website.

### Example

Here's an example of how to clone a website using goclone:

```bash
goclone clone https://www.example.com /path/to/output_directory
```

This will create an exact replica of the website www.example.com and save it in the specified output directory.

### Conclusion

goclone is a powerful tool that allows you to clone websites quickly and easily. However, it's important to use this tool responsibly and ethically. Always ensure that you have proper authorization before cloning a website, and use it for legitimate purposes only.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## 社会工程学工具包

### Clone a Website

### 克隆网站

One of the most effective techniques in phishing is to clone a legitimate website and make it look identical to the original. This way, when victims enter their credentials or sensitive information, it is captured by the attacker.

在钓鱼中最有效的技术之一是克隆一个合法的网站，并使其看起来与原始网站完全相同。这样，当受害者输入他们的凭据或敏感信息时，攻击者就可以获取到。

#### Methodology

#### 方法论

1. Identify the target website: Choose the website you want to clone. It could be a popular social media platform, an online banking portal, or any other website that is likely to attract users.

1. 确定目标网站：选择您想要克隆的网站。可以是一个流行的社交媒体平台、一个在线银行门户网站，或者任何其他可能吸引用户的网站。

2. Analyze the target website: Study the structure, design, and functionality of the target website. Take note of the different pages, forms, and elements present.

2. 分析目标网站：研究目标网站的结构、设计和功能。注意目标网站上的不同页面、表单和元素。

3. Set up a phishing server: Create a server that will host the cloned website. This can be done using a cloud/SaaS platform or a local web server.

3. 设置钓鱼服务器：创建一个用于托管克隆网站的服务器。可以使用云/SaaS平台或本地Web服务器来完成此操作。

4. Clone the website: Use tools like HTTrack or Wget to download the entire website, including all its files and directories. Make sure to preserve the directory structure and file names.

4. 克隆网站：使用HTTrack或Wget等工具下载整个网站，包括所有文件和目录。确保保留目录结构和文件名。

5. Customize the cloned website: Modify the cloned website to include the necessary phishing elements. This may involve adding a login page, modifying forms, or injecting malicious scripts.

5. 自定义克隆网站：修改克隆网站以包含必要的钓鱼元素。这可能涉及添加登录页面、修改表单或注入恶意脚本。

6. Set up phishing email or campaign: Create a convincing phishing email or campaign to lure victims to the cloned website. This may involve crafting a compelling message, using social engineering techniques, or exploiting current events.

6. 设置钓鱼邮件或活动：创建一个令人信服的钓鱼邮件或活动，诱使受害者访问克隆网站。这可能涉及编写一个引人注目的消息，使用社会工程学技术或利用当前事件。

7. Launch the phishing attack: Send the phishing email or initiate the campaign to target users. Monitor the server logs to capture the credentials or sensitive information entered by the victims.

7. 发动钓鱼攻击：发送钓鱼邮件或启动活动以针对用户。监视服务器日志，以获取受害者输入的凭据或敏感信息。

8. Harvest the captured data: Retrieve the captured credentials or sensitive information from the server logs or database. This data can be used for further exploitation or sold on the dark web.

8. 提取捕获的数据：从服务器日志或数据库中检索捕获的凭据或敏感信息。这些数据可以用于进一步的利用或在暗网上出售。

#### Tools

#### 工具

- HTTrack: A tool for cloning websites by downloading the entire site structure.

- HTTrack：一个通过下载整个网站结构来克隆网站的工具。

- Wget: A command-line utility for retrieving files from the web.

- Wget：一个用于从Web检索文件的命令行实用程序。

- Social engineering techniques: Various methods used to manipulate individuals into performing certain actions or divulging sensitive information.

- 社会工程学技术：用于操纵个人执行特定操作或泄露敏感信息的各种方法。

#### Countermeasures

#### 对策

- User education: Train users to be cautious of phishing emails and suspicious websites. Teach them to verify the legitimacy of a website before entering any sensitive information.

- 用户教育：培训用户对钓鱼邮件和可疑网站保持警惕。教导他们在输入任何敏感信息之前验证网站的合法性。

- Two-factor authentication (2FA): Implement 2FA to add an extra layer of security to user accounts. This can help prevent unauthorized access even if credentials are compromised.

- 双因素身份验证（2FA）：实施2FA以为用户账户增加额外的安全层。即使凭据被泄露，这可以帮助防止未经授权的访问。

- Web application security: Regularly update and patch web applications to fix vulnerabilities that could be exploited for cloning or phishing attacks.

- Web应用程序安全：定期更新和修补Web应用程序，以修复可能被用于克隆或钓鱼攻击的漏洞。

- Email filtering: Implement email filters to detect and block phishing emails before they reach users' inboxes.

- 电子邮件过滤：实施电子邮件过滤器，在钓鱼邮件到达用户收件箱之前检测并阻止它们。

- Security awareness training: Conduct regular security awareness training sessions to educate users about the risks and best practices for avoiding phishing attacks.

- 安全意识培训：定期进行安全意识培训，向用户介绍有关避免钓鱼攻击的风险和最佳实践。

#### References

#### 参考资料

- [Phishing - Wikipedia](https://en.wikipedia.org/wiki/Phishing)

- [钓鱼 - 维基百科](https://zh.wikipedia.org/wiki/%E9%92%93%E9%B1%BC)

- [HTTrack Website Copier](https://www.httrack.com/)

- [HTTrack网站拷贝工具](https://www.httrack.com/)

- [Wget - GNU Project](https://www.gnu.org/software/wget/)

- [Wget - GNU项目](https://www.gnu.org/software/wget/)
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者在**Twitter**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
