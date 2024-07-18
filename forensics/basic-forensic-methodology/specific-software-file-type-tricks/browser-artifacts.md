# 浏览器伪迹

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 浏览器伪迹 <a href="#id-3def" id="id-3def"></a>

浏览器伪迹包括由网页浏览器存储的各种类型的数据，如导航历史、书签和缓存数据。这些伪迹保存在操作系统中的特定文件夹中，不同浏览器的位置和名称各异，但通常存储相似的数据类型。

以下是最常见的浏览器伪迹的总结：

* **导航历史**：跟踪用户访问的网站，识别访问恶意网站的情况。
* **自动完成数据**：基于频繁搜索的建议，与导航历史结合提供见解。
* **书签**：用户保存以便快速访问的网站。
* **扩展和附加组件**：用户安装的浏览器扩展或附加组件。
* **缓存**：存储网页内容（例如，图像、JavaScript 文件），以提高网站加载速度，对取证分析有价值。
* **登录信息**：存储的登录凭据。
* **网站图标**：与网站相关的图标，出现在标签和书签中，有助于提供用户访问的额外信息。
* **浏览器会话**：与打开的浏览器会话相关的数据。
* **下载**：通过浏览器下载的文件记录。
* **表单数据**：在网页表单中输入的信息，保存以供将来的自动填充建议。
* **缩略图**：网站的预览图像。
* **Custom Dictionary.txt**：用户添加到浏览器字典中的单词。

## Firefox

Firefox 在用户数据中组织配置文件，存储在基于操作系统的特定位置：

* **Linux**：`~/.mozilla/firefox/`
* **MacOS**：`/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**：`%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

这些目录中的 `profiles.ini` 文件列出了用户配置文件。每个配置文件的数据存储在 `profiles.ini` 中 `Path` 变量命名的文件夹中，位于与 `profiles.ini` 本身相同的目录中。如果某个配置文件的文件夹缺失，可能已被删除。

在每个配置文件文件夹中，您可以找到几个重要文件：

* **places.sqlite**：存储历史、书签和下载。Windows 上的工具如 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) 可以访问历史数据。
* 使用特定的 SQL 查询提取历史和下载信息。
* **bookmarkbackups**：包含书签的备份。
* **formhistory.sqlite**：存储网页表单数据。
* **handlers.json**：管理协议处理程序。
* **persdict.dat**：自定义字典单词。
* **addons.json** 和 **extensions.sqlite**：有关已安装的附加组件和扩展的信息。
* **cookies.sqlite**：Cookie 存储，Windows 上可使用 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) 进行检查。
* **cache2/entries** 或 **startupCache**：缓存数据，可通过工具如 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) 访问。
* **favicons.sqlite**：存储网站图标。
* **prefs.js**：用户设置和偏好。
* **downloads.sqlite**：旧的下载数据库，现在已集成到 places.sqlite 中。
* **thumbnails**：网站缩略图。
* **logins.json**：加密的登录信息。
* **key4.db** 或 **key3.db**：存储用于保护敏感信息的加密密钥。

此外，可以通过在 `prefs.js` 中搜索 `browser.safebrowsing` 条目来检查浏览器的反钓鱼设置，以指示安全浏览功能是否启用或禁用。

要尝试解密主密码，可以使用 [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
使用以下脚本和调用，您可以指定一个密码文件进行暴力破解：

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome 根据操作系统将用户配置文件存储在特定位置：

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

在这些目录中，大多数用户数据可以在 **Default/** 或 **ChromeDefaultData/** 文件夹中找到。以下文件包含重要数据：

* **History**: 包含 URL、下载和搜索关键字。在 Windows 上，可以使用 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) 来读取历史记录。“Transition Type” 列有多种含义，包括用户点击链接、输入的 URL、表单提交和页面重新加载。
* **Cookies**: 存储 cookies。可以使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) 进行检查。
* **Cache**: 存储缓存数据。要检查，Windows 用户可以使用 [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html)。
* **Bookmarks**: 用户书签。
* **Web Data**: 包含表单历史。
* **Favicons**: 存储网站图标。
* **Login Data**: 包含登录凭据，如用户名和密码。
* **Current Session**/**Current Tabs**: 当前浏览会话和打开标签页的数据。
* **Last Session**/**Last Tabs**: Chrome 关闭前最后一次会话期间活动网站的信息。
* **Extensions**: 浏览器扩展和附加组件的目录。
* **Thumbnails**: 存储网站缩略图。
* **Preferences**: 一个信息丰富的文件，包括插件、扩展、弹出窗口、通知等的设置。
* **Browser’s built-in anti-phishing**: 要检查反钓鱼和恶意软件保护是否启用，请运行 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`。在输出中查找 `{"enabled: true,"}`。

## **SQLite DB Data Recovery**

如前所述，Chrome 和 Firefox 使用 **SQLite** 数据库存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) **或** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 11 在多个位置管理其数据和元数据，帮助分离存储的信息及其相应的详细信息，以便于访问和管理。

### Metadata Storage

Internet Explorer 的元数据存储在 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（VX 为 V01、V16 或 V24）。此外，`V01.log` 文件可能显示与 `WebcacheVX.data` 的修改时间差异，表明需要使用 `esentutl /r V01 /d` 进行修复。此元数据存储在 ESE 数据库中，可以使用工具如 photorec 和 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) 进行恢复和检查。在 **Containers** 表中，可以辨别每个数据段存储的特定表或容器，包括其他 Microsoft 工具（如 Skype）的缓存详细信息。

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) 工具允许检查缓存，需要缓存数据提取文件夹位置。缓存的元数据包括文件名、目录、访问计数、URL 来源和指示缓存创建、访问、修改和过期时间的时间戳。

### Cookies Management

可以使用 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 探索 cookies，元数据包括名称、URL、访问计数和各种时间相关的详细信息。持久性 cookies 存储在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` 中，会话 cookies 存储在内存中。

### Download Details

下载元数据可以通过 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) 访问，特定容器中保存 URL、文件类型和下载位置等数据。物理文件可以在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 下找到。

### Browsing History

要查看浏览历史，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)，需要提取的历史文件位置和 Internet Explorer 的配置。这里的元数据包括修改和访问时间，以及访问计数。历史文件位于 `%userprofile%\Appdata\Local\Microsoft\Windows\History`。

### Typed URLs

输入的 URL 及其使用时间存储在注册表中的 `NTUSER.DAT` 下的 `Software\Microsoft\InternetExplorer\TypedURLs` 和 `Software\Microsoft\InternetExplorer\TypedURLsTime`，跟踪用户输入的最后 50 个 URL 及其最后输入时间。

## Microsoft Edge

Microsoft Edge 将用户数据存储在 `%userprofile%\Appdata\Local\Packages` 中。各种数据类型的路径为：

* **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 数据存储在 `/Users/$User/Library/Safari`。关键文件包括：

* **History.db**: 包含 `history_visits` 和 `history_items` 表，存储 URL 和访问时间戳。使用 `sqlite3` 查询。
* **Downloads.plist**: 有关下载文件的信息。
* **Bookmarks.plist**: 存储书签 URL。
* **TopSites.plist**: 最常访问的网站。
* **Extensions.plist**: Safari 浏览器扩展的列表。使用 `plutil` 或 `pluginkit` 检索。
* **UserNotificationPermissions.plist**: 允许推送通知的域。使用 `plutil` 进行解析。
* **LastSession.plist**: 上一会话的标签。使用 `plutil` 进行解析。
* **Browser’s built-in anti-phishing**: 使用 `defaults read com.apple.Safari WarnAboutFraudulentWebsites` 检查。响应为 1 表示该功能处于活动状态。

## Opera

Opera 的数据位于 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`，并与 Chrome 的历史和下载格式相同。

* **Browser’s built-in anti-phishing**: 通过检查 Preferences 文件中的 `fraud_protection_enabled` 是否设置为 `true` 来验证，使用 `grep`。

这些路径和命令对于访问和理解不同网络浏览器存储的浏览数据至关重要。

## References

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
学习和实践 AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
