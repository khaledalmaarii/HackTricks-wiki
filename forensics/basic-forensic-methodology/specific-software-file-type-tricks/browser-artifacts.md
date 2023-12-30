# 浏览器工件

<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 浏览器工件 <a href="#3def" id="3def"></a>

当我们谈论浏览器工件时，我们指的是浏览历史、书签、下载文件列表、缓存数据等。

这些工件是存储在操作系统特定文件夹中的文件。

每个浏览器都将其文件存储在与其他浏览器不同的位置，它们都有不同的名称，但它们都存储（大多数时候）相同类型的数据（工件）。

让我们来看看浏览器存储的最常见工件。

* **浏览历史：** 包含用户的浏览历史数据。例如，可以用来追踪用户是否访问了一些恶意网站。
* **自动完成数据：** 这是浏览器根据您最常搜索的内容提出的建议数据。可以与浏览历史一起使用以获得更多见解。
* **书签：** 不言自明。
* **扩展和插件：** 不言自明。
* **缓存：** 浏览网站时，浏览器会创建各种缓存数据（图片、javascript文件等）出于多种原因。例如，加快网站的加载时间。这些缓存文件在取证调查中可能是数据的重要来源。
* **登录信息：** 不言自明。
* **Favicons：** 它们是在标签页、URL、书签等中找到的小图标。它们可以作为获取有关网站或用户访问地点的更多信息的另一个来源。
* **浏览器会话：** 不言自明。
* **下载：** 不言自明。
* **表单数据：** 浏览器通常会存储在表单中键入的任何内容，所以下次用户在表单中输入内容时，浏览器可以建议之前输入的数据。
* **缩略图：** 不言自明。
* **自定义字典.txt：** 用户添加到字典中的单词。

## Firefox

Firefox在\~/_**.mozilla/firefox/**_（Linux）、**/Users/$USER/Library/Application Support/Firefox/Profiles/**（MacOS）、_**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_（Windows）中创建配置文件文件夹。\
在这个文件夹中，应该会出现名为_**profiles.ini**_的文件，其中包含用户配置文件的名称。\
每个配置文件都有一个“**Path**”变量，指示其数据将被存储的文件夹名称。该文件夹应该**存在于\_profiles.ini**\_\*\*所在的同一目录中\*\*。如果不存在，那么可能已被删除。

在每个配置文件的文件夹（_\~/.mozilla/firefox/\<ProfileName>/_）路径中，您应该能够找到以下有趣的文件：

* _**places.sqlite**_：历史记录（moz_places）、书签（moz_bookmarks）和下载（moz_annos）。在Windows中，可以使用工具[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)来阅读_**places.sqlite**_中的历史记录。
* 查询转储历史记录：`select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* 请注意链接类型是一个数字，表示：
* 1：用户跟随链接
* 2：用户输入URL
* 3：用户使用收藏夹
* 4：通过Iframe加载
* 5：通过HTTP重定向301访问
* 6：通过HTTP重定向302访问
* 7：下载文件
* 8：用户在Iframe中跟随链接
* 查询转储下载：`SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_：书签备份
* _**formhistory.sqlite**_：**Web表单数据**（如电子邮件）
* _**handlers.json**_：协议处理程序（例如，哪个应用程序将处理_mailto://_协议）
* _**persdict.dat**_：添加到字典中的单词
* _**addons.json**_和\_**extensions.sqlite**\_：已安装的插件和扩展
* _**cookies.sqlite**_：包含**cookies。**在Windows中可以使用[**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html)来检查这个文件。
*   _**cache2/entries**_或_**startupCache**_：缓存数据（约350MB）。像**数据雕刻**这样的技巧也可以用来获取缓存中保存的文件。可以使用[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)来查看**缓存中保存的文件**。

可以获得的信息：

* URL、获取次数、文件名、内容类型、文件大小、最后修改时间、最后获取时间、服务器最后修改时间、服务器响应
* _**favicons.sqlite**_：Favicons
* _**prefs.js**_：设置和偏好
* _**downloads.sqlite**_：旧下载数据库（现在在places.sqlite中）
* _**thumbnails/**_：缩略图
* _**logins.json**_：加密的用户名和密码
* **浏览器内置的反网络钓鱼功能：** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* 如果已禁用安全搜索设置，则会返回“safebrowsing.malware.enabled”和“phishing.enabled”为false
* _**key4.db**_或_**key3.db**_：主密钥？

尝试解密主密码，您可以使用[https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
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
```markdown
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome 在用户的主目录 _**\~/.config/google-chrome/**_ (Linux)、_**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows) 或 _**/Users/$USER/Library/Application Support/Google/Chrome/**_ (MacOS) 中创建配置文件。\
大部分信息将保存在前面路径中的 _**Default/**_ 或 _**ChromeDefaultData/**_ 文件夹内。在这里，你可以找到以下有趣的文件：

* _**History**_：URL、下载甚至搜索关键词。在 Windows 中，你可以使用工具 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) 来阅读历史记录。"Transition Type" 列的含义：
  * Link: 用户点击了链接
  * Typed: URL 被输入
  * Auto Bookmark
  * Auto Subframe: 添加
  * Start page: 主页
  * Form Submit: 表单被填写并发送
  * Reloaded
* _**Cookies**_：Cookies。可以使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) 来检查 cookies。
* _**Cache**_：缓存。在 Windows 中，你可以使用工具 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) 来检查缓存。
* _**Bookmarks**_：书签
* _**Web Data**_：表单历史
* _**Favicons**_：网站图标
* _**Login Data**_：登录信息（用户名、密码等）
* _**Current Session**_ 和 _**Current Tabs**_：当前会话数据和当前标签页
* _**Last Session**_ 和 _**Last Tabs**_：这些文件保存了上次关闭 Chrome 时活跃的网站。
* _**Extensions**_：扩展和插件文件夹
* **Thumbnails**：缩略图
* **Preferences**：此文件包含大量有用信息，如插件、扩展、使用地理位置的网站、弹出窗口、通知、DNS 预取、证书例外等等。如果你正在研究是否启用了特定的 Chrome 设置，你很可能会在这里找到该设置。
* **浏览器内置的反钓鱼功能：** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* 你可以简单地搜索 "**safebrowsing**" 并在结果中查找 `{"enabled: true,"}` 来指示反钓鱼和恶意软件保护已开启。

## **SQLite DB 数据恢复**

如前面章节所述，Chrome 和 Firefox 都使用 **SQLite** 数据库来存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) **或** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 在不同位置存储 **数据** 和 **元数据**。元数据将帮助找到数据。

**元数据** 可以在文件夹 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` 中找到，其中 VX 可能是 V01、V16 或 V24。\
在上述文件夹中，你还可以找到 V01.log 文件。如果这个文件和 WebcacheVX.data 文件的 **修改时间** **不同**，你可能需要运行命令 `esentutl /r V01 /d` 来 **修复** 可能的 **不兼容问题**。

一旦 **恢复** 了这个工件（它是一个 ESE 数据库，photorec 可以使用 Exchange Database 或 EDB 选项来恢复它），你可以使用程序 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 来打开它。一旦 **打开**，转到名为 "**Containers**" 的表。

![](<../../../.gitbook/assets/image (446).png>)

在这个表内，你可以找到存储信息的其他表或容器的位置。接下来，你可以找到浏览器存储的 **数据位置** 和其中的 **元数据**。

**注意，这个表也指示了其他 Microsoft 工具（例如 skype）缓存的元数据**

### 缓存

你可以使用工具 [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 来检查缓存。你需要指定你提取缓存日期的文件夹。

#### 元数据

关于缓存的元数据信息包括：

* 磁盘上的文件名
* SecureDIrectory: 文件在缓存目录中的位置
* AccessCount: 它被保存在缓存中的次数
* URL: 原始 URL
* CreationTime: 第一次被缓存的时间
* AccessedTime: 使用缓存的时间
* ModifiedTime: 网页的最后版本
* ExpiryTime: 缓存过期的时间

#### 文件

缓存信息可以在 _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ 和 _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_ 中找到

这些文件夹内的信息是 **用户所看到的快照**。缓存的大小为 **250 MB**，时间戳表明了页面被访问的时间（第一次，NTFS 的创建日期，最后一次，NTFS 的修改时间）。

### Cookies

你可以使用工具 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 来检查 cookies。你需要指定你提取 cookies 的文件夹。

#### **元数据**

存储的 cookies 的元数据信息包括：

* 文件系统中的 Cookie 名称
* URL
* AccessCount: cookies 被发送到服务器的次数
* CreationTime: Cookie 第一次创建的时间
* ModifiedTime: Cookie 最后一次被修改的时间
* AccessedTime: Cookie 最后一次被访问的时间
* ExpiryTime: Cookie 过期的时间

#### 文件

Cookies 数据可以在 _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ 和 _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_ 中找到

会话 cookies 将驻留在内存中，持久 cookies 在磁盘上。

### 下载

#### **元数据**

检查工具 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)，你可以找到包含下载元数据的容器：

![](<../../../.gitbook/assets/image (445).png>)

获取 "ResponseHeaders" 列的信息，你可以将该信息从十六进制转换，并获得 URL、文件类型和下载文件的位置。

#### 文件

查看路径 _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **历史记录**

工具 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 可用于阅读历史记录。但首先，你需要在高级选项中指定浏览器和提取的历史文件的位置。

#### **元数据**

* ModifiedTime: 第一次发现 URL 的时间
* AccessedTime: 最后一次
* AccessCount: 访问次数

#### **文件**

搜索 _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ 和 _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **输入的 URL**

这些信息可以在注册表 NTDUSER.DAT 中的以下路径找到：

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
  * 存储用户输入的最后 50 个 URL
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
  * 最后一次输入 URL 的时间

## Microsoft Edge

分析 Microsoft Edge 工件时，前一节（IE 11）关于缓存和位置的所有**解释都适用**，唯一的区别是这种情况下的基本位置是 _**%userprofile%\Appdata\Local\Packages**_（如下路径所示）：

* 配置文件路径：_**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* 历史记录、Cookies 和下载：_**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* 设置、书签和阅读列表：_**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* 缓存：_**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* 最后活跃的会话：_**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

数据库可以在 `/Users/$User/Library/Safari` 中找到

* **History.db**：表 `history_visits` _和_ `history_items` 包含历史记录和时间戳信息。
  * `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**：包含下载文件的信息。
* **Book-marks.plist**：URL 书签。
* **TopSites.plist**：用户浏览的最常访问网站列表。
* **Extensions.plist**：检索旧式 Safari 浏览器扩展列表。
  * `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
  * `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**：允许推送通知的域。
  * `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**：用户退出 Safari 时打开的标签页。
  * `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **浏览器内置的反钓鱼功能：** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
  * 回复应为 1，以表示设置已激活

## Opera

数据库可以在 `/Users/$USER/Library/Application Support/com.operasoftware.Opera` 中找到

Opera **以与 Google Chrome 完全相同的格式存储浏览器历史记录和下载数据**。这适用于文件名以及表名。

* **浏览器内置的反钓鱼功能：** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
  * **fraud_protection_enabled** 应为 **true**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客攻击到高手，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。

</details>
```
