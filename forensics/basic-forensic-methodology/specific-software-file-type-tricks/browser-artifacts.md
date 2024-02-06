# 浏览器遗留物

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 浏览器遗留物 <a href="#id-3def" id="id-3def"></a>

当我们谈论浏览器遗留物时，我们指的是浏览历史、书签、下载文件列表、缓存数据等。

这些遗留物是存储在操作系统特定文件夹中的文件。

每个浏览器将其文件存储在与其他浏览器不同的位置，并且它们都有不同的名称，但它们（大多数情况下）存储相同类型的数据（遗留物）。

让我们看看浏览器通常存储的最常见遗留物。

- **浏览历史：** 包含用户的浏览历史数据。可用于跟踪用户是否访问过一些恶意网站，例如
- **自动完成数据：** 这是浏览器根据您最常搜索的内容提供的数据。可以与浏览历史一起使用，以获得更多见解。
- **书签：** 不言而喻。
- **扩展和插件：** 不言而喻。
- **缓存：** 在浏览网站时，浏览器为许多原因创建各种缓存数据（图像、JavaScript文件等），例如为了加快网站的加载时间。这些缓存文件在取证调查期间可以成为重要数据来源。
- **登录信息：** 不言而喻。
- **网站图标：** 它们是在标签、URL、书签等处找到的小图标。它们可以作为另一个信息来源，以获取有关用户访问的网站或位置的更多信息。
- **浏览器会话：** 不言而喻。
- **下载：** 不言而喻。
- **表单数据：** 浏览器通常会存储用户在表单中输入的任何内容，以便用户下次在表单中输入内容时，浏览器可以建议先前输入的数据。
- **缩略图：** 不言而喻。
- **自定义字典.txt：** 用户添加到字典中的单词。

## 火狐浏览器

Firefox在\~/_**.mozilla/firefox/**_（Linux）中创建配置文件文件夹，在**/Users/$USER/Library/Application Support/Firefox/Profiles/**（MacOS）中，在_**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_（Windows）中。\
在此文件夹中，应该会出现名为_**profiles.ini**_的文件，其中包含用户配置文件的名称。\
每个配置文件都有一个“**Path**”变量，其中包含其数据将存储的文件夹的名称。该文件夹应该**位于与\_profiles.ini**\_\*\*相同目录中存在的位置\*\*。如果不存在，则可能已被删除。

在每个配置文件的文件夹（_\~/.mozilla/firefox/\<ProfileName>/_）路径中，您应该能够找到以下有趣的文件：

- _**places.sqlite**_：历史记录（moz\_\_places）、书签（moz\_bookmarks）和下载文件（moz\_\_annos）。在Windows中，可以使用工具[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)来读取_**places.sqlite**_中的历史记录。
- 转储历史的查询：`select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
- 请注意，链接类型是一个指示数字，表示：
  - 1：用户跟随链接
  - 2：用户输入URL
  - 3：用户使用收藏夹
  - 4：从Iframe加载
  - 5：通过HTTP重定向301访问
  - 6：通过HTTP重定向302访问
  - 7：下载文件
  - 8：用户在Iframe内跟随链接
- 转储下载的查询：`SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
- _**bookmarkbackups/**_：书签备份
- _**formhistory.sqlite**_：**Web表单数据**（如电子邮件）
- _**handlers.json**_：协议处理程序（例如，哪个应用程序将处理_mailto://_协议）
- _**persdict.dat**_：用户添加到字典中的单词
- _**addons.json**_和_**extensions.sqlite**_：已安装的插件和扩展
- _**cookies.sqlite**_：包含**cookies**。在Windows中，可以使用[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)来检查此文件。
- _**cache2/entries**_或_**startupCache**_：缓存数据（\~350MB）。可以使用**数据雕刻**等技巧来获取缓存中保存的文件。[MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html)可用于查看**缓存中保存的文件**。

可以获取的信息：

- URL、获取次数、文件名、内容类型、文件大小、上次修改时间、上次获取时间、服务器上次修改、服务器响应
- _**favicons.sqlite**_：网站图标
- _**prefs.js**_：设置和首选项
- _**downloads.sqlite**_：旧下载数据库（现在已合并到places.sqlite中）
- _**thumbnails/**_：缩略图
- _**logins.json**_：加密的用户名和密码
- **浏览器内置的反钓鱼功能：** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
  - 如果安全搜索设置已禁用，则将返回“safebrowsing.malware.enabled”和“phishing.enabled”为false
- _**key4.db**_或_**key3.db**_：主密钥？

要尝试解密主密码，您可以使用[https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
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

Google Chrome将用户配置文件创建在用户主目录下的 _**\~/.config/google-chrome/**_ (Linux)、_**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows) 或者 \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS)。\
大部分信息将保存在之前提到的路径下的 _**Default/**_ 或 _**ChromeDefaultData/**_ 文件夹中。您可以在这里找到以下有趣的文件：

* _**History**_: 包括URL、下载记录甚至搜索关键词。在Windows中，您可以使用工具 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) 查看历史记录。"Transition Type" 列含义如下：
  * Link: 用户点击了链接
  * Typed: 输入了URL
  * Auto Bookmark
  * Auto Subframe: 添加
  * Start page: 主页
  * Form Submit: 填写并发送表单
  * Reloaded
* _**Cookies**_: Cookies。您可以使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) 工具检查Cookies。
* _**Cache**_: 缓存。在Windows中，您可以使用工具 [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) 检查缓存。
* _**Bookmarks**_: 书签
* _**Web Data**_: 表单历史
* _**Favicons**_: 网站图标
* _**Login Data**_: 登录信息（用户名、密码...）
* _**Current Session**_ 和 _**Current Tabs**_: 当前会话数据和当前标签页
* _**Last Session**_ 和 _**Last Tabs**_: 这些文件保存了在Chrome上次关闭时活动的网站。
* _**Extensions**_: 扩展和插件文件夹
* **Thumbnails** : 缩略图
* **Preferences**: 该文件包含大量有用信息，如插件、扩展、使用地理位置的网站、弹出窗口、通知、DNS预取、证书异常等。如果您想研究特定Chrome设置是否已启用，您很可能会在这里找到该设置。
* **浏览器内置反钓鱼:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* 您可以简单地使用grep搜索“**safebrowsing**”，并查找结果中的 `{"enabled: true,"}`，以指示反钓鱼和恶意软件保护已开启。

## **SQLite数据库数据恢复**

正如您在前面的部分中所看到的，Chrome和Firefox都使用 **SQLite** 数据库存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) 或 [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer将 **数据** 和 **元数据** 存储在不同位置。元数据将帮助找到数据。

**元数据** 可以在文件夹 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` 中找到，其中VX可以是V01、V16或V24。\
在前面的文件夹中，您还可以找到文件V01.log。如果此文件的 **修改时间** 和 WebcacheVX.data 文件的 **不同**，则可能需要运行命令 `esentutl /r V01 /d` 来 **修复** 可能的 **不兼容性**。

一旦 **恢复** 了这个工件（这是一个ESE数据库，photorec可以使用选项 Exchange Database 或 EDB 恢复它），您可以使用程序 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) 打开它。打开后，转到名为 "**Containers**" 的表。

![](<../../../.gitbook/assets/image (446).png>)

在这个表中，您可以找到存储信息各部分的其他表或容器。随后，您可以找到浏览器存储的数据的 **位置** 和内部的 **元数据**。

**请注意，此表还指示了其他Microsoft工具（例如skype）的缓存元数据**

### 缓存

您可以使用工具 [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) 检查缓存。您需要指定提取缓存数据的文件夹。

#### 元数据

关于缓存的元数据存储了：

* 磁盘中的文件名
* SecureDIrectory: 缓存目录中文件的位置
* AccessCount: 文件在缓存中保存的次数
* URL: URL来源
* CreationTime: 缓存的第一次时间
* AccessedTime: 缓存使用时间
* ModifiedTime: 最后的网页版本
* ExpiryTime: 缓存将过期的时间

#### 文件

缓存信息可以在 _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ 和 _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_ 中找到

这些文件夹中的信息是用户看到的 **快照**。缓存大小为 **250 MB**，时间戳指示页面访问时间（第一次、NTFS的创建日期、最后一次、NTFS的修改时间）。

### Cookies

您可以使用工具 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 检查Cookies。您需要指定提取Cookies的文件夹。

#### **元数据**

关于存储的Cookies的元数据包括：

* 文件系统中的Cookie名称
* URL
* AccessCount: 将Cookie发送到服务器的次数
* CreationTime: 创建Cookie的时间
* ModifiedTime: 修改Cookie的时间
* AccessedTime: 访问Cookie的时间
* ExpiryTime: Cookie的过期时间

#### 文件

Cookies数据可以在 _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ 和 _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_ 中找到

会话Cookie存储在内存中，持久Cookie存储在磁盘中。

### 下载

#### **元数据**

使用工具 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) 您可以找到包含下载元数据的容器：

![](<../../../.gitbook/assets/image (445).png>)

通过获取“ResponseHeaders”列的信息，您可以将其从十六进制转换为URL、文件类型和下载文件的位置。

#### 文件

查看路径 _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **历史记录**

工具 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) 可用于查看历史记录。但首先，您需要在高级选项中指定浏览器和提取历史记录文件的位置。

#### **元数据**

* ModifiedTime: 发现URL的第一次时间
* AccessedTime: 最后一次时间
* AccessCount: 访问次数

#### **文件**

搜索 _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ 和 _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **输入的URL**

此信息可以在注册表 NTDUSER.DAT 的路径中找到：

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* 存储用户最后输入的50个URL
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* URL最后输入的时间

## Microsoft Edge

要分析Microsoft Edge的工件，所有关于缓存和位置的 **解释（IE 11中）仍然有效**，唯一的区别是基本位置，在这种情况下是 _**%userprofile%\Appdata\Local\Packages**_（如下面的路径所示）：

* 配置文件路径: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* 历史记录、Cookies和下载: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* 设置、书签和阅读列表: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* 缓存: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* 最后活动会话: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

数据库可以在 `/Users/$User/Library/Safari` 中找到

* **History.db**: 表 `history_visits` _和_ `history_items` 包含有关历史记录和时间戳的信息。
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: 包含有关下载文件的信息。
* **Book-marks.plist**: 书签的URL。
* **TopSites.plist**: 用户浏览的最常访问网站列表。
* **Extensions.plist**: 检索Safari浏览器扩展的旧式列表。
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: 允许推送通知的域。
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: 用户退出Safari时打开的标签页。
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **浏览器内置反钓鱼:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* 回复应为1，表示设置已激活

## Opera

数据库可以在 `/Users/$USER/Library/Application Support/com.operasoftware.Opera` 中找到

Opera **以与Google Chrome完全相同的格式存储浏览器历史记录和下载数据**。这适用于文件名以及表名。

* **浏览器内置反钓鱼:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud\_protection\_enabled** 应为 **true**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可以轻松构建和 **自动化** 由全球 **最先进** 的社区工具提供支持的工作流。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的 **公司广告** 或 **下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
