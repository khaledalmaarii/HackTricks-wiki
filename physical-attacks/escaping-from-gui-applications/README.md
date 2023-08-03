<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家NFT收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 检查GUI应用程序中的可能操作

**常见对话框**是指**保存文件**、**打开文件**、选择字体、颜色等选项。大多数对话框将提供完整的资源管理器功能。这意味着如果您可以访问这些选项，您将能够访问资源管理器功能：

* 关闭/关闭为
* 打开/打开方式
* 打印
* 导出/导入
* 搜索
* 扫描

您应该检查是否可以：

* 修改或创建新文件
* 创建符号链接
* 访问受限区域
* 执行其他应用程序

## 命令执行

也许**使用“打开方式”选项**，您可以打开/执行某种类型的shell。

### Windows

例如_cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._在这里找到更多可用于执行命令（并执行意外操作）的二进制文件：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ 在这里找到更多：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## 绕过路径限制

* **环境变量**：有很多环境变量指向某个路径
* **其他协议**：_about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **符号链接**
* **快捷方式**：CTRL+N（打开新会话），CTRL+R（执行命令），CTRL+SHIFT+ESC（任务管理器），Windows+E（打开资源管理器），CTRL-B，CTRL-I（收藏夹），CTRL-H（历史记录），CTRL-L，CTRL-O（文件/打开对话框），CTRL-P（打印对话框），CTRL-S（另存为）
* 隐藏的管理菜单：CTRL-ALT-F8，CTRL-ESC-F9
* **Shell URI**：_shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC路径**：连接到共享文件夹的路径。您应该尝试连接到本地机器的C$（"\\\127.0.0.1\c$\Windows\System32"）
* **更多UNC路径**：

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## 下载您的二进制文件

控制台：[https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
资源管理器：[https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
注册表编辑器：[https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## 从浏览器访问文件系统

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |
## 快捷键

* 粘滞键 - 连续按5次SHIFT键
* 鼠标键 - SHIFT+ALT+NUMLOCK
* 高对比度 - SHIFT+ALT+PRINTSCN
* 切换键 - 按住NUMLOCK键5秒钟
* 过滤键 - 按住右SHIFT键12秒钟
* WINDOWS+F1 - Windows搜索
* WINDOWS+D - 显示桌面
* WINDOWS+E - 打开Windows资源管理器
* WINDOWS+R - 运行
* WINDOWS+U - 辅助功能中心
* WINDOWS+F - 搜索
* SHIFT+F10 - 上下文菜单
* CTRL+SHIFT+ESC - 任务管理器
* CTRL+ALT+DEL - 在较新的Windows版本上显示启动画面
* F1 - 帮助
* F3 - 搜索
* F6 - 地址栏
* F11 - 在Internet Explorer中切换全屏模式
* CTRL+H - Internet Explorer历史记录
* CTRL+T - Internet Explorer - 新建标签页
* CTRL+N - Internet Explorer - 新建页面
* CTRL+O - 打开文件
* CTRL+S - 保存
* CTRL+N - 新建RDP / Citrix

## 滑动手势

* 从左侧向右滑动以查看所有打开的窗口，最小化KIOSK应用程序并直接访问整个操作系统；
* 从右侧向左滑动以打开操作中心，最小化KIOSK应用程序并直接访问整个操作系统；
* 从顶部边缘向内滑动以使应用程序在全屏模式下显示标题栏；
* 从底部向上滑动以在全屏应用程序中显示任务栏。

## Internet Explorer技巧

### '图像工具栏'

这是一个在单击图像时出现在图像左上角的工具栏。您将能够保存、打印、发送邮件、在资源管理器中打开“我的图片”。Kiosk需要使用Internet Explorer。

### Shell协议

输入以下URL以获取资源管理器视图：

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> 控制面板
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> 我的电脑
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> 我的网络位置
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

# 浏览器技巧

备份iKat版本：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

使用JavaScript创建一个常见的对话框并访问文件资源管理器：`document.write('<input/type=file>')`
来源：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## 手势和按钮

### 使用四（或五）个手指向上滑动/双击Home按钮

查看多任务视图并切换应用程序

### 使用四或五个手指向左或向右滑动

切换到下一个/上一个应用程序

### 使用五个手指捏屏幕/触摸Home按钮/使用一个手指从屏幕底部向上快速滑动

访问主屏幕

### 使用一个手指从屏幕底部向上慢速滑动

会出现Dock栏

### 使用一个手指从屏幕顶部向下滑动

查看通知

### 使用一个手指从屏幕右上角向下滑动

查看iPad Pro的控制中心

### 使用一个手指从屏幕左侧向右滑动1-2英寸

查看今天视图

### 使用一个手指快速从屏幕中心向右或向左滑动

切换到下一个/上一个应用程序

### 按住iPad右上角的开/关/睡眠按钮并将“滑动以关机”滑块全部向右移动

关机

### 按住iPad右上角的开/关/睡眠按钮和Home按钮几秒钟

强制硬关机

### 快速按下iPad右上角的开/关/睡眠按钮和Home按钮

截屏，截屏将在显示屏左下角弹出。同时按下两个按钮，按住几秒钟会执行强制硬关机。

## 快捷键

您应该有一个iPad键盘或USB键盘适配器。这里只显示可以帮助退出应用程序的快捷键。

| 键   | 名称         |
| ---- | ------------ |
| ⌘    | Command      |
| ⌥    | Option (Alt) |
| ⇧    | Shift        |
| ↩    | Return       |
| ⇥    | Tab          |
| ^    | Control      |
| ←    | Left Arrow   |
| →    | Right Arrow  |
| ↑    | Up Arrow     |
| ↓    | Down Arrow   |

### 系统快捷键

这些快捷键用于视觉设置和声音设置，具体取决于iPad的使用方式。

| 快捷键 | 动作                     |
| ------ | ------------------------ |
| F1     | 降低屏幕亮度             |
| F2     | 增加屏幕亮度             |
| F7     | 后退到上一首歌曲         |
| F8     | 播放/暂停                |
| F9     | 跳过歌曲                 |
| F10    | 静音                     |
| F11    | 降低音量                 |
| F12    | 增加音量                 |
| ⌘ Space | 显示可用语言列表；再次点击空格键选择一种语言。 |

### iPad导航

| 快捷键                 | 动作                           |
| ---------------------- | ------------------------------ |
| ⌘H                     | 转到主屏幕                     |
| ⌘⇧H (Command-Shift-H)  | 转到主屏幕                     |
| ⌘ (Space)              | 打开Spotlight                  |
| ⌘⇥ (Command-Tab)       | 列出最近使用的十个应用程序     |
| ⌘\~                    | 转到上一个应用程序             |
| ⌘⇧3 (Command-Shift-3)  | 截屏（在左下角悬停以保存或操作） |
| ⌘⇧4                    | 截屏并在编辑器中打开            |
| 按住⌘                  | 显示应用程序可用的快捷键列表   |
| ⌘⌥D (Command-Option/Alt-D) | 打开Dock栏                   |
| ^⌥H (Control-Option-H) | 主页按钮                       |
| ^⌥H H (Control-Option-H-H) | 显示多任务栏                 |
| ^⌥I (Control-Option-i) | 项目选择器                     |
| Escape                 | 返回按钮                       |
| → (右箭头)             | 下一个项目                     |
| ← (左箭头)             | 上一个项目                     |
| ↑↓ (上箭头，下箭头)    | 同时点击选定的项目             |
| ⌥ ↓ (Option-下箭头)    | 向下滚动                       |
| ⌥↑ (Option-上箭头)    | 向上滚动                       |
| ⌥← or ⌥→ (Option-左箭头或Option-右箭头) | 向左或向右滚动 |
| ^⌥S (Control-Option-S) | 打开或关闭VoiceOver语音        |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 切换到上一个应用程序                              |
| ⌘⇥ (Command-Tab)                                   | 切换回原始应用程序                         |
| ←+→, 然后 Option + ← 或 Option+→                   | 在 Dock 中导航                                   |

### Safari 快捷键

| 快捷键                | 动作                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 打开位置                                    |
| ⌘T                      | 打开新标签                                   |
| ⌘W                      | 关闭当前标签                            |
| ⌘R                      | 刷新当前标签                          |
| ⌘.                      | 停止加载当前标签                     |
| ^⇥                      | 切换到下一个标签                           |
| ^⇧⇥ (Control-Shift-Tab) | 移动到上一个标签                         |
| ⌘L                      | 选择文本输入/URL字段以修改它     |
| ⌘⇧T (Command-Shift-T)   | 打开最后关闭的标签（可多次使用） |
| ⌘\[                     | 在浏览历史中返回一页      |
| ⌘]                      | 在浏览历史中前进一页   |
| ⌘⇧R                     | 激活阅读模式                             |

### 邮件快捷键

| 快捷键                   | 动作                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 打开位置                |
| ⌘T                         | 打开新标签               |
| ⌘W                         | 关闭当前标签        |
| ⌘R                         | 刷新当前标签      |
| ⌘.                         | 停止加载当前标签 |
| ⌘⌥F (Command-Option/Alt-F) | 在邮箱中搜索       |

## 参考资料

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家 **网络安全公司** 工作吗？想要在 HackTricks 中 **为你的公司做广告** 吗？或者你想要访问 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
