<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>


# 检查GUI应用程序内的可能操作

**常见对话框**是指**保存文件**、**打开文件**、选择字体、颜色等选项。它们大多数会**提供完整的资源管理器功能**。这意味着如果您能够访问这些选项，您将能够访问资源管理器的功能：

* 关闭/另存为
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

也许**使用**_**打开方式**_**选项**，您可以打开/执行某种类型的shell。

### Windows

例如 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 在这里找到更多可以用来执行命令（并执行意外操作）的二进制文件：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ 更多信息在这里：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## 绕过路径限制

* **环境变量**：有很多环境变量指向某些路径
* **其他协议**：_about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **符号链接**
* **快捷键**：CTRL+N (打开新会话), CTRL+R (执行命令), CTRL+SHIFT+ESC (任务管理器),  Windows+E (打开资源管理器), CTRL-B, CTRL-I (收藏夹), CTRL-H (历史记录), CTRL-L, CTRL-O (文件/打开对话框), CTRL-P (打印对话框), CTRL-S (另存为)
* 隐藏的管理菜单：CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**：_shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC路径**：连接到共享文件夹的路径。您应该尝试连接到本地机器的C$ ("\\\127.0.0.1\c$\Windows\System32")
* **更多UNC路径：**

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

* Sticky Keys – 连按SHIFT键5次
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – 按住NUMLOCK键5秒
* Filter Keys – 按住右SHIFT键12秒
* WINDOWS+F1 – Windows搜索
* WINDOWS+D – 显示桌面
* WINDOWS+E – 启动Windows资源管理器
* WINDOWS+R – 运行
* WINDOWS+U – 便捷操作中心
* WINDOWS+F – 搜索
* SHIFT+F10 – 上下文菜单
* CTRL+SHIFT+ESC – 任务管理器
* CTRL+ALT+DEL – 在新版Windows上显示启动屏幕
* F1 – 帮助 F3 – 搜索
* F6 – 地址栏
* F11 – 在Internet Explorer中切换全屏
* CTRL+H – Internet Explorer历史记录
* CTRL+T – Internet Explorer – 新标签页
* CTRL+N – Internet Explorer – 新页面
* CTRL+O – 打开文件
* CTRL+S – 保存 CTRL+N – 新RDP / Citrix

## 滑动操作

* 从左侧向右滑动，查看所有打开的Windows，最小化KIOSK应用程序并直接访问整个操作系统；
* 从右侧向左滑动，打开操作中心，最小化KIOSK应用程序并直接访问整个操作系统；
* 从顶部边缘向内滑动，使全屏模式下打开的应用的标题栏可见；
* 从底部向上滑动，在全屏应用中显示任务栏。

## Internet Explorer技巧

### '图片工具栏'

点击图片时，在图片左上角出现的工具栏。您将能够保存、打印、邮件、在资源管理器中打开"我的图片"。Kiosk需要使用Internet Explorer。

### Shell协议

输入这些URL以获得资源管理器视图：

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

使用JavaScript创建一个常见对话框并访问文件资源管理器：`document.write('<input/type=file>')`
来源：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## 手势和底部按钮

### 四指或五指向上滑动 / 双击Home按钮

查看多任务视图并更换应用程序

### 四指或五指向一个方向滑动

切换到下一个/上一个应用程序

### 五指捏合屏幕 / 触摸Home按钮 / 从屏幕底部快速向上滑动一指

访问主页

### 一指从屏幕底部慢慢滑动1-2英寸

将出现dock

### 一指从屏幕顶部向下滑动

查看您的通知

### 一指从屏幕右上角向下滑动

查看iPad Pro的控制中心

### 一指从屏幕左侧滑动1-2英寸

查看今日视图

### 一指从屏幕中心快速向右或左滑动

切换到下一个/上一个应用程序

### 按住iPad右上角的开/关/休眠按钮 + 将滑动电源关闭滑块全部滑到右侧，

关闭电源

### 同时按iPad右上角的开/关/休眠按钮和Home按钮几秒钟

强制硬关闭电源

### 快速按iPad右上角的开/关/休眠按钮和Home按钮

拍摄屏幕截图，它会出现在显示屏的左下角。同时非常短暂地按下两个按钮，因为如果您按住它们几秒钟，将执行硬关闭电源。

## 快捷键

您应该有一个iPad键盘或USB键盘适配器。这里只会显示有助于从应用程序逃离的快捷键。

| 键  | 名称         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

### 系统快捷键

这些快捷键用于视觉设置和声音设置，取决于iPad的使用。

| 快捷键 | 动作                                                                         |
| ------ | ---------------------------------------------------------------------------- |
| F1     | 调暗屏幕                                                                     |
| F2     | 提高屏幕亮度                                                                 |
| F7     | 上一首歌曲                                                                   |
| F8     | 播放/暂停                                                                    |
| F9     | 跳过歌曲                                                                     |
| F10    | 静音                                                                         |
| F11    | 减小音量                                                                     |
| F12    | 增加音量                                                                     |
| ⌘ Space| 显示可用语言列表；要选择一种语言，再次点击空格键。                             |

### iPad导航

| 快捷键                                             | 动作                                                  |
| -------------------------------------------------- | ----------------------------------------------------- |
| ⌘H                                                 | 回到主页                                              |
| ⌘⇧H (Command-Shift-H)                              | 回到主页                                              |
| ⌘ (Space)                                          | 打开Spotlight                                         |
| ⌘⇥ (Command-Tab)                                   | 列出最近使用的十个应用程序                            |
| ⌘\~                                                | 转到上一个应用程序                                    |
| ⌘⇧3 (Command-Shift-3)                              | 截屏（悬浮在左下角以保存或操作）                      |
| ⌘⇧4                                                | 截屏并在编辑器中打开                                  |
| 长按⌘                                              | 列出应用程序可用的快捷键列表                          |
| ⌘⌥D (Command-Option/Alt-D)                         | 显示dock                                              |
| ^⌥H (Control-Option-H)                             | Home按钮                                              |
| ^⌥H H (Control-Option-H-H)                         | 显示多任务栏                                          |
| ^⌥I (Control-Option-i)                             | 项目选择器                                            |
| Escape                                             | 返回按钮                                              |
| → (右箭头)                                         | 下一个项目                                            |
| ← (左箭头)                                         | 上一个项目                                            |
| ↑↓ (上箭头, 下箭头)                                | 同时点击选中的项目                                    |
| ⌥ ↓ (Option-Down arrow)                            | 向下滚动                                              |
| ⌥↑ (Option-Up arrow)                               | 向上滚动                                              |
| ⌥← 或 ⌥→ (Option-Left arrow 或 Option-Right arrow) | 向左或向右滚动                                        |
| ^⌥S (Control-Option-S)                             | 打开或关闭VoiceOver语音                               |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 切换到上一个应用程序                                  |
| ⌘⇥ (Command-Tab)                                   | 切换回原来的应用程序                                  |
| ←+→, 然后 Option + ← 或 Option+→                   | 在Dock中导航                                          |

### Safari快捷键

| 快捷键                  | 动作                                             |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 打开位置                                         |
| ⌘T                      | 打开新标签页                                     |
| ⌘W                      | 关闭当前标签页                                   |
| ⌘R                      | 刷新当前标签页                                   |
| ⌘.                      | 停止加载当前标签页                               |
| ^⇥                      | 切换到下一个标签页                               |
| ^⇧⇥ (Control-Shift-Tab) | 移动到上一个标签页                               |
| ⌘L                      | 选择文本输入/URL字段以修改它                     |
| ⌘⇧T (Command-Shift-T)   | 打开最后关闭的标签页（可以多次使用）             |
| ⌘\[                     | 在浏览历史中后退一页                             |
| ⌘]                      | 在浏览历史中前进一页                             |
| ⌘⇧R                     | 激活阅读模式                                     |

### 邮件快捷键

| 快捷键                     | 动作                       |
| -------------------------- | -------------------------- |
| ⌘L                         | 打开位置                   |
| ⌘T                         | 打开新标签
