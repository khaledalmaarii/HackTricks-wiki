# macOS自动启动位置

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

本节内容主要基于博客系列[**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)，目标是添加更多的**自动启动位置**（如果可能的话），指出最新版本的macOS（13.4）中仍然有效的技术，并指定所需的**权限**。

### Launchd

#### 位置

* **`/Library/LaunchAgents`**
* **触发器**：重启
* 需要Root权限
* **`/Library/LaunchDaemons`**
* **触发器**：重启
* 需要Root权限
* **`/System/Library/LaunchAgents`**
* **触发器**：重启
* 需要Root权限
* **`/System/Library/LaunchDaemons`**
* **触发器**：重启
* 需要Root权限
* **`~/Library/LaunchAgents`**
* **触发器**：重新登录
* **`~/Library/LaunchDemons`**
* **触发器**：重新登录

#### 描述和有效载荷

**`launchd`**是在启动时由OS X内核执行的**第一个进程**，也是在关机时最后一个完成的进程。它应该始终具有**PID 1**。此进程将**读取和执行**在以下位置的**ASEP** **plists**中指定的配置：

* `/Library/LaunchAgents`：由管理员安装的每个用户代理
* `/Library/LaunchDaemons`：由管理员安装的系统级守护程序
* `/System/Library/LaunchAgents`：由Apple提供的每个用户代理。
* `/System/Library/LaunchDaemons`：由Apple提供的系统级守护程序。

当用户登录时，位于`/Users/$USER/Library/LaunchAgents`和`/Users/$USER/Library/LaunchDemons`的plists将以**登录用户的权限**启动。

**代理和守护程序的主要区别在于代理在用户登录时加载，而守护程序在系统启动时加载**（因为有一些服务（如ssh）需要在任何用户访问系统之前执行）。此外，代理可以使用GUI，而守护程序需要在后台运行。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
有些情况下，需要在用户登录之前执行代理程序，这些被称为**PreLoginAgents**。例如，这在登录时提供辅助技术时非常有用。它们也可以在`/Library/LaunchAgents`中找到（参见[**这里**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)的示例）。

{% hint style="info" %}
新的守护程序或代理程序配置文件将在下次重启后加载，或使用`launchctl load <target.plist>`命令加载。也可以使用`launchctl -F <file>`加载没有扩展名的.plist文件（但这些plist文件在重启后不会自动加载）。
也可以使用`launchctl unload <target.plist>`命令卸载（指向它的进程将被终止）。

为了确保没有任何东西（如覆盖）阻止代理程序或守护程序运行，请运行：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

列出当前用户加载的所有代理程序和守护程序：
```bash
launchctl list
```
### shell启动文件

写作：[https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
写作（xterm）：[https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### 位置

* **`~/.zshrc`，`~/.zlogin`，`~/.zshenv`，`~/.zprofile`**
* **触发条件**：使用zsh打开终端
* **`/etc/zshenv`，`/etc/zprofile`，`/etc/zshrc`，`/etc/zlogin`**
* **触发条件**：使用zsh打开终端
* 需要root权限
* **`~/.zlogout`**
* **触发条件**：使用zsh退出终端
* **`/etc/zlogout`**
* **触发条件**：使用zsh退出终端
* 需要root权限
* 可能还有其他位置：**`man zsh`**
* **`~/.bashrc`**
* **触发条件**：使用bash打开终端
* `/etc/profile`（未生效）
* `~/.profile`（未生效）
* `~/.xinitrc`，`~/.xserverrc`，`/opt/X11/etc/X11/xinit/xinitrc.d/`
* **触发条件**：预期与xterm一起触发，但**未安装**，即使安装后也会出现以下错误：xterm：`DISPLAY未设置`

#### 描述

当我们的shell环境（如`zsh`或`bash`）**启动**时，会执行shell启动文件。现在，macOS默认使用`/bin/zsh`，每当我们打开`Terminal`或通过SSH连接到设备时，我们都会进入这个shell环境。`bash`和`sh`仍然可用，但必须明确启动。

我们可以使用**`man zsh`**阅读zsh的man页面，其中有关于启动文件的详细描述。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

#### 位置

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **触发条件**: 打开 iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **触发条件**: 打开 iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **触发条件**: 打开 iTerm

#### 描述

存储在 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** 中的脚本将被执行。例如：
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
脚本 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 也将被执行：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2偏好设置位于**`~/Library/Preferences/com.googlecode.iterm2.plist`**，可以在iTerm2终端打开时**指示要执行的命令**。

可以在iTerm2设置中配置此设置：

<figure><img src="../.gitbook/assets/image.png" alt="" width="563"><figcaption></figcaption></figure>

命令会反映在偏好设置中：
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
您可以使用以下命令设置要执行的命令：

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
很有可能有其他方法可以滥用iTerm2的偏好设置来执行任意命令。
{% endhint %}

### 重新打开的应用程序

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

#### 位置

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **触发器**: 重新启动时重新打开应用程序

#### 描述和利用

所有要重新打开的应用程序都在plist文件`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`中。

因此，要使重新打开的应用程序启动您自己的应用程序，您只需要**将您的应用程序添加到列表中**。

可以通过列出该目录或使用`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`来找到UUID。

要检查将要重新打开的应用程序，可以执行以下操作：
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
要将应用程序添加到此列表中，您可以使用以下方法：
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
{% hint style="danger" %}
添加上一节的内容并注销并重新登录，甚至重新启动都无法让我执行该应用程序。（该应用程序没有被执行，可能需要在执行这些操作时保持运行状态）
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

#### 位置

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* 需要root权限才能直接写入。如果可以执行`crontab <file>`则不需要root权限。
* **触发条件**：取决于cron作业

#### 描述和利用

使用以下命令列出**当前用户**的cron作业：
```bash
crontab -l
```
您还可以在**`/usr/lib/cron/tabs/`**和**`/var/at/tabs/`**（需要root权限）中查看用户的所有cron作业。

在MacOS中，可以找到以**特定频率**执行脚本的几个文件夹：
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在这里，您可以找到常规的cron作业、at作业（不常用）和周期性作业（主要用于清理临时文件）。例如，可以使用`periodic daily`来执行每日周期性作业。

要以编程方式添加用户cron作业，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### 周期性

Writeup: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

#### 位置

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* 需要 root 权限
* **触发条件**：时间到达时
* `/etc/daily.local`, `/etc/weekly.local` 或 `/etc/monthly.local`
* 需要 root 权限
* **触发条件**：时间到达时

#### 描述和利用

周期性脚本（**`/etc/periodic`**）是由在 `/System/Library/LaunchDaemons/com.apple.periodic*` 中配置的**启动守护程序**执行的。请注意，存储在 `/etc/periodic/` 中的脚本将以**文件的所有者身份**执行，因此这对于潜在的特权升级无效。

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

还有其他定期脚本将在 **`/etc/defaults/periodic.conf`** 中执行：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
如果你成功写入文件`/etc/daily.local`、`/etc/weekly.local`或`/etc/monthly.local`，它们将会**在早晚某个时候被执行**。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

#### 位置

* 必须具备 root 权限

#### 描述

由于 PAM 更加关注在 macOS 中的**持久性**和恶意软件，本文不会详细解释，**请阅读 writeup 以更好地理解这个技术**。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

#### 位置

* **`~/.ssh/rc`**
* **触发条件**：通过 SSH 登录
* **`/etc/ssh/sshrc`**
* 需要 root 权限
* **触发条件**：通过 SSH 登录

#### 描述

默认情况下，除非在`/etc/ssh/sshd_config`中设置了`PermitUserRC no`，当用户通过 SSH 登录时，脚本`/etc/ssh/sshrc`和`~/.ssh/rc`将被执行。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

#### 位置

* **`~/Library/Application\ Support/xbar/plugins/`**
* **触发条件**：xbar 启动时

#### 描述

如果安装了流行的程序 [**xbar**](https://github.com/matryer/xbar)，可以在**`~/Library/Application\ Support/xbar/plugins/`**中编写一个 shell 脚本，在 xbar 启动时执行该脚本：
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**写作**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

#### 位置

* **`~/.hammerspoon/init.lua`**
* **触发器**: 一旦执行 Hammerspoon

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一个自动化工具，允许通过 LUA 脚本语言进行 macOS 脚本编写。我们甚至可以嵌入完整的 AppleScript 代码以及运行 shell 脚本。

该应用程序寻找一个名为 `~/.hammerspoon/init.lua` 的单个文件，并在启动时执行该脚本。
```bash
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("id > /tmp/hs.txt")
EOF
```
### 首选项面板

写作：[https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

#### 位置

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### 描述

看起来这个方法已经不再起作用了。

### Spotlight 导入器

写作：[https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

#### 位置

* **`/Library/Spotlight`**&#x20;
* **`~/Library/Spotlight`**

#### 描述

你将进入一个**严格的沙盒**，所以你可能不想使用这个技术。

### 音频插件

写作：[https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
写作：[https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

#### 位置

* **`/Library/Audio/Plug-Ins/HAL`**
* 需要 root 权限
* **触发器**：重新启动 coreaudiod 或计算机
* **`/Library/Audio/Plug-ins/Components`**
* 需要 root 权限
* **触发器**：重新启动 coreaudiod 或计算机
* **`~/Library/Audio/Plug-ins/Components`**
* **触发器**：重新启动 coreaudiod 或计算机
* **`/System/Library/Components`**
* 需要 root 权限
* **触发器**：重新启动 coreaudiod 或计算机

#### 描述

根据之前的写作，可以**编译一些音频插件**并加载它们。

### 文件夹操作

写作：[https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
写作：[https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

#### 位置

* `/Library/Scripts/Folder Action Scripts`
* 需要 root 权限
* `~/Library/Scripts/Folder Action Scripts`

#### 描述和利用

当附加了文件夹操作脚本的文件夹中添加或删除项目，或者打开、关闭、移动或调整其窗口时，将执行文件夹操作脚本：

* 通过 Finder UI 打开文件夹
* 向文件夹中添加文件（可以通过拖放或甚至在终端的 shell 提示符中完成）
* 从文件夹中删除文件（可以通过拖放或甚至在终端的 shell 提示符中完成）
* 通过 UI 导航离开文件夹

有几种实现方法：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 程序创建一个文件夹操作工作流文件（.workflow）并将其安装为服务。
2. 右键单击文件夹，选择“文件夹操作设置...”，“运行服务”，并手动附加脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以编程方式查询和注册新的“文件夹操作”。

* 这是使用 OSAScript 实现持久性的方法，通过向 `System Events.app` 发送 Apple Event 消息。

将执行以下脚本：

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

使用以下命令编译：`osacompile -l JavaScript -o folder.scpt source.js`

然后执行以下脚本以启用文件夹操作，并将先前编译的脚本附加到文件夹 **`/users/username/Desktop`**：
```javascript
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
使用以下命令执行脚本：`osascript -l JavaScript /Users/carlospolop/attach.scpt`



* 这是通过GUI实现持久性的方法：

将执行以下脚本：

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

使用以下命令进行编译：`osacompile -l JavaScript -o folder.scpt source.js`

将其移动到：
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
然后，打开`Folder Actions Setup`应用程序，选择您想要监视的**文件夹**，并在您的情况下选择**`folder.scpt`**（在我的情况下，我称其为output2.scp）：

<figure><img src="../.gitbook/assets/image (2).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果您使用**Finder**打开该文件夹，您的脚本将被执行。

此配置以base64格式存储在位于**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**的**plist**中。

现在，让我们尝试在没有GUI访问权限的情况下准备此持久性：

1. **将`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**复制到`/tmp`进行备份：
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **删除**您刚刚设置的文件夹操作：

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

现在，我们有了一个空的环境

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开Folder Actions Setup.app以使用此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
对我来说，这没有起作用，但这是写作的说明:( 
{% endhint %}

### Dock快捷方式

写作：[https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

#### 位置

* `~/Library/Preferences/com.apple.dock.plist`
* **触发器**：当用户在Dock中点击应用程序时

#### 描述和利用

Dock中显示的所有应用程序都在plist文件中指定：**`~/Library/Preferences/com.apple.dock.plist`**

可以使用以下命令**添加一个应用程序**：

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

### emond

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

我在我的 macOS 中找不到这个组件，所以要获取更多信息，请查看 writeup。

### QuickLook 插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

#### 位置

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述和利用

当你**触发文件的预览**（在 Finder 中选择文件后按下空格键）并且安装了**支持该文件类型的插件**时，QuickLook 插件会被执行。

你可以编译自己的 QuickLook 插件，将其放置在上述位置之一以加载它，然后转到支持的文件并按下空格键来触发它。

### 授权插件

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

#### 位置

* `/Library/Security/SecurityAgentPlugins/`
* 需要 root 权限
* 还需要&#x20;

#### 描述和利用

待定

### 调色器

Writeup: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

#### 位置

* `/Library/ColorPickers`&#x20;
* 需要 root 权限
* 触发方式：使用调色器
* `~/Library/ColorPickers`
* 触发方式：使用调色器

#### 描述和利用

使用你的代码编译一个调色器 bundle（你可以使用[**这个作为例子**](https://github.com/viktorstrate/color-picker-plus)），并添加一个构造函数（就像[屏幕保护程序部分](macos-auto-start-locations.md#screen-saver)中的那样），然后将 bundle 复制到 `~/Library/ColorPickers`。

然后，当触发调色器时，你的代码也应该被触发。

请注意，加载你的库的二进制文件有一个**非常严格的沙盒**：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### XQuartz

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### 位置

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* 需要root权限
* **触发条件**：使用XQuartz

#### 描述和利用

XQuartz在macOS中**不再安装**，如果您想获取更多信息，请查看writeup。

### kext

要将KEXT安装为启动项，它需要**安装在以下位置之一**：

* `/System/Library/Extensions`
* 内置于OS X操作系统中的KEXT文件。
* `/Library/Extensions`
* 第三方软件安装的KEXT文件

您可以使用以下命令列出当前加载的kext文件：
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
有关[**内核扩展的更多信息，请查看此部分**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers)。

### amstoold

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### 位置

* **`/usr/local/bin/amstoold`**
* 需要 root 权限

#### 描述和利用

显然，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 使用了这个二进制文件，同时暴露了一个 XPC 服务...问题是该二进制文件不存在，因此你可以将某个东西放在那里，当调用 XPC 服务时，你的二进制文件将被调用。

我在我的 macOS 中找不到这个文件了。

### xsanctl

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### 位置

* **`/Library/Preferences/Xsan/.xsanrc`**
* 需要 root 权限
* **触发条件**：运行服务（很少发生）

#### 描述和利用

显然，运行此脚本并不常见，我甚至在我的 macOS 中找不到它，所以如果你想获取更多信息，请查看 writeup。

### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

#### 位置

* `/System/Library/Screen Savers`&#x20;
* 需要 root 权限
* **触发条件**：选择屏幕保护程序
* `/Library/Screen Savers`
* 需要 root 权限
* **触发条件**：选择屏幕保护程序
* `~/Library/Screen Savers`
* **触发条件**：选择屏幕保护程序

<figure><img src="../.gitbook/assets/image (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述和利用

在 Xcode 中创建一个新项目，并选择模板生成一个新的**屏幕保护程序**。然后，将代码添加到其中，例如以下代码以生成日志。

**构建**它，并将 `.saver` 捆绑包复制到 **`~/Library/Screen Savers`**。然后，打开屏幕保护程序 GUI，如果你只是点击它，它应该生成大量的日志：

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
请注意，由于在加载此代码的二进制文件（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）的权限中，您可以找到**`com.apple.security.app-sandbox`**，因此您将位于**常见应用程序沙盒**中。
{% endhint %}

屏幕保护程序代码：
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### **登录项**

写作：[https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

#### 位置

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **触发器：**登录
* 利用负载存储调用**`osascript`**
* TODO：找到一种直接在磁盘中执行的方法（如果有的话）
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **触发器：**登录
* 需要 root 权限

#### 描述

在系统偏好设置 -> 用户与群组 -> **登录项** 中，您可以找到用户登录时要执行的**项目**。\
可以通过命令行列出、添加和删除它们：
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
这些项目存储在文件**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**中。

**登录项**也可以使用API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc)来指示，在这种情况下，配置将存储在**`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**中。

### 将ZIP文件作为登录项

如果将**ZIP**文件存储为**登录项**，则**`Archive Utility`**将打开它，如果ZIP文件例如存储在**`~/Library`**中，并且包含具有后门的文件夹**`LaunchAgents/file.plist`**，那么该文件夹将被创建（默认情况下不会创建），并且plist将被添加，因此下次用户再次登录时，将执行plist中指定的**后门**。

另一个选项是在用户主目录中创建文件**`.bash_profile`**和**`.zshenv`**，因此如果文件夹LaunchAgents已经存在，此技术仍将起作用。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

#### 位置

* 需要**执行** **`at`** 并且必须**启用**

#### **描述**

“At tasks”用于**在特定时间安排任务**。\
这些任务与cron不同，它们是**一次性任务**，在执行后会被删除。但是，它们将**在系统重启后保留**，因此不能将其排除为潜在威胁。

默认情况下，它们是**禁用的**，但**root**用户可以使用以下命令**启用**它们：
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
这将在1小时内创建一个文件：
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
使用 `atq` 命令来检查作业队列：
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上面我们可以看到两个已计划的任务。我们可以使用 `at -c JOBNUMBER` 命令打印任务的详细信息。
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
如果未启用 AT 任务，则创建的任务将不会被执行。
{% endhint %}

**作业文件**可以在 `/private/var/at/jobs/` 找到。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
文件名包含队列、作业编号和计划运行时间的信息。例如，让我们看看`a0001a019bdcd2`。

* `a` - 这是队列
* `0001a` - 十六进制的作业编号，`0x1a = 26`
* `019bdcd2` - 十六进制的时间。它表示自纪元以来经过的分钟数。`0x019bdcd2`在十进制中是`26991826`。如果我们将其乘以60，我们得到`1619509560`，即`GMT: 2021年4月27日，星期二7:46:00`。

如果我们打印作业文件，我们会发现它包含了我们使用`at -c`得到的相同信息。

### 登录/注销钩子

**文档**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

#### 位置

* 您需要能够执行类似于`defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`的命令

它们已被弃用，但仍可用于在用户登录时执行命令。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
这个设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` 文件中。
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
要删除它：
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
**根用户**的自动启动位置存储在**`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**中。

{% hint style="danger" %}
对我来说，这个方法不起作用，无论是使用用户LoginHook还是根用户LoginHook。
{% endhint %}

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

#### 位置

* **`/etc/apache2/httpd.conf`**
* 需要根权限
* 触发条件：当启动Apache2时

#### 描述和利用方法

您可以在`/etc/apache2/httpd.conf`中指示加载模块，添加一行代码，例如：
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

这样，您编译的模块将由Apache加载。唯一的问题是，您需要使用有效的Apple证书进行签名，或者您需要在系统中添加一个新的受信任的证书并使用它进行签名。

然后，如果需要确保服务器启动，您可以执行以下操作：
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb的代码示例：
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### Finder Sync插件

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

#### 位置

* 特定的应用程序

#### 描述和利用

一个应用程序示例，其中包含一个Finder Sync扩展[**可以在这里找到**](https://github.com/D00MFist/InSync)。

应用程序可以拥有`Finder Sync扩展`。这个扩展将放在将要执行的应用程序中。此外，为了使扩展能够执行其代码，它**必须使用一些有效的苹果开发者证书进行签名**，它必须**被沙盒化**（尽管可以添加放宽的例外），并且必须注册到类似以下的东西中：
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### BSM审计框架

写作：[https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

#### 位置

* **`/etc/security/audit_warn`**
* 需要Root权限
* **触发条件**：当auditd检测到警告时

#### 描述和利用

每当auditd检测到警告时，脚本**`/etc/security/audit_warn`**会被**执行**。因此，您可以在其中添加您的有效负载。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
您可以使用`sudo audit -n`来强制发出警告。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

#### 位置

* **`/private/etc/man.conf`**
* 需要root权限
* **`/private/etc/man.conf`**: 每当使用man命令时

#### 描述和利用

配置文件**`/private/etc/man.conf`**指示打开man文档文件时要使用的二进制文件/脚本。因此，可以修改可执行文件的路径，以便每当用户使用man命令阅读文档时，将执行一个后门。

例如，在**`/private/etc/man.conf`**中设置：
```
MANPAGER /tmp/view
```
然后创建 `/tmp/view` 文件：
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### 终端

在 **`~/Library/Preferences`** 目录下存储了用户在应用程序中的偏好设置。其中一些偏好设置可以包含执行其他应用程序/脚本的配置。

例如，终端可以在启动时执行一个命令：

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

这个配置会在文件 **`~/Library/Preferences/com.apple.Terminal.plist`** 中反映出来，如下所示：
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
所以，如果系统中终端的偏好设置的plist文件可以被覆盖，那么可以使用`open`功能来打开终端并执行该命令。

您可以通过命令行添加此功能：

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Emond

苹果引入了一种名为**emond**的日志记录机制。看起来它从未完全开发，并且苹果可能已经**放弃**了它以使用其他机制，但它仍然**可用**。

这个鲜为人知的服务对于Mac管理员来说**可能没有太多用处**，但对于威胁行为者来说，一个非常好的理由是将其用作**持久性机制，大多数macOS管理员可能不知道**去寻找。检测到emond的恶意使用不应该很困难，因为该服务的系统LaunchDaemon只会在一个地方寻找要运行的脚本：
```bash
ls -l /private/var/db/emondClients
```
{% hint style="danger" %}
**由于这个不常用，所以该文件夹中的任何内容都应该是可疑的**
{% endhint %}

### 启动项

{% hint style="danger" %}
**这已经被弃用了，所以在以下目录中不应该找到任何内容。**
{% endhint %}

**StartupItem** 是一个被放置在以下两个文件夹之一的 **目录**：`/Library/StartupItems/` 或 `/System/Library/StartupItems/`

在这两个位置之一放置一个新的目录后，还需要在该目录中放置另外两个项目。这两个项目是一个 **rc 脚本** 和一个包含一些设置的 **plist**。这个 plist 必须被命名为 "**StartupParameters.plist**"。

{% tabs %}
{% tab title="StartupParameters.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% tab title="超级服务名称" %}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### /etc/rc.common

{% hint style="danger" %}
**这在现代 MacOS 版本中不起作用**
{% endhint %}

还可以在这里放置**在启动时执行的命令**。以下是一个常规的 rc.common 脚本示例：
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
### 配置文件

配置文件可以强制用户使用特定的浏览器设置、DNS代理设置或VPN设置。还有许多其他的有效载荷可以被滥用。

您可以运行以下命令来枚举它们：
```bash
ls -Rl /Library/Managed\ Preferences/
```
### 其他持久化技术和工具

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
